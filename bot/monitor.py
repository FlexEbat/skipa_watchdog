"""
Постоянный мониторинг подключений к серверу. Два метода на выбор
(настраивается через monitoring.method в config.yaml):

1. "psutil" - опрос активных сетевых соединений через psutil.net_connections().
   Работает "из коробки" без дополнительной настройки, но может пропускать
   очень короткие TCP-сессии (одиночный SYN от zmap/zgrab, который сразу
   рвётся RST) - именно так часто ведёт себя Skipa.

2. "kernel_log" - хвостует `journalctl -k -f` и ищет строки лога nftables/
   iptables (правило с `log prefix "CONN: "`), парсит SRC=/DPT= из каждой
   записи. Ловит вообще любой входящий SYN, независимо от того, успело ли
   соединение дойти до ESTABLISHED. Требует настройки nftables/iptables -
   см. README.md, раздел "Расширенный мониторинг через nftables".

3. "both" - оба метода одновременно (два независимых asyncio-таска),
   антиспам-кулдаун общий на IP, так что дублей алертов не будет.

Оба метода в итоге вызывают один и тот же on_hit(Hit) callback, поэтому
вся остальная цепочка (обогащение -> форматирование -> отправка в Telegram)
не зависит от источника события.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import time
from dataclasses import dataclass

import psutil

from .ip_lists import ThreatDB

log = logging.getLogger("skipa_watchdog.monitor")

# Пример строки лога netfilter, которую парсим:
# CONN: IN=eth0 OUT= MAC=... SRC=203.0.113.42 DST=203.0.113.10 LEN=60 TOS=0x00
# PREC=0x00 TTL=63 ID=12345 DF PROTO=TCP SPT=54321 DPT=80 WINDOW=... SYN
_SRC_RE = re.compile(r"SRC=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
_DPT_RE = re.compile(r"DPT=(\d+)")


@dataclass
class Hit:
    ip: str
    matched_source: str
    local_port: int | None
    method: str = "psutil"


def _is_ignored(ip: str, ignore_networks) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return any(ip_obj in net for net in ignore_networks)


class Deduper:
    """Общий антиспам-кулдаун на IP, разделяется между всеми методами мониторинга."""

    def __init__(self, cooldown_minutes: int):
        self._cooldown_seconds = cooldown_minutes * 60
        self._last_alert: dict[str, float] = {}

    def should_alert(self, ip: str) -> bool:
        now = time.time()
        last = self._last_alert.get(ip, 0)
        if now - last < self._cooldown_seconds:
            return False
        self._last_alert[ip] = now
        return True


# ---------------------------------------------------------------------------
# Метод 1: опрос через psutil
# ---------------------------------------------------------------------------

async def poll_connections_loop(
    get_db,
    ignore_networks,
    poll_interval: int,
    dedup: Deduper,
    on_hit,
):
    """Каждые poll_interval секунд смотрит активные inet-соединения и сверяет
    удалённые IP с базой угроз. get_db() возвращает текущий ThreatDB (чтобы
    подхватывать еженедельные обновления на лету)."""

    log.info("Мониторинг соединений (psutil) запущен, интервал опроса: %ss", poll_interval)

    while True:
        try:
            db: ThreatDB = get_db()
            if db is not None and (db.networks or db.ranges):
                seen_this_round = set()
                for conn in psutil.net_connections(kind="inet"):
                    if not conn.raddr:
                        continue
                    remote_ip = conn.raddr.ip
                    if remote_ip in seen_this_round or _is_ignored(remote_ip, ignore_networks):
                        continue

                    matched = db.match(remote_ip)
                    if not matched:
                        continue
                    seen_this_round.add(remote_ip)

                    if not dedup.should_alert(remote_ip):
                        continue

                    local_port = conn.laddr.port if conn.laddr else None
                    hit = Hit(ip=remote_ip, matched_source=matched, local_port=local_port, method="psutil")
                    log.warning(
                        "[psutil] Подключение от известного сканера: %s (совпадение: %s, порт: %s)",
                        remote_ip, matched, local_port,
                    )
                    await on_hit(hit)
        except psutil.AccessDenied:
            log.error(
                "Недостаточно прав для чтения сетевых соединений (psutil.AccessDenied). "
                "Запустите бота от root либо через systemd с нужными capabilities."
            )
        except Exception as e:  # noqa: BLE001
            log.exception("Ошибка в цикле мониторинга (psutil): %s", e)

        await asyncio.sleep(poll_interval)


# ---------------------------------------------------------------------------
# Метод 2: хвостование kernel-лога (nftables/iptables LOG)
# ---------------------------------------------------------------------------

async def tail_kernel_log_loop(
    get_db,
    ignore_networks,
    dedup: Deduper,
    on_hit,
    log_prefix: str = "CONN: ",
    command: list[str] | None = None,
):
    """
    Запускает `journalctl -k -f -o cat` (или произвольную command) как
    подпроцесс, построчно читает stdout, ищет строки с log_prefix и
    вытаскивает SRC=/DPT= регуляркой. При падении подпроцесса - перезапуск
    с небольшой паузой (например, после `journalctl` перезапуска systemd-journald).
    """
    if command is None:
        # -o cat: только "голое" сообщение без метаданных journald, так проще парсить
        # -f: следить за новыми записями (аналог tail -f)
        # -n 0: не показывать историю при старте, только новые события
        command = ["journalctl", "-k", "-f", "-n", "0", "-o", "cat"]

    log.info("Мониторинг соединений (kernel_log) запущен: %s", " ".join(command))

    while True:
        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )

            while True:
                line_bytes = await proc.stdout.readline()
                if not line_bytes:
                    # процесс завершился (например journald перезапустился) - выходим
                    # из внутреннего цикла, чтобы пересоздать подпроцесс
                    log.warning("journalctl -k -f неожиданно завершился, перезапускаю через 5с")
                    break

                line = line_bytes.decode(errors="replace").strip()
                if log_prefix not in line:
                    continue

                src_match = _SRC_RE.search(line)
                if not src_match:
                    continue
                remote_ip = src_match.group(1)

                if _is_ignored(remote_ip, ignore_networks):
                    continue

                db: ThreatDB = get_db()
                if db is None or not (db.networks or db.ranges):
                    continue

                matched = db.match(remote_ip)
                if not matched:
                    continue

                if not dedup.should_alert(remote_ip):
                    continue

                dpt_match = _DPT_RE.search(line)
                local_port = int(dpt_match.group(1)) if dpt_match else None

                hit = Hit(ip=remote_ip, matched_source=matched, local_port=local_port, method="kernel_log")
                log.warning(
                    "[kernel_log] SYN от известного сканера: %s (совпадение: %s, порт: %s)",
                    remote_ip, matched, local_port,
                )
                await on_hit(hit)

        except FileNotFoundError:
            log.error(
                "Команда %r не найдена. Убедитесь, что journalctl установлен, "
                "либо задайте monitoring.kernel_log_command в config.yaml (например, "
                "['tail', '-F', '/var/log/kern.log'] для систем с rsyslog вместо journald).",
                command[0],
            )
            await asyncio.sleep(30)
        except Exception as e:  # noqa: BLE001
            log.exception("Ошибка в цикле мониторинга (kernel_log): %s", e)
        finally:
            if proc is not None and proc.returncode is None:
                proc.kill()

        await asyncio.sleep(5)
