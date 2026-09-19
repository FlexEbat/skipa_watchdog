"""
Постоянный мониторинг подключений к серверу. Два метода на выбор
(настраивается через monitoring.method в config.yaml):

1. "poll" - периодический опрос активных TCP-соединений напрямую из
   /proc/net/tcp и /proc/net/tcp6 (без сторонних библиотек вроде psutil -
   это просто текстовые файлы, которые ядро Linux и так ведёт). Работает
   "из коробки" без дополнительной настройки, но может пропускать очень
   короткие TCP-сессии (одиночный SYN от zmap/zgrab, который сразу рвётся
   RST) - именно так часто ведёт себя Skipa.

2. "kernel_log" - хвостует `journalctl -k -f` и ищет строки лога nftables/
   iptables (правило с `log prefix "CONN: "`), парсит SRC=/DPT= из каждой
   записи. Ловит вообще любой входящий SYN, независимо от того, успело ли
   соединение дойти до ESTABLISHED. Требует настройки nftables/iptables -
   см. README.md, раздел "Расширенный мониторинг через nftables".

3. "both" - оба метода одновременно (два независимых asyncio-таска),
   антиспам-кулдаун общий на IP, так что дублей алертов не будет.

Оба метода в итоге вызывают один и тот же on_hit(Hit) callback, поэтому
вся остальная цепочка (обогащение -> блокировка -> уведомление) не
зависит от источника события.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import time
from dataclasses import dataclass

from .ip_lists import ThreatDB

log = logging.getLogger("skipa_watchdog.monitor")

# Пример строки лога netfilter, которую парсим:
# CONN: IN=eth0 OUT= MAC=... SRC=203.0.113.42 DST=203.0.113.10 LEN=60 TOS=0x00
# PREC=0x00 TTL=63 ID=12345 DF PROTO=TCP SPT=54321 DPT=80 WINDOW=... SYN
_SRC_RE = re.compile(r"SRC=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
_DPT_RE = re.compile(r"DPT=(\d+)")

# /proc/net/tcp(6): столбец state, интересуют реально живые соединения.
# 01=ESTABLISHED, 02=SYN_SENT, 03=SYN_RECV - соединение уже видно по remote-адресу.
_LIVE_TCP_STATES = {"01", "02", "03"}


@dataclass
class Hit:
    ip: str
    matched_source: str
    local_port: int | None
    method: str = "poll"


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
# Метод 1: опрос /proc/net/tcp(4/6) - без сторонних зависимостей
# ---------------------------------------------------------------------------

def _hex_to_ip_port(hex_addr: str, ipv6: bool) -> tuple[str, int] | None:
    """Разбирает поле вида 'ADDR:PORT' из /proc/net/tcp(6), где ADDR -
    little-endian hex (по 32-битным словам для IPv6)."""
    try:
        ip_hex, port_hex = hex_addr.split(":")
        port = int(port_hex, 16)
        raw = bytes.fromhex(ip_hex)
        if ipv6:
            # 16 байт = 4 слова по 4 байта, каждое слово little-endian
            packed = b"".join(raw[i : i + 4][::-1] for i in range(0, 16, 4))
            ip = ipaddress.IPv6Address(packed).compressed
        else:
            packed = raw[::-1]
            ip = ipaddress.IPv4Address(packed).compressed
        return ip, port
    except (ValueError, IndexError):
        return None


def _read_live_tcp_connections() -> list[tuple[str, int, int | None]]:
    """Читает /proc/net/tcp и /proc/net/tcp6, возвращает список
    (remote_ip, remote_port, local_port) для соединений с непустым удалённым
    адресом. Не требует прав root - в отличие от опроса чужих сокетов через
    psutil, /proc/net/tcp(6) и так виден любому процессу в том же network
    namespace."""
    results: list[tuple[str, int, int | None]] = []
    for path, ipv6 in (("/proc/net/tcp", False), ("/proc/net/tcp6", True)):
        try:
            with open(path, encoding="ascii", errors="replace") as f:
                next(f, None)  # пропускаем заголовок
                for line in f:
                    parts = line.split()
                    if len(parts) < 3:
                        continue
                    if parts[3] not in _LIVE_TCP_STATES:
                        continue
                    remote = _hex_to_ip_port(parts[2], ipv6)
                    if remote is None or remote[1] == 0:
                        continue
                    local = _hex_to_ip_port(parts[1], ipv6)
                    results.append((remote[0], remote[1], local[1] if local else None))
        except FileNotFoundError:
            continue  # система без IPv6 (или без tcp вовсе) - не ошибка
        except OSError as e:
            log.debug("Не удалось прочитать %s: %s", path, e)
    return results


async def poll_connections_loop(
    get_db,
    ignore_networks,
    poll_interval: int,
    dedup: Deduper,
    on_hit,
):
    """Каждые poll_interval секунд смотрит активные TCP-соединения и сверяет
    удалённые IP с базой угроз. get_db() возвращает текущий ThreatDB (чтобы
    подхватывать обновления базы на лету)."""

    log.info("Мониторинг соединений (poll /proc/net/tcp) запущен, интервал опроса: %ss", poll_interval)

    while True:
        try:
            db: ThreatDB = get_db()
            if db is not None and (db.networks or db.ranges):
                seen_this_round = set()
                # чтение /proc - блокирующий файловый ввод-вывод, но по факту это
                # быстрая операция с виртуальной файловой системой, отдельный
                # поток ради неё не нужен
                for remote_ip, _remote_port, local_port in _read_live_tcp_connections():
                    if remote_ip in seen_this_round or _is_ignored(remote_ip, ignore_networks):
                        continue

                    matched = db.match(remote_ip)
                    if not matched:
                        continue
                    seen_this_round.add(remote_ip)

                    if not dedup.should_alert(remote_ip):
                        continue

                    hit = Hit(ip=remote_ip, matched_source=matched, local_port=local_port, method="poll")
                    log.warning(
                        "[poll] Подключение от известного сканера: %s (совпадение: %s, порт: %s)",
                        remote_ip, matched, local_port,
                    )
                    await on_hit(hit)
        except Exception as e:  # noqa: BLE001
            log.exception("Ошибка в цикле мониторинга (poll): %s", e)

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
