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

from .healthcheck import heartbeat
from .ip_lists import ThreatDB, normalize_ip

log = logging.getLogger("skipa_watchdog.monitor")

# Пример строки лога netfilter, которую парсим:
# CONN: IN=eth0 OUT= MAC=... SRC=203.0.113.42 DST=203.0.113.10 LEN=60 TOS=0x00
# PREC=0x00 TTL=63 ID=12345 DF PROTO=TCP SPT=54321 DPT=80 WINDOW=... SYN
_SRC_RE = re.compile(r"SRC=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
_DPT_RE = re.compile(r"DPT=(\d+)")

# /proc/net/tcp(6): столбец state. Интересуют только ВХОДЯЩИЕ соединения:
# 01=ESTABLISHED, 03=SYN_RECV (SYN_SENT=02 - это исходящее подключение самого
# сервера, его раньше тоже считали "сканером", из-за чего можно было заблокировать
# адрес, к которому ходит сам сервер). Входящее - то, у которого локальный порт
# слушается нами (state 0A=LISTEN).
_STATE_ESTABLISHED = "01"
_STATE_SYN_RECV = "03"
_STATE_LISTEN = "0A"
_INBOUND_STATES = {_STATE_ESTABLISHED, _STATE_SYN_RECV}


@dataclass
class Hit:
    ip: str
    matched_source: str
    local_port: int | None
    method: str = "poll"

    @property
    def source_name(self) -> str:
        """Имя базы-источника из matched_source вида "Метка: 1.2.3.0/24"."""
        return self.matched_source.split(": ", 1)[0] if ": " in self.matched_source else ""

    @property
    def matched_cidr(self) -> str:
        """Конкретная сеть/диапазон, по которой совпало."""
        return self.matched_source.split(": ", 1)[1] if ": " in self.matched_source else self.matched_source


def _is_ignored(ip: str, ignore_networks) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return any(ip_obj in net for net in ignore_networks)


class Deduper:
    """Общий антиспам-кулдаун на IP, разделяется между всеми методами мониторинга."""

    _MAX_ENTRIES = 20000

    def __init__(self, cooldown_minutes: int):
        self._cooldown_seconds = cooldown_minutes * 60
        self._last_alert: dict[str, float] = {}

    def should_alert(self, ip: str) -> bool:
        now = time.time()
        last = self._last_alert.get(ip, 0)
        if now - last < self._cooldown_seconds:
            return False
        if len(self._last_alert) >= self._MAX_ENTRIES:
            self._purge(now)
        self._last_alert[ip] = now
        return True

    def penalize_retry(self, ip: str, retry_seconds: int = 60) -> None:
        """Обработка IP не удалась (например, не получилось заблокировать) -
        разрешаем повторную попытку через retry_seconds, а не через весь
        кулдаун."""
        self._last_alert[ip] = time.time() - self._cooldown_seconds + min(
            retry_seconds, self._cooldown_seconds
        )

    def _purge(self, now: float) -> None:
        self._last_alert = {
            k: v for k, v in self._last_alert.items() if now - v < self._cooldown_seconds
        }


async def _dispatch(on_hit, dedup: Deduper, hit: "Hit") -> None:
    """Вызывает on_hit так, чтобы сбой на одном IP не ломал обработку остальных.
    on_hit возвращает False, если не удалось выполнить действие (блокировку) -
    тогда повторная попытка разрешается через минуту."""
    try:
        result = await on_hit(hit)
    except Exception as e:  # noqa: BLE001
        log.exception("Ошибка при обработке %s: %s", hit.ip, e)
        result = False
    if result is False:
        dedup.penalize_retry(hit.ip)


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
            addr6 = ipaddress.IPv6Address(packed)
            # IPv4-клиент на dual-stack сокете выглядит как ::ffff:a.b.c.d -
            # приводим к обычному IPv4, иначе он не совпадёт ни с одним CIDR базы
            ip = addr6.ipv4_mapped.compressed if addr6.ipv4_mapped else addr6.compressed
        else:
            packed = raw[::-1]
            ip = ipaddress.IPv4Address(packed).compressed
        return ip, port
    except (ValueError, IndexError):
        return None


def read_tcp_table() -> list[tuple[str, str, int, int]]:
    """Читает /proc/net/tcp и /proc/net/tcp6, возвращает список
    (state_hex, remote_ip, remote_port, local_port). Не требует прав root -
    /proc/net/tcp(6) виден любому процессу в том же network namespace."""
    results: list[tuple[str, str, int, int]] = []
    for path, ipv6 in (("/proc/net/tcp", False), ("/proc/net/tcp6", True)):
        try:
            with open(path, encoding="ascii", errors="replace") as f:
                next(f, None)  # пропускаем заголовок
                for line in f:
                    parts = line.split()
                    if len(parts) < 4:
                        continue
                    state = parts[3]
                    remote = _hex_to_ip_port(parts[2], ipv6)
                    local = _hex_to_ip_port(parts[1], ipv6)
                    if remote is None or local is None:
                        continue
                    results.append((state, remote[0], remote[1], local[1]))
        except FileNotFoundError:
            continue  # система без IPv6 (или без tcp вовсе) - не ошибка
        except OSError as e:
            log.debug("Не удалось прочитать %s: %s", path, e)
    return results


_CONNTRACK_PATHS = ("/proc/net/nf_conntrack", "/proc/net/ip_conntrack")
_MAX_CONNTRACK_LINES = 300_000


def parse_conntrack_line(line: str) -> tuple[str, int, int] | None:
    """Разбирает строку /proc/net/nf_conntrack для TCP:
        ipv4 2 tcp 6 431999 ESTABLISHED src=1.2.3.4 dst=10.0.0.5 sport=51234 dport=443 ... src=172.17.0.2 ...
    Возвращает (src, sport, dport) ИСХОДНОГО направления, т.е. адрес того, кто
    инициировал соединение. Для трафика на опубликованный порт контейнера
    (DNAT) это внешний клиент - именно то, чего нет в /proc/net/tcp хоста. Для
    исходящих подключений самого сервера src - адрес сервера/контейнера, он в
    базе сканеров не окажется."""
    parts = line.split()
    if len(parts) < 8 or parts[2] != "tcp":
        return None
    src = sport = dport = None
    for token in parts[5:]:
        if token.startswith("src=") and src is None:
            src = token[4:]
        elif token.startswith("sport=") and sport is None:
            sport = token[6:]
        elif token.startswith("dport=") and dport is None:
            dport = token[6:]
        if src and sport and dport:
            break
    if not (src and sport and dport):
        return None
    try:
        return str(normalize_ip(src) or src), int(sport), int(dport)
    except ValueError:
        return None


def read_conntrack() -> list[tuple[str, int, int]]:
    """Входящие TCP-соединения из таблицы conntrack ядра (нужен root и загруженный
    nf_conntrack - при Docker/NAT он всегда есть). Видит и трафик на
    опубликованные порты контейнеров, и уже закрытые коротким сканом соединения
    (записи живут ещё до 2 минут в TIME_WAIT), которые опрос /proc/net/tcp
    пропускает. Если файла нет или нет прав - тихо возвращает пустой список."""
    for path in _CONNTRACK_PATHS:
        try:
            out = []
            with open(path, encoding="ascii", errors="replace") as f:
                for i, line in enumerate(f):
                    if i >= _MAX_CONNTRACK_LINES:
                        break
                    parsed = parse_conntrack_line(line)
                    if parsed:
                        out.append(parsed)
            return out
        except FileNotFoundError:
            continue
        except OSError as e:
            log.debug("Не удалось прочитать %s: %s", path, e)
            return []
    return []


def _inbound_connections(table=None, conntrack=None) -> list[tuple[str, int, int | None]]:
    """(remote_ip, remote_port, local_port) только для ВХОДЯЩИХ соединений:
    состояние ESTABLISHED/SYN_RECV и локальный порт есть среди слушаемых."""
    table = read_tcp_table() if table is None else table
    listen_ports = {lport for state, _ip, _rp, lport in table if state == _STATE_LISTEN}
    result: list[tuple[str, int, int | None]] = [
        (ip, rport, lport)
        for state, ip, rport, lport in table
        if state in _INBOUND_STATES and rport != 0 and lport in listen_ports
    ]
    # conntrack: инициатор соединения (в т.ч. к контейнерам и мимолётные сканы)
    result.extend((ip, sport, dport) for ip, sport, dport in (conntrack or []))
    return result


def established_peers(local_ports: set[int]) -> set[str]:
    """Удалённые IP установленных соединений на заданные локальные порты
    (используется для автодобавления текущих SSH-сессий администратора в
    allowlist, чтобы не отрезать себя от сервера)."""
    peers = set()
    for state, ip, _rp, lport in read_tcp_table():
        if state == _STATE_ESTABLISHED and lport in local_ports:
            peers.add(ip)
    return peers


async def poll_connections_loop(
    get_db,
    ignore_networks,
    poll_interval: int,
    dedup: Deduper,
    on_hit,
    use_conntrack: bool = True,
):
    """Каждые poll_interval секунд смотрит активные TCP-соединения и сверяет
    удалённые IP с базой угроз. get_db() возвращает текущий ThreatDB (чтобы
    подхватывать обновления базы на лету)."""

    log.info(
        "Мониторинг соединений (poll /proc/net/tcp%s) запущен, интервал опроса: %ss",
        " + conntrack" if use_conntrack else "", poll_interval,
    )

    while True:
        heartbeat("poll")  # health-check: цикл жив, даже если ничего не найдено
        try:
            db: ThreatDB = get_db()
            if db is not None and (db.networks or db.ranges):
                checked: set[str] = set()
                # чтение /proc - блокирующий файловый ввод-вывод, но по факту это
                # быстрая операция с виртуальной файловой системой, отдельный
                # поток ради неё не нужен
                conntrack = await asyncio.to_thread(read_conntrack) if use_conntrack else []
                for remote_ip, _remote_port, local_port in _inbound_connections(conntrack=conntrack):
                    if remote_ip in checked:
                        continue
                    checked.add(remote_ip)
                    if _is_ignored(remote_ip, ignore_networks):
                        continue

                    matched = db.match(remote_ip)
                    if not matched:
                        continue

                    if not dedup.should_alert(remote_ip):
                        continue

                    hit = Hit(ip=remote_ip, matched_source=matched, local_port=local_port, method="poll")
                    log.warning(
                        "[poll] Подключение от известного сканера: %s (совпадение: %s, порт: %s)",
                        remote_ip, matched, local_port,
                    )
                    await _dispatch(on_hit, dedup, hit)
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
        heartbeat("kernel_log")
        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )

            while True:
                try:
                    line_bytes = await asyncio.wait_for(proc.stdout.readline(), timeout=30)
                except asyncio.TimeoutError:
                    # 30с без строк в логе ядра - нормально в тихие периоды: отмечаем,
                    # что цикл жив, и продолжаем читать тот же подпроцесс
                    heartbeat("kernel_log")
                    continue

                heartbeat("kernel_log")
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
                ip_obj = normalize_ip(remote_ip)
                if ip_obj is None:
                    continue
                remote_ip = str(ip_obj)

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
                await _dispatch(on_hit, dedup, hit)

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
