"""
Постоянный мониторинг подключений к серверу.

По умолчанию используется опрос активных сетевых соединений через psutil
(`net_connections`) - работает "из коробки" без дополнительной настройки
на любом Linux-сервере (нужны права на чтение /proc/net, обычно бот стоит
запускать от root или с CAP_NET_ADMIN/CAP_NET_RAW при необходимости).

Для более надёжного обнаружения (в том числе одиночных SYN-пакетов
zmap/zgrab, которые могут не долетать до состояния ESTABLISHED за время
между опросами) рекомендуется дополнительно вести лог через iptables/nftables
и подключить `tail_log_file()` - см. README.md, раздел "Расширенный мониторинг".
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass

import psutil

from .ip_lists import ThreatDB

log = logging.getLogger("skipa_watchdog.monitor")


@dataclass
class Hit:
    ip: str
    matched_source: str
    local_port: int | None


def _own_networks_ignored(ip: str, ignore_networks) -> bool:
    import ipaddress

    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return any(ip_obj in net for net in ignore_networks)


async def poll_connections_loop(
    get_db,
    ignore_networks,
    poll_interval: int,
    cooldown_minutes: int,
    on_hit,
):
    """
    Бесконечный цикл: каждые poll_interval секунд смотрит активные inet-соединения
    сервера и сверяет удалённые IP с базой угроз. get_db - функция без аргументов,
    возвращающая текущий ThreatDB (чтобы подхватывать еженедельные обновления на
    лету). on_hit(Hit) - async callback, вызывается при обнаружении.
    """
    last_alert: dict[str, float] = {}
    cooldown_seconds = cooldown_minutes * 60

    log.info("Мониторинг соединений запущен (интервал опроса: %ss)", poll_interval)

    while True:
        try:
            db: ThreatDB = get_db()
            if db is not None and (db.networks or db.ranges):
                seen_this_round = set()
                for conn in psutil.net_connections(kind="inet"):
                    if not conn.raddr:
                        continue
                    remote_ip = conn.raddr.ip
                    if remote_ip in seen_this_round:
                        continue
                    if _own_networks_ignored(remote_ip, ignore_networks):
                        continue

                    matched = db.match(remote_ip)
                    if not matched:
                        continue

                    seen_this_round.add(remote_ip)

                    now = time.time()
                    last = last_alert.get(remote_ip, 0)
                    if now - last < cooldown_seconds:
                        continue
                    last_alert[remote_ip] = now

                    local_port = conn.laddr.port if conn.laddr else None
                    hit = Hit(ip=remote_ip, matched_source=matched, local_port=local_port)
                    log.warning(
                        "Обнаружено подключение от известного сканера: %s (совпадение: %s, порт: %s)",
                        remote_ip, matched, local_port,
                    )
                    await on_hit(hit)
        except psutil.AccessDenied:
            log.error(
                "Недостаточно прав для чтения сетевых соединений (psutil.AccessDenied). "
                "Запустите бота от root либо через systemd с нужными capabilities."
            )
        except Exception as e:  # noqa: BLE001
            log.exception("Ошибка в цикле мониторинга: %s", e)

        await asyncio.sleep(poll_interval)
