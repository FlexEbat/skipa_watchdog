"""
Защита от самоблокировки.

Список адресов, которые watchdog не имеет права блокировать, как бы ни
выглядело совпадение с внешними списками:

  * loopback, частные сети (RFC1918), link-local - это либо сам сервер, либо
    ваша LAN/Docker-сети;
  * ignore_ips из config.yaml;
  * (monitoring.auto_allowlist) IP-адреса, с которых прямо сейчас открыты
    SSH-сессии на monitoring.ssh_ports - чтобы случайное попадание вашего
    домашнего/рабочего адреса в сторонний список не отрезало вас от сервера.

Список пересобирается раз в guard_interval_seconds (см. watchdog.py).
"""
from __future__ import annotations

import ipaddress

from .monitor import established_peers

BUILTIN_NETWORKS = [
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
]


def build_allowlist(ignore_networks, auto: bool = True, ssh_ports=(22,)) -> list:
    nets = [ipaddress.ip_network(n) for n in BUILTIN_NETWORKS]
    nets.extend(ignore_networks)
    if auto:
        try:
            for ip in established_peers(set(ssh_ports)):
                try:
                    addr = ipaddress.ip_address(ip)
                except ValueError:
                    continue
                nets.append(ipaddress.ip_network(f"{addr}/{addr.max_prefixlen}"))
        except Exception:  # noqa: BLE001  - best-effort, не должно ронять цикл
            pass
    # убираем дубли, сохраняя порядок
    seen, out = set(), []
    for n in nets:
        if n not in seen:
            seen.add(n)
            out.append(n)
    return out
