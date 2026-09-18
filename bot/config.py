"""Загрузка и валидация конфигурации из YAML.

Используется двумя точками входа:
- main.py             -> Config.load(path)                        (полный бот, нужен telegram)
- watchdog_service.py -> Config.load(path, require_telegram=False) (лёгкий режим "service")

Оба режима используют один и тот же набор полей sources/monitoring/environment,
поэтому парсинг общий, а секция telegram становится опциональной для сервис-режима.
"""
from __future__ import annotations

import ipaddress
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml

DEFAULT_CIDR_URL = (
    "https://raw.githubusercontent.com/tread-lightly/CyberOK_Skipa_ips/main/lists/skipa_cidr.txt"
)
DEFAULT_RANGE_URL = (
    "https://raw.githubusercontent.com/tread-lightly/CyberOK_Skipa_ips/main/lists/skipa_range.txt"
)
# Дополнительный список (см. README, п. "Дополнительные списки"): смешанный
# формат (одиночные IP / CIDR / диапазоны), автоопределяется построчно.
DEFAULT_BLACKLIST_URL = (
    "https://gist.githubusercontent.com/sngvy/07cee7ac810c9d222fbebddff8c1d1b8/raw/"
    "37cde2b27a560c647d0e8eb9d274e3409082d3e7/blacklist.txt"
)


@dataclass
class Config:
    # ---- telegram (обязательно только для main.py / режима "bot") ----
    bot_token: str
    chat_id: int
    admin_ids: list[int]

    # ---- источники баз IP ----
    cidr_list_url: str
    range_list_url: str
    blacklist_url: str
    blacklist_name: str
    update_interval_days: int

    # ---- мониторинг ----
    poll_interval_seconds: int
    alert_cooldown_minutes: int
    ignore_networks: list[ipaddress._BaseNetwork] = field(default_factory=list)

    method: str = "psutil"
    kernel_log_prefix: str = "CONN: "
    kernel_log_command: list[str] = field(default_factory=list)

    # ---- обогащение (используется ботом; в service-режиме по умолчанию выключено) ----
    ipinfo_token: str = ""
    ipregistry_key: str = ""
    enrich_in_service_mode: bool = False

    retry_interval_seconds: int = 300

    log_level: str = "INFO"
    service_log_dir: str = "/var/log/skipa_watchdog"

    # ---- окружение: docker/kubernetes ----
    docker_scan_enabled: bool = True
    k8s_scan_enabled: bool = True

    @classmethod
    def load(cls, path: str | Path, require_telegram: bool = True) -> "Config":
        path = Path(path)
        if not path.exists():
            example = "config.example.yaml" if require_telegram else "service.example.yaml"
            sys.exit(
                f"Конфиг {path} не найден. Скопируйте {example} в {path.name} "
                f"и заполните его перед запуском (см. также install.sh)."
            )

        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}

        tg = raw.get("telegram", {}) or {}
        src = raw.get("sources", {}) or {}
        mon = raw.get("monitoring", {}) or {}
        enr = raw.get("enrichment", {}) or {}
        log = raw.get("logging", {}) or {}
        env = raw.get("environment", {}) or {}

        ignore_nets = []
        for item in mon.get("ignore_ips", []) or []:
            try:
                ignore_nets.append(ipaddress.ip_network(item, strict=False))
            except ValueError:
                print(f"[config] Пропускаю некорректный ignore_ips элемент: {item!r}")

        bot_token = tg.get("bot_token", "") or ""
        chat_id_raw = tg.get("chat_id")

        if require_telegram:
            if not bot_token or "your-bot-token-here" in bot_token:
                sys.exit("Заполните telegram.bot_token в config.yaml")
            if not chat_id_raw:
                sys.exit("Заполните telegram.chat_id в config.yaml")

        return cls(
            bot_token=bot_token,
            chat_id=int(chat_id_raw) if chat_id_raw else 0,
            admin_ids=[int(x) for x in (tg.get("admin_ids") or [])],
            cidr_list_url=src.get("cidr_list_url", DEFAULT_CIDR_URL),
            range_list_url=src.get("range_list_url", DEFAULT_RANGE_URL),
            blacklist_url=src.get("blacklist_url", DEFAULT_BLACKLIST_URL) or "",
            blacklist_name=src.get("blacklist_name", "blacklist"),
            update_interval_days=int(src.get("update_interval_days", 7)),
            poll_interval_seconds=int(mon.get("poll_interval_seconds", 5)),
            alert_cooldown_minutes=int(mon.get("alert_cooldown_minutes", 60)),
            ignore_networks=ignore_nets,
            method=mon.get("method", "psutil"),
            kernel_log_prefix=mon.get("kernel_log_prefix", "CONN: "),
            kernel_log_command=list(mon.get("kernel_log_command") or []),
            ipinfo_token=enr.get("ipinfo_token", "") or "",
            ipregistry_key=enr.get("ipregistry_key", "") or "",
            enrich_in_service_mode=bool(enr.get("enrich_in_service_mode", False)),
            retry_interval_seconds=int(raw.get("alerting", {}).get("retry_interval_seconds", 300)),
            log_level=log.get("level", "INFO"),
            service_log_dir=log.get("service_log_dir", "/var/log/skipa_watchdog"),
            docker_scan_enabled=bool(env.get("docker_scan", True)),
            k8s_scan_enabled=bool(env.get("k8s_scan", True)),
        )
