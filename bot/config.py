"""Загрузка и валидация конфигурации бота из YAML."""
from __future__ import annotations

import ipaddress
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class Config:
    bot_token: str
    chat_id: int
    admin_ids: list[int]

    cidr_list_url: str
    range_list_url: str
    update_interval_days: int

    poll_interval_seconds: int
    alert_cooldown_minutes: int
    ignore_networks: list[ipaddress._BaseNetwork] = field(default_factory=list)

    ipinfo_token: str = ""
    ipregistry_key: str = ""

    log_level: str = "INFO"

    @classmethod
    def load(cls, path: str | Path) -> "Config":
        path = Path(path)
        if not path.exists():
            sys.exit(
                f"Конфиг {path} не найден. Скопируйте config.example.yaml в config.yaml "
                f"и заполните его перед запуском."
            )

        raw = yaml.safe_load(path.read_text(encoding="utf-8"))

        tg = raw.get("telegram", {})
        src = raw.get("sources", {})
        mon = raw.get("monitoring", {})
        enr = raw.get("enrichment", {})
        log = raw.get("logging", {})

        ignore_nets = []
        for item in mon.get("ignore_ips", []) or []:
            try:
                ignore_nets.append(ipaddress.ip_network(item, strict=False))
            except ValueError:
                print(f"[config] Пропускаю некорректный ignore_ips элемент: {item!r}")

        bot_token = tg.get("bot_token", "")
        if not bot_token or "your-bot-token-here" in bot_token:
            sys.exit("Заполните telegram.bot_token в config.yaml")

        chat_id = tg.get("chat_id")
        if not chat_id:
            sys.exit("Заполните telegram.chat_id в config.yaml")

        return cls(
            bot_token=bot_token,
            chat_id=int(chat_id),
            admin_ids=[int(x) for x in (tg.get("admin_ids") or [])],
            cidr_list_url=src.get(
                "cidr_list_url",
                "https://raw.githubusercontent.com/tread-lightly/CyberOK_Skipa_ips/main/lists/skipa_cidr.txt",
            ),
            range_list_url=src.get(
                "range_list_url",
                "https://raw.githubusercontent.com/tread-lightly/CyberOK_Skipa_ips/main/lists/skipa_range.txt",
            ),
            update_interval_days=int(src.get("update_interval_days", 7)),
            poll_interval_seconds=int(mon.get("poll_interval_seconds", 5)),
            alert_cooldown_minutes=int(mon.get("alert_cooldown_minutes", 60)),
            ignore_networks=ignore_nets,
            ipinfo_token=enr.get("ipinfo_token", "") or "",
            ipregistry_key=enr.get("ipregistry_key", "") or "",
            log_level=log.get("level", "INFO"),
        )
