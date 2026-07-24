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
    extra_sources: list[dict] = field(default_factory=list)

    poll_interval_seconds: int = 5
    alert_cooldown_minutes: int = 60
    ignore_networks: list = field(default_factory=list)

    method: str = "psutil"
    kernel_log_prefix: str = "CONN: "
    kernel_log_command: list[str] = field(default_factory=list)

    ipinfo_token: str = ""
    ipregistry_key: str = ""

    retry_interval_seconds: int = 300

    # --- бан ---
    ban_enabled: bool = False
    ban_ipset_name: str = "skipa_watchdog_ban"
    auto_ban_new_hits: bool = False
    auto_ban_duration_minutes: int = 60
    manual_ban_duration_minutes: int = 1440
    fail2ban_jail: str = ""

    # --- health-check ---
    healthcheck_enabled: bool = True
    healthcheck_stale_after_minutes: int = 15
    healthcheck_check_interval_minutes: int = 5

    # --- дашборд ---
    dashboard_enabled: bool = False
    dashboard_host: str = "127.0.0.1"
    dashboard_port: int = 8080
    dashboard_username: str = ""
    dashboard_password: str = ""

    # --- дайджест ---
    digest_enabled: bool = True
    digest_weekday: int = 0   # 0=понедельник ... 6=воскресенье
    digest_hour: int = 9
    digest_minute: int = 0

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
        alerting = raw.get("alerting", {})
        banning = raw.get("banning", {})
        healthcheck = raw.get("healthcheck", {})
        dashboard = raw.get("dashboard", {})
        digest = raw.get("digest", {})
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
            extra_sources=list(src.get("extra") or []),
            poll_interval_seconds=int(mon.get("poll_interval_seconds", 5)),
            alert_cooldown_minutes=int(mon.get("alert_cooldown_minutes", 60)),
            ignore_networks=ignore_nets,
            method=mon.get("method", "psutil"),
            kernel_log_prefix=mon.get("kernel_log_prefix", "CONN: "),
            kernel_log_command=list(mon.get("kernel_log_command") or []),
            ipinfo_token=enr.get("ipinfo_token", "") or "",
            ipregistry_key=enr.get("ipregistry_key", "") or "",
            retry_interval_seconds=int(alerting.get("retry_interval_seconds", 300)),
            ban_enabled=bool(banning.get("enabled", False)),
            ban_ipset_name=banning.get("ipset_name", "skipa_watchdog_ban"),
            auto_ban_new_hits=bool(banning.get("auto_ban_new_hits", False)),
            auto_ban_duration_minutes=int(banning.get("auto_ban_duration_minutes", 60)),
            manual_ban_duration_minutes=int(banning.get("manual_ban_duration_minutes", 1440)),
            fail2ban_jail=banning.get("fail2ban_jail", "") or "",
            healthcheck_enabled=bool(healthcheck.get("enabled", True)),
            healthcheck_stale_after_minutes=int(healthcheck.get("stale_after_minutes", 15)),
            healthcheck_check_interval_minutes=int(healthcheck.get("check_interval_minutes", 5)),
            dashboard_enabled=bool(dashboard.get("enabled", False)),
            dashboard_host=dashboard.get("host", "127.0.0.1"),
            dashboard_port=int(dashboard.get("port", 8080)),
            dashboard_username=dashboard.get("username", "") or "",
            dashboard_password=dashboard.get("password", "") or "",
            digest_enabled=bool(digest.get("enabled", True)),
            digest_weekday=int(digest.get("weekday", 0)),
            digest_hour=int(digest.get("hour", 9)),
            digest_minute=int(digest.get("minute", 0)),
            log_level=log.get("level", "INFO"),
        )
