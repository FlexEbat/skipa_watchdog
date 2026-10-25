"""
Загрузка и валидация конфигурации из config.yaml.

Архитектура: Skipa Watchdog - это ОДИН процесс (watchdog.py), который
всегда мониторит соединения, ведёт локальный лог (/var/log/skipa_watchdog/)
и (при action_mode "block"/"block_notify") блокирует сканеры через iptables.
Telegram - это не отдельный режим, а необязательная надстройка поверх того
же процесса: если telegram.bot_token заполнен, тот же процесс запускает ещё
и Telegram-бота (уведомления + команды/меню), если оставить bot_token
пустым - процесс работает точно так же, просто без Telegram.
"""
from __future__ import annotations

import ipaddress
import stat
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml

# Раньше было два отдельных источника (skipa_cidr.txt/skipa_range.txt) с
# одинаковыми по сути данными в разных нотациях (CIDR vs диапазон). Чтобы не
# дублировать одни и те же адреса под двумя разными подписями и не тратить
# лишний запрос, оставлен один - CIDR (проще всего использовать и для
# iptables-блокировки: `-s <cidr> -j DROP`).
DEFAULT_PRIMARY_URL = (
    "https://raw.githubusercontent.com/tread-lightly/CyberOK_Skipa_ips/main/lists/skipa_cidr.txt"
)
# Дополнительный смешанный список (CIDR/диапазоны/одиночные IP, автоопределяется построчно).
DEFAULT_BLACKLIST_URL = (
    "https://gist.githubusercontent.com/sngvy/07cee7ac810c9d222fbebddff8c1d1b8/raw/"
    "37cde2b27a560c647d0e8eb9d274e3409082d3e7/blacklist.txt"
)

VALID_ACTION_MODES = ("notify", "block", "block_notify")
VALID_METHODS = ("poll", "kernel_log", "both")
VALID_ACTIVE_LISTS = ("list1", "list2", "merged")


@dataclass
class Config:
    # ---- telegram (необязательно; пусто = слой Telegram просто не стартует) ----
    bot_token: str
    chat_id: int
    admin_ids: list[int]

    # ---- источники базы IP ----
    primary_list_url: str
    blacklist_url: str
    blacklist_name: str
    # "list1" (только primary_list_url), "list2" (только blacklist_url)
    # или "merged" (оба, без повторов)
    active_list: str
    update_interval_days: int

    # ---- что делать при обнаружении ----
    # "notify"       - только уведомление (лог + telegram, если настроен)
    # "block"        - только блокировка через iptables, без уведомления
    # "block_notify" - блокировка И уведомление (по умолчанию)
    action_mode: str

    # ---- мониторинг ----
    poll_interval_seconds: int
    alert_cooldown_minutes: int
    ignore_networks: list[ipaddress._BaseNetwork] = field(default_factory=list)

    method: str = "both"
    kernel_log_prefix: str = "CONN: "
    kernel_log_command: list[str] = field(default_factory=list)

    # ---- обогащение алертов гео/ASN-данными ----
    ipinfo_token: str = ""
    ipregistry_key: str = ""
    enrich_enabled: bool = True

    retry_interval_seconds: int = 300

    log_level: str = "INFO"
    log_dir: str = "/var/log/skipa_watchdog"

    # ---- окружение: docker/kubernetes ----
    docker_scan_enabled: bool = True
    k8s_scan_enabled: bool = True

    # ---- telegram: прокси (если Telegram недоступен напрямую), http://, https:// или socks5:// ----
    telegram_proxy: str = ""

    # ---- блокировка ----
    # на сколько часов блокировать автоматически (0 = бессрочно); ручные /block - бессрочно
    block_timeout_hours: float = 72
    # загружать всю базу в ipset заранее (сканер отсекается на первом SYN)
    preload_db: bool = True

    # ---- защита от самоблокировки ----
    # автоматически не блокировать loopback/частные сети и IP текущих SSH-сессий
    auto_allowlist: bool = True
    ssh_ports: list[int] = field(default_factory=lambda: [22])
    # как часто проверять, что правила iptables на месте (сек.)
    guard_interval_seconds: int = 60

    # ---- параметры LOG-правила ----
    log_limit: str = "30/second"
    log_burst: int = 40

    @property
    def telegram_enabled(self) -> bool:
        return bool(self.bot_token) and "your-bot-token-here" not in self.bot_token

    @property
    def firewall_needed(self) -> bool:
        """Нужны ли правила iptables: для блокировки и для kernel_log-мониторинга."""
        return self.action_mode in ("block", "block_notify") or self.method in ("kernel_log", "both")

    @property
    def drop_enabled(self) -> bool:
        return self.action_mode in ("block", "block_notify")

    @classmethod
    def load(cls, path: str | Path = "config.yaml") -> "Config":
        path = Path(path)
        if not path.exists():
            sys.exit(
                f"Конфиг {path} не найден. Скопируйте config.example.yaml в {path.name} "
                f"(это обычно делает install.sh)."
            )

        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}

        def sect(name: str) -> dict:
            value = raw.get(name)
            return value if isinstance(value, dict) else {}

        tg = sect("telegram")
        src = sect("sources")
        mon = sect("monitoring")
        act = sect("action")
        enr = sect("enrichment")
        log_cfg = sect("logging")
        env = sect("environment")
        alerting = sect("alerting")
        fw = sect("firewall")

        ignore_nets = []
        for item in mon.get("ignore_ips", []) or []:
            try:
                ignore_nets.append(ipaddress.ip_network(item, strict=False))
            except ValueError:
                print(f"[config] Пропускаю некорректный ignore_ips элемент: {item!r}")

        active_list = str(src.get("active_list", "merged") or "merged").strip().lower()
        if active_list not in VALID_ACTIVE_LISTS:
            print(f"[config] Неизвестный sources.active_list={active_list!r}, использую 'merged'")
            active_list = "merged"

        action_mode = str(act.get("mode", "block_notify") or "block_notify").strip().lower()
        if action_mode not in VALID_ACTION_MODES:
            print(f"[config] Неизвестный action.mode={action_mode!r}, использую 'block_notify'")
            action_mode = "block_notify"

        method = str(mon.get("method", "both") or "both").strip().lower()
        if method == "psutil":  # старое имя метода - алиас "poll"
            method = "poll"
        if method not in VALID_METHODS:
            print(f"[config] Неизвестный monitoring.method={method!r}, использую 'poll'")
            method = "poll"

        # sources.cidr_list_url - старое имя поля, оставлено как алиас primary_list_url
        primary_url = src.get("primary_list_url") or src.get("cidr_list_url") or DEFAULT_PRIMARY_URL

        ssh_ports = []
        for item in mon.get("ssh_ports", [22]) or []:
            try:
                ssh_ports.append(int(item))
            except (TypeError, ValueError):
                print(f"[config] Пропускаю некорректный monitoring.ssh_ports элемент: {item!r}")

        bot_token = tg.get("bot_token", "") or ""
        chat_id = int(tg.get("chat_id") or 0)
        admin_ids = [int(x) for x in (tg.get("admin_ids") or [])]

        cfg = cls(
            bot_token=bot_token,
            chat_id=chat_id,
            admin_ids=admin_ids,
            primary_list_url=primary_url,
            blacklist_url=src.get("blacklist_url", DEFAULT_BLACKLIST_URL) or "",
            blacklist_name=src.get("blacklist_name", "blacklist"),
            active_list=active_list,
            update_interval_days=max(1, int(src.get("update_interval_days", 7))),
            action_mode=action_mode,
            poll_interval_seconds=max(1, int(mon.get("poll_interval_seconds", 5))),
            alert_cooldown_minutes=max(0, int(mon.get("alert_cooldown_minutes", 60))),
            ignore_networks=ignore_nets,
            method=method,
            kernel_log_prefix=mon.get("kernel_log_prefix", "CONN: "),
            kernel_log_command=list(mon.get("kernel_log_command") or []),
            ipinfo_token=enr.get("ipinfo_token", "") or "",
            ipregistry_key=enr.get("ipregistry_key", "") or "",
            enrich_enabled=bool(enr.get("enabled", True)),
            retry_interval_seconds=max(10, int(alerting.get("retry_interval_seconds", 300))),
            log_level=log_cfg.get("level", "INFO"),
            log_dir=log_cfg.get("log_dir", "/var/log/skipa_watchdog"),
            docker_scan_enabled=bool(env.get("docker_scan", True)),
            k8s_scan_enabled=bool(env.get("k8s_scan", True)),
            telegram_proxy=str(tg.get("proxy", "") or ""),
            block_timeout_hours=max(0.0, float(act.get("block_timeout_hours", 72))),
            preload_db=bool(act.get("preload_db", True)),
            auto_allowlist=bool(mon.get("auto_allowlist", True)),
            ssh_ports=ssh_ports or [22],
            guard_interval_seconds=max(10, int(mon.get("guard_interval_seconds", 60))),
            log_limit=str(fw.get("log_limit", "30/second")),
            log_burst=max(1, int(fw.get("log_burst", 40))),
        )
        cfg._sanity_warnings(path)
        return cfg

    def _sanity_warnings(self, path: Path) -> None:
        if self.telegram_enabled:
            if self.chat_id == 0:
                print("[config] telegram.bot_token задан, а chat_id=0 - уведомления некуда отправлять")
            if not self.admin_ids:
                print(
                    "[config] telegram.admin_ids пуст - команды бота будут приняты только из чата "
                    "telegram.chat_id. Укажите свой Telegram user id в admin_ids."
                )
            try:
                mode = path.stat().st_mode
                if mode & (stat.S_IRWXG | stat.S_IRWXO):
                    print(
                        f"[config] {path} содержит токен бота, но доступен другим пользователям "
                        f"(права {stat.filemode(mode)}) - выполните: chmod 600 {path}"
                    )
            except OSError:
                pass
