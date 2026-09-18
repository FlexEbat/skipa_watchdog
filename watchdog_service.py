"""
Skipa Watchdog - режим "service" (без Telegram-бота).

Делает то же самое, что и main.py, с точки зрения обнаружения сканов
(psutil и/или kernel_log, та же база угроз из bot/ip_lists.py), но:

- не тянет python-telegram-bot (см. requirements-service.txt) - легче
  ставить туда, где Telegram вообще не нужен, а нужен только факт
  детектирования;
- ничего никуда не отправляет - каждое обнаружение просто пишется в
  /var/log/skipa_watchdog/detections.log (+ обычный лог процесса в
  skipa-watchdog-svc.log, его же видно через journalctl при запуске
  как systemd-юнит skipa-watchdog-svc.service);
- обогащение (ipinfo/RIPE/ipregistry) по умолчанию выключено, чтобы
  не делать лишних сетевых запросов на каждый скан - см.
  enrichment.enrich_in_service_mode в service.yaml, если оно всё же
  нужно.

Конфиг: service.yaml (шаблон - service.example.yaml), секции sources/
monitoring/environment такие же, как в config.yaml, но без telegram.

Запуск:
    pip install -r requirements-service.txt
    cp service.example.yaml service.yaml   # и заполнить при необходимости
    python watchdog_service.py
"""
from __future__ import annotations

import asyncio
import logging
import logging.handlers
import sys
from pathlib import Path

from bot.config import Config
from bot.env_detect import format_summary_text, summarize_environment
from bot.fallback import append_audit_log
from bot.formatter import build_alert_message
from bot.ip_lists import fetch_threat_db, load_cache, needs_update, save_cache
from bot.monitor import Deduper, poll_connections_loop, tail_kernel_log_loop

CONFIG_PATH = sys.argv[1] if len(sys.argv) > 1 else "service.yaml"

log = logging.getLogger("skipa_watchdog.service")


def _setup_logging(config: Config) -> Path:
    log_dir = Path(config.service_log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)

    level = getattr(logging, config.log_level.upper(), logging.INFO)
    root = logging.getLogger()
    root.setLevel(level)

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(fmt)
    root.addHandler(console)

    file_handler = logging.handlers.RotatingFileHandler(
        log_dir / "skipa-watchdog-svc.log", maxBytes=10 * 1024 * 1024, backupCount=5,
        encoding="utf-8",
    )
    file_handler.setFormatter(fmt)
    root.addHandler(file_handler)

    return log_dir


def _make_hit_handler(config: Config, detections_log: Path):
    async def on_hit(hit) -> None:
        # Без обогащения по умолчанию: строим упрощённый текст без гео-данных,
        # чтобы не делать сетевые запросы на каждый скан в лёгком режиме.
        if config.enrich_in_service_mode:
            from bot.enrich import enrich_ip

            data = await enrich_ip(hit.ip, config.ipinfo_token, config.ipregistry_key)
            text = build_alert_message(hit.ip, hit.matched_source, data)
        else:
            text = (
                f"IP: {hit.ip}\n"
                f"Совпадение по базе: {hit.matched_source}\n"
                f"Метод обнаружения: {hit.method}\n"
                f"Локальный порт: {hit.local_port}"
            )

        log.warning(
            "СКАНЕР ОБНАРУЖЕН: %s (совпадение: %s, метод: %s, порт: %s)",
            hit.ip, hit.matched_source, hit.method, hit.local_port,
        )
        append_audit_log(hit.ip, hit.matched_source, text, log_path=detections_log)

    return on_hit


async def _periodic_db_updates(config: Config, get_db, set_db) -> None:
    """Раз в час проверяет, не пора ли обновить базу (реальный интервал
    обновления - update_interval_days, как и в основном боте)."""
    while True:
        db = get_db()
        if needs_update(db, config.update_interval_days):
            log.info("Обновляю базу IP-адресов...")
            new_db = await fetch_threat_db(
                config.cidr_list_url, config.range_list_url,
                config.blacklist_url, config.blacklist_name,
            )
            if new_db.networks or new_db.ranges:
                set_db(new_db)
                save_cache(new_db)
                log.info("База обновлена: %d записей", new_db.source_line_count)
            else:
                log.warning("Обновление базы не удалось, оставляю старую версию")
        await asyncio.sleep(3600)


async def async_main() -> None:
    config = Config.load(CONFIG_PATH, require_telegram=False)
    log_dir = _setup_logging(config)
    detections_log = log_dir / "detections.log"

    log.info("Skipa Watchdog (service-режим) запускается, логи: %s", log_dir)

    if config.docker_scan_enabled or config.k8s_scan_enabled:
        summary = summarize_environment(config.kernel_log_prefix)
        if summary.any_container_platform():
            for line in format_summary_text(summary).splitlines():
                log.info("[environment] %s", line)

    db = load_cache()
    if needs_update(db, config.update_interval_days):
        log.info("Локального кэша нет или он устарел, качаю базу впервые...")
        db = await fetch_threat_db(
            config.cidr_list_url, config.range_list_url,
            config.blacklist_url, config.blacklist_name,
        )
        save_cache(db)

    state = {"db": db}
    get_db = lambda: state["db"]  # noqa: E731
    set_db = lambda new_db: state.__setitem__("db", new_db)  # noqa: E731

    on_hit = _make_hit_handler(config, detections_log)
    dedup = Deduper(config.alert_cooldown_minutes)

    method = config.method
    if method not in ("psutil", "kernel_log", "both"):
        log.warning("Неизвестный monitoring.method=%r, использую 'psutil'", method)
        method = "psutil"

    tasks = [_periodic_db_updates(config, get_db, set_db)]

    if method in ("psutil", "both"):
        tasks.append(
            poll_connections_loop(
                get_db=get_db,
                ignore_networks=config.ignore_networks,
                poll_interval=config.poll_interval_seconds,
                dedup=dedup,
                on_hit=on_hit,
            )
        )

    if method in ("kernel_log", "both"):
        tasks.append(
            tail_kernel_log_loop(
                get_db=get_db,
                ignore_networks=config.ignore_networks,
                dedup=dedup,
                on_hit=on_hit,
                log_prefix=config.kernel_log_prefix,
                command=config.kernel_log_command or None,
            )
        )

    await asyncio.gather(*tasks)


def main() -> None:
    try:
        asyncio.run(async_main())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
