"""
Skipa Watchdog — единая точка входа.

Это НЕ "бот" в смысле отдельного режима - это один процесс, который:

1. Постоянно мониторит сетевые соединения к серверу (psutil и/или чтение
   kernel-лога) и сверяет источник с базой IP-адресов сканеров
   (CyberOK/Skipa, ГРЧЦ, НКЦКИ + доп. списки, см. bot/ip_lists.py).
2. При обнаружении, в зависимости от action.mode в config.yaml:
     - "notify"       - только уведомление (локальный лог + Telegram, если настроен)
     - "block"        - только блокировка через iptables (см. bot/blocker.py),
                         работает и для хоста, и для Docker/Kubernetes
     - "block_notify" - и то, и другое (по умолчанию)
3. Ведёт лог в /var/log/skipa_watchdog/ (или другой logging.log_dir) -
   всегда, независимо от Telegram.
4. Если telegram.bot_token заполнен в config.yaml, этот же процесс
   ДОПОЛНИТЕЛЬНО поднимает Telegram-слой (bot/telegram_layer.py):
   уведомления дублируются в чат, становятся доступны команды/меню.
   Telegram - это надстройка поверх watchdog, а не отдельный процесс/режим.
   Если bot_token пуст - процесс работает точно так же, просто без Telegram.

Запуск:
    pip install -r requirements.txt
    cp config.example.yaml config.yaml   # и заполнить (Telegram - по желанию)
    python watchdog.py
(обычно это делает install.sh и systemd-юнит skipa-watchdog.service)
"""
from __future__ import annotations

import asyncio
import logging
import logging.handlers
import sys
from pathlib import Path

from bot import blocker
from bot.config import Config
from bot.env_detect import format_summary_text, summarize_environment
from bot.fallback import append_audit_log, load_pending, queue_pending_alert, save_pending
from bot.ip_lists import check_list_versions, fetch_threat_db, load_cache, needs_update, save_cache
from bot.monitor import Deduper, poll_connections_loop, tail_kernel_log_loop

CONFIG_PATH = sys.argv[1] if len(sys.argv) > 1 else "config.yaml"

log = logging.getLogger("skipa_watchdog")


def _setup_logging(config: Config) -> Path:
    log_dir = Path(config.log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)

    level = getattr(logging, config.log_level.upper(), logging.INFO)
    root = logging.getLogger()
    root.setLevel(level)

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(fmt)
    root.addHandler(console)

    file_handler = logging.handlers.RotatingFileHandler(
        log_dir / "skipa-watchdog.log", maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
    )
    file_handler.setFormatter(fmt)
    root.addHandler(file_handler)

    return log_dir


def _make_hit_handler(config: Config, state: dict, detections_log: Path):
    do_notify = config.action_mode in ("notify", "block_notify")
    do_block = config.action_mode in ("block", "block_notify")

    async def on_hit(hit) -> None:
        blocked = False
        if do_block:
            blocked = blocker.block_ip(hit.ip)
            if blocked:
                log.warning("IP %s заблокирован (совпадение: %s)", hit.ip, hit.matched_source)
            else:
                log.error("Не удалось заблокировать %s (см. лог выше)", hit.ip)

        if not do_notify:
            log.warning(
                "СКАНЕР ОБНАРУЖЕН: %s (совпадение: %s, метод: %s, порт: %s)%s",
                hit.ip, hit.matched_source, hit.method, hit.local_port,
                " [заблокирован]" if blocked else "",
            )
            return

        if config.enrich_enabled:
            from bot.enrich import enrich_ip
            from bot.formatter import build_alert_message

            data = await enrich_ip(hit.ip, config.ipinfo_token, config.ipregistry_key)
            text = build_alert_message(hit.ip, hit.matched_source, data)
        else:
            text = (
                f"IP: {hit.ip}\n"
                f"Совпадение по базе: {hit.matched_source}\n"
                f"Метод обнаружения: {hit.method}\n"
                f"Локальный порт: {hit.local_port}"
            )
        if do_block:
            text += "\n\n🚫 IP заблокирован." if blocked else "\n\n⚠️ Не удалось заблокировать IP."

        log.warning(
            "СКАНЕР ОБНАРУЖЕН: %s (совпадение: %s, метод: %s, порт: %s)%s",
            hit.ip, hit.matched_source, hit.method, hit.local_port,
            " [заблокирован]" if blocked else "",
        )
        append_audit_log(hit.ip, hit.matched_source, text, log_path=detections_log)

        app = state.get("telegram_app")
        if app is not None:
            from bot.telegram_layer import send_notification

            try:
                await send_notification(app, config.chat_id, text)
            except Exception as e:  # noqa: BLE001
                log.error("Не удалось отправить в Telegram (%s), кладу в очередь на повтор", e)
                queue_pending_alert(config.chat_id, text)

    return on_hit


async def _periodic_db_updates(config: Config, state: dict) -> None:
    """Раз в час проверяет, не пора ли обновить базу (реальный интервал -
    update_interval_days), и дополнительно раз в сутки проверяет, не вышли
    ли новые версии листов (даже если update_interval_days ещё не наступил -
    чтобы администратор узнал заранее)."""
    last_version_check = 0.0
    while True:
        db = state.get("db")
        if needs_update(db, config.update_interval_days):
            log.info("Обновляю базу IP-адресов...")
            new_db = await fetch_threat_db(
                config.primary_list_url, config.blacklist_url, config.blacklist_name,
                config.active_list,
            )
            if new_db.networks or new_db.ranges:
                state["db"] = new_db
                save_cache(new_db)
                log.info("База обновлена: %d записей", new_db.source_line_count)
            else:
                log.warning("Обновление базы не удалось, оставляю старую версию")

        import time

        if time.time() - last_version_check > 86400:
            changed = await check_list_versions(
                config.primary_list_url, config.blacklist_url, config.blacklist_name
            )
            if changed:
                log.info(
                    "Обнаружены новые версии листов: %s (используйте /update или меню install.sh)",
                    ", ".join(changed),
                )
            last_version_check = time.time()

        await asyncio.sleep(3600)


async def _flush_pending_alerts(config: Config, state: dict) -> None:
    """Периодически пытается доотправить алерты, которые не ушли в Telegram
    из-за временной недоступности связи."""
    while True:
        await asyncio.sleep(config.retry_interval_seconds)
        app = state.get("telegram_app")
        if app is None:
            continue
        records = load_pending()
        if not records:
            continue
        log.info("В очереди %d отложенных алертов, пробую отправить...", len(records))
        from bot.telegram_layer import send_notification

        still_pending = []
        for record in records:
            try:
                await send_notification(app, record["chat_id"], record["text"])
            except Exception as e:  # noqa: BLE001
                log.warning("Повтор снова не удался, оставляю в очереди: %s", e)
                still_pending.append(record)
        save_pending(still_pending)
        sent = len(records) - len(still_pending)
        if sent:
            log.info("Успешно доотправлено %d ранее отложенных алертов", sent)


async def async_main() -> None:
    config = Config.load(CONFIG_PATH)
    log_dir = _setup_logging(config)
    detections_log = log_dir / "detections.log"

    log.info(
        "Skipa Watchdog запускается (action.mode=%s, telegram=%s), логи: %s",
        config.action_mode, "включён" if config.telegram_enabled else "выключен", log_dir,
    )

    state: dict = {"db": None, "telegram_app": None}

    db = load_cache()
    if needs_update(db, config.update_interval_days):
        log.info("Локального кэша нет или он устарел, качаю базу впервые...")
        db = await fetch_threat_db(
            config.primary_list_url, config.blacklist_url, config.blacklist_name, config.active_list
        )
        save_cache(db)
    state["db"] = db

    if config.action_mode in ("block", "block_notify"):
        blocker.ensure_chain()
        blocker.restore_persisted_blocks()

    if config.docker_scan_enabled or config.k8s_scan_enabled:
        summary = summarize_environment(config.kernel_log_prefix)
        if summary.any_container_platform():
            for line in format_summary_text(summary).splitlines():
                log.info("[environment] %s", line)

    tasks = [_periodic_db_updates(config, state)]

    telegram_app = None
    if config.telegram_enabled:
        from bot.telegram_layer import build_application

        telegram_app = await build_application(config, state)
        state["telegram_app"] = telegram_app
        await telegram_app.initialize()
        await telegram_app.start()
        await telegram_app.updater.start_polling()
        log.info("Telegram-слой запущен (уведомления и команды доступны в чате)")
        tasks.append(_flush_pending_alerts(config, state))
    else:
        log.info(
            "Telegram не настроен (telegram.bot_token пуст) - работаю только с локальным логом."
        )

    on_hit = _make_hit_handler(config, state, detections_log)
    dedup = Deduper(config.alert_cooldown_minutes)

    method = config.method
    if method not in ("psutil", "kernel_log", "both"):
        log.warning("Неизвестный monitoring.method=%r, использую 'psutil'", method)
        method = "psutil"

    if method in ("psutil", "both"):
        tasks.append(
            poll_connections_loop(
                get_db=lambda: state.get("db"),
                ignore_networks=config.ignore_networks,
                poll_interval=config.poll_interval_seconds,
                dedup=dedup,
                on_hit=on_hit,
            )
        )

    if method in ("kernel_log", "both"):
        tasks.append(
            tail_kernel_log_loop(
                get_db=lambda: state.get("db"),
                ignore_networks=config.ignore_networks,
                dedup=dedup,
                on_hit=on_hit,
                log_prefix=config.kernel_log_prefix,
                command=config.kernel_log_command or None,
            )
        )

    try:
        await asyncio.gather(*tasks)
    finally:
        if telegram_app is not None:
            await telegram_app.updater.stop()
            await telegram_app.stop()
            await telegram_app.shutdown()


def main() -> None:
    try:
        asyncio.run(async_main())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
