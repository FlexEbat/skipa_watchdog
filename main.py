from __future__ import annotations

import asyncio
import logging

from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes

from bot.config import Config
from bot.enrich import enrich_ip
from bot.formatter import build_alert_message
from bot.ip_lists import fetch_threat_db, load_cache, needs_update, save_cache
from bot.monitor import Deduper, poll_connections_loop, tail_kernel_log_loop

CONFIG_PATH = "config.yaml"

log = logging.getLogger("skipa_watchdog")


def _is_admin(config: Config, user_id: int) -> bool:
    return not config.admin_ids or user_id in config.admin_ids


# ---------------------------------------------------------------------------
# Job'ы (фоновые задачи через встроенный JobQueue PTB)
# ---------------------------------------------------------------------------

async def job_update_threat_db(context: ContextTypes.DEFAULT_TYPE) -> None:
    config: Config = context.bot_data["config"]
    db = context.bot_data.get("db")

    if not needs_update(db, config.update_interval_days):
        return

    log.info("Запускаю плановое обновление базы IP (раз в %s дн.)...", config.update_interval_days)
    new_db = await fetch_threat_db(config.cidr_list_url, config.range_list_url)
    if new_db.networks or new_db.ranges:
        context.bot_data["db"] = new_db
        save_cache(new_db)
        log.info("База обновлена: %s записей", new_db.source_line_count)
    else:
        log.warning("Обновление базы не удалось (пустой ответ), оставляю старую версию")


async def job_check_updates_tick(context: ContextTypes.DEFAULT_TYPE) -> None:
    """Лёгкая проверка раз в час: не пора ли обновить базу (см. update_interval_days)."""
    await job_update_threat_db(context)


# ---------------------------------------------------------------------------
# Обработка обнаруженного скана + отправка алерта
# ---------------------------------------------------------------------------

def make_hit_handler(app: Application, config: Config):
    async def on_hit(hit) -> None:
        data = await enrich_ip(hit.ip, config.ipinfo_token, config.ipregistry_key)
        text = build_alert_message(hit.ip, hit.matched_source, data)
        try:
            await app.bot.send_message(
                chat_id=config.chat_id,
                text=text,
                parse_mode="HTML",
                disable_web_page_preview=True,
            )
        except Exception as e:  # noqa: BLE001
            log.error("Не удалось отправить алерт в Telegram: %s", e)

    return on_hit


# ---------------------------------------------------------------------------
# Команды бота
# ---------------------------------------------------------------------------

async def cmd_status(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    config: Config = context.bot_data["config"]
    if not _is_admin(config, update.effective_user.id):
        return
    db = context.bot_data.get("db")
    if db is None:
        await update.message.reply_text("База ещё не загружена.")
        return
    import datetime

    last_update = datetime.datetime.fromtimestamp(db.last_update_ts).strftime("%Y-%m-%d %H:%M:%S")
    await update.message.reply_text(
        "📊 Статус Skipa Watchdog\n"
        f"Записей в базе: {db.source_line_count}\n"
        f"Последнее обновление: {last_update}\n"
        f"Метод мониторинга: {config.method}\n"
        f"Интервал опроса соединений: {config.poll_interval_seconds} сек.\n"
        f"Антиспам-кулдаун: {config.alert_cooldown_minutes} мин."
    )


async def cmd_update(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    config: Config = context.bot_data["config"]
    if not _is_admin(config, update.effective_user.id):
        return
    await update.message.reply_text("Обновляю базу IP-адресов...")
    new_db = await fetch_threat_db(config.cidr_list_url, config.range_list_url)
    if new_db.networks or new_db.ranges:
        context.bot_data["db"] = new_db
        save_cache(new_db)
        await update.message.reply_text(f"Готово: {new_db.source_line_count} записей.")
    else:
        await update.message.reply_text("Не удалось получить свежую базу, оставил старую версию.")


async def cmd_testalert(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Присылает тестовый алерт с примером из ТЗ, чтобы проверить форматирование в чате."""
    config: Config = context.bot_data["config"]
    if not _is_admin(config, update.effective_user.id):
        return
    test_ip = context.args[0] if context.args else "89.169.28.214"
    data = await enrich_ip(test_ip, config.ipinfo_token, config.ipregistry_key)
    text = build_alert_message(test_ip, "тестовый вызов /testalert", data)
    await update.message.reply_text(text, parse_mode="HTML", disable_web_page_preview=True)


async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(
        "Skipa Watchdog запущен и следит за подключениями известных сканеров "
        "(CyberOK/Skipa, ГРЧЦ, НКЦКИ). Команды: /status, /update, /testalert [ip]"
    )


# ---------------------------------------------------------------------------
# Точка входа
# ---------------------------------------------------------------------------

async def post_init(app: Application) -> None:
    config: Config = app.bot_data["config"]

    db = load_cache()
    if needs_update(db, config.update_interval_days):
        log.info("Локального кэша нет или он устарел, качаю базу впервые...")
        db = await fetch_threat_db(config.cidr_list_url, config.range_list_url)
        save_cache(db)
    app.bot_data["db"] = db

    on_hit = make_hit_handler(app, config)
    dedup = Deduper(config.alert_cooldown_minutes)

    method = config.method
    if method not in ("psutil", "kernel_log", "both"):
        log.warning("Неизвестный monitoring.method=%r, использую 'psutil'", method)
        method = "psutil"

    if method in ("psutil", "both"):
        app.create_task(
            poll_connections_loop(
                get_db=lambda: app.bot_data.get("db"),
                ignore_networks=config.ignore_networks,
                poll_interval=config.poll_interval_seconds,
                dedup=dedup,
                on_hit=on_hit,
            )
        )

    if method in ("kernel_log", "both"):
        app.create_task(
            tail_kernel_log_loop(
                get_db=lambda: app.bot_data.get("db"),
                ignore_networks=config.ignore_networks,
                dedup=dedup,
                on_hit=on_hit,
                log_prefix=config.kernel_log_prefix,
                command=config.kernel_log_command or None,
            )
        )

    # раз в час проверяем, не пора ли обновить базу (реальное обновление - раз в неделю,
    # см. update_interval_days в config.yaml)
    app.job_queue.run_repeating(job_check_updates_tick, interval=3600, first=60)


def main() -> None:
    config = Config.load(CONFIG_PATH)

    logging.basicConfig(
        level=getattr(logging, config.log_level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    application = Application.builder().token(config.bot_token).post_init(post_init).build()
    application.bot_data["config"] = config

    application.add_handler(CommandHandler("start", cmd_start))
    application.add_handler(CommandHandler("status", cmd_status))
    application.add_handler(CommandHandler("update", cmd_update))
    application.add_handler(CommandHandler("testalert", cmd_testalert))

    log.info("Skipa Watchdog запускается...")
    application.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
