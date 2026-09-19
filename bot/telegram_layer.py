"""
Слой Telegram - НЕ отдельный процесс/режим. Если telegram.bot_token в
config.yaml заполнен, watchdog.py поднимает это поверх обычного мониторинга
в том же процессе: уведомления дублируются в Telegram, плюс становятся
доступны команды/инлайн-меню. Если bot_token пуст, этот модуль просто не
используется - всё остальное (мониторинг, блокировка, локальный лог)
работает как обычно.

Весь общий стейт (`db`, конфиг) передаётся через shared_state - один и тот
же dict, на который смотрит и основной цикл мониторинга в watchdog.py, и
обработчики команд здесь (мутации в одном месте сразу видны в другом).
"""
from __future__ import annotations

import datetime
import logging
from pathlib import Path

from telegram import InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CallbackQueryHandler, CommandHandler, ContextTypes

from bot import blocker
from bot.config import Config
from bot.env_detect import format_summary_text, summarize_environment
from bot.fallback import pending_count
from bot.ip_lists import fetch_threat_db, save_cache

log = logging.getLogger("skipa_watchdog.telegram")


def _is_admin(config: Config, user_id: int) -> bool:
    return not config.admin_ids or user_id in config.admin_ids


def _read_version() -> str:
    try:
        return Path("VERSION").read_text(encoding="utf-8").strip() or "unknown"
    except OSError:
        return "unknown"


def _state(context: ContextTypes.DEFAULT_TYPE) -> dict:
    return context.bot_data["state"]


def build_status_text(config: Config, state: dict) -> str:
    db = state.get("db")
    if db is None:
        return "База ещё не загружена."
    last_update = datetime.datetime.fromtimestamp(db.last_update_ts).strftime("%Y-%m-%d %H:%M:%S")
    per_source = ", ".join(f"{k}={v}" for k, v in db.per_source_counts.items()) or "-"
    blocked = len(blocker.list_blocked_ips())
    return (
        "📊 Статус Skipa Watchdog\n"
        f"Версия: {_read_version()}\n"
        f"Режим действия: {config.action_mode}\n"
        f"Активный список: {config.active_list}\n"
        f"Записей в базе: {db.source_line_count} ({per_source})\n"
        f"Последнее обновление: {last_update}\n"
        f"Метод мониторинга: {config.method}\n"
        f"Заблокировано IP: {blocked}\n"
        f"Отложенных алертов в очереди: {pending_count()}"
    )


async def _do_update_db(config: Config, state: dict) -> str:
    new_db = await fetch_threat_db(
        config.primary_list_url, config.blacklist_url, config.blacklist_name, config.active_list
    )
    if new_db.networks or new_db.ranges:
        state["db"] = new_db
        save_cache(new_db)
        return f"Готово: {new_db.source_line_count} записей."
    return "Не удалось получить свежую базу, оставил старую версию."


# ---------------------------------------------------------------------------
# Команды
# ---------------------------------------------------------------------------

async def cmd_start(update, context: ContextTypes.DEFAULT_TYPE) -> None:
    config: Config = context.bot_data["config"]
    text = (
        "Skipa Watchdog подключён к Telegram: уведомления о сканерах (CyberOK/Skipa, ГРЧЦ, "
        "НКЦКИ + доп. списки) будут приходить сюда. Текущий режим действия: {mode}.\n"
        "Команды: /menu, /status, /update, /testalert [ip], /pending, /env, "
        "/blocklist, /block <ip>, /unblock <ip>"
    ).replace("{mode}", config.action_mode)
    await update.message.reply_text(text)


async def cmd_menu(update, context: ContextTypes.DEFAULT_TYPE) -> None:
    keyboard = [
        [
            InlineKeyboardButton("📊 Статус", callback_data="status"),
            InlineKeyboardButton("🔄 Обновить базу", callback_data="update"),
        ],
        [
            InlineKeyboardButton("⏳ Очередь", callback_data="pending"),
            InlineKeyboardButton("🐳 Docker/K8s", callback_data="env"),
        ],
        [
            InlineKeyboardButton("🚫 Блокировки", callback_data="blocklist"),
            InlineKeyboardButton("❓ Помощь", callback_data="help"),
        ],
    ]
    await update.message.reply_text(
        "Меню Skipa Watchdog:", reply_markup=InlineKeyboardMarkup(keyboard)
    )


async def cmd_status(update, context: ContextTypes.DEFAULT_TYPE) -> None:
    config: Config = context.bot_data["config"]
    if not _is_admin(config, update.effective_user.id):
        return
    await update.message.reply_text(build_status_text(config, _state(context)))


async def cmd_update(update, context: ContextTypes.DEFAULT_TYPE) -> None:
    config: Config = context.bot_data["config"]
    if not _is_admin(config, update.effective_user.id):
        return
    await update.message.reply_text("Обновляю базу IP-адресов...")
    await update.message.reply_text(await _do_update_db(config, _state(context)))


async def cmd_testalert(update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Присылает тестовый алерт с примером из ТЗ, чтобы проверить форматирование в чате."""
    from bot.enrich import enrich_ip
    from bot.formatter import build_alert_message

    config: Config = context.bot_data["config"]
    if not _is_admin(config, update.effective_user.id):
        return
    test_ip = context.args[0] if context.args else "203.0.113.42"
    data = (
        await enrich_ip(test_ip, config.ipinfo_token, config.ipregistry_key)
        if config.enrich_enabled
        else {}
    )
    text = build_alert_message(test_ip, "тестовый вызов /testalert", data)
    await update.message.reply_text(text, parse_mode="HTML", disable_web_page_preview=True)


async def cmd_pending(update, context: ContextTypes.DEFAULT_TYPE) -> None:
    config: Config = context.bot_data["config"]
    if not _is_admin(config, update.effective_user.id):
        return
    count = pending_count()
    if count == 0:
        await update.message.reply_text("Очередь отложенных алертов пуста, всё доставлено.")
    else:
        await update.message.reply_text(
            f"⏳ В очереди {count} алертов, которые не удалось отправить ранее. "
            f"Пробую доотправить их каждые {config.retry_interval_seconds} сек."
        )


async def cmd_env(update, context: ContextTypes.DEFAULT_TYPE) -> None:
    config: Config = context.bot_data["config"]
    if not _is_admin(config, update.effective_user.id):
        return
    await update.message.reply_text("Анализирую окружение (docker/k8s)...")
    summary = summarize_environment(config.kernel_log_prefix)
    await update.message.reply_text(format_summary_text(summary))


async def cmd_blocklist(update, context: ContextTypes.DEFAULT_TYPE) -> None:
    config: Config = context.bot_data["config"]
    if not _is_admin(config, update.effective_user.id):
        return
    ips = blocker.list_blocked_ips()
    if not ips:
        await update.message.reply_text("Сейчас никто не заблокирован.")
        return
    text = "🚫 Заблокированные IP:\n" + "\n".join(ips[:50])
    if len(ips) > 50:
        text += f"\n... и ещё {len(ips) - 50}"
    await update.message.reply_text(text)


async def cmd_block(update, context: ContextTypes.DEFAULT_TYPE) -> None:
    config: Config = context.bot_data["config"]
    if not _is_admin(config, update.effective_user.id):
        return
    if not context.args:
        await update.message.reply_text("Использование: /block <ip>")
        return
    ip = context.args[0]
    if blocker.block_ip(ip):
        await update.message.reply_text(f"IP {ip} заблокирован вручную.")
    else:
        await update.message.reply_text(f"Не удалось заблокировать {ip} (см. логи).")


async def cmd_unblock(update, context: ContextTypes.DEFAULT_TYPE) -> None:
    config: Config = context.bot_data["config"]
    if not _is_admin(config, update.effective_user.id):
        return
    if not context.args:
        await update.message.reply_text("Использование: /unblock <ip>")
        return
    ip = context.args[0]
    if blocker.unblock_ip(ip):
        await update.message.reply_text(f"IP {ip} разблокирован.")
    else:
        await update.message.reply_text(f"Не удалось разблокировать {ip} (см. логи).")


async def menu_callback(update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Обрабатывает нажатия кнопок из /menu, переиспользуя логику команд выше."""
    query = update.callback_query
    config: Config = context.bot_data["config"]
    if not _is_admin(config, query.from_user.id):
        await query.answer()
        return
    await query.answer()

    if query.data == "status":
        await query.message.reply_text(build_status_text(config, _state(context)))
    elif query.data == "update":
        await query.message.reply_text("Обновляю базу IP-адресов...")
        await query.message.reply_text(await _do_update_db(config, _state(context)))
    elif query.data == "pending":
        count = pending_count()
        await query.message.reply_text(
            "Очередь пуста." if count == 0 else f"⏳ В очереди {count} алертов."
        )
    elif query.data == "env":
        await query.message.reply_text("Анализирую окружение (docker/k8s)...")
        summary = summarize_environment(config.kernel_log_prefix)
        await query.message.reply_text(format_summary_text(summary))
    elif query.data == "blocklist":
        ips = blocker.list_blocked_ips()
        await query.message.reply_text(
            "Никто не заблокирован." if not ips else "🚫 " + ", ".join(ips[:50])
        )
    elif query.data == "help":
        await query.message.reply_text(
            "/status, /update, /testalert [ip], /pending, /env, /blocklist, "
            "/block <ip>, /unblock <ip> - подробности в README."
        )


async def build_application(config: Config, shared_state: dict) -> Application:
    """Собирает Telegram Application. Жизненным циклом (initialize/start/
    polling/shutdown) управляет watchdog.py, чтобы всё жило в одном
    asyncio-луп вместе с циклами мониторинга."""
    app = Application.builder().token(config.bot_token).build()
    app.bot_data["state"] = shared_state
    app.bot_data["config"] = config

    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("menu", cmd_menu))
    app.add_handler(CommandHandler("status", cmd_status))
    app.add_handler(CommandHandler("update", cmd_update))
    app.add_handler(CommandHandler("testalert", cmd_testalert))
    app.add_handler(CommandHandler("pending", cmd_pending))
    app.add_handler(CommandHandler("env", cmd_env))
    app.add_handler(CommandHandler("blocklist", cmd_blocklist))
    app.add_handler(CommandHandler("block", cmd_block))
    app.add_handler(CommandHandler("unblock", cmd_unblock))
    app.add_handler(CallbackQueryHandler(menu_callback))
    return app


async def send_notification(app: Application, chat_id: int, text: str) -> None:
    await app.bot.send_message(
        chat_id=chat_id, text=text, parse_mode="HTML", disable_web_page_preview=True
    )
