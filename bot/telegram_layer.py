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

Безопасность: команды принимаются только от администраторов. Если
telegram.admin_ids пуст, администратором считается только тот, кто пишет из
чата telegram.chat_id (раньше при пустом списке командами мог пользоваться
любой, кто нашёл бота). Все IP, пришедшие в командах, проверяются перед
использованием.
"""
from __future__ import annotations

import asyncio
import datetime
import ipaddress
import logging
from pathlib import Path

from telegram import InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CallbackQueryHandler, CommandHandler, ContextTypes

from bot import blocker
from bot.config import Config
from bot.dbupdate import refresh_db
from bot.env_detect import format_summary_text, summarize_environment
from bot.fallback import pending_count
from bot.ip_lists import normalize_ip

log = logging.getLogger("skipa_watchdog.telegram")

VERSION_FILE = Path(__file__).resolve().parent.parent / "VERSION"


def _is_admin(config: Config, user_id: int | None, chat_id: int | None = None) -> bool:
    if user_id is None:
        return False
    if config.admin_ids:
        return user_id in config.admin_ids
    # admin_ids не задан: доверяем только настроенному чату (личка или группа)
    return bool(config.chat_id) and chat_id == config.chat_id


def _read_version() -> str:
    try:
        return VERSION_FILE.read_text(encoding="utf-8").strip() or "unknown"
    except OSError:
        return "unknown"


def _state(context: ContextTypes.DEFAULT_TYPE) -> dict:
    return context.bot_data["state"]


def _parse_ip_arg(raw: str) -> str | None:
    """Строго разбирает IP-адрес из аргумента команды. Возвращает каноническую
    строку или None - сырой пользовательский ввод дальше не идёт ни в URL, ни
    в iptables."""
    ip_obj = normalize_ip((raw or "").strip())
    return str(ip_obj) if ip_obj is not None else None


async def build_status_text(config: Config, state: dict) -> str:
    db = state.get("db")
    if db is None:
        return "База ещё не загружена."
    last_update = datetime.datetime.fromtimestamp(db.last_update_ts).strftime("%Y-%m-%d %H:%M:%S")
    per_source = ", ".join(f"{k}={v}" for k, v in db.per_source_counts.items()) or "-"

    lines = [
        "📊 Статус Skipa Watchdog",
        f"Версия: {_read_version()}",
        f"Режим действия: {config.action_mode}",
        f"Активный список: {config.active_list}",
        f"Записей в базе: {db.source_line_count} ({per_source})",
        f"Последнее обновление: {last_update}",
        f"Метод мониторинга: {config.method}",
    ]
    if db.degraded:
        lines.append("⚠️ База неполная: часть источников недоступна, используется прошлая версия")

    if config.firewall_needed:
        info = await asyncio.to_thread(blocker.status_info)
        lines.append(f"Блокировка: режим {info['mode']}" + (", база предзагружена" if info["preload"] else ""))
        for chain, ok in info["wiring"].items():
            lines.append(f"  {'✅' if ok else '⚠️'} {chain} -> SKIPA-BLOCK" + ("" if ok else " (не подключена!)"))
        if config.method in ("kernel_log", "both"):
            lines.append(
                "  ✅ LOG-правило на месте" if info["log_rule"]
                else "  ⚠️ LOG-правило отсутствует - kernel_log ничего не увидит"
            )
        if info["mode"] == "ipset":
            lines.append(
                f"  ipset: база={info.get('db_set')}, блокировки={info.get('dyn_set')}, allowlist={info.get('allow_set')}"
            )
        elif config.drop_enabled:
            lines.append(f"  Заблокировано IP: {len(await asyncio.to_thread(blocker.list_blocked_ips))}")
    lines.append(f"Отложенных алертов в очереди: {pending_count()}")
    return "\n".join(lines)


async def _guard(update, context) -> Config | None:
    """Возвращает конфиг, если отправитель - администратор, иначе None."""
    config: Config = context.bot_data["config"]
    user = update.effective_user
    chat = update.effective_chat
    if _is_admin(config, user.id if user else None, chat.id if chat else None):
        return config
    log.warning("Команда отклонена: user=%s chat=%s не администратор", getattr(user, "id", None), getattr(chat, "id", None))
    return None


# ---------------------------------------------------------------------------
# Команды
# ---------------------------------------------------------------------------

async def cmd_start(update, context: ContextTypes.DEFAULT_TYPE) -> None:
    config = await _guard(update, context)
    if config is None:
        return
    text = (
        "Skipa Watchdog подключён к Telegram: уведомления о сканерах (CyberOK/Skipa, ГРЧЦ, "
        "НКЦКИ + доп. списки) будут приходить сюда. Текущий режим действия: {mode}.\n"
        "Команды: /menu, /status, /update, /testalert [ip], /pending, /env, "
        "/blocklist, /block <ip> [часы], /unblock <ip>"
    ).replace("{mode}", config.action_mode)
    await update.message.reply_text(text)


async def cmd_menu(update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if await _guard(update, context) is None:
        return
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
    config = await _guard(update, context)
    if config is None:
        return
    await update.message.reply_text(await build_status_text(config, _state(context)))


async def cmd_update(update, context: ContextTypes.DEFAULT_TYPE) -> None:
    config = await _guard(update, context)
    if config is None:
        return
    await update.message.reply_text("Обновляю базу IP-адресов...")
    await update.message.reply_text(await refresh_db(config, _state(context)))


async def cmd_testalert(update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Присылает тестовый алерт, чтобы проверить форматирование в чате."""
    from bot.enrich import EnrichedIP, enrich_ip
    from bot.formatter import build_alert_message

    config = await _guard(update, context)
    if config is None:
        return
    test_ip = "203.0.113.42"
    if context.args:
        test_ip = _parse_ip_arg(context.args[0])
        if test_ip is None:
            await update.message.reply_text("Некорректный IP. Использование: /testalert [ip]")
            return
    data = (
        await enrich_ip(test_ip, config.ipinfo_token, config.ipregistry_key)
        if config.enrich_enabled
        else EnrichedIP(ip=test_ip)
    )
    text = build_alert_message(test_ip, "тестовый вызов /testalert", data)
    await update.message.reply_text(text, parse_mode="HTML", disable_web_page_preview=True)


async def cmd_pending(update, context: ContextTypes.DEFAULT_TYPE) -> None:
    config = await _guard(update, context)
    if config is None:
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
    config = await _guard(update, context)
    if config is None:
        return
    await update.message.reply_text("Анализирую окружение (docker/k8s)...")
    summary = await asyncio.to_thread(summarize_environment, config.kernel_log_prefix)
    await update.message.reply_text(format_summary_text(summary))


async def _blocklist_text() -> str:
    ips = await asyncio.to_thread(blocker.list_blocked_ips)
    if not ips:
        return "Сейчас никто не заблокирован."
    text = "🚫 Заблокированные IP:\n" + "\n".join(ips[:50])
    if len(ips) > 50:
        text += f"\n... и ещё {len(ips) - 50}"
    return text


async def cmd_blocklist(update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if await _guard(update, context) is None:
        return
    await update.message.reply_text(await _blocklist_text())


async def cmd_block(update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if await _guard(update, context) is None:
        return
    if not context.args:
        await update.message.reply_text("Использование: /block <ip или сеть> [часы]  (без часов - бессрочно)")
        return
    target = context.args[0]
    net, reason = blocker.validate_target(target)
    if net is None:
        await update.message.reply_text(f"Не блокирую {target}: {reason}.")
        return
    timeout_s = 0
    if len(context.args) > 1:
        try:
            hours = float(context.args[1])
            if hours < 0:
                raise ValueError
            timeout_s = int(hours * 3600)
        except ValueError:
            await update.message.reply_text("Число часов должно быть неотрицательным числом.")
            return
    ok = await asyncio.to_thread(blocker.block_ip, target, timeout_s)
    if ok:
        suffix = f" на {context.args[1]} ч" if timeout_s else " бессрочно"
        await update.message.reply_text(f"{net} заблокирован вручную{suffix}.")
    else:
        await update.message.reply_text(f"Не удалось заблокировать {net} (см. логи).")


async def cmd_unblock(update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if await _guard(update, context) is None:
        return
    if not context.args:
        await update.message.reply_text("Использование: /unblock <ip>")
        return
    ip = _parse_ip_arg(context.args[0].split("/")[0])
    if ip is None:
        await update.message.reply_text("Некорректный IP.")
        return
    arg = context.args[0] if "/" in context.args[0] else ip
    if await asyncio.to_thread(blocker.unblock_ip, arg):
        text = f"{arg} разблокирован."
        if await asyncio.to_thread(blocker.is_in_db_set, ip):
            text += (
                "\n⚠️ Адрес входит в базу сканеров (ipset skipa-db) и всё равно будет "
                "блокироваться. Чтобы исключить его, добавьте в monitoring.ignore_ips."
            )
        await update.message.reply_text(text)
    else:
        await update.message.reply_text(f"Не удалось разблокировать {arg} (см. логи).")


async def menu_callback(update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Обрабатывает нажатия кнопок из /menu, переиспользуя логику команд выше."""
    query = update.callback_query
    config: Config = context.bot_data["config"]
    chat_id = query.message.chat.id if query.message else None
    if not _is_admin(config, query.from_user.id, chat_id):
        await query.answer()
        return
    await query.answer()

    if query.data == "status":
        await query.message.reply_text(await build_status_text(config, _state(context)))
    elif query.data == "update":
        await query.message.reply_text("Обновляю базу IP-адресов...")
        await query.message.reply_text(await refresh_db(config, _state(context)))
    elif query.data == "pending":
        count = pending_count()
        await query.message.reply_text(
            "Очередь пуста." if count == 0 else f"⏳ В очереди {count} алертов."
        )
    elif query.data == "env":
        await query.message.reply_text("Анализирую окружение (docker/k8s)...")
        summary = await asyncio.to_thread(summarize_environment, config.kernel_log_prefix)
        await query.message.reply_text(format_summary_text(summary))
    elif query.data == "blocklist":
        await query.message.reply_text(await _blocklist_text())
    elif query.data == "help":
        await query.message.reply_text(
            "/status, /update, /testalert [ip], /pending, /env, /blocklist, "
            "/block <ip> [часы], /unblock <ip> - подробности в README."
        )


async def build_application(config: Config, shared_state: dict) -> Application:
    """Собирает Telegram Application. Жизненным циклом (initialize/start/
    polling/shutdown) управляет watchdog.py, чтобы всё жило в одном
    asyncio-луп вместе с циклами мониторинга."""
    builder = Application.builder().token(config.bot_token)
    if config.telegram_proxy:
        # для socks5:// нужен extra: pip install "python-telegram-bot[socks]"
        builder = builder.proxy(config.telegram_proxy).get_updates_proxy(config.telegram_proxy)
    app = builder.build()
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
