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
telegram.admin_ids пуст, администратором считается только пользователь, чей
личный чат с ботом совпадает с telegram.chat_id (в группе без admin_ids команды
закрыты: иначе ими мог бы пользоваться любой участник группы). Все IP, пришедшие в командах, проверяются перед
использованием.
"""
from __future__ import annotations

import asyncio
import datetime
import io
import logging
import tempfile
import time
from pathlib import Path

from telegram import InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CallbackQueryHandler, CommandHandler, ContextTypes

from bot import banning, blocker
from bot.events_store import load_events
from bot.stats import format_summary_text as format_stats_text
from bot.stats import stats_for_period
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
    # admin_ids не задан: доверяем только личной переписке с настроенным пользователем
    # (в личке id чата равен id пользователя). В группе командовать мог бы любой её
    # участник, поэтому для группы нужно явно перечислить администраторов в admin_ids.
    return bool(config.chat_id) and chat_id == config.chat_id and user_id == chat_id


def _read_version() -> str:
    try:
        return VERSION_FILE.read_text(encoding="utf-8").strip() or "unknown"
    except OSError:
        return "unknown"


def _state(context: ContextTypes.DEFAULT_TYPE) -> dict:
    return context.bot_data["state"]


def ban_keyboard(ip: str) -> InlineKeyboardMarkup:
    """Кнопка «🚫 Забанить» под алертом (banning.enabled)."""
    return InlineKeyboardMarkup([[InlineKeyboardButton("🚫 Забанить", callback_data=f"ban:{ip}")]])


def _days_arg(args, default: int = 7) -> int:
    try:
        return min(365, max(1, int(args[0]))) if args else default
    except ValueError:
        return default


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
    if config.dashboard_enabled:
        lines.append(f"Дашборд: http://{config.dashboard_host}:{config.dashboard_port}/")
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
        "/stats [дней], /export [дней], /blocklist (/banlist), /block <ip> [часы], "
        "/unblock (/unban) <ip>"
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
            InlineKeyboardButton("📈 Статистика", callback_data="stats"),
        ],
        [
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
    markup = ban_keyboard(test_ip) if config.ban_enabled else None
    await update.message.reply_text(
        text, parse_mode="HTML", disable_web_page_preview=True, reply_markup=markup
    )


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
    ips = await banning.list_banned()
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
        except (ValueError, OverflowError):
            await update.message.reply_text("Число часов должно быть неотрицательным числом.")
            return
    ok = await asyncio.to_thread(blocker.block_ip, target, timeout_s)
    if ok:
        suffix = f" на {context.args[1]} ч" if timeout_s else " бессрочно"
        await update.message.reply_text(f"{net} заблокирован вручную{suffix}.")
    else:
        await update.message.reply_text(f"Не удалось заблокировать {net} (см. логи).")


async def cmd_unblock(update, context: ContextTypes.DEFAULT_TYPE) -> None:
    config = await _guard(update, context)
    if config is None:
        return
    if not context.args:
        await update.message.reply_text("Использование: /unblock <ip>")
        return
    ip = _parse_ip_arg(context.args[0].split("/")[0])
    if ip is None:
        await update.message.reply_text("Некорректный IP.")
        return
    arg = context.args[0] if "/" in context.args[0] else ip
    by = f"@{update.effective_user.username or update.effective_user.id}"
    # через banning: запись в bans.jsonl и снятие бана в fail2ban (раньше они терялись)
    if await banning.unban_ip(arg, fail2ban_jail=config.fail2ban_jail, by=by):
        text = f"{arg} разблокирован."
        if await asyncio.to_thread(blocker.is_in_db_set, ip):
            text += (
                "\n⚠️ Адрес входит в базу сканеров (ipset skipa-db) и всё равно будет "
                "блокироваться. Чтобы исключить его, добавьте в monitoring.ignore_ips."
            )
        await update.message.reply_text(text)
    else:
        await update.message.reply_text(f"Не удалось разблокировать {arg} (см. логи).")


async def cmd_stats(update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if await _guard(update, context) is None:
        return
    days = _days_arg(context.args)
    summary, chart_png, hist = await asyncio.to_thread(stats_for_period, days)
    text = format_stats_text(summary, f"последние {days} дн.")
    if chart_png:
        await update.message.reply_photo(photo=io.BytesIO(chart_png), caption=text[:1024], parse_mode="HTML")
    else:
        extra = ("\n\n" + hist) if hist else "\n\n(данных пока недостаточно для графика)"
        await update.message.reply_text(text + extra, parse_mode="HTML")


async def cmd_export(update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Выгружает события за период текстовым файлом."""
    if await _guard(update, context) is None:
        return
    days = _days_arg(context.args)
    events = await asyncio.to_thread(load_events, time.time() - days * 86400)
    events.sort(key=lambda e: e["ts"])
    if not events:
        await update.message.reply_text(f"За последние {days} дн. событий не найдено.")
        return

    lines = [f"Skipa Watchdog - экспорт событий за последние {days} дн.", f"Всего записей: {len(events)}", ""]
    for e in events:
        dt = datetime.datetime.fromtimestamp(e["ts"]).strftime("%Y-%m-%d %H:%M:%S")
        lines.append(
            f"{dt} | IP={e['ip']} | база={e.get('source_name', '?')} | "
            f"страна={e.get('country_code', '?')} | org={e.get('org_name', '?')} | "
            f"метод={e.get('method', '?')} | порт={e.get('local_port', '?')}"
        )
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8") as f:
        f.write("\n".join(lines))
        tmp_path = f.name
    try:
        with open(tmp_path, "rb") as f:
            await update.message.reply_document(
                document=f,
                filename=f"skipa_watchdog_export_{days}d.txt",
                caption=f"Экспорт за последние {days} дн.: {len(events)} событий",
            )
    finally:
        Path(tmp_path).unlink(missing_ok=True)


async def on_ban_callback(update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Кнопка «🚫 Забанить» под алертом."""
    config: Config = context.bot_data["config"]
    query = update.callback_query
    chat_id = query.message.chat.id if query.message else None
    if not _is_admin(config, query.from_user.id, chat_id):
        await query.answer("Недостаточно прав для этого действия.", show_alert=True)
        return
    ip = _parse_ip_arg(query.data.split(":", 1)[1] if ":" in query.data else "")
    if ip is None:
        await query.answer("Некорректный IP.", show_alert=True)
        return

    ok, reason = await banning.ban_ip(
        ip,
        duration_minutes=config.manual_ban_duration_minutes,
        reason="забанен вручную через кнопку в Telegram",
        by=f"@{query.from_user.username or query.from_user.id}",
        fail2ban_jail=config.fail2ban_jail,
    )
    if not ok:
        await query.answer(f"Не удалось забанить: {reason}", show_alert=True)
        return
    await query.answer()
    duration = "навсегда" if config.manual_ban_duration_minutes == 0 else f"на {config.manual_ban_duration_minutes} мин."
    from html import escape

    await query.edit_message_text(
        query.message.text_html + f"\n\n✅ <b>Забанен ({duration})</b> — {escape(query.from_user.first_name or '')}",
        parse_mode="HTML",
        disable_web_page_preview=True,
    )


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
    elif query.data == "stats":
        summary, chart_png, hist = await asyncio.to_thread(stats_for_period, 7)
        text = format_stats_text(summary, "последние 7 дн.") + (("\n\n" + hist) if hist else "")
        if chart_png:
            await query.message.reply_photo(photo=io.BytesIO(chart_png), caption=text[:1024], parse_mode="HTML")
        else:
            await query.message.reply_text(text, parse_mode="HTML")
    elif query.data == "help":
        await query.message.reply_text(
            "/status, /update, /testalert [ip], /pending, /env, /stats [дней], /export [дней], "
            "/blocklist (/banlist), /block <ip> [часы], /unblock (/unban) <ip> - подробности в README."
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
    app.add_handler(CommandHandler(["blocklist", "banlist"], cmd_blocklist))
    app.add_handler(CommandHandler("block", cmd_block))
    app.add_handler(CommandHandler(["unblock", "unban"], cmd_unblock))
    app.add_handler(CommandHandler("stats", cmd_stats))
    app.add_handler(CommandHandler("export", cmd_export))
    app.add_handler(CallbackQueryHandler(on_ban_callback, pattern=r"^ban:"))
    app.add_handler(CallbackQueryHandler(menu_callback))
    return app


async def send_notification(app: Application, chat_id: int, text: str, reply_markup=None) -> None:
    await app.bot.send_message(
        chat_id=chat_id, text=text, parse_mode="HTML", disable_web_page_preview=True,
        reply_markup=reply_markup,
    )
