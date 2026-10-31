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
import ipaddress
import logging
import re
import tempfile
import time
from html import escape
from pathlib import Path

from telegram import InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CallbackQueryHandler, CommandHandler, ContextTypes

from bot import banning, blocker, confedit, updater
from bot.events_store import load_events
from bot.stats import format_summary_text as format_stats_text
from bot.stats import stats_for_period
from bot.config import Config
from bot.dbupdate import refresh_db
from bot.env_detect import format_summary_text, summarize_environment
from bot.fallback import pending_count
from bot.allowlist import build_allowlist
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
        f"НКЦКИ + доп. списки) будут приходить сюда. Текущий режим действия: {config.action_mode}.\n"
        + HELP_TEXT
    )
    await update.message.reply_text(text)


_TOKEN_RE = re.compile(r"\b\d{6,}:[A-Za-z0-9_-]{30,}\b")


def _tail_lines(path: Path, n: int, max_bytes: int = 256 * 1024) -> list[str]:
    """Последние n строк файла без чтения всего файла."""
    try:
        with path.open("rb") as f:
            size = f.seek(0, 2)
            f.seek(max(0, size - max_bytes))
            data = f.read()
    except OSError:
        return []
    return data.decode("utf-8", errors="replace").splitlines()[-n:]


async def cmd_logs(update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Последние строки журнала службы (то же, что пункт «Просмотр логов» панели)."""
    config = await _guard(update, context)
    if config is None:
        return
    try:
        n = max(1, min(100, int(context.args[0]))) if context.args else 30
    except ValueError:
        n = 30
    lines = await asyncio.to_thread(_tail_lines, Path(config.log_dir) / "skipa-watchdog.log", n)
    if not lines:
        await update.message.reply_text("Журнал пуст или недоступен.")
        return
    text = _TOKEN_RE.sub("<токен скрыт>", "\n".join(lines))
    while len(text) > 3500:                       # лимит Telegram - 4096 символов на сообщение
        text = text[text.index("\n") + 1:]
    await update.message.reply_text(f"<pre>{escape(text)}</pre>", parse_mode="HTML")


# ---------- белый список (monitoring.ignore_ips) ----------

def _parse_allow_arg(arg: str) -> str | None:
    """Канонический вид IP/сети для записи в конфиг или None."""
    try:
        if "/" in arg:
            return str(ipaddress.ip_network(arg, strict=False))
        return str(ipaddress.ip_address(arg))
    except ValueError:
        return None


async def _apply_allowlist(config: Config) -> None:
    """Сразу в ядро (ipset skipa-allow), не дожидаясь очередного цикла проверки."""
    nets = await asyncio.to_thread(build_allowlist, config.ignore_networks, config.auto_allowlist, config.ssh_ports)
    await asyncio.to_thread(blocker.sync_allowlist, nets)


async def cmd_allowlist(update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if await _guard(update, context) is None:
        return
    items = await confedit.ignore_list()
    body = "\n".join(f"• <code>{escape(i)}</code>" for i in items) or "(пусто)"
    await update.message.reply_text(
        "<b>Белый список</b> (monitoring.ignore_ips): эти адреса никогда не блокируются.\n" + body +
        "\nДобавить: /allow &lt;ip|сеть&gt;, убрать: /unallow &lt;ip|сеть&gt;. "
        "Свои SSH-сессии защищаются автоматически (monitoring.auto_allowlist).",
        parse_mode="HTML",
    )


async def cmd_allow(update, context: ContextTypes.DEFAULT_TYPE) -> None:
    config = await _guard(update, context)
    if config is None:
        return
    arg = context.args[0] if context.args else ""
    value = _parse_allow_arg(arg)
    if value is None:
        await update.message.reply_text("Использование: /allow <ip|сеть>, например /allow 203.0.113.5 или /allow 198.51.100.0/24")
        return
    result = await confedit.ignore_add(value)
    if result.startswith("error"):
        await update.message.reply_text(f"Не удалось записать в config.yaml: {escape(result)}")
        return
    net = ipaddress.ip_network(value, strict=False)
    if net not in config.ignore_networks:
        config.ignore_networks.append(net)    # тот же список читают циклы мониторинга - действует сразу
    await _apply_allowlist(config)
    # если адрес уже был заблокирован - снимаем блокировку, иначе они противоречат друг другу
    unblocked = False
    if net.num_addresses == 1 and await asyncio.to_thread(blocker.is_blocked, str(net.network_address)):
        by = f"@{update.effective_user.username or update.effective_user.id}"
        unblocked = await banning.unban_ip(str(net.network_address), fail2ban_jail=config.fail2ban_jail, by=by)
    text = f"✅ {value} добавлен в белый список." if result == "added" else f"ℹ️ {value} уже в белом списке."
    if unblocked:
        text += " Блокировка снята."
    await update.message.reply_text(text)


async def cmd_unallow(update, context: ContextTypes.DEFAULT_TYPE) -> None:
    config = await _guard(update, context)
    if config is None:
        return
    arg = context.args[0] if context.args else ""
    value = _parse_allow_arg(arg)
    if value is None:
        await update.message.reply_text("Использование: /unallow <ip|сеть>")
        return
    # в конфиге адрес мог быть записан иначе (1.2.3.4 и 1.2.3.4/32) - пробуем оба вида
    result = await confedit.ignore_del(value)
    if result == "missing" and "/" not in arg:
        result = await confedit.ignore_del(value + ("/32" if ":" not in value else "/128"))
    if result.startswith("error"):
        await update.message.reply_text(f"Не удалось записать в config.yaml: {escape(result)}")
        return
    if result == "missing":
        await update.message.reply_text(f"{value} нет в monitoring.ignore_ips.")
        return
    net = ipaddress.ip_network(value, strict=False)
    config.ignore_networks[:] = [n for n in config.ignore_networks if n != net]
    await _apply_allowlist(config)
    await update.message.reply_text(f"✅ {value} убран из белого списка.")


# ---------- настройки (режим действия, список, метод) ----------

def _settings_keyboard(current: dict[str, str]) -> InlineKeyboardMarkup:
    rows = []
    for key, meta in confedit.SETTINGS.items():
        rows.append([InlineKeyboardButton(
            f"{'✓ ' if current.get(key) == value else ''}{title}",
            callback_data=f"cfg:ask:{key}:{value}",
        ) for value, title in meta["values"].items()][:3])
    return InlineKeyboardMarkup(rows)


async def _settings_text(config: Config) -> tuple[str, dict[str, str]]:
    current = {key: await confedit.get_value(key) or "?" for key in confedit.SETTINGS}
    lines = ["<b>Настройки</b> (нажмите значение, затем подтвердите; служба перезапустится):"]
    for key, meta in confedit.SETTINGS.items():
        shown = meta["values"].get(current[key], current[key])
        lines.append(f"• {meta['title']}: <b>{escape(shown)}</b> (<code>{key}</code>)")
    return "\n".join(lines), current


async def cmd_settings(update, context: ContextTypes.DEFAULT_TYPE) -> None:
    config = await _guard(update, context)
    if config is None:
        return
    text, current = await _settings_text(config)
    await update.message.reply_text(text, parse_mode="HTML", reply_markup=_settings_keyboard(current))


async def on_settings_callback(update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """cfg:ask:<ключ>:<значение> -> подтверждение; cfg:do:... -> запись и перезапуск; cfg:no -> отмена."""
    query = update.callback_query
    config: Config = context.bot_data["config"]
    chat_id = query.message.chat.id if query.message else None
    if not _is_admin(config, query.from_user.id, chat_id):
        await query.answer()
        return
    await query.answer()
    parts = query.data.split(":", 3)
    action = parts[1]
    if action == "no":
        await query.message.reply_text("Отменено.")
        return
    if len(parts) != 4 or parts[2] not in confedit.SETTINGS or parts[3] not in confedit.SETTINGS[parts[2]]["values"]:
        return
    key, value = parts[2], parts[3]
    meta = confedit.SETTINGS[key]
    if action == "ask":
        warn = "\n⚠️ Начнётся блокировка новых IP." if key == "action.mode" and value in ("block", "block_notify") else ""
        keyboard = InlineKeyboardMarkup([[
            InlineKeyboardButton("✅ Применить и перезапустить", callback_data=f"cfg:do:{key}:{value}"),
            InlineKeyboardButton("Отмена", callback_data="cfg:no"),
        ]])
        await query.message.reply_text(
            f"Изменить «{meta['title']}» на «{meta['values'][value]}»?{warn}", reply_markup=keyboard)
    elif action == "do":
        ok, err = await confedit.set_value(key, value)
        if not ok:
            await query.message.reply_text(f"Не удалось записать настройку: {err}")
            return
        await query.message.reply_text(f"✅ {meta['title']}: {meta['values'][value]}. Перезапускаю службу...")
        _ok, text = await confedit.restart_service()
        if not _ok:
            await query.message.reply_text(f"⚠️ {text}")


HELP_TEXT = (
    "Команды: /menu, /status, /update (база IP), /testalert [ip], /pending, /env, "
    "/stats [дней], /export [дней], /logs [строк], /blocklist (/banlist), /block <ip> [часы], "
    "/unblock (/unban) <ip>, /allowlist, /allow <ip|сеть>, /unallow <ip|сеть>, /settings, "
    "/version (обновления проекта). Подробности - в README."
)


def _update_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([[
        InlineKeyboardButton("⬆️ Установить", callback_data="upd:install"),
        InlineKeyboardButton("Позже", callback_data="upd:later"),
    ]])


async def _reply_update_status(message) -> None:
    """Версия + есть ли обновление (с кнопкой «Установить»)."""
    await message.reply_text(f"Skipa Watchdog, версия: {updater.read_version() or '?'}. Проверяю обновления...")
    info = await updater.check_update()
    if info:
        await message.reply_text(updater.format_update_text(info), parse_mode="HTML",
                                 reply_markup=_update_keyboard())
    else:
        await message.reply_text("Установлена актуальная версия (или репозиторий сейчас недоступен).")


async def cmd_version(update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if await _guard(update, context) is None:
        return
    await _reply_update_status(update.message)


async def on_update_callback(update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Кнопки обновления: upd:check / upd:install / upd:later (только администраторам)."""
    query = update.callback_query
    config: Config = context.bot_data["config"]
    chat_id = query.message.chat.id if query.message else None
    if not _is_admin(config, query.from_user.id, chat_id):
        await query.answer()
        return
    await query.answer()
    action = query.data.split(":", 1)[1]
    if action == "check":
        await _reply_update_status(query.message)
        return
    try:  # кнопки убираем, чтобы не нажали дважды
        await query.edit_message_reply_markup(reply_markup=None)
    except Exception:  # noqa: BLE001
        pass
    if action == "later":
        await query.message.reply_text("Хорошо, напомню при следующем запуске службы.")
        return
    if action == "install":
        info = await updater.check_update()
        if not info:
            await query.message.reply_text("Уже установлена актуальная версия.")
            return
        await query.message.reply_text(f"Устанавливаю {info.local or '?'} → {info.remote or '?'}...")
        ok, text = await updater.start_update(info)
        await query.message.reply_text(("⏳ " if ok else "⚠️ ") + text)


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
            InlineKeyboardButton("✅ Белый список", callback_data="allowlist"),
            InlineKeyboardButton("⚙️ Настройки", callback_data="settings"),
        ],
        [
            InlineKeyboardButton("⬆️ Обновления", callback_data="upd:check"),
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
    elif query.data == "allowlist":
        items = await confedit.ignore_list()
        body = "\n".join(f"• <code>{escape(i)}</code>" for i in items) or "(пусто)"
        await query.message.reply_text(
            "<b>Белый список</b>:\n" + body + "\n/allow &lt;ip|сеть&gt;, /unallow &lt;ip|сеть&gt;", parse_mode="HTML")
    elif query.data == "settings":
        text, current = await _settings_text(config)
        await query.message.reply_text(text, parse_mode="HTML", reply_markup=_settings_keyboard(current))
    elif query.data == "help":
        await query.message.reply_text(HELP_TEXT)


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
    app.add_handler(CommandHandler(["version", "upgrade"], cmd_version))
    app.add_handler(CommandHandler("allowlist", cmd_allowlist))
    app.add_handler(CommandHandler("allow", cmd_allow))
    app.add_handler(CommandHandler("unallow", cmd_unallow))
    app.add_handler(CommandHandler("settings", cmd_settings))
    app.add_handler(CommandHandler("logs", cmd_logs))
    app.add_handler(CallbackQueryHandler(on_settings_callback, pattern=r"^cfg:"))
    app.add_handler(CallbackQueryHandler(on_ban_callback, pattern=r"^ban:"))
    app.add_handler(CallbackQueryHandler(on_update_callback, pattern=r"^upd:"))
    app.add_handler(CallbackQueryHandler(menu_callback))
    return app


async def send_notification(app: Application, chat_id: int, text: str, reply_markup=None) -> None:
    await app.bot.send_message(
        chat_id=chat_id, text=text, parse_mode="HTML", disable_web_page_preview=True,
        reply_markup=reply_markup,
    )
