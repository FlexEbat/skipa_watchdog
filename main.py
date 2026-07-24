"""
Skipa Watchdog — Telegram-бот, который постоянно мониторит подключения к
серверу и присылает уведомления, если источник входит в одну или несколько
баз IP-адресов угроз: Skipa/CyberOK/ГРЧЦ/НКЦКИ
(https://github.com/tread-lightly/CyberOK_Skipa_ips) плюс опционально
Spamhaus DROP, FireHOL, AbuseIPDB и любые другие CIDR-листы (см.
config.example.yaml -> sources.extra).

Также умеет: банить IP по кнопке или автоматически (ipset + опционально
fail2ban), присылать статистику и график по расписанию, экспортировать
audit-лог, следить за собственным здоровьем (heartbeat мониторов) и
поднимать простой веб-дашборд.

Запуск:
    pip install -r requirements.txt
    cp config.example.yaml config.yaml   # и заполнить
    python main.py
"""
from __future__ import annotations

import datetime
import io
import logging
import tempfile
import time
from pathlib import Path

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
)

from bot.banning import ban_ip, is_ipset_ready, list_banned, unban_ip
from bot.config import Config
from bot.enrich import enrich_ip
from bot.events_store import load_events, prune_events, record_event
from bot.fallback import append_audit_log, load_pending, pending_count, queue_pending_alert, save_pending
from bot.formatter import build_alert_message
from bot.healthcheck import seconds_since_last
from bot.ip_lists import fetch_threat_db, load_cache, needs_update, save_cache
from bot.monitor import Deduper, poll_connections_loop, tail_kernel_log_loop
from bot.stats import format_summary_text, stats_for_period

CONFIG_PATH = "config.yaml"

log = logging.getLogger("skipa_watchdog")

# состояние health-check между проверками: чтобы не спамить одним и тем же
# предупреждением каждые check_interval_minutes, пока монитор не восстановится
_healthcheck_already_alerted: dict[str, bool] = {}


def _is_admin(config: Config, user_id: int) -> bool:
    return not config.admin_ids or user_id in config.admin_ids


def _ban_keyboard(ip: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([[InlineKeyboardButton("🚫 Забанить", callback_data=f"ban:{ip}")]])


# ---------------------------------------------------------------------------
# Job'ы (фоновые задачи через встроенный JobQueue PTB)
# ---------------------------------------------------------------------------

async def job_update_threat_db(context: ContextTypes.DEFAULT_TYPE) -> None:
    config: Config = context.bot_data["config"]
    db = context.bot_data.get("db")

    if not needs_update(db, config.update_interval_days):
        return

    log.info("Запускаю плановое обновление базы IP (раз в %s дн.)...", config.update_interval_days)
    new_db = await fetch_threat_db(config)
    if new_db.sources:
        context.bot_data["db"] = new_db
        save_cache(new_db)
        prune_events()
        log.info("База обновлена: %s записей из %d источников", new_db.source_line_count, len(new_db.sources))
    else:
        log.warning("Обновление базы не удалось (пустой ответ), оставляю старую версию")


async def job_check_updates_tick(context: ContextTypes.DEFAULT_TYPE) -> None:
    """Лёгкая проверка раз в час: не пора ли обновить базу (см. update_interval_days)."""
    await job_update_threat_db(context)


async def job_flush_pending_alerts(context: ContextTypes.DEFAULT_TYPE) -> None:
    """Периодически пытается доотправить алерты, которые не ушли в Telegram
    из-за временной недоступности связи (см. bot/fallback.py)."""
    records = load_pending()
    if not records:
        return

    log.info("В очереди %d отложенных алертов, пробую отправить...", len(records))
    still_pending = []
    for record in records:
        markup = None
        if record.get("reply_markup"):
            try:
                markup = InlineKeyboardMarkup.de_json(record["reply_markup"], context.bot)
            except Exception:  # noqa: BLE001
                markup = None
        try:
            await context.bot.send_message(
                chat_id=record["chat_id"],
                text=record["text"],
                parse_mode="HTML",
                disable_web_page_preview=True,
                reply_markup=markup,
            )
        except Exception as e:  # noqa: BLE001
            log.warning("Повтор снова не удался, оставляю в очереди: %s", e)
            still_pending.append(record)

    save_pending(still_pending)
    sent = len(records) - len(still_pending)
    if sent:
        log.info("Успешно доотправлено %d ранее отложенных алертов", sent)


async def job_healthcheck(context: ContextTypes.DEFAULT_TYPE) -> None:
    config: Config = context.bot_data["config"]
    if not config.healthcheck_enabled:
        return

    expected_monitors = []
    if config.method in ("psutil", "both"):
        expected_monitors.append("psutil")
    if config.method in ("kernel_log", "both"):
        expected_monitors.append("kernel_log")

    stale_seconds = config.healthcheck_stale_after_minutes * 60

    for name in expected_monitors:
        ago = seconds_since_last(name)
        is_stale = ago is None or ago > stale_seconds

        if is_stale and not _healthcheck_already_alerted.get(name):
            minutes = "неизвестно сколько" if ago is None else f"{ago / 60:.1f} мин."
            await context.bot.send_message(
                chat_id=config.chat_id,
                text=(
                    f"⚠️ <b>Watchdog для watchdog'а:</b> монитор <code>{name}</code> "
                    f"не подавал признаков жизни последние {minutes}. Возможно, завис "
                    f"или упал без явной ошибки в логах - проверьте "
                    f"<code>sudo journalctl -u skipa-watchdog -n 100</code>."
                ),
                parse_mode="HTML",
            )
            _healthcheck_already_alerted[name] = True
        elif not is_stale and _healthcheck_already_alerted.get(name):
            await context.bot.send_message(
                chat_id=config.chat_id,
                text=f"✅ Монитор <code>{name}</code> снова в порядке.",
                parse_mode="HTML",
            )
            _healthcheck_already_alerted[name] = False


async def job_weekly_digest(context: ContextTypes.DEFAULT_TYPE) -> None:
    config: Config = context.bot_data["config"]
    summary, chart_png = stats_for_period(days=7)
    text = format_summary_text(summary, "неделю")
    text = "📬 <b>Еженедельный дайджест Skipa Watchdog</b>\n\n" + text

    if chart_png:
        await context.bot.send_photo(
            chat_id=config.chat_id, photo=io.BytesIO(chart_png), caption=text, parse_mode="HTML"
        )
    else:
        await context.bot.send_message(chat_id=config.chat_id, text=text, parse_mode="HTML")


async def job_auto_unban_sweep(context: ContextTypes.DEFAULT_TYPE) -> None:
    """ipset сам снимает временные баны по истечении timeout - эта задача не
    обязательна для работы автобана, но пригодится, если понадобится logика
    поверх (сейчас не используется, оставлено как точка расширения)."""
    return


# ---------------------------------------------------------------------------
# Обработка обнаруженного скана + отправка алерта
# ---------------------------------------------------------------------------

def make_hit_handler(app: Application, config: Config):
    async def on_hit(hit) -> None:
        data = await enrich_ip(hit.ip, config.ipinfo_token, config.ipregistry_key)
        text = build_alert_message(hit.ip, hit.matched_source, hit.source_name, data)

        # Пишем в audit-лог и структурированное хранилище ВСЕГДА, независимо
        # от успеха отправки в Telegram - так ни один скан не потеряется.
        append_audit_log(hit.ip, hit.matched_source, text)
        record_event(
            ip=hit.ip,
            matched_source=hit.matched_source,
            source_name=hit.source_name,
            method=hit.method,
            enriched=data,
            local_port=hit.local_port,
        )

        markup = _ban_keyboard(hit.ip) if config.ban_enabled else None

        try:
            await app.bot.send_message(
                chat_id=config.chat_id,
                text=text,
                parse_mode="HTML",
                disable_web_page_preview=True,
                reply_markup=markup,
            )
        except Exception as e:  # noqa: BLE001
            log.error(
                "Не удалось отправить алерт в Telegram (%s), кладу в очередь на повтор", e
            )
            queue_pending_alert(config.chat_id, text, markup.to_dict() if markup else None)

        if config.ban_enabled and config.auto_ban_new_hits:
            ok = await ban_ip(
                hit.ip,
                ipset_name=config.ban_ipset_name,
                duration_minutes=config.auto_ban_duration_minutes,
                reason=f"авто-бан: совпадение с базой {hit.source_name}",
                by="auto",
                fail2ban_jail=config.fail2ban_jail,
            )
            if ok:
                log.info("Автобан сработал для %s", hit.ip)

    return on_hit


# ---------------------------------------------------------------------------
# Callback-кнопки (инлайн-клавиатура под алертом)
# ---------------------------------------------------------------------------

async def on_ban_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    config: Config = context.bot_data["config"]
    query = update.callback_query
    await query.answer()

    if not _is_admin(config, query.from_user.id):
        await query.answer("Недостаточно прав для этого действия.", show_alert=True)
        return

    ip = query.data.split(":", 1)[1]
    ok = await ban_ip(
        ip,
        ipset_name=config.ban_ipset_name,
        duration_minutes=config.manual_ban_duration_minutes,
        reason="забанен вручную через кнопку в Telegram",
        by=f"@{query.from_user.username or query.from_user.id}",
        fail2ban_jail=config.fail2ban_jail,
    )

    if ok:
        duration = (
            "навсегда" if config.manual_ban_duration_minutes == 0
            else f"на {config.manual_ban_duration_minutes} мин."
        )
        new_text = query.message.text_html + f"\n\n✅ <b>Забанен ({duration})</b> — {query.from_user.first_name}"
        await query.edit_message_text(new_text, parse_mode="HTML")
    else:
        await query.answer("Не удалось забанить (проверьте, установлен ли ipset). Смотрите логи бота.", show_alert=True)

    return


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

    last_update = datetime.datetime.fromtimestamp(db.last_update_ts).strftime("%Y-%m-%d %H:%M:%S")
    sources_line = ", ".join(f"{s.display_name} ({s.line_count()})" for s in db.sources.values())

    banned_line = ""
    if config.ban_enabled:
        banned = await list_banned(config.ban_ipset_name)
        banned_line = f"\nЗабанено сейчас: {len(banned)}"

    dashboard_line = ""
    if config.dashboard_enabled:
        dashboard_line = f"\nДашборд: http://{config.dashboard_host}:{config.dashboard_port}/"

    await update.message.reply_text(
        "📊 Статус Skipa Watchdog\n"
        f"Записей в базе: {db.source_line_count} ({sources_line})\n"
        f"Последнее обновление: {last_update}\n"
        f"Метод мониторинга: {config.method}\n"
        f"Интервал опроса соединений: {config.poll_interval_seconds} сек.\n"
        f"Антиспам-кулдаун: {config.alert_cooldown_minutes} мин.\n"
        f"Отложенных алертов в очереди: {pending_count()}"
        f"{banned_line}{dashboard_line}"
    )


async def cmd_update(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    config: Config = context.bot_data["config"]
    if not _is_admin(config, update.effective_user.id):
        return
    await update.message.reply_text("Обновляю базы IP-адресов...")
    new_db = await fetch_threat_db(config)
    if new_db.sources:
        context.bot_data["db"] = new_db
        save_cache(new_db)
        await update.message.reply_text(f"Готово: {new_db.source_line_count} записей из {len(new_db.sources)} источников.")
    else:
        await update.message.reply_text("Не удалось получить свежую базу, оставил старую версию.")


async def cmd_testalert(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Присылает тестовый алерт, чтобы проверить форматирование и кнопку бана в чате."""
    config: Config = context.bot_data["config"]
    if not _is_admin(config, update.effective_user.id):
        return
    test_ip = context.args[0] if context.args else "203.0.113.42"
    data = await enrich_ip(test_ip, config.ipinfo_token, config.ipregistry_key)
    text = build_alert_message(test_ip, "203.0.113.0/24", "тестовый вызов /testalert", data)
    markup = _ban_keyboard(test_ip) if config.ban_enabled else None
    await update.message.reply_text(text, parse_mode="HTML", disable_web_page_preview=True, reply_markup=markup)


async def cmd_pending(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    config: Config = context.bot_data["config"]
    if not _is_admin(config, update.effective_user.id):
        return
    count = pending_count()
    if count == 0:
        await update.message.reply_text("Очередь отложенных алертов пуста, всё доставлено.")
    else:
        await update.message.reply_text(
            f"⏳ В очереди {count} алертов, которые не удалось отправить ранее. "
            f"Бот пытается доотправить их каждые {config.retry_interval_seconds} сек."
        )


async def cmd_banlist(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    config: Config = context.bot_data["config"]
    if not _is_admin(config, update.effective_user.id):
        return
    if not config.ban_enabled:
        await update.message.reply_text("Бан отключён в config.yaml (banning.enabled: false).")
        return
    banned = await list_banned(config.ban_ipset_name)
    if not banned:
        await update.message.reply_text("Сейчас никто не забанен.")
        return
    text = "🚫 Забанено сейчас:\n" + "\n".join(f"<code>{ip}</code>" for ip in banned[:100])
    if len(banned) > 100:
        text += f"\n... и ещё {len(banned) - 100}"
    await update.message.reply_text(text, parse_mode="HTML")


async def cmd_unban(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    config: Config = context.bot_data["config"]
    if not _is_admin(config, update.effective_user.id):
        return
    if not context.args:
        await update.message.reply_text("Использование: /unban <ip>")
        return
    ip = context.args[0]
    ok = await unban_ip(ip, ipset_name=config.ban_ipset_name, fail2ban_jail=config.fail2ban_jail,
                          by=f"@{update.effective_user.username or update.effective_user.id}")
    await update.message.reply_text(f"{'✅ Разбанен' if ok else '❌ Не удалось разбанить'}: {ip}")


async def cmd_stats(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    config: Config = context.bot_data["config"]
    if not _is_admin(config, update.effective_user.id):
        return
    days = 7
    if context.args:
        try:
            days = int(context.args[0])
        except ValueError:
            pass
    summary, chart_png = stats_for_period(days=days)
    text = format_summary_text(summary, f"последние {days} дн.")
    if chart_png:
        await update.message.reply_photo(photo=io.BytesIO(chart_png), caption=text, parse_mode="HTML")
    else:
        await update.message.reply_text(text + "\n\n(данных пока недостаточно для графика)", parse_mode="HTML")


async def cmd_export(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    config: Config = context.bot_data["config"]
    if not _is_admin(config, update.effective_user.id):
        return
    days = 7
    if context.args:
        try:
            days = int(context.args[0])
        except ValueError:
            pass

    since_ts = time.time() - days * 86400
    events = load_events(since_ts=since_ts)
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


async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(
        "Skipa Watchdog запущен и следит за подключениями известных сканеров.\n\n"
        "Команды:\n"
        "/status - текущее состояние\n"
        "/update - обновить базу IP сейчас\n"
        "/testalert [ip] - тестовое уведомление\n"
        "/pending - очередь неотправленных алертов\n"
        "/stats [дней] - статистика + график (по умолчанию 7 дн.)\n"
        "/export [дней] - выгрузить события файлом\n"
        "/banlist - кто сейчас забанен\n"
        "/unban <ip> - снять бан"
    )


# ---------------------------------------------------------------------------
# Точка входа
# ---------------------------------------------------------------------------

async def post_init(app: Application) -> None:
    config: Config = app.bot_data["config"]

    db = load_cache()
    if needs_update(db, config.update_interval_days):
        log.info("Локального кэша нет или он устарел, качаю базу впервые...")
        db = await fetch_threat_db(config)
        save_cache(db)
    app.bot_data["db"] = db

    if config.ban_enabled and not await is_ipset_ready(config.ban_ipset_name):
        log.warning(
            "banning.enabled=true, но ipset-набор %r не найден. Выполните "
            "install-logging-rules.sh (создаёт ipset и DROP-правила) перед использованием бана.",
            config.ban_ipset_name,
        )

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

    # периодически пытаемся доотправить алерты, застрявшие в очереди из-за
    # временной недоступности Telegram (см. bot/fallback.py)
    app.job_queue.run_repeating(
        job_flush_pending_alerts, interval=config.retry_interval_seconds, first=30
    )

    # health-check самих мониторов
    if config.healthcheck_enabled:
        app.job_queue.run_repeating(
            job_healthcheck,
            interval=config.healthcheck_check_interval_minutes * 60,
            first=config.healthcheck_check_interval_minutes * 60,
        )

    # еженедельный дайджест
    if config.digest_enabled:
        app.job_queue.run_daily(
            job_weekly_digest,
            time=datetime.time(hour=config.digest_hour, minute=config.digest_minute),
            days=(config.digest_weekday,),
        )

    # веб-дашборд (опционально)
    if config.dashboard_enabled:
        import uvicorn

        from bot.webapp import create_app

        web_app = create_app(get_db=lambda: app.bot_data.get("db"), config=config)
        uv_config = uvicorn.Config(
            web_app, host=config.dashboard_host, port=config.dashboard_port, log_level="warning"
        )
        server = uvicorn.Server(uv_config)
        server.install_signal_handlers = False
        app.create_task(server.serve())
        log.info("Веб-дашборд запущен на http://%s:%s/", config.dashboard_host, config.dashboard_port)


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
    application.add_handler(CommandHandler("pending", cmd_pending))
    application.add_handler(CommandHandler("stats", cmd_stats))
    application.add_handler(CommandHandler("export", cmd_export))
    application.add_handler(CommandHandler("banlist", cmd_banlist))
    application.add_handler(CommandHandler("unban", cmd_unban))
    application.add_handler(CallbackQueryHandler(on_ban_callback, pattern=r"^ban:"))

    log.info("Skipa Watchdog запускается...")
    application.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
