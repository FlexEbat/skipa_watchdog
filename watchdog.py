"""
Skipa Watchdog — единая точка входа.

Это НЕ "бот" в смысле отдельного режима - это один процесс, который:

1. Постоянно мониторит сетевые соединения к серверу (/proc/net/tcp и/или чтение
   kernel-лога) и сверяет источник с базой IP-адресов сканеров
   (CyberOK/Skipa, ГРЧЦ, НКЦКИ + доп. списки, см. bot/ip_lists.py).
2. При обнаружении, в зависимости от action.mode в config.yaml:
     - "notify"       - только уведомление (локальный лог + Telegram, если настроен)
     - "block"        - только блокировка через iptables/ipset (см. bot/blocker.py),
                         работает и для хоста, и для Docker/Kubernetes
     - "block_notify" - и то, и другое (по умолчанию)
3. Ведёт лог в /var/log/skipa_watchdog/ (или другой logging.log_dir) -
   всегда, независимо от Telegram.
4. Если telegram.bot_token заполнен в config.yaml, этот же процесс
   ДОПОЛНИТЕЛЬНО поднимает Telegram-слой (bot/telegram_layer.py):
   уведомления дублируются в чат, становятся доступны команды/меню.
   Telegram - это надстройка поверх watchdog, а не отдельный процесс/режим:
   его недоступность (блокировка, нет сети) НЕ останавливает мониторинг и
   блокировку - поднимается в фоне с повторными попытками.
5. Сам следит, что правила iptables на месте (после перезагрузки, рестарта
   Docker, ufw/firewalld reload), и чинит их.

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
import re
import signal
import sys
import time
from html import escape
from pathlib import Path

from bot import blocker, http_client, ip_lists
from bot.allowlist import build_allowlist
from bot.config import Config
from bot.dbupdate import apply_db_to_firewall, preload_effective, refresh_db
from bot.env_detect import format_summary_text, summarize_environment
from bot.events_store import prune_events, record_event
from bot.fallback import append_audit_log, drain_pending, queue_pending_alert, requeue
from bot.healthcheck import heartbeat, seconds_since_last
from bot.ip_lists import check_list_versions, fetch_threat_db, has_data, load_cache, needs_update, save_cache
from bot.monitor import Deduper, poll_connections_loop, tail_kernel_log_loop

CONFIG_PATH = sys.argv[1] if len(sys.argv) > 1 else "config.yaml"

log = logging.getLogger("skipa_watchdog")

# Максимум ожидающих уведомлений в памяти; при переполнении (шторм сканов при
# недоступных сервисах обогащения) лишнее остаётся только в локальном логе.
NOTIFY_QUEUE_SIZE = 1000
ENRICH_TIMEOUT_SECONDS = 25


_SECRET_PATTERNS = (
    (re.compile(r"bot\d{5,}:[A-Za-z0-9_-]{20,}"), "bot<скрыто>"),                     # токен Telegram в URL
    (re.compile(r"(?i)\b(token|api_key|apikey|key)=[^&\s\"']+"), r"\1=<скрыто>"),     # ключи в строке запроса
)


class _RedactingFormatter(logging.Formatter):
    """Не даёт секретам попасть в журнал: маскирует токен бота и ключи API в
    итоговой строке (включая трейсбеки) и точные значения секретов из конфига."""

    def __init__(self, fmt: str, secrets: list[str]):
        super().__init__(fmt)
        self._secrets = [x for x in secrets if x and len(x) >= 8]

    def format(self, record: logging.LogRecord) -> str:
        text = super().format(record)
        for pattern, repl in _SECRET_PATTERNS:
            text = pattern.sub(repl, text)
        for secret in self._secrets:
            text = text.replace(secret, "<скрыто>")
        return text


def _setup_logging(config: Config) -> Path:
    log_dir = Path(config.log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)

    level = getattr(logging, config.log_level.upper(), logging.INFO)
    root = logging.getLogger()
    root.setLevel(level)

    fmt = _RedactingFormatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        [config.bot_token, config.ipinfo_token, config.ipregistry_key, config.dashboard_password]
        + [str(e.get("api_key", "")) for e in config.extra_sources],
    )
    # httpx (под python-telegram-bot) на уровне INFO пишет каждый запрос вместе с
    # адресом, а в адресе Bot API лежит токен бота: тихо раз в несколько секунд
    for noisy in ("httpx", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(fmt)
    root.addHandler(console)

    file_handler = logging.handlers.RotatingFileHandler(
        log_dir / "skipa-watchdog.log", maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
    )
    file_handler.setFormatter(fmt)
    root.addHandler(file_handler)

    return log_dir


async def _supervised(name: str, factory) -> None:
    """Запускает бесконечную фоновую задачу и перезапускает её при исключении.
    Раньше необработанная ошибка в любой из них (например, нет прав записать
    кэш) через gather() роняла весь процесс вместе с мониторингом."""
    while True:
        try:
            await factory()
            return
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            log.exception("Задача %s упала, перезапускаю через 10с", name)
            await asyncio.sleep(10)


# ---------------------------------------------------------------------------
# Обработка срабатываний
# ---------------------------------------------------------------------------

def _record_event(hit, enriched=None) -> None:
    """Структурированный журнал событий (data/events.jsonl) для /stats, /export,
    еженедельного дайджеста и дашборда."""
    record_event(
        ip=hit.ip,
        matched_source=hit.matched_cidr,
        source_name=hit.source_name,
        method=hit.method,
        enriched=enriched,
        local_port=hit.local_port,
    )


def _make_hit_handler(config: Config, state: dict, detections_log: Path, notify_queue: asyncio.Queue):
    do_notify = config.action_mode in ("notify", "block_notify")
    do_block = config.drop_enabled
    # Если алерт обогащается, запись в detections.log делает воркер уведомлений
    # (уже с гео/ASN-данными); иначе - сразу, из on_hit.
    audit_in_worker = do_notify and config.enrich_enabled

    async def on_hit(hit) -> bool:
        """Возвращает False, если блокировку выполнить не удалось (тогда
        повторная попытка будет через минуту, а не через весь кулдаун)."""
        blocked = False
        block_note = ""
        ok = True
        if do_block:
            net, reason = blocker.validate_target(hit.ip)
            if net is None:
                # осознанный отказ (allowlist, служебный адрес и т.п.) - не ошибка, повторять не нужно
                block_note = f"ℹ️ Не блокирую: {reason}."
                log.warning("Не блокирую %s: %s", hit.ip, reason)
            else:
                # блокировка - в потоке и ДО всего остального: iptables может ждать
                # xtables-lock, а защита важнее уведомления
                blocked = await asyncio.to_thread(blocker.block_ip, hit.ip)
                ok = blocked
                block_note = "🚫 IP заблокирован." if blocked else "⚠️ Не удалось заблокировать IP."
                if not blocked:
                    log.error("Не удалось заблокировать %s (см. лог выше)", hit.ip)

        log.warning(
            "СКАНЕР ОБНАРУЖЕН: %s (совпадение: %s, метод: %s, порт: %s)%s",
            hit.ip, hit.matched_source, hit.method, hit.local_port,
            " [заблокирован]" if blocked else "",
        )

        if not audit_in_worker:
            plain = (
                f"IP: {hit.ip}\n"
                f"Совпадение по базе: {hit.matched_source}\n"
                f"Метод обнаружения: {hit.method}\n"
                f"Локальный порт: {hit.local_port}"
            )
            if block_note:
                plain += f"\n{block_note}"
            await asyncio.to_thread(append_audit_log, hit.ip, hit.matched_source, plain, detections_log)
            await asyncio.to_thread(_record_event, hit, None)

        if do_notify:
            try:
                notify_queue.put_nowait((hit, block_note, blocked))
            except asyncio.QueueFull:
                log.error("Очередь уведомлений переполнена, алерт по %s остался только в логе", hit.ip)
        return ok

    return on_hit


async def _notify_worker(config: Config, state: dict, queue: asyncio.Queue, detections_log: Path) -> None:
    """Обогащает алерты (гео/ASN) и отправляет в Telegram - в фоне, чтобы
    медленные внешние сервисы не тормозили мониторинг и блокировку."""
    from bot.enrich import EnrichedIP, enrich_ip
    from bot.formatter import build_alert_message

    while True:
        hit, block_note, blocked = await queue.get()
        try:
            if config.enrich_enabled:
                try:
                    data = await asyncio.wait_for(
                        enrich_ip(hit.ip, config.ipinfo_token, config.ipregistry_key),
                        ENRICH_TIMEOUT_SECONDS,
                    )
                except Exception as e:  # noqa: BLE001  (в т.ч. таймаут)
                    log.warning("Не удалось обогатить %s (%s) - отправляю без гео-данных", hit.ip, e)
                    data = EnrichedIP(ip=hit.ip)
                text = build_alert_message(hit.ip, hit.matched_source, data)
            else:
                text = (
                    f"IP: <code>{escape(hit.ip)}</code>\n"
                    f"Совпадение по базе: {escape(hit.matched_source)}\n"
                    f"Метод обнаружения: {escape(hit.method)}\n"
                    f"Локальный порт: {escape(str(hit.local_port))}"
                )
            if block_note:
                text += f"\n\n{escape(block_note)}"

            if config.enrich_enabled:
                await asyncio.to_thread(append_audit_log, hit.ip, hit.matched_source, text, detections_log)
                await asyncio.to_thread(_record_event, hit, data)

            if not config.telegram_enabled:
                continue
            markup = None
            if config.ban_enabled and not blocked:
                from bot.telegram_layer import ban_keyboard

                markup = ban_keyboard(hit.ip)  # кнопка «🚫 Забанить» под алертом
            markup_json = markup.to_dict() if markup else None

            app = state.get("telegram_app")
            if app is None:
                # Telegram ещё не поднялся (или временно недоступен) - не теряем алерт
                queue_pending_alert(config.chat_id, text, markup_json)
                continue
            from bot.telegram_layer import send_notification

            try:
                await send_notification(app, config.chat_id, text, markup)
            except Exception as e:  # noqa: BLE001
                log.error("Не удалось отправить в Telegram (%s), кладу в очередь на повтор", e)
                queue_pending_alert(config.chat_id, text, markup_json)
        except Exception:  # noqa: BLE001
            log.exception("Ошибка при отправке уведомления по %s", hit.ip)


# ---------------------------------------------------------------------------
# Фоновые задачи
# ---------------------------------------------------------------------------

async def _periodic_db_updates(config: Config, state: dict) -> None:
    """Раз в час проверяет, не пора ли обновить базу (интервал -
    update_interval_days; для неполной базы - через час), и раз в сутки
    проверяет, не изменились ли списки у источника: если изменились - база
    обновляется сразу, а не через неделю."""
    last_version_check = 0.0
    while True:
        if needs_update(state.get("db"), config.update_interval_days):
            log.info("Обновляю базу IP-адресов...")
            log.info("%s", await refresh_db(config, state))
            await asyncio.to_thread(prune_events)  # журнал событий не должен расти бесконечно

        if time.time() - last_version_check > 86400:
            last_version_check = time.time()
            changed = await check_list_versions(
                config.primary_list_url, config.blacklist_url, config.blacklist_name
            )
            if changed:
                log.info("Обнаружены новые версии листов: %s - обновляю базу", ", ".join(changed))
                log.info("%s", await refresh_db(config, state))

        await asyncio.sleep(3600)


async def _flush_pending_alerts(config: Config, state: dict) -> None:
    """Периодически пытается доотправить алерты, которые не ушли в Telegram
    из-за временной недоступности связи."""
    from bot.telegram_layer import send_notification

    while True:
        await asyncio.sleep(config.retry_interval_seconds)
        app = state.get("telegram_app")
        if app is None:
            continue
        # drain_pending забирает очередь целиком и очищает файл без await между
        # чтением и очисткой, поэтому алерты, добавленные пока идёт отправка,
        # не затираются; неотправленное возвращается обратно через requeue()
        records = drain_pending()
        if not records:
            continue
        log.info("В очереди %d отложенных алертов, пробую отправить...", len(records))

        failed = []
        for i, record in enumerate(records):
            markup = None
            if record.get("reply_markup"):
                try:
                    from telegram import InlineKeyboardMarkup

                    markup = InlineKeyboardMarkup.de_json(record["reply_markup"], app.bot)
                except Exception:  # noqa: BLE001
                    markup = None
            try:
                await send_notification(app, record["chat_id"], record["text"], markup)
            except Exception as e:  # noqa: BLE001
                log.warning("Повтор снова не удался (%s), остальное оставляю в очереди", e)
                failed = records[i:]  # связи нет - не тратим время на таймауты по каждому
                break
        requeue(failed)
        sent = len(records) - len(failed)
        if sent:
            log.info("Успешно доотправлено %d ранее отложенных алертов", sent)


async def _telegram_supervisor(config: Config, state: dict) -> None:
    """Поднимает Telegram-слой в фоне. Если Telegram недоступен (нет сети,
    блокировка и т.п.) - повторяет попытки с нарастающей паузой, а мониторинг и
    блокировка всё это время работают. Раньше ошибка initialize() при старте
    роняла весь процесс."""
    from bot.telegram_layer import build_application

    backoff = 30
    while True:
        app = None
        started = False
        try:
            app = await build_application(config, state)
            await app.initialize()
            await app.start()
            await app.updater.start_polling()
            started = True
            state["telegram_app"] = app
            backoff = 30
            log.info("Telegram-слой запущен (уведомления и команды доступны в чате)")
            await asyncio.Event().wait()  # живём, пока задачу не отменят
        except asyncio.CancelledError:
            raise
        except Exception as e:  # noqa: BLE001
            log.error("Telegram недоступен (%s: %s), повторю через %d с; мониторинг продолжает работать",
                      type(e).__name__, e, backoff)
            state["telegram_app"] = None
        finally:
            state["telegram_app"] = None
            if app is not None:
                for step in ("updater.stop", "stop", "shutdown"):
                    try:
                        target = app.updater if step.startswith("updater") else app
                        await getattr(target, step.split(".")[-1])()
                    except Exception:  # noqa: BLE001
                        pass
            if started:
                log.info("Telegram-слой остановлен")
        await asyncio.sleep(backoff)
        backoff = min(backoff * 2, 600)


async def _send_text(config: Config, state: dict, text: str) -> None:
    """Отправляет служебное сообщение администратору; при недоступном Telegram -
    в очередь на повтор. Без Telegram - только в лог."""
    if not config.telegram_enabled:
        return
    app = state.get("telegram_app")
    if app is None:
        queue_pending_alert(config.chat_id, text)
        return
    from bot.telegram_layer import send_notification

    try:
        await send_notification(app, config.chat_id, text)
    except Exception as e:  # noqa: BLE001
        log.error("Не удалось отправить служебное сообщение (%s), кладу в очередь", e)
        queue_pending_alert(config.chat_id, text)


async def _healthcheck_loop(config: Config, state: dict) -> None:
    """«Watchdog для watchdog'а»: проверяет, что циклы мониторинга не зависли
    молча (каждый обязан отмечаться через heartbeat()). Если монитор молчит
    дольше healthcheck.stale_after_minutes - предупреждение в лог и в Telegram,
    а когда он оживает - сообщение о восстановлении."""
    expected = []
    if config.method in ("poll", "both"):
        expected.append("poll")
    if config.method in ("kernel_log", "both"):
        expected.append("kernel_log")
    if config.firewall_needed:
        expected.append("firewall-guard")

    stale_seconds = config.healthcheck_stale_after_minutes * 60
    already_alerted: dict[str, bool] = {}
    while True:
        await asyncio.sleep(config.healthcheck_check_interval_minutes * 60)
        for name in expected:
            ago = seconds_since_last(name)
            is_stale = ago is None or ago > stale_seconds
            if is_stale and not already_alerted.get(name):
                minutes = "неизвестно сколько" if ago is None else f"{ago / 60:.1f} мин."
                log.error("Health-check: монитор %s не подавал признаков жизни %s", name, minutes)
                await _send_text(
                    config, state,
                    f"⚠️ <b>Watchdog для watchdog'а:</b> монитор <code>{escape(name)}</code> "
                    f"не подавал признаков жизни последние {minutes}. Возможно, завис или упал "
                    f"без явной ошибки в логах - проверьте "
                    f"<code>sudo journalctl -u skipa-watchdog -n 100</code>.",
                )
                already_alerted[name] = True
            elif not is_stale and already_alerted.get(name):
                log.info("Health-check: монитор %s снова в порядке", name)
                await _send_text(config, state, f"✅ Монитор <code>{escape(name)}</code> снова в порядке.")
                already_alerted[name] = False


def _seconds_until_digest(config: Config) -> float:
    import datetime

    now = datetime.datetime.now()
    target = now.replace(hour=config.digest_hour, minute=config.digest_minute, second=0, microsecond=0)
    target += datetime.timedelta(days=(config.digest_weekday - now.weekday()) % 7)
    if target <= now:
        target += datetime.timedelta(days=7)
    return (target - now).total_seconds()


async def _weekly_digest_loop(config: Config, state: dict) -> None:
    """Раз в неделю (digest.weekday/hour/minute по времени сервера) присылает в
    Telegram статистику и график, не дожидаясь команды /stats."""
    import io

    from bot.stats import format_summary_text as format_stats_text
    from bot.stats import stats_for_period

    while True:
        await asyncio.sleep(_seconds_until_digest(config))
        try:
            summary, chart_png, hist = await asyncio.to_thread(stats_for_period, 7)
            text = "📬 <b>Еженедельный дайджест Skipa Watchdog</b>\n\n" + format_stats_text(summary, "неделю")
            if hist:
                text += "\n\n" + hist
            app = state.get("telegram_app")
            if chart_png and app is not None:
                await app.bot.send_photo(
                    chat_id=config.chat_id, photo=io.BytesIO(chart_png), caption=text[:1024], parse_mode="HTML"
                )
                if len(text) > 1024:
                    await _send_text(config, state, text)
            else:
                await _send_text(config, state, text)
        except Exception:  # noqa: BLE001
            log.exception("Не удалось отправить еженедельный дайджест")
        await asyncio.sleep(61)  # чтобы не сработать дважды в ту же минуту


def _configure_blocker(config: Config) -> None:
    blocker.configure(
        log_prefix=config.kernel_log_prefix,
        log_limit=config.log_limit,
        log_burst=config.log_burst,
        preload_db=preload_effective(config),
        drop_enabled=config.drop_enabled,
        auto_timeout_s=config.auto_block_timeout_s,
        skip_docker=not config.docker_scan_enabled,
        skip_k8s=not config.k8s_scan_enabled,
    )


async def _guard_loop(config: Config, state: dict) -> None:
    """Каждые guard_interval_seconds: обновляет allowlist (в т.ч. текущие SSH-
    сессии), проверяет и при необходимости чинит переходы SKIPA-BLOCK из
    INPUT/DOCKER-USER/KUBE-* и содержимое ipset (после reboot, рестарта Docker,
    ufw/firewalld reload эти правила пропадают)."""
    last_allow_key = None
    last_status: dict[str, str] = {}
    while True:
        heartbeat("firewall-guard")
        try:
            nets = await asyncio.to_thread(
                build_allowlist, config.ignore_networks, config.auto_allowlist, config.ssh_ports
            )
            key = frozenset(str(n) for n in nets)
            if key != last_allow_key:
                await asyncio.to_thread(blocker.sync_allowlist, nets)
                last_allow_key = key

            result = await asyncio.to_thread(blocker.ensure_wiring)
            if result != last_status and any(v != "ok" for v in result.values()):
                log.warning("Состояние правил iptables: %s", result)
            last_status = result

            # набор skipa-db мог быть очищен/потерян - заливаем базу заново
            db = state.get("db")
            if preload_effective(config) and has_data(db):
                size = await asyncio.to_thread(blocker.db_set_size)
                if size == 0:
                    log.warning("ipset skipa-db пуст - загружаю базу заново")
                    await apply_db_to_firewall(config, db)
        except Exception:  # noqa: BLE001
            log.exception("Ошибка в цикле проверки правил firewall")
        await asyncio.sleep(config.guard_interval_seconds)


async def _init_firewall(config: Config, state: dict) -> None:
    """Первичная настройка ядра до старта мониторинга: allowlist -> правила ->
    восстановление блокировок -> предзагрузка базы."""
    _configure_blocker(config)
    nets = await asyncio.to_thread(
        build_allowlist, config.ignore_networks, config.auto_allowlist, config.ssh_ports
    )
    await asyncio.to_thread(blocker.sync_allowlist, nets)  # allowlist первым - до любых блокировок
    result = await asyncio.to_thread(blocker.ensure_wiring)
    log.info("Правила firewall: %s", result)
    if config.drop_enabled or config.ban_enabled:
        await asyncio.to_thread(blocker.restore_persisted_blocks)
    db = state.get("db")
    if has_data(db):
        await apply_db_to_firewall(config, db)


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

async def async_main() -> None:
    config = Config.load(CONFIG_PATH)
    log_dir = _setup_logging(config)
    detections_log = log_dir / "detections.log"

    log.info(
        "Skipa Watchdog запускается (action.mode=%s, method=%s, telegram=%s), логи: %s",
        config.action_mode, config.method, "включён" if config.telegram_enabled else "выключен", log_dir,
    )

    state: dict = {"db": None, "telegram_app": None}
    ip_lists.configure_limits(config.min_list_prefix)
    http_client.configure(config.allow_insecure_http)

    # Если кэш есть, но устарел, а сети нет - остаёмся на старом кэше, а не
    # подменяем его пустой базой (раньше так терялась вся защита на час).
    db = load_cache()
    if needs_update(db, config.update_interval_days):
        log.info("Локального кэша нет или он устарел, качаю базу...")
        new_db = await fetch_threat_db(
            config.primary_list_url, config.blacklist_url, config.blacklist_name,
            config.active_list, previous=db, extra_sources=config.extra_sources,
        )
        if has_data(new_db):
            db = new_db
            save_cache(db)
        elif has_data(db):
            log.warning("Не удалось обновить базу - продолжаю со старым кэшем")
        else:
            log.error("База IP пуста и скачать её не удалось - мониторинг заработает после успешной загрузки")
    state["db"] = db if has_data(db) else None
    await asyncio.to_thread(prune_events)

    if config.firewall_needed:
        await _init_firewall(config, state)

    if config.docker_scan_enabled or config.k8s_scan_enabled:
        summary = await asyncio.to_thread(summarize_environment, config.kernel_log_prefix)
        if summary.any_container_platform():
            for line in format_summary_text(summary).splitlines():
                log.info("[environment] %s", line)

    notify_queue: asyncio.Queue = asyncio.Queue(maxsize=NOTIFY_QUEUE_SIZE)
    on_hit = _make_hit_handler(config, state, detections_log, notify_queue)
    dedup = Deduper(config.alert_cooldown_minutes)

    jobs: list[tuple[str, object]] = [
        ("db-updates", lambda: _periodic_db_updates(config, state)),
    ]
    if config.action_mode in ("notify", "block_notify"):
        jobs.append(("notify-worker", lambda: _notify_worker(config, state, notify_queue, detections_log)))
    if config.firewall_needed:
        jobs.append(("firewall-guard", lambda: _guard_loop(config, state)))
    if config.healthcheck_enabled:
        jobs.append(("healthcheck", lambda: _healthcheck_loop(config, state)))
    if config.dashboard_enabled:
        from bot.webapp import serve_dashboard

        jobs.append(("dashboard", lambda: serve_dashboard(lambda: state.get("db"), config)))
    if config.telegram_enabled and config.digest_enabled:
        jobs.append(("weekly-digest", lambda: _weekly_digest_loop(config, state)))

    if config.telegram_enabled:
        jobs.append(("telegram", lambda: _telegram_supervisor(config, state)))
        jobs.append(("pending-alerts", lambda: _flush_pending_alerts(config, state)))
    else:
        log.info("Telegram не настроен (telegram.bot_token пуст) - работаю только с локальным логом.")

    method = config.method
    if method in ("poll", "both"):
        jobs.append((
            "poll",
            lambda: poll_connections_loop(
                get_db=lambda: state.get("db"),
                ignore_networks=config.ignore_networks,
                poll_interval=config.poll_interval_seconds,
                dedup=dedup,
                on_hit=on_hit,
                use_conntrack=config.use_conntrack,
            ),
        ))
    if method in ("kernel_log", "both"):
        jobs.append((
            "kernel-log",
            lambda: tail_kernel_log_loop(
                get_db=lambda: state.get("db"),
                ignore_networks=config.ignore_networks,
                dedup=dedup,
                on_hit=on_hit,
                log_prefix=config.kernel_log_prefix,
                command=config.kernel_log_command or None,
            ),
        ))

    # Корректное завершение по SIGTERM (systemctl stop/restart) и SIGINT
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:  # не-Unix
            pass

    tasks = [asyncio.create_task(_supervised(name, factory), name=name) for name, factory in jobs]
    stopper = asyncio.create_task(stop.wait())
    try:
        await asyncio.wait([stopper, *tasks], return_when=asyncio.FIRST_COMPLETED)
    finally:
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)  # даёт Telegram-слою остановиться
        stopper.cancel()
        log.info("Skipa Watchdog остановлен")


def main() -> None:
    try:
        asyncio.run(async_main())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
