"""
Резервное сохранение алертов. Решает две задачи:

1. Audit-лог: КАЖДЫЙ обнаруженный скан пишется в data/alerts.log в виде
   простого читаемого текста, независимо от того, удалось ли отправить
   его в Telegram. Полезно как полная история на случай, если бот долго
   не мог достучаться до Telegram (или просто для собственного архива).

2. Очередь на повтор: если отправка в Telegram упала с ошибкой (сеть легла,
   Telegram недоступен, невалидный chat_id и т.п.), сообщение не теряется -
   оно складывается в data/pending_telegram.jsonl и периодически (см.
   job_flush_pending_alerts в main.py) пытается отправиться заново, пока
   не уйдёт успешно.
"""
from __future__ import annotations

import json
import logging
import re
import time
from pathlib import Path

log = logging.getLogger("skipa_watchdog.fallback")

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
AUDIT_LOG = DATA_DIR / "alerts.log"
PENDING_FILE = DATA_DIR / "pending_telegram.jsonl"

_TAG_RE = re.compile(r"<[^>]+>")
_LINK_RE = re.compile(r'<a href="[^"]*">([^<]*)</a>')


def _strip_html(text: str) -> str:
    """Грубая очистка HTML-разметки для читаемого текстового лога."""
    text = _LINK_RE.sub(r"\1", text)
    return _TAG_RE.sub("", text)


def append_audit_log(ip: str, matched_source: str, html_text: str) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    plain = _strip_html(html_text)
    try:
        with AUDIT_LOG.open("a", encoding="utf-8") as f:
            f.write(f"===== {ts} | IP={ip} | match={matched_source} =====\n{plain}\n\n")
    except Exception as e:  # noqa: BLE001
        log.error("Не удалось записать audit-лог %s: %s", AUDIT_LOG, e)


def queue_pending_alert(chat_id: int, html_text: str, reply_markup_json: dict | None = None) -> None:
    """Кладёт неотправленный алерт в очередь на диске для повторной отправки.
    reply_markup_json - сериализованная (через .to_dict()) инлайн-клавиатура
    с кнопкой "Забанить", если она была на исходном сообщении."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    record = {"ts": time.time(), "chat_id": chat_id, "text": html_text, "reply_markup": reply_markup_json}
    try:
        with PENDING_FILE.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
        log.warning("Алерт сохранён в очередь на повтор (%s), попробую позже", PENDING_FILE)
    except Exception as e:  # noqa: BLE001
        log.error("Не удалось сохранить алерт в очередь %s: %s", PENDING_FILE, e)


def load_pending() -> list[dict]:
    if not PENDING_FILE.exists():
        return []
    records = []
    try:
        for line in PENDING_FILE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                log.warning("Пропускаю повреждённую строку в очереди: %r", line)
    except Exception as e:  # noqa: BLE001
        log.error("Не удалось прочитать очередь %s: %s", PENDING_FILE, e)
    return records


def save_pending(records: list[dict]) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    try:
        with PENDING_FILE.open("w", encoding="utf-8") as f:
            for r in records:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
    except Exception as e:  # noqa: BLE001
        log.error("Не удалось перезаписать очередь %s: %s", PENDING_FILE, e)


def pending_count() -> int:
    return len(load_pending())
