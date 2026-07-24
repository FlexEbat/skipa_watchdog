"""
Структурированный журнал всех обнаруженных угроз (в дополнение к
человекочитаемому data/alerts.log из bot/fallback.py). Хранится построчно
в JSON (JSONL) - удобно для /stats, /export, еженедельного дайджеста и
веб-дашборда, в отличие от свободного текста.

Формат одной строки в data/events.jsonl:
{
  "ts": 1721654321.123,
  "ip": "203.0.113.42",
  "matched_source": "203.0.113.0/24",
  "source_name": "CyberOK/Skipa/ГРЧЦ/НКЦКИ",
  "method": "kernel_log",
  "country_code": "DE",
  "country_name": "Germany",
  "asn": "AS64500",
  "org_name": "Example Hosting GmbH",
  "local_port": 80
}
"""
from __future__ import annotations

import json
import logging
import time
from pathlib import Path

log = logging.getLogger("skipa_watchdog.events_store")

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
EVENTS_FILE = DATA_DIR / "events.jsonl"

# Событий может накопиться много за месяцы работы - храним не более этого
# количества строк, старые тихо обрезаются при следующей записи.
MAX_EVENTS_KEPT = 200_000


def record_event(
    ip: str,
    matched_source: str,
    source_name: str,
    method: str,
    enriched=None,
    local_port: int | None = None,
) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    record = {
        "ts": time.time(),
        "ip": ip,
        "matched_source": matched_source,
        "source_name": source_name,
        "method": method,
        "local_port": local_port,
    }
    if enriched is not None:
        record.update(
            country_code=enriched.country_code,
            country_name=enriched.country_name,
            asn=enriched.asn,
            org_name=enriched.org_name,
        )
    try:
        with EVENTS_FILE.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception as e:  # noqa: BLE001
        log.error("Не удалось записать событие в %s: %s", EVENTS_FILE, e)


def load_events(since_ts: float | None = None, until_ts: float | None = None) -> list[dict]:
    if not EVENTS_FILE.exists():
        return []
    events = []
    try:
        for line in EVENTS_FILE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if since_ts is not None and rec.get("ts", 0) < since_ts:
                continue
            if until_ts is not None and rec.get("ts", 0) > until_ts:
                continue
            events.append(rec)
    except Exception as e:  # noqa: BLE001
        log.error("Не удалось прочитать %s: %s", EVENTS_FILE, e)
    return events


def prune_events(keep_last: int = MAX_EVENTS_KEPT) -> None:
    """Обрезает файл событий, оставляя только последние keep_last записей.
    Вызывается изредка (например, вместе с еженедельным обновлением базы),
    чтобы файл не рос бесконечно на нагруженных серверах."""
    all_events = load_events()
    if len(all_events) <= keep_last:
        return
    trimmed = all_events[-keep_last:]
    try:
        with EVENTS_FILE.open("w", encoding="utf-8") as f:
            for rec in trimmed:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        log.info("events.jsonl обрезан до последних %d записей", keep_last)
    except Exception as e:  # noqa: BLE001
        log.error("Не удалось обрезать %s: %s", EVENTS_FILE, e)
