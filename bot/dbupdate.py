"""
Единая точка обновления базы сканеров - используется и фоновым циклом
(watchdog.py), и командой /update в Telegram, чтобы поведение было одинаковым:
не затирать рабочую базу пустой, сохранять кэш, обновлять правила ядра.
"""
from __future__ import annotations

import asyncio
import logging

from . import blocker
from .config import Config
from .ip_lists import fetch_threat_db, has_data, save_cache

log = logging.getLogger("skipa_watchdog.dbupdate")


def preload_effective(config: Config) -> bool:
    """Нужна ли предзагрузка базы в ipset: если включена и есть зачем -
    блокировать сразу или ловить сканеры по LOG-правилу."""
    return config.preload_db and (
        config.drop_enabled or config.method in ("kernel_log", "both")
    )


async def apply_db_to_firewall(config: Config, db) -> int:
    """Загружает базу в ipset (если это включено и ipset доступен)."""
    if not config.firewall_needed or not preload_effective(config) or not has_data(db):
        return 0
    return await asyncio.to_thread(blocker.preload_db, db.ipset_entries())


async def refresh_db(config: Config, state: dict) -> str:
    """Скачивает базу, при успехе подменяет state['db'], сохраняет кэш и
    обновляет ipset. Возвращает текст для пользователя/лога."""
    previous = state.get("db")
    new_db = await fetch_threat_db(
        config.primary_list_url,
        config.blacklist_url,
        config.blacklist_name,
        config.active_list,
        previous=previous,
    )
    if not has_data(new_db):
        return "Не удалось получить свежую базу, оставил старую версию."
    state["db"] = new_db
    await asyncio.to_thread(save_cache, new_db)
    loaded = await apply_db_to_firewall(config, new_db)
    note = " (часть источников недоступна - использована прошлая версия)" if new_db.degraded else ""
    extra = f", в ipset: {loaded}" if loaded else ""
    return f"Готово: {new_db.source_line_count} записей{extra}{note}."
