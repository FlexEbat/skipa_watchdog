"""
Минимальный HTTP-клиент на чистом stdlib (urllib) - без aiohttp.

Весь HTTP в проекте - это редкие одиночные GET-запросы (раз в несколько
часов скачать список IP, при обнаружении скана - несколько запросов к
гео/ASN-сервисам). Ради такой нагрузки не нужен полноценный асинхронный
HTTP-клиент со своим пулом соединений - достаточно синхронного urllib,
выполненного в отдельном потоке (asyncio.to_thread), чтобы не блокировать
цикл мониторинга. Это убирает aiohttp и всю его цепочку зависимостей из
базовой установки.
"""
from __future__ import annotations

import asyncio
import json
import logging
import urllib.error
import urllib.request
from typing import Any

log = logging.getLogger("skipa_watchdog.http")

DEFAULT_TIMEOUT = 15.0
USER_AGENT = "skipa-watchdog (+https://github.com/FlexEbat/skipa_watchdog)"


def _get_bytes(url: str, timeout: float) -> bytes | None:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (URLs пришли из конфига)
            if resp.status != 200:
                log.debug("GET %s -> HTTP %s", url, resp.status)
                return None
            return resp.read()
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
        log.debug("GET %s не удался: %s", url, e)
        return None


async def get_text(url: str, timeout: float = DEFAULT_TIMEOUT) -> str:
    """Возвращает тело ответа как текст, либо '' при любой ошибке (сеть,
    таймаут, не-200 статус) - вызывающий код сам решает, что делать с
    пустым результатом."""
    data = await asyncio.to_thread(_get_bytes, url, timeout)
    if data is None:
        return ""
    try:
        return data.decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        return ""


async def get_json(url: str, timeout: float = DEFAULT_TIMEOUT) -> Any | None:
    """Возвращает распарсенный JSON, либо None при любой ошибке."""
    data = await asyncio.to_thread(_get_bytes, url, timeout)
    if data is None:
        return None
    try:
        return json.loads(data)
    except json.JSONDecodeError as e:
        log.debug("Некорректный JSON от %s: %s", url, e)
        return None
