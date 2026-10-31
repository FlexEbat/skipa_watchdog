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
# Предохранитель: списки IP - это единицы мегабайт максимум. Всё, что больше,
# скорее ошибка источника (или подмена) - не тянем такое в память.
MAX_BYTES = 20 * 1024 * 1024
USER_AGENT = "skipa-watchdog (+https://github.com/FlexEbat/skipa_watchdog)"


# Списки IP блокируются автоматически, поэтому подмена по пути (MITM) по обычному http
# равна управлению блокировками. По умолчанию разрешён только https; http включается
# явно (sources.allow_insecure_http) - например, для списка во внутренней сети.
_allow_insecure_http = False


def configure(allow_insecure_http: bool = False) -> None:
    global _allow_insecure_http
    _allow_insecure_http = bool(allow_insecure_http)


class _NoDowngradeRedirect(urllib.request.HTTPRedirectHandler):
    """Редирект не должен менять схему на менее защищённую или на не-http(s)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = newurl.lower()
        if not new.startswith("https://") and not (_allow_insecure_http and new.startswith("http://")):
            raise urllib.error.URLError(f"редирект на небезопасный адрес отклонён: {_safe_url(newurl)}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_opener = urllib.request.build_opener(_NoDowngradeRedirect)


def _get_bytes(url: str, timeout: float, headers: dict | None = None) -> bytes | None:
    low = url.lower()
    if not (low.startswith("https://") or (_allow_insecure_http and low.startswith("http://"))):
        log.warning(
            "Пропускаю URL %s: разрешён только https (для http задайте sources.allow_insecure_http: true)",
            _safe_url(url),
        )
        return None
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    try:
        with _opener.open(req, timeout=timeout) as resp:
            if resp.status != 200:
                log.debug("GET %s -> HTTP %s", _safe_url(url), resp.status)
                return None
            data = resp.read(MAX_BYTES + 1)
            if len(data) > MAX_BYTES:
                log.warning("GET %s: ответ больше %d байт, отбрасываю", _safe_url(url), MAX_BYTES)
                return None
            return data
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
        log.debug("GET %s не удался: %s", _safe_url(url), e)
        return None


def _safe_url(url: str) -> str:
    """URL без строки запроса для журнала: в ней бывают токены (ipinfo)."""
    return url.split("?", 1)[0]


async def get_text(url: str, timeout: float = DEFAULT_TIMEOUT, headers: dict | None = None) -> str:
    """Возвращает тело ответа как текст, либо '' при любой ошибке (сеть,
    таймаут, не-200 статус) - вызывающий код сам решает, что делать с
    пустым результатом."""
    data = await asyncio.to_thread(_get_bytes, url, timeout, headers)
    if data is None:
        return ""
    try:
        return data.decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        return ""


async def get_json(url: str, timeout: float = DEFAULT_TIMEOUT, headers: dict | None = None) -> Any | None:
    """Возвращает распарсенный JSON, либо None при любой ошибке."""
    data = await asyncio.to_thread(_get_bytes, url, timeout, headers)
    if data is None:
        return None
    try:
        return json.loads(data)
    except json.JSONDecodeError as e:
        log.debug("Некорректный JSON от %s: %s", _safe_url(url), e)
        return None
