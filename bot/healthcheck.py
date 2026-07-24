"""
"Watchdog для watchdog'а": следит, что сами циклы мониторинга (psutil-опрос,
чтение kernel-лога) не зависли и не упали тихо без явной ошибки в логах.

Каждый цикл мониторинга обязан вызывать heartbeat(name) на каждой итерации
(даже если ничего не найдено - сам факт "я ещё жив и проверяю" важен).
Отдельная периодическая задача (job_healthcheck в main.py) сверяет, что
все ожидаемые мониторы "тикали" не позже stale_after_minutes назад, и если
нет - шлёт алерт в Telegram.
"""
from __future__ import annotations

import time

_last_heartbeat: dict[str, float] = {}


def heartbeat(name: str) -> None:
    _last_heartbeat[name] = time.time()


def seconds_since_last(name: str) -> float | None:
    ts = _last_heartbeat.get(name)
    if ts is None:
        return None
    return time.time() - ts


def snapshot() -> dict[str, float]:
    """Копия текущих heartbeat-меток (для дашборда/отладки)."""
    return dict(_last_heartbeat)
