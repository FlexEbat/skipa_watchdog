"""
Правка config.yaml из бота. Записывает не Python, а тот же service/confctl.sh, которым
пользуются панель и сервисные скрипты: так формат файла, комментарии и списки
обрабатываются одинаково, где бы ни была сделана правка.
"""
from __future__ import annotations

import asyncio
import logging
import shutil
from pathlib import Path

log = logging.getLogger("skipa_watchdog.confedit")

INSTALL_DIR = Path(__file__).resolve().parent.parent
CONFIG_FILE = INSTALL_DIR / "config.yaml"      # watchdog.py подставляет реальный путь
CONFCTL = INSTALL_DIR / "service" / "confctl.sh"
SERVICE_UNIT = "skipa-watchdog"

# Что разрешено менять из чата (то же, что в меню панели) -> допустимые значения
SETTINGS: dict[str, dict] = {
    "action.mode": {
        "title": "Режим действия",
        "values": {"block_notify": "блокировать + уведомлять", "block": "только блокировать", "notify": "только уведомлять"},
    },
    "sources.active_list": {
        "title": "Источник IP-листов",
        "values": {"list1": "основной (skipa_cidr)", "list2": "blacklist", "merged": "оба списка"},
    },
    "monitoring.method": {
        "title": "Метод обнаружения",
        "values": {"both": "оба метода", "poll": "опрос соединений", "kernel_log": "журнал ядра"},
    },
}


async def _confctl(*args: str) -> tuple[int, str, str]:
    proc = await asyncio.create_subprocess_exec(
        "bash", str(CONFCTL), str(CONFIG_FILE), *args,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    out, err = await asyncio.wait_for(proc.communicate(), timeout=20)
    return proc.returncode or 0, out.decode("utf-8", "replace").strip(), err.decode("utf-8", "replace").strip()


async def get_value(key: str) -> str:
    _rc, out, _err = await _confctl("get", key)
    return out


async def set_value(key: str, value: str) -> tuple[bool, str]:
    if key not in SETTINGS or value not in SETTINGS[key]["values"]:
        return False, "Недопустимая настройка или значение."
    rc, _out, err = await _confctl("set", key, value)
    return rc == 0, err


async def ignore_list() -> list[str]:
    _rc, out, _err = await _confctl("ignore-list")
    return [line for line in out.splitlines() if line.strip()]


async def ignore_add(net: str) -> str:
    """'added' | 'exists' | 'error: <причина>'."""
    rc, _out, err = await _confctl("ignore-add", net)
    return {0: "added", 3: "exists"}.get(rc, f"error: {err or rc}")


async def ignore_del(net: str) -> str:
    """'removed' | 'missing' | 'error: <причина>'."""
    rc, _out, err = await _confctl("ignore-del", net)
    return {0: "removed", 3: "missing"}.get(rc, f"error: {err or rc}")


async def restart_service() -> tuple[bool, str]:
    """Перезапуск службы отдельным транзиентным юнитом: процесс, запущенный внутри
    самой службы, остановился бы вместе с ней, не успев дождаться запуска."""
    if not shutil.which("systemd-run"):
        return False, "systemd-run не найден: перезапустите службу вручную (systemctl restart skipa-watchdog)."
    try:
        proc = await asyncio.create_subprocess_exec(
            "systemd-run", "--no-block", "--collect", "systemctl", "restart", SERVICE_UNIT,
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE,
        )
        _, err = await asyncio.wait_for(proc.communicate(), timeout=20)
    except (OSError, asyncio.TimeoutError) as e:
        return False, f"Не удалось перезапустить службу: {e}"
    if proc.returncode != 0:
        return False, f"systemd-run завершился с ошибкой: {err.decode(errors='replace').strip()[:200]}"
    return True, "Служба перезапускается."
