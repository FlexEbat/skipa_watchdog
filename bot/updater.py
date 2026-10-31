"""
Проверка и установка обновлений проекта (логика та же, что в service/lib-update.sh).

Каталог установки - git-клон репозитория: сравниваем локальную ветку с её upstream.
Любая проблема (нет git, нет сети, не клон, нет upstream) трактуется как «обновлений
нет»: проверка обновлений не должна мешать защите работать.

Установка обновления делегируется install.sh (тому же, что и пункт 10 панели), чтобы
у бота, панели и сервиса был ровно один путь обновления. Запускается он отдельным
systemd-юнитом (systemd-run): сам install.sh перезапускает службу бота, а процесс,
запущенный внутри этой службы, был бы остановлен вместе с ней на полпути.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger("skipa_watchdog.updater")

INSTALL_DIR = Path(__file__).resolve().parent.parent
PENDING_FILE = INSTALL_DIR / "data" / "update-pending.json"
GIT_TIMEOUT = 25.0
UPDATE_UNIT = "skipa-watchdog-self-update"


@dataclass
class UpdateInfo:
    local: str = ""
    remote: str = ""
    behind: int = 0
    commits: list[str] = field(default_factory=list)


def read_version(install_dir: Path | None = None) -> str:
    try:
        return ((install_dir or INSTALL_DIR) / "VERSION").read_text(encoding="utf-8").split()[0]
    except (OSError, IndexError):
        return ""


async def _git(install_dir: Path, *args: str) -> str | None:
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
    try:
        proc = await asyncio.create_subprocess_exec(
            "git", "-C", str(install_dir), *args,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL, env=env,
        )
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=GIT_TIMEOUT)
    except (OSError, asyncio.TimeoutError):
        return None
    return out.decode("utf-8", errors="replace") if proc.returncode == 0 else None


async def check_update(install_dir: Path | None = None) -> UpdateInfo | None:
    """UpdateInfo, если в репозитории есть новые коммиты, иначе None."""
    if os.environ.get("SKIPA_NO_UPDATE_CHECK") == "1":
        return None
    d = install_dir or INSTALL_DIR
    if not shutil.which("git") or not (d / ".git").exists():
        return None
    if await _git(d, "fetch", "--quiet", "origin") is None:
        log.debug("Проверка обновлений: git fetch не удался (нет сети?)")
        return None
    behind_raw = await _git(d, "rev-list", "--count", "HEAD..@{u}")
    if behind_raw is None or not behind_raw.strip().isdigit() or int(behind_raw) == 0:
        return None
    remote = ((await _git(d, "show", "@{u}:VERSION")) or "").split()
    commits = (await _git(d, "log", "--format=%h %s", "-n", "5", "HEAD..@{u}")) or ""
    return UpdateInfo(
        local=read_version(d), remote=remote[0] if remote else "",
        behind=int(behind_raw), commits=[c for c in commits.splitlines() if c.strip()],
    )


def format_update_text(info: UpdateInfo) -> str:
    from html import escape

    lines = [f"⬆️ <b>Доступно обновление Skipa Watchdog</b>: {escape(info.local or '?')} → {escape(info.remote or '?')}"
             f" (новых коммитов: {info.behind})"]
    lines += [f"• <code>{escape(c)}</code>" for c in info.commits]
    return "\n".join(lines)


def mark_pending(info: UpdateInfo) -> None:
    PENDING_FILE.parent.mkdir(parents=True, exist_ok=True)
    PENDING_FILE.write_text(
        json.dumps({"from": info.local, "to": info.remote, "ts": time.time()}), encoding="utf-8")


def take_pending_result(install_dir: Path | None = None) -> str | None:
    """Если перед перезапуском бот запускал обновление - итог для сообщения в чат
    (и сброс отметки); иначе None."""
    try:
        data = json.loads(PENDING_FILE.read_text(encoding="utf-8"))
        PENDING_FILE.unlink()
    except (OSError, json.JSONDecodeError):
        return None
    now = read_version(install_dir)
    if data.get("from") and now == data.get("from"):
        return ("⚠️ Обновление не применилось: версия осталась "
                f"{now}. Запустите на сервере <code>sudo skipa-watchdog</code> и обновитесь из меню.")
    return f"✅ Обновление установлено: {data.get('from') or '?'} → {now or '?'}"


async def start_update(info: UpdateInfo, install_dir: Path | None = None) -> tuple[bool, str]:
    """Запускает install.sh install отдельным юнитом. (успех запуска, пояснение)."""
    d = install_dir or INSTALL_DIR
    if not shutil.which("systemd-run"):
        return False, "systemd-run не найден: обновитесь через панель (sudo skipa-watchdog, пункт 10)."
    mark_pending(info)
    try:
        proc = await asyncio.create_subprocess_exec(
            "systemd-run", "--no-block", "--collect", f"--unit={UPDATE_UNIT}",
            f"--setenv=SKIPA_INSTALL_DIR={d}", "--setenv=SKIPA_NO_UPDATE_CHECK=1",
            "bash", str(d / "install.sh"), "install",
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE,
        )
        _, err = await asyncio.wait_for(proc.communicate(), timeout=20)
    except (OSError, asyncio.TimeoutError) as e:
        PENDING_FILE.unlink(missing_ok=True)
        return False, f"Не удалось запустить обновление: {e}"
    if proc.returncode != 0:
        PENDING_FILE.unlink(missing_ok=True)
        return False, f"systemd-run завершился с ошибкой: {err.decode(errors='replace').strip()[:200]}"
    return True, "Обновление запущено, служба перезапустится сама."
