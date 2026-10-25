"""
Бан IP по кнопке «🚫 Забанить» под алертом, автобан и команды /ban(list),
/unban - единый слой над bot/blocker.py.

Сама блокировка выполняется общим механизмом watchdog (цепочка SKIPA-BLOCK +
ipset `skipa-dyn` с таймаутом, либо правила iptables без ipset, см.
bot/blocker.py) - отдельный набор `skipa_watchdog_ban` из старых версий больше
не нужен. Этот модуль добавляет:

- историю банов в data/bans.jsonl (кто, когда, на сколько, почему);
- «зеркалирование» бана в fail2ban (если в config.yaml задан
  banning.fail2ban_jail): `fail2ban-client set <jail> banip <ip>`, чтобы бан
  был виден в общей картине `fail2ban-client status` вместе с остальными
  джейлами.

Все проверки безопасности (служебные/частные адреса, сети шире /16, allowlist
с вашими SSH-сессиями) делает blocker.validate_target().
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from pathlib import Path

from . import blocker

log = logging.getLogger("skipa_watchdog.banning")

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
BAN_LOG_FILE = DATA_DIR / "bans.jsonl"


async def _run(*args: str) -> tuple[int, str, str]:
    try:
        proc = await asyncio.create_subprocess_exec(
            *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
    except FileNotFoundError:
        return 127, "", f"команда {args[0]!r} не найдена (не установлена?)"
    stdout, stderr = await proc.communicate()
    return proc.returncode, stdout.decode(errors="replace"), stderr.decode(errors="replace")


def _log_ban_action(action: str, ip: str, duration_minutes: int, reason: str, by: str) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    record = {
        "ts": time.time(),
        "action": action,  # "ban" | "unban"
        "ip": ip,
        "duration_minutes": duration_minutes,
        "reason": reason,
        "by": by,
    }
    try:
        with BAN_LOG_FILE.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception as e:  # noqa: BLE001
        log.error("Не удалось записать в bans.jsonl: %s", e)


async def ban_ip(
    ip: str,
    duration_minutes: int = 0,
    reason: str = "",
    by: str = "auto",
    fail2ban_jail: str = "",
) -> tuple[bool, str]:
    """duration_minutes=0 - бан навсегда (пока не снимут вручную).
    Возвращает (успех, пояснение при отказе)."""
    net, refusal = blocker.validate_target(ip)
    if net is None:
        log.warning("Бан %s отклонён: %s", ip, refusal)
        return False, refusal

    ok = await asyncio.to_thread(blocker.block_ip, ip, int(duration_minutes) * 60)
    if not ok:
        return False, "не удалось применить правило (см. логи)"

    log.warning(
        "IP забанен: %s (на %s, причина: %s, кем: %s)",
        ip, f"{duration_minutes} мин." if duration_minutes else "навсегда", reason or "-", by,
    )
    _log_ban_action("ban", ip, duration_minutes, reason, by)

    if fail2ban_jail:
        code, _, err = await _run("fail2ban-client", "set", fail2ban_jail, "banip", ip)
        if code != 0:
            log.warning("Не удалось зеркалировать бан %s в fail2ban jail %r: %s", ip, fail2ban_jail, err.strip())
    return True, ""


async def unban_ip(ip: str, fail2ban_jail: str = "", by: str = "auto") -> bool:
    ok = await asyncio.to_thread(blocker.unblock_ip, ip)
    if not ok:
        return False
    log.info("IP разбанен: %s (кем: %s)", ip, by)
    _log_ban_action("unban", ip, 0, "", by)
    if fail2ban_jail:
        await _run("fail2ban-client", "set", fail2ban_jail, "unbanip", ip)
    return True


async def list_banned() -> list[str]:
    """Список сейчас заблокированных IP (ipset сам убирает протухшие по timeout)."""
    return await asyncio.to_thread(blocker.list_blocked_ips)


async def is_ready() -> bool:
    """Есть ли цепочка SKIPA-BLOCK (watchdog создаёт её при старте сам)."""
    return await asyncio.to_thread(blocker.chain_exists)
