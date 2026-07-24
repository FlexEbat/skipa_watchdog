"""
Бан IP-адресов через ipset (набор `skipa_watchdog_ban`, создаётся заранее
скриптом install-logging-rules.sh вместе с DROP-правилами в iptables).

Почему ipset, а не отдельное iptables-правило на каждый IP:
- ipset умеет автоматическое истечение бана по таймауту (`timeout N`),
  не нужно городить отдельный планировщик для снятия временных банов;
- один iptables DROP-правило матчит весь набор сразу (`-m set --match-set`),
  вместо тысяч отдельных iptables-правил при большом количестве банов;
- добавление/снятие/список - простые атомарные команды `ipset add/del/list`.

Дополнительно поддерживается "зеркалирование" бана в fail2ban (если он
установлен и настроен конкретный jail в config.yaml -> banning.fail2ban_jail) -
это просто вызов `fail2ban-client set <jail> banip <ip>`, чтобы бан было видно
в общей картине `fail2ban-client status` вместе с остальными джейлами.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from pathlib import Path

log = logging.getLogger("skipa_watchdog.banning")

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
BAN_LOG_FILE = DATA_DIR / "bans.jsonl"

_IPSET_LIST_IP_RE = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")


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
    ipset_name: str = "skipa_watchdog_ban",
    duration_minutes: int = 0,
    reason: str = "",
    by: str = "auto",
    fail2ban_jail: str = "",
) -> bool:
    """duration_minutes=0 значит бан навсегда (пока не снимут вручную)."""
    timeout_seconds = duration_minutes * 60
    if timeout_seconds > 0:
        args = ["ipset", "add", ipset_name, ip, "timeout", str(timeout_seconds), "-exist"]
    else:
        args = ["ipset", "add", ipset_name, ip, "-exist"]

    code, out, err = await _run(*args)
    if code != 0:
        log.error("Не удалось забанить %s через ipset: %s", ip, err.strip())
        return False

    log.warning(
        "IP забанен: %s (на %s, причина: %s, кем: %s)",
        ip, f"{duration_minutes} мин." if duration_minutes else "навсегда", reason or "-", by,
    )
    _log_ban_action("ban", ip, duration_minutes, reason, by)

    if fail2ban_jail:
        f2b_code, _, f2b_err = await _run("fail2ban-client", "set", fail2ban_jail, "banip", ip)
        if f2b_code != 0:
            log.warning("Не удалось зеркалировать бан %s в fail2ban jail %r: %s", ip, fail2ban_jail, f2b_err.strip())

    return True


async def unban_ip(ip: str, ipset_name: str = "skipa_watchdog_ban", fail2ban_jail: str = "", by: str = "auto") -> bool:
    code, out, err = await _run("ipset", "del", ipset_name, ip, "-exist")
    if code != 0:
        log.error("Не удалось разбанить %s через ipset: %s", ip, err.strip())
        return False

    log.info("IP разбанен: %s (кем: %s)", ip, by)
    _log_ban_action("unban", ip, 0, "", by)

    if fail2ban_jail:
        await _run("fail2ban-client", "set", fail2ban_jail, "unbanip", ip)

    return True


async def list_banned(ipset_name: str = "skipa_watchdog_ban") -> list[str]:
    """Возвращает список сейчас забаненных IP (учитывая timeout - ipset сам
    убирает протухшие записи из вывода)."""
    code, out, err = await _run("ipset", "list", ipset_name)
    if code != 0:
        log.error("Не удалось получить список бана (ipset list %s): %s", ipset_name, err.strip())
        return []

    ips = []
    in_members = False
    for line in out.splitlines():
        if line.strip() == "Members:":
            in_members = True
            continue
        if in_members:
            m = _IPSET_LIST_IP_RE.match(line.strip())
            if m:
                ips.append(m.group(1))
    return ips


async def is_ipset_ready(ipset_name: str = "skipa_watchdog_ban") -> bool:
    """Проверяет, что ipset вообще установлен и набор создан (install-logging-rules.sh
    должен был это сделать заранее)."""
    code, _, _ = await _run("ipset", "list", "-n", ipset_name)
    return code == 0
