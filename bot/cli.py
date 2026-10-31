"""
Командная строка для панели install.sh в варианте с Python: те же операции, что и у
команд бота (/block, /unblock, /blocklist), но без инлайн-кода в bash-скрипте.

    python -m bot.cli list
    python -m bot.cli block <ip|сеть> [часы]     (без часов - бессрочно)
    python -m bot.cli unblock <ip>

Код возврата: 0 - выполнено, 1 - не выполнено (причина выводится).
"""
from __future__ import annotations

import asyncio
import os
import sys

from bot import banning, blocker
from bot.config import Config


def _config() -> Config:
    return Config.load(os.environ.get("SKIPA_CONFIG", "config.yaml"))


def cmd_list() -> int:
    ips = blocker.list_blocked_ips()
    print("  (никто не заблокирован вручную или автоматически)" if not ips else "\n".join(f"  {ip}" for ip in ips))
    return 0


def cmd_block(target: str, hours: str | None) -> int:
    net, reason = blocker.validate_target(target)
    if net is None:
        print(f"Не блокирую {target}: {reason}.")
        return 1
    timeout_s = 0
    if hours:
        try:
            value = float(hours)
            if value < 0:
                raise ValueError
            timeout_s = int(value * 3600)
        except (ValueError, OverflowError):
            print("Число часов должно быть неотрицательным числом.")
            return 1
    if blocker.block_ip(target, timeout_s):
        print(f"OK: {net} заблокирован" + (f" на {hours} ч" if timeout_s else " бессрочно"))
        return 0
    print(f"FAIL: не удалось заблокировать {net} (см. логи)")
    return 1


def cmd_unblock(ip: str) -> int:
    # через banning, как и /unblock в боте: снимает бан в fail2ban и пишет журнал
    ok = asyncio.run(banning.unban_ip(ip, fail2ban_jail=_config().fail2ban_jail, by="panel"))
    print("OK" if ok else "FAIL")
    return 0 if ok else 1


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 1
    cmd, args = argv[0], argv[1:]
    if cmd == "list":
        return cmd_list()
    if cmd == "block" and args:
        return cmd_block(args[0], args[1] if len(args) > 1 else None)
    if cmd == "unblock" and args:
        return cmd_unblock(args[0])
    print(__doc__)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
