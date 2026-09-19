"""
Блокировка сканеров через iptables.

Все обнаруженные IP (при action.mode "block"/"block_notify") добавляются в
отдельную цепочку SKIPA-BLOCK. На неё настроен переход (-j SKIPA-BLOCK) из
INPUT, DOCKER-USER и KUBE-EXTERNAL-SERVICES/KUBE-NODEPORTS - см.
install-firewall-rules.sh. Поэтому ОДНА блокировка сразу закрывает доступ
и к хосту, и к сервисам, опубликованным через Docker/Kubernetes.

Список заблокированных IP дублируется в файл (BLOCKLIST_FILE), чтобы
restore_persisted_blocks() мог восстановить блокировки после перезапуска
процесса или перезагрузки сервера (сами правила iptables reboot не
переживают, если не настроен iptables-persistent).
"""
from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path

log = logging.getLogger("skipa_watchdog.blocker")

CHAIN = "SKIPA-BLOCK"
BLOCKLIST_FILE_DEFAULT = Path(__file__).resolve().parent.parent / "data" / "blocked_ips.json"

_warned_no_chain = False


def _run(cmd: list[str]) -> tuple[bool, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False)
        return r.returncode == 0, (r.stdout or r.stderr or "")
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
        return False, str(e)


def chain_exists() -> bool:
    ok, _ = _run(["iptables", "-L", CHAIN, "-n"])
    return ok


def ensure_chain() -> bool:
    """Создаёт цепочку SKIPA-BLOCK, если её ещё нет.

    ВАЖНО: сама по себе эта функция НЕ втыкает переходы из INPUT/
    DOCKER-USER/KUBE-* - это делает install-firewall-rules.sh (пункт меню
    install.sh или systemd-юнит skipa-watchdog-fw-rules). Без них
    блокировка технически "работает" (правило добавляется), но трафик до
    неё не доходит - реальной защиты нет, поэтому при первом обращении
    выводится предупреждение."""
    global _warned_no_chain
    if chain_exists():
        return True
    ok, out = _run(["iptables", "-N", CHAIN])
    if not ok and "Chain already exists" not in out:
        log.error("Не удалось создать цепочку %s: %s", CHAIN, out)
        return False
    if not _warned_no_chain:
        log.warning(
            "Цепочка %s создана, но переходы из INPUT/DOCKER-USER/KUBE-* ещё не настроены - "
            "заблокированные IP реально не будут отсекаться, пока не выполните "
            "install-firewall-rules.sh (sudo bash install.sh -> пункт меню про firewall).",
            CHAIN,
        )
        _warned_no_chain = True
    return True


def is_wired_into_input() -> bool:
    """Проверяет, стоит ли переход -j SKIPA-BLOCK в INPUT (минимальный
    признак того, что блокировка реально работает хотя бы для хоста)."""
    ok, out = _run(["iptables", "-C", "INPUT", "-j", CHAIN])
    return ok


def is_blocked(ip: str) -> bool:
    ok, _ = _run(["iptables", "-C", CHAIN, "-s", ip, "-j", "DROP"])
    return ok


def block_ip(ip: str, blocklist_file: Path | None = None) -> bool:
    if not ensure_chain():
        return False
    if is_blocked(ip):
        return True
    ok, out = _run(["iptables", "-A", CHAIN, "-s", ip, "-j", "DROP"])
    if not ok:
        log.error("Не удалось заблокировать %s: %s", ip, out)
        return False
    log.warning("IP %s заблокирован (цепочка %s)", ip, CHAIN)
    _persist_add(ip, blocklist_file or BLOCKLIST_FILE_DEFAULT)
    return True


def unblock_ip(ip: str, blocklist_file: Path | None = None) -> bool:
    ok, out = _run(["iptables", "-D", CHAIN, "-s", ip, "-j", "DROP"])
    _persist_remove(ip, blocklist_file or BLOCKLIST_FILE_DEFAULT)
    if not ok and "matching rule exist" not in out.lower() and "No chain" not in out:
        log.error("Не удалось разблокировать %s: %s", ip, out)
        return False
    log.info("IP %s разблокирован", ip)
    return True


def list_blocked_ips() -> list[str]:
    ok, out = _run(["iptables", "-S", CHAIN])
    if not ok:
        return []
    ips = []
    for line in out.splitlines():
        # -A SKIPA-BLOCK -s 1.2.3.4/32 -j DROP
        parts = line.split()
        if "-s" in parts:
            ip = parts[parts.index("-s") + 1]
            ips.append(ip.split("/")[0])
    return ips


def _load_persisted(path: Path) -> set[str]:
    if not path.exists():
        return set()
    try:
        return set(json.loads(path.read_text(encoding="utf-8")))
    except Exception:  # noqa: BLE001
        return set()


def _persist_add(ip: str, path: Path) -> None:
    ips = _load_persisted(path)
    ips.add(ip)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(sorted(ips)), encoding="utf-8")


def _persist_remove(ip: str, path: Path) -> None:
    ips = _load_persisted(path)
    ips.discard(ip)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(sorted(ips)), encoding="utf-8")


def restore_persisted_blocks(blocklist_file: Path | None = None) -> int:
    """Вызывается при старте watchdog.py: накатывает на iptables все IP,
    заблокированные в прошлых запусках (переживает reboot/перезапуск
    процесса, если правила iptables были сброшены)."""
    path = blocklist_file or BLOCKLIST_FILE_DEFAULT
    ips = _load_persisted(path)
    if not ips:
        return 0
    ensure_chain()
    restored = 0
    for ip in ips:
        if not is_blocked(ip):
            ok, _ = _run(["iptables", "-A", CHAIN, "-s", ip, "-j", "DROP"])
            if ok:
                restored += 1
    if restored:
        log.info("Восстановлено %d блокировок из прошлого запуска", restored)
    return restored
