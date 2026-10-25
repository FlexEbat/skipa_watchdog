"""
Блокировка сканеров через iptables (+ ipset, если он установлен).

Схема. Все блокировки живут в отдельной цепочке SKIPA-BLOCK. На неё настроен
переход (-j SKIPA-BLOCK) из INPUT, DOCKER-USER и KUBE-EXTERNAL-SERVICES/
KUBE-NODEPORTS, поэтому ОДНА блокировка закрывает доступ и к хосту, и к
сервисам, опубликованным через Docker/Kubernetes. Переходы ставит и (главное)
САМ ЧИНИТ сам процесс - ensure_wiring() вызывается при старте и периодически
из watchdog.py; ждать, пока кто-то вручную применит install-firewall-rules.sh
после перезагрузки/перезапуска Docker/ufw reload, больше не нужно.

Два режима внутри цепочки (выбирается автоматически):

  * ipset (предпочтительно). Три набора hash:net:
      skipa-allow - allowlist (свои/служебные адреса, SSH-сессии админа): первым
                    правилом идёт RETURN, т.е. эти адреса НИКОГДА не блокируются;
      skipa-db    - вся база сканеров, загруженная заранее (preload_db): сканер
                    отсекается ещё на первом SYN, а не после него. Перед DROP
                    стоит LOG "CONN: " только для SYN из этого набора - поэтому
                    общий LOG всех SYN больше не нужен, а kernel_log-мониторинг
                    видит именно сканеров;
      skipa-dyn   - динамические/ручные блокировки с таймаутом (timeout 0 =
                    бессрочно).
  * iptables-only (fallback, если ipset нет): по одному правилу
    `-s <ip> -j DROP` в цепочке + общий LOG всех SYN в каждой подключённой
    цепочке (как в старых версиях).

Список динамических блокировок дублируется в JSON-файл (атомарная запись),
чтобы restore_persisted_blocks() восстановил их после перезагрузки.

IPv6: блокировка работает только для IPv4 (списки сканеров IPv4; ip6tables не
используется). Для IPv6-адресов block_ip() честно возвращает False.

Все функции здесь синхронные (subprocess); из async-кода их нужно вызывать
через asyncio.to_thread(), чтобы не блокировать цикл мониторинга.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from .ip_lists import atomic_write_text, normalize_ip

log = logging.getLogger("skipa_watchdog.blocker")

CHAIN = "SKIPA-BLOCK"
SET_DYN = "skipa-dyn"
SET_DB = "skipa-db"
SET_ALLOW = "skipa-allow"
MAXELEM_DYN = 65536
MAXELEM_DB = 200000
MAXELEM_ALLOW = 4096

BLOCKLIST_FILE_DEFAULT = Path(__file__).resolve().parent.parent / "data" / "blocked_ips.json"

# -w 5: ждать xtables-lock до 5 секунд. Без этого iptables сразу падает, если в
# этот момент Docker/kube-proxy/другой iptables держит блокировку - и блокировка
# молча не ставится.
IPT = ["iptables", "-w", "5"]

# Самая широкая сеть, которую разрешено блокировать вручную/автоматически
MIN_BLOCK_PREFIX = 16

_lock = threading.RLock()


@dataclass
class Settings:
    log_prefix: str = "CONN: "
    log_limit: str = "30/second"
    log_burst: int = 40
    preload_db: bool = True      # загружать всю базу в ipset заранее
    drop_enabled: bool = True    # False при action.mode = notify (только LOG, без DROP)
    auto_timeout_s: int = 0      # таймаут автоблокировок (0 = бессрочно)
    skip_docker: bool = False
    skip_k8s: bool = False


_settings = Settings()
_allow_nets: list = []
_use_ipset: bool | None = None  # None = ещё не определено
_wired_seen: set[str] = set()   # цепочки, которые мы уже подключали в этом процессе


def configure(**kwargs) -> None:
    """Применяет настройки из config.yaml (вызывается из watchdog.py)."""
    for k, v in kwargs.items():
        if not hasattr(_settings, k):
            raise AttributeError(k)
        setattr(_settings, k, v)


def settings() -> Settings:
    return _settings


# ---------------------------------------------------------------------------
# Низкоуровневые вызовы
# ---------------------------------------------------------------------------

def _run(cmd: list[str], timeout: float = 15, input_text: str | None = None) -> tuple[bool, str]:
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False, input=input_text
        )
        return r.returncode == 0, (r.stdout or "") + (r.stderr or "")
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
        return False, str(e)


def _ipt(*args: str) -> tuple[bool, str]:
    return _run(IPT + list(args))


def ipset_available() -> bool:
    if shutil.which("ipset") is None:
        return False
    ok, _ = _run(["ipset", "version"])
    return ok


def _detect_mode() -> None:
    """Определяет режим (ipset/iptables) один раз за жизнь процесса."""
    global _use_ipset
    with _lock:
        if _use_ipset is None:
            _use_ipset = ipset_available() and _ensure_sets()
            log.info("Режим блокировки: %s", "ipset" if _use_ipset else "iptables (ipset не найден)")


def using_ipset() -> bool:
    if _use_ipset is None:
        _detect_mode()
    return bool(_use_ipset)


# ---------------------------------------------------------------------------
# Валидация целей блокировки (защита от самоблокировки)
# ---------------------------------------------------------------------------

def set_allowlist(nets) -> None:
    """Запоминает allowlist для проверок в Python (в ядро он попадает через
    sync_allowlist)."""
    global _allow_nets
    _allow_nets = list(nets)


def validate_target(target: str) -> tuple[ipaddress._BaseNetwork | None, str]:
    """Разбирает IP/сеть для блокировки. Возвращает (сеть, "") или (None, причина).
    Отказывает для: мусора, IPv6, слишком широких сетей (короче /16), служебных и
    частных адресов и всего, что пересекается с allowlist."""
    target = (target or "").strip()
    ip_obj = normalize_ip(target.split("/")[0]) if target else None
    if ip_obj is None:
        return None, "это не похоже на IP-адрес или сеть"
    try:
        if "/" in target:
            net = ipaddress.ip_network(f"{ip_obj}/{target.split('/', 1)[1]}", strict=False)
        else:
            net = ipaddress.ip_network(f"{ip_obj}/{ip_obj.max_prefixlen}")
    except ValueError:
        return None, "некорректная маска сети"
    if net.version != 4:
        return None, "блокировка IPv6 не поддерживается (списки сканеров - IPv4)"
    if net.prefixlen < MIN_BLOCK_PREFIX:
        return None, f"слишком широкая сеть (минимум /{MIN_BLOCK_PREFIX})"
    if net.is_loopback or net.is_private or net.is_link_local or net.is_multicast or net.is_unspecified:
        return None, "служебный или частный адрес - не блокирую"
    for allowed in _allow_nets:
        if allowed.version == net.version and net.overlaps(allowed):
            return None, f"пересекается с allowlist ({allowed})"
    return net, ""


# ---------------------------------------------------------------------------
# ipset
# ---------------------------------------------------------------------------

def _ensure_sets() -> bool:
    specs = [
        (SET_DYN, MAXELEM_DYN, True),
        (SET_DB, MAXELEM_DB, False),
        (SET_ALLOW, MAXELEM_ALLOW, False),
    ]
    for name, maxelem, with_timeout in specs:
        cmd = ["ipset", "create", name, "hash:net", "family", "inet", "maxelem", str(maxelem)]
        if with_timeout:
            cmd += ["timeout", "0"]
        ok, out = _run(cmd + ["-exist"])
        if not ok:
            log.error("Не удалось создать ipset %s: %s", name, out.strip())
            return False
    return True


def _replace_set(name: str, entries: list[str], maxelem: int) -> bool:
    """Атомарно подменяет содержимое набора (restore во временный + swap): нет
    окна, когда набор пуст или заполнен наполовину."""
    tmp = f"{name}-tmp"
    lines = [f"create {tmp} hash:net family inet maxelem {maxelem} -exist", f"flush {tmp}"]
    lines += [f"add {tmp} {e} -exist" for e in entries]
    ok, out = _run(["ipset", "restore", "-exist"], timeout=120, input_text="\n".join(lines) + "\n")
    if not ok:
        log.error("ipset restore для %s не удался: %s", name, out.strip()[:300])
        _run(["ipset", "destroy", tmp])
        return False
    _run(["ipset", "create", name, "hash:net", "family", "inet", "maxelem", str(maxelem), "-exist"])
    ok, out = _run(["ipset", "swap", tmp, name])
    _run(["ipset", "destroy", tmp])
    if not ok:
        log.error("ipset swap %s не удался: %s", name, out.strip())
        return False
    return True


def _set_size(name: str) -> int | None:
    ok, out = _run(["ipset", "list", name, "-terse"])
    if not ok:
        return None
    for line in out.splitlines():
        if line.startswith("Number of entries:"):
            try:
                return int(line.split(":", 1)[1])
            except ValueError:
                return None
    return None


def _set_members(name: str) -> list[str]:
    ok, out = _run(["ipset", "list", name])
    if not ok:
        return []
    members, in_members = [], False
    for line in out.splitlines():
        if line.startswith("Members:"):
            in_members = True
            continue
        if in_members and line.strip():
            members.append(line.split()[0])
    return members


def preload_db(entries: list[str]) -> int:
    """Загружает всю базу сканеров в набор skipa-db. Возвращает число записей
    (0, если ipset недоступен или загрузка не удалась)."""
    with _lock:
        if not ensure_chain() or not using_ipset():
            return 0
        if not entries:
            return 0
        if len(entries) > MAXELEM_DB:
            log.error("В базе %d записей - больше лимита ipset %d, preload пропущен", len(entries), MAXELEM_DB)
            return 0
        if not _replace_set(SET_DB, entries, MAXELEM_DB):
            return 0
        log.info("В ipset %s загружено %d записей", SET_DB, len(entries))
        return len(entries)


def sync_allowlist(nets) -> bool:
    """Обновляет allowlist: и в Python (для проверок), и в ядре (ipset)."""
    nets = list(nets)
    set_allowlist(nets)
    with _lock:
        if not ensure_chain() or not using_ipset():
            return True  # без ipset allowlist работает только в Python-проверках
        v4 = sorted({str(n) for n in nets if n.version == 4})
        return _replace_set(SET_ALLOW, v4, MAXELEM_ALLOW)


# ---------------------------------------------------------------------------
# Цепочка и правила
# ---------------------------------------------------------------------------

def chain_exists() -> bool:
    ok, _ = _ipt("-L", CHAIN, "-n")
    return ok


def _log_args() -> list[str]:
    return [
        "-m", "limit", "--limit", _settings.log_limit, "--limit-burst", str(_settings.log_burst),
        "-j", "LOG", "--log-prefix", _settings.log_prefix, "--log-level", "4",
    ]


def _desired_rules() -> list[tuple[str, list[str], bool]]:
    """Правила цепочки SKIPA-BLOCK в нужном порядке: (ключ, аргументы, нужно ли)."""
    return [
        ("allow", ["-m", "set", "--match-set", SET_ALLOW, "src", "-j", "RETURN"], True),
        (
            "db-log",
            ["-p", "tcp", "--syn", "-m", "set", "--match-set", SET_DB, "src"] + _log_args(),
            _settings.preload_db,
        ),
        (
            "db-drop",
            ["-m", "set", "--match-set", SET_DB, "src", "-j", "DROP"],
            _settings.preload_db and _settings.drop_enabled,
        ),
        (
            "dyn-drop",
            ["-m", "set", "--match-set", SET_DYN, "src", "-j", "DROP"],
            _settings.drop_enabled,
        ),
    ]


def _ensure_rule(args: list[str], present: bool, insert_first: bool = False) -> bool:
    exists, _ = _ipt("-C", CHAIN, *args)
    if present and not exists:
        if insert_first:
            ok, out = _ipt("-I", CHAIN, "1", *args)
        else:
            ok, out = _ipt("-A", CHAIN, *args)
        if not ok:
            log.error("Не удалось добавить правило в %s: %s", CHAIN, out.strip())
            return False
    elif not present and exists:
        _ipt("-D", CHAIN, *args)
    return True


def ensure_chain() -> bool:
    """Создаёт цепочку SKIPA-BLOCK (и наборы/правила ipset-режима), если их нет.
    Идемпотентно и дёшево - можно вызывать часто."""
    with _lock:
        if not chain_exists():
            ok, out = _ipt("-N", CHAIN)
            if not ok and "Chain already exists" not in out:
                log.error("Не удалось создать цепочку %s: %s", CHAIN, out.strip())
                return False
            log.info("Создана цепочка %s", CHAIN)

        if using_ipset():
            if not _ensure_sets():
                return False

        if using_ipset():
            for key, args, wanted in _desired_rules():
                _ensure_rule(args, wanted, insert_first=(key == "allow"))
        return True


def _wired_chains() -> list[str]:
    """Цепочки, из которых должен быть переход в SKIPA-BLOCK (только существующие)."""
    chains = ["INPUT"]
    if not _settings.skip_docker:
        ok, _ = _ipt("-L", "DOCKER-USER", "-n")
        if ok:
            chains.append("DOCKER-USER")
    if not _settings.skip_k8s:
        for c in ("KUBE-EXTERNAL-SERVICES", "KUBE-NODEPORTS"):
            ok, _ = _ipt("-L", c, "-n")
            if ok:
                chains.append(c)
    return chains


def _legacy_log_args() -> list[str]:
    return ["-p", "tcp", "--syn"] + _log_args()


def wiring_status() -> dict[str, bool]:
    """{цепочка: есть ли переход в SKIPA-BLOCK} - только чтение."""
    return {c: _ipt("-C", c, "-j", CHAIN)[0] for c in _wired_chains()}


def ensure_wiring() -> dict[str, str]:
    """Гарантирует переходы -j SKIPA-BLOCK (позиция 1) из INPUT/DOCKER-USER/KUBE-*
    и, если предзагрузка базы в ipset не используется, общий LOG всех SYN сразу
    после перехода (нужен kernel_log-мониторингу).
    Возвращает {цепочка: "ok" | "fixed" | "failed"}."""
    result: dict[str, str] = {}
    with _lock:
        if not ensure_chain():
            return {"INPUT": "failed"}
        for chain in _wired_chains():
            status = "ok"
            if not _ipt("-C", chain, "-j", CHAIN)[0]:
                ok, out = _ipt("-I", chain, "1", "-j", CHAIN)
                if ok:
                    status = "fixed"
                    # первое подключение при старте - штатно; повторное - значит правила
                    # кто-то сбросил (reload ufw/firewalld, рестарт Docker) - это важно видеть
                    if chain in _wired_seen:
                        log.warning("Переход %s -> %s пропал (сброс правил?), восстановлен", chain, CHAIN)
                    else:
                        log.info("Переход %s -> %s установлен", chain, CHAIN)
                    _wired_seen.add(chain)
                else:
                    status = "failed"
                    log.error("Не удалось подключить %s к %s: %s", CHAIN, chain, out.strip())
            if status != "failed":
                legacy_log = _ipt("-C", chain, *_legacy_log_args())[0]
                if using_ipset() and _settings.preload_db:
                    # LOG делается внутри SKIPA-BLOCK только для SYN из базы сканеров;
                    # общий LOG всех SYN (остался от старых установок) - лишний шум
                    if legacy_log:
                        _ipt("-D", chain, *_legacy_log_args())
                elif not legacy_log:
                    _ipt("-I", chain, "2", *_legacy_log_args())
            if status == "ok":
                _wired_seen.add(chain)
            result[chain] = status
    return result


def db_set_size() -> int | None:
    """Сколько записей сейчас в наборе skipa-db (None - нет ipset-режима)."""
    return _set_size(SET_DB) if using_ipset() else None


def is_wired_into_input() -> bool:
    ok, _ = _ipt("-C", "INPUT", "-j", CHAIN)
    return ok


def log_rule_present() -> bool:
    """Есть ли LOG-правило, на которое опирается kernel_log-мониторинг."""
    if using_ipset() and _settings.preload_db:
        return _ipt("-C", CHAIN, "-p", "tcp", "--syn", "-m", "set", "--match-set", SET_DB, "src", *_log_args())[0]
    return _ipt("-C", "INPUT", *_legacy_log_args())[0]


def status_info() -> dict:
    """Сводка для /status и логов."""
    info: dict = {
        "mode": "ipset" if using_ipset() else "iptables",
        "wiring": wiring_status(),
        "log_rule": log_rule_present(),
        "preload": _settings.preload_db and using_ipset(),
    }
    if using_ipset():
        info["db_set"] = _set_size(SET_DB)
        info["dyn_set"] = _set_size(SET_DYN)
        info["allow_set"] = _set_size(SET_ALLOW)
    return info


# ---------------------------------------------------------------------------
# Динамические блокировки
# ---------------------------------------------------------------------------

def is_blocked(ip: str) -> bool:
    if using_ipset():
        if _run(["ipset", "test", SET_DYN, ip])[0]:
            return True
    return _ipt("-C", CHAIN, "-s", ip, "-j", "DROP")[0]


def is_in_db_set(ip: str) -> bool:
    return using_ipset() and _run(["ipset", "test", SET_DB, ip])[0]


def block_ip(ip: str, timeout_s: int | None = None, blocklist_file: Path | None = None) -> bool:
    """Блокирует IP (или сеть). timeout_s=None - таймаут по умолчанию из
    настроек (автоблокировки), 0 - бессрочно."""
    net, reason = validate_target(ip)
    if net is None:
        log.warning("Не блокирую %r: %s", ip, reason)
        return False
    target = str(net.network_address) if net.prefixlen == 32 else str(net)
    if timeout_s is None:
        timeout_s = _settings.auto_timeout_s

    with _lock:
        if not ensure_chain():
            return False
        if using_ipset():
            cmd = ["ipset", "add", SET_DYN, target, "-exist"]
            if timeout_s:
                cmd[4:4] = ["timeout", str(int(timeout_s))]
            ok, out = _run(cmd)
        else:
            if is_blocked(target):
                ok, out = True, ""
            else:
                ok, out = _ipt("-A", CHAIN, "-s", target, "-j", "DROP")
        if not ok:
            log.error("Не удалось заблокировать %s: %s", target, out.strip())
            return False
        log.warning("IP %s заблокирован (%s%s)", target, "ipset" if using_ipset() else CHAIN,
                    f", на {int(timeout_s)} с" if timeout_s else ", бессрочно")
        _persist_add(target, (time.time() + timeout_s) if timeout_s else 0.0,
                     blocklist_file or BLOCKLIST_FILE_DEFAULT)
        return True


def unblock_ip(ip: str, blocklist_file: Path | None = None) -> bool:
    ip_obj = normalize_ip(ip.split("/")[0]) if ip else None
    if ip_obj is None:
        return False
    target = ip if "/" in ip else str(ip_obj)
    with _lock:
        _persist_remove(target, blocklist_file or BLOCKLIST_FILE_DEFAULT)
        ok_any = False
        if using_ipset():
            ok, out = _run(["ipset", "del", SET_DYN, target, "-exist"])
            ok_any = ok_any or ok
            if not ok:
                log.error("Не удалось разблокировать %s: %s", target, out.strip())
        # правила старого формата (-s ip -j DROP), если остались с прошлых версий
        while _ipt("-C", CHAIN, "-s", target, "-j", "DROP")[0]:
            ok, _ = _ipt("-D", CHAIN, "-s", target, "-j", "DROP")
            ok_any = ok_any or ok
            if not ok:
                break
        if not using_ipset() and not ok_any:
            ok_any = True  # нечего было удалять - не ошибка
        if ok_any:
            log.info("IP %s разблокирован", target)
        return ok_any


def list_blocked_ips() -> list[str]:
    ips: list[str] = []
    if using_ipset():
        ips.extend(_set_members(SET_DYN))
    ok, out = _ipt("-S", CHAIN)
    if ok:
        for line in out.splitlines():
            parts = line.split()
            if "-s" in parts and "DROP" in parts:
                ip = parts[parts.index("-s") + 1]
                ips.append(ip[:-3] if ip.endswith("/32") else ip)
    seen, out_list = set(), []
    for ip in ips:
        if ip not in seen:
            seen.add(ip)
            out_list.append(ip)
    return out_list


# ---------------------------------------------------------------------------
# Персистентность: {"ips": {"1.2.3.4": expires_ts_or_0}}
# ---------------------------------------------------------------------------

def _load_persisted(path: Path) -> dict[str, float]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:  # noqa: BLE001
        # не затираем молча: повреждённый файл переименовываем, чтобы его можно было разобрать
        try:
            path.replace(path.with_name(path.name + ".corrupt"))
            log.error("Файл блокировок %s повреждён (%s), сохранён как .corrupt", path, e)
        except OSError:
            pass
        return {}
    if isinstance(data, list):  # старый формат: просто список IP (бессрочно)
        return {str(ip): 0.0 for ip in data}
    return {str(k): float(v) for k, v in (data.get("ips") or {}).items()}


def _save_persisted(path: Path, ips: dict[str, float]) -> None:
    atomic_write_text(path, json.dumps({"ips": dict(sorted(ips.items()))}, indent=1))


def _persist_add(ip: str, expires: float, path: Path) -> None:
    ips = _load_persisted(path)
    ips[ip] = expires
    _save_persisted(path, ips)


def _persist_remove(ip: str, path: Path) -> None:
    ips = _load_persisted(path)
    if ips.pop(ip, None) is not None:
        _save_persisted(path, ips)


def restore_persisted_blocks(blocklist_file: Path | None = None) -> int:
    """Вызывается при старте watchdog.py: накатывает на ядро все блокировки из
    прошлых запусков (с учётом оставшегося таймаута; просроченные отбрасываются).
    В ipset-режиме - одним вызовом restore, а не по два iptables на IP."""
    path = blocklist_file or BLOCKLIST_FILE_DEFAULT
    with _lock:
        ips = _load_persisted(path)
        if not ips:
            return 0
        now = time.time()
        alive = {ip: exp for ip, exp in ips.items() if exp == 0 or exp > now}
        if len(alive) != len(ips):
            _save_persisted(path, alive)
        if not alive or not ensure_chain():
            return 0

        restored = 0
        if using_ipset():
            lines = []
            for ip, exp in alive.items():
                net, reason = validate_target(ip)
                if net is None:
                    log.warning("Пропускаю сохранённую блокировку %s: %s", ip, reason)
                    continue
                t = "" if exp == 0 else f" timeout {max(1, int(exp - now))}"
                lines.append(f"add {SET_DYN} {ip}{t} -exist")
            if lines:
                ok, out = _run(["ipset", "restore", "-exist"], timeout=60, input_text="\n".join(lines) + "\n")
                if ok:
                    restored = len(lines)
                else:
                    log.error("Не удалось восстановить блокировки: %s", out.strip()[:300])
        else:
            for ip in alive:
                net, reason = validate_target(ip)
                if net is None:
                    log.warning("Пропускаю сохранённую блокировку %s: %s", ip, reason)
                    continue
                if not is_blocked(ip) and _ipt("-A", CHAIN, "-s", ip, "-j", "DROP")[0]:
                    restored += 1
        if restored:
            log.info("Восстановлено %d блокировок из прошлого запуска", restored)
        return restored
