"""Поддельные ipset/iptables для тестов bash-скриптов режима «только сервис».

Не требуют root и ядра: наборы хранятся файлами, правила - JSON. Модель намеренно простая
(членство проверяется точным совпадением строки), но достаточна, чтобы проверять потоки
«сохранить / восстановить / проверить», а не семантику ядра - её проверяет сквозной сценарий
на настоящих ipset/iptables (tests/e2e_service_real.sh, включается явно).
"""
import stat
from pathlib import Path

FAKE_IPSET = r'''#!/usr/bin/env bash
D="${FAKE_IPSET:?}"; mkdir -p "$D"
cmd="${1:-}"; shift || true
case "$cmd" in
  version) echo "ipset v7.0" ;;
  create) [ -e "$D/$1" ] || : > "$D/$1" ;;
  add) [ -e "$D/$1" ] || { echo "ipset: set $1 doesn't exist" >&2; exit 1; }
       grep -qxF -- "$2" "$D/$1" || echo "$2" >> "$D/$1" ;;
  del) [ -e "$D/$1" ] || exit 1
       grep -vxF -- "$2" "$D/$1" > "$D/$1.t"; mv "$D/$1.t" "$D/$1"; true ;;
  test) [ -e "$D/$1" ] && grep -qxF -- "$2" "$D/$1" ;;
  flush) [ -e "$D/$1" ] && : > "$D/$1" ;;
  destroy) rm -f "$D/$1" ;;
  swap) [ -e "$D/$1" ] && [ -e "$D/$2" ] || exit 1
        mv "$D/$1" "$D/swap.t"; mv "$D/$2" "$D/$1"; mv "$D/swap.t" "$D/$2" ;;
  list)
    if [ "${1:-}" = "-n" ]; then
        if [ -n "${2:-}" ]; then [ -e "$D/$2" ] && echo "$2"; else ls "$D" | grep -v '\.t$'; fi
        exit 0
    fi
    [ -e "$D/$1" ] || exit 1
    echo "Name: $1"; echo "Number of entries: $(grep -c . "$D/$1")"; echo "Members:"; cat "$D/$1" ;;
  save) [ -e "$D/$1" ] || exit 1
        echo "create $1 hash:net family inet hashsize 1024 maxelem 65536"
        while IFS= read -r ip; do [ -n "$ip" ] && echo "add $1 $ip"; done < "$D/$1" ;;
  restore) [ -n "${FAKE_IPSET_RESTORE_FAIL:-}" ] && { cat >/dev/null; echo "ipset: restore failed" >&2; exit 1; }
           while IFS= read -r line; do
               set -- $line
               case "$1" in
                   create) [ -e "$D/$2" ] || : > "$D/$2" ;;
                   add) [ -e "$D/$2" ] || exit 1; grep -qxF -- "$3" "$D/$2" || echo "$3" >> "$D/$2" ;;
               esac
           done ;;
  *) exit 0 ;;
esac
'''

FAKE_IPTABLES = r'''#!/usr/bin/env python3
import json, os, sys
path = os.path.join(os.environ["FAKE_IPT"], "state.json")
os.makedirs(os.environ["FAKE_IPT"], exist_ok=True)
try:
    state = json.load(open(path))
except (OSError, ValueError):
    state = {"INPUT": []}
args = sys.argv[1:]
if args[:2] == ["-w", "5"]:
    args = args[2:]
op, chain, rest = args[0], args[1] if len(args) > 1 else "", args[2:]
rc = 0
if op == "-L":
    rc = 0 if chain in state else 1
elif op == "-S":
    if chain not in state:
        rc = 1
    else:
        print(f"-N {chain}")
        for r in state[chain]:
            print(f"-A {chain} {r}")
elif op == "-C":
    rc = 0 if chain in state and " ".join(rest) in state[chain] else 1
elif op == "-N":
    state.setdefault(chain, [])
elif op in ("-I", "-A"):
    if os.environ.get("FAKE_IPT_BROKEN"):
        rc = 0                       # «правило поставлено», но фактически нет (имитация сбоя)
    elif chain not in state:
        rc = 1
    else:
        if op == "-I":
            pos = int(rest[0]); state[chain].insert(pos - 1, " ".join(rest[1:]))
        else:
            state[chain].append(" ".join(rest))
elif op == "-D":
    rule = " ".join(rest)
    if chain in state and rule in state[chain]:
        state[chain].remove(rule)
    else:
        rc = 1
json.dump(state, open(path, "w"))
sys.exit(rc)
'''


def install(bindir: Path) -> None:
    """Кладёт поддельные ipset и iptables в bindir."""
    bindir.mkdir(parents=True, exist_ok=True)
    for name, body in (("ipset", FAKE_IPSET), ("iptables", FAKE_IPTABLES)):
        p = bindir / name
        p.write_text(body, encoding="utf-8")
        p.chmod(p.stat().st_mode | stat.S_IEXEC)


def env_for(base: dict, root: Path, bindir: Path) -> dict:
    env = dict(base)
    env.update(
        PATH=f"{bindir}:{base['PATH']}", FAKE_IPSET=str(root / "ipsets"), FAKE_IPT=str(root / "ipt"),
        SKIPA_STATE_DIR=str(root / "state"), SKIPA_NO_UPDATE_CHECK="1",
    )
    return env
