"""Минимальная имитация iptables/ipset для тестов bot.blocker (без root и без ядра)."""
from __future__ import annotations


class FakeNetfilter:
    def __init__(self, ipset: bool = True, chains=("INPUT", "DOCKER-USER")):
        self.has_ipset = ipset
        self.chains: dict[str, list[tuple]] = {c: [] for c in chains}
        self.sets: dict[str, dict] = {}   # name -> {entry: timeout or None}
        self.calls: list[list[str]] = []

    # ---- iptables ----
    def _ipt(self, args: list[str]):
        op = args[0]
        if op == "-N":
            if args[1] in self.chains:
                return False, "Chain already exists"
            self.chains[args[1]] = []
            return True, ""
        if op == "-L":
            return (args[1] in self.chains), ""
        chain = args[1]
        if chain not in self.chains:
            return False, "No chain/target/match by that name"
        rules = self.chains[chain]
        if op == "-C":
            return (tuple(args[2:]) in rules), ""
        if op == "-A":
            rules.append(tuple(args[2:]))
            return True, ""
        if op == "-I":
            rules.insert(int(args[2]) - 1, tuple(args[3:]))
            return True, ""
        if op == "-D":
            r = tuple(args[2:])
            if r in rules:
                rules.remove(r)
                return True, ""
            return False, "Bad rule"
        if op == "-S":
            return True, "\n".join(f"-A {chain} " + " ".join(r) for r in rules)
        return False, "unsupported"

    # ---- ipset ----
    def _ipset(self, cmd: list[str], input_text):
        op = cmd[1]
        if op == "version":
            return True, ""
        if op == "create":
            self.sets.setdefault(cmd[2], {})
            return True, ""
        if op == "add":
            entry = cmd[3]
            timeout = None
            if "timeout" in cmd:
                timeout = int(cmd[cmd.index("timeout") + 1])
            self.sets.setdefault(cmd[2], {})[entry] = timeout
            return True, ""
        if op == "del":
            self.sets.get(cmd[2], {}).pop(cmd[3], None)
            return True, ""
        if op == "test":
            return (cmd[3] in self.sets.get(cmd[2], {})), ""
        if op == "list":
            members = self.sets.get(cmd[2])
            if members is None:
                return False, "no such set"
            if "-terse" in cmd:
                return True, f"Number of entries: {len(members)}"
            return True, "Members:\n" + "\n".join(members)
        if op == "swap":
            self.sets[cmd[2]], self.sets[cmd[3]] = self.sets[cmd[3]], self.sets[cmd[2]]
            return True, ""
        if op == "destroy":
            self.sets.pop(cmd[2], None)
            return True, ""
        if op == "restore":
            for line in (input_text or "").splitlines():
                p = line.split()
                if not p:
                    continue
                if p[0] == "create":
                    self.sets.setdefault(p[1], {})
                elif p[0] == "flush":
                    self.sets[p[1]] = {}
                elif p[0] == "add":
                    t = int(p[p.index("timeout") + 1]) if "timeout" in p else None
                    self.sets.setdefault(p[1], {})[p[2]] = t
            return True, ""
        return False, "unsupported"

    def run(self, cmd, timeout=15, input_text=None):
        self.calls.append(list(cmd))
        if cmd[0] == "iptables":
            return self._ipt(cmd[3:] if cmd[1] == "-w" else cmd[1:])
        if cmd[0] == "ipset":
            if not self.has_ipset:
                return False, "ipset: not found"
            return self._ipset(cmd, input_text)
        return False, "unknown command"
