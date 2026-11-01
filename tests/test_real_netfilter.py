"""Сквозной сценарий на настоящих ipset/iptables. По умолчанию ПРОПУСКАЕТСЯ.

Включение: SKIPA_REAL_NETFILTER_TESTS=1 (и root). Сценарий меняет наборы и правила skipa-*
на хосте, поэтому запускать его стоит только в одноразовой среде.
"""
import os
import re
import shutil
import subprocess
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "e2e_service_real.sh"


def _can_use_netfilter() -> bool:
    if os.environ.get("SKIPA_REAL_NETFILTER_TESTS") != "1" or os.geteuid() != 0:
        return False
    if not (shutil.which("ipset") and shutil.which("iptables")):
        return False
    probe = "skipa-probe-test"
    ok = subprocess.run(["ipset", "create", probe, "hash:net"], capture_output=True).returncode == 0
    subprocess.run(["ipset", "destroy", probe], capture_output=True)
    return ok


@unittest.skipUnless(_can_use_netfilter(), "нужен явный SKIPA_REAL_NETFILTER_TESTS=1, root, ipset и iptables")
class RealNetfilterScenario(unittest.TestCase):
    def test_сквозной_сценарий(self):
        """все проверки сценария проходят на реальном ядре"""
        r = subprocess.run(["bash", str(SCRIPT)], capture_output=True, text=True, timeout=300)
        m = re.search(r"ИТОГО: PASS=(\d+) FAIL=(\d+)", r.stdout)
        self.assertIsNotNone(m, r.stdout + r.stderr)
        self.assertEqual(m.group(2), "0", "\n".join(line for line in r.stdout.splitlines() if "FAIL" in line))
        self.assertGreater(int(m.group(1)), 30)


def _can_use_netns() -> bool:
    if not (_can_use_netfilter() and shutil.which("ip")):
        return False
    ok = subprocess.run(["ip", "netns", "add", "skipa-probe"], capture_output=True).returncode == 0
    subprocess.run(["ip", "netns", "del", "skipa-probe"], capture_output=True)
    return ok


@unittest.skipUnless(_can_use_netns(), "нужен явный SKIPA_REAL_NETFILTER_TESTS=1, root и ip netns")
class RealTrafficScenarios(unittest.TestCase):
    """Поведение на настоящих пакетах: что происходит с установленной сессией, новым TCP и UDP."""

    def _run(self, name: str, minimum: int) -> None:
        r = subprocess.run(["bash", str(HERE / name)], capture_output=True, text=True, timeout=300)
        m = re.search(r"ИТОГО: PASS=(\d+) FAIL=(\d+)", r.stdout)
        self.assertIsNotNone(m, r.stdout + r.stderr)
        self.assertEqual(m.group(2), "0", "\n".join(line for line in r.stdout.splitlines() if "FAIL" in line))
        self.assertGreaterEqual(int(m.group(1)), minimum)

    def test_сервис_keep_established_tcp(self):
        """только сервис: по умолчанию рвётся всё, с опцией живёт установленная TCP-сессия"""
        self._run("e2e_traffic_bash_real.sh", 12)

    def test_python_keep_established_tcp(self):
        """вариант с Python: то же поведение через bot.blocker"""
        self._run("e2e_traffic_python_real.sh", 6)


if __name__ == "__main__":
    unittest.main()
