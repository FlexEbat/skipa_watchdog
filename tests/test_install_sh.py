"""Проверки функций install.sh без root и без реального iptables (подмена через PATH)."""
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

FAKE_IPTABLES = """#!/usr/bin/env bash
# имитация: -S INPUT показывает правила в НОВОЙ форме (с проверкой allowlist), DOCKER-USER отсутствует
args=("$@"); [ "${args[0]}" = "-w" ] && args=("${args[@]:2}")
case "${args[0]} ${args[1]}" in
  "-S INPUT") echo "-P INPUT ACCEPT"
              echo "-A INPUT -m set --match-set skipa-scanners src -m set ! --match-set skipa-allow src -j DROP"
              echo "-A INPUT -p tcp -m set --match-set skipa-manual src -j LOG --log-prefix \\"CONN: \\"";;
  "-S DOCKER-USER") echo "-N DOCKER-USER";;
  "-L INPUT") exit 0;;
  *) exit 1;;
esac
"""


def run(script: str, stdin: str = "", env_extra=None):
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        (d / "bin").mkdir()
        fake = d / "bin" / "iptables"
        fake.write_text(FAKE_IPTABLES)
        fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
        install_dir = d / "inst"
        (install_dir / "service").mkdir(parents=True)
        shutil.copy(ROOT / "service" / "lib-config.sh", install_dir / "service")
        shutil.copy(ROOT / "config.example.yaml", install_dir / "config.example.yaml")
        env = {
            **os.environ, "PATH": f"{d / 'bin'}:{os.environ['PATH']}", "SKIPA_SOURCE_ONLY": "1",
            "SKIPA_INSTALL_DIR": str(install_dir), "SKIPA_LOG_DIR": str(d / "log"),
            **(env_extra or {}),
        }
        r = subprocess.run(
            ["bash", "-c", f'source "{ROOT / "install.sh"}"\n{script}'],
            input=stdin, capture_output=True, text=True, env=env, timeout=30, cwd=d,
        )
        return r, install_dir


@unittest.skipUnless(shutil.which("bash"), "нужен bash")
class InstallShTests(unittest.TestCase):
    def test_rule_detection_understands_current_rule_form(self):
        r, _ = run('_chain_has_skipa_rules INPUT && echo yes || echo no; _chain_has_skipa_rules DOCKER-USER && echo yes || echo no')
        self.assertEqual(r.stdout.split(), ["yes", "no"])

    def test_confirm(self):
        for answer, expected in (("y\n", "0"), ("д\n", "0"), ("n\n", "1"), ("\n", "1"), ("", "1")):
            r, _ = run('confirm "Точно?" >/dev/null; echo $?', stdin=answer)
            self.assertEqual(r.stdout.strip().splitlines()[-1], expected, repr(answer))

    def test_single_config_get_set(self):
        r, inst = run(
            'cp "$INSTALL_DIR/config.example.yaml" "$SERVICE_CONF"\n'
            '_service_conf_get ACTIVE_LIST\n_service_conf_set ACTIVE_LIST list2\n_service_conf_get ACTIVE_LIST\n'
            '_service_conf_get ACTION_MODE\n_set_yaml_scalar "$SERVICE_CONF" chat_id 123\n'
            'yaml_get "$SERVICE_CONF" telegram.chat_id'
        )
        self.assertEqual(r.stdout.split(), ["merged", "list2", "block_notify", "123"], r.stderr)

    def test_legacy_service_conf_migrates_into_config_yaml(self):
        r, inst = run(
            'cat > "$INSTALL_DIR/service.conf" <<EOF\n'
            'ACTION_MODE="block"\nACTIVE_LIST="list1"\nUPDATE_INTERVAL_DAYS=3\nIGNORE_IPS="1.2.3.4 5.6.7.0/24"\nBLACKLIST_URL=""\nEOF\n'
            '_migrate_legacy_service_conf\n'
            '_service_conf_get ACTION_MODE; _service_conf_get ACTIVE_LIST; _service_conf_get UPDATE_INTERVAL_DAYS\n'
            'yaml_list "$SERVICE_CONF" monitoring.ignore_ips; yaml_get "$SERVICE_CONF" sources.blacklist_url | wc -c\n'
            '[ -f "$INSTALL_DIR/service.conf.migrated" ] && echo migrated_ok\n'
            '[ ! -f "$INSTALL_DIR/service.conf" ] && echo old_gone\n'
            'stat -c "mode=%a" "$SERVICE_CONF"'
        )
        out = r.stdout.split("\n")
        self.assertIn("block", out)
        self.assertIn("list1", out)
        self.assertIn("3", out)
        self.assertIn("1.2.3.4", out)
        self.assertIn("5.6.7.0/24", out)
        self.assertIn("migrated_ok", out)
        self.assertIn("old_gone", out)
        self.assertIn("mode=600", out)


if __name__ == "__main__":
    unittest.main()
