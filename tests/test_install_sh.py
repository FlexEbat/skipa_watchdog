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
        """проверка правил узнаёт текущую форму правил и не падает по SIGPIPE"""
        r, _ = run('_chain_has_skipa_rules INPUT && echo yes || echo no; _chain_has_skipa_rules DOCKER-USER && echo yes || echo no')
        self.assertEqual(r.stdout.split(), ["yes", "no"])

    def test_confirm(self):
        """подтверждение принимает y и д, остальное считает отказом"""
        for answer, expected in (("y\n", "0"), ("д\n", "0"), ("n\n", "1"), ("\n", "1"), ("", "1")):
            r, _ = run('confirm "Точно?" >/dev/null; echo $?', stdin=answer)
            self.assertEqual(r.stdout.strip().splitlines()[-1], expected, repr(answer))

    def test_single_config_get_set(self):
        """чтение и запись единого config.yaml из install.sh"""
        r, inst = run(
            'cp "$INSTALL_DIR/config.example.yaml" "$SERVICE_CONF"\n'
            '_service_conf_get ACTIVE_LIST\n_service_conf_set ACTIVE_LIST list2\n_service_conf_get ACTIVE_LIST\n'
            '_service_conf_get ACTION_MODE\n_set_yaml_scalar "$SERVICE_CONF" chat_id 123\n'
            'yaml_get "$SERVICE_CONF" telegram.chat_id'
        )
        self.assertEqual(r.stdout.split(), ["merged", "list2", "block_notify", "123"], r.stderr)

    def test_legacy_service_conf_migrates_into_config_yaml(self):
        """старый service.conf переносится в config.yaml"""
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


@unittest.skipUnless(shutil.which("git") and shutil.which("bash"), "нужны git и bash")
class UpdateRepoTests(unittest.TestCase):
    def _git(self, cwd, *args):
        env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}
        subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, env=env)

    def _scenario(self, answer):
        """Клон отстаёт от origin, а история origin переписана: быстрое обновление невозможно."""
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            origin, clone = d / "origin", d / "clone"
            origin.mkdir()
            self._git(origin, "init", "-q", "-b", "main")
            (origin / "a.txt").write_text("1\n")
            self._git(origin, "add", "."); self._git(origin, "commit", "-q", "-m", "one")
            subprocess.run(["git", "clone", "-q", str(origin), str(clone)], check=True, capture_output=True)
            (clone / "config.yaml").write_text("секрет\n")                     # не отслеживается git
            (origin / "a.txt").write_text("2\n")                                 # переписываем историю origin
            self._git(origin, "add", "."); self._git(origin, "commit", "-q", "--amend", "-m", "one (переписан)")
            r = subprocess.run(
                ["bash", "-c", f'source "{ROOT / "install.sh"}"\n_update_repo "{clone}" >/dev/null 2>&1; cat "{clone}/a.txt"; cat "{clone}/config.yaml"'],
                input=answer, capture_output=True, text=True, timeout=30, env={**os.environ, "SKIPA_SOURCE_ONLY": "1"},
            )
            return r.stdout.split()

    def test_rewritten_history_is_handled_after_confirmation(self):
        """после переписанной истории origin обновление идёт только с подтверждением и не трогает config.yaml"""
        self.assertEqual(self._scenario("y\n"), ["2", "секрет"])
        self.assertEqual(self._scenario("n\n"), ["1", "секрет"])
        self.assertEqual(self._scenario(""), ["1", "секрет"])       # без терминала: ничего не сбрасываем


@unittest.skipUnless(shutil.which("bash"), "нужен bash")
class MonitoringMethodMenuTests(unittest.TestCase):
    def _run(self, answers, mode="bot"):
        r, _ = run(
            'cp "$INSTALL_DIR/config.example.yaml" "$SERVICE_CONF"\n'
            f'echo {mode} > "$INSTALL_MODE_FILE"\n'
            f'printf "%b" "{answers}" | select_monitoring_method >/dev/null 2>&1\n'
            '_conf_lib; yaml_get "$SERVICE_CONF" monitoring.method; yaml_get "$SERVICE_CONF" monitoring.poll_interval_seconds'
        )
        return r.stdout.split()

    def test_method_changes_only_after_confirmation(self):
        """метод обнаружения меняется только после подтверждения и не трогает соседние ключи"""
        self.assertEqual(self._run("2\\ny\\n\\n"), ["kernel_log", "5"])
        self.assertEqual(self._run("1\\nn\\n\\n"), ["both", "5"])      # отказ: значение по умолчанию
        self.assertEqual(self._run("0\\n"), ["both", "5"])             # выход без изменений
        self.assertEqual(self._run("9\\n"), ["both", "5"])             # неизвестный пункт
        self.assertEqual(self._run("1\\ny\\n\\n", mode="service"), ["poll", "5"])


FAKE_IPTABLES_STATEFUL = """#!/usr/bin/env bash
# запоминает вызовы; переход `-j SKIPA-BLOCK` считается стоящим один раз в каждой цепочке
args=("$@"); [ "${args[0]}" = "-w" ] && args=("${args[@]:2}")
echo "${args[*]}" >> "$FAKE_LOG"
case "${args[0]}" in
  -L) exit 0;;
  -C) if [ "${args[2]}" = "-j" ] && [ "${args[3]}" = "SKIPA-BLOCK" ] && [ ! -e "$FAKE_LOG.del.${args[1]}" ]; then exit 0; fi; exit 1;;
  -D) touch "$FAKE_LOG.del.${args[1]}"; exit 0;;
  *) exit 0;;
esac
"""


@unittest.skipUnless(shutil.which("bash"), "нужен bash")
class ModeSwitchTests(unittest.TestCase):
    """переключение режимов на лету и отсутствие ручной блокировки в режиме «только сервис»"""

    def _run(self, script: str, stdin: str = "", mode: str = "service", fake_ipt: bool = False):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            (d / "bin").mkdir()
            log = d / "ipt.log"
            ipt = d / "bin" / "iptables"
            ipt.write_text(FAKE_IPTABLES_STATEFUL if fake_ipt else FAKE_IPTABLES)
            ipt.chmod(ipt.stat().st_mode | stat.S_IXUSR)
            inst = d / "inst"
            shutil.copytree(ROOT / "service", inst / "service")
            shutil.copy(ROOT / "config.example.yaml", inst / "config.example.yaml")
            (inst / "data").mkdir()
            if mode:
                (inst / ".install_mode").write_text(mode + "\n")
            env = {**os.environ, "PATH": f"{d / 'bin'}:{os.environ['PATH']}", "SKIPA_SOURCE_ONLY": "1",
                   "SKIPA_INSTALL_DIR": str(inst), "SKIPA_LOG_DIR": str(d / "log"), "FAKE_LOG": str(log)}
            r = subprocess.run(["bash", "-c", f'source "{ROOT / "install.sh"}"\n{script}'], input=stdin,
                               capture_output=True, text=True, env=env, timeout=30, cwd=d)
            mode_after = (inst / ".install_mode").read_text().strip() if (inst / ".install_mode").exists() else ""
            return r, mode_after, (log.read_text() if log.exists() else "")

    def test_в_сервис_режиме_меню_блокировок_только_просмотр(self):
        """пункт 6 в режиме «только сервис» ничего не спрашивает про блокировку/разблокировку"""
        r, _, _ = self._run("blocklist_menu", stdin="\n")
        out = r.stdout
        self.assertIn("только просмотр", out)
        self.assertIn("белый список", out)
        self.assertNotIn("Заблокировать IP вручную", out)
        self.assertNotIn("Разблокировать IP", out)

    def test_в_варианте_с_ботом_ручная_блокировка_остаётся(self):
        """в варианте с Telegram пункты блокировки/разблокировки на месте"""
        r, _, _ = self._run("blocklist_menu", stdin="0\n", mode="bot")
        self.assertIn("Заблокировать IP вручную", r.stdout)
        self.assertIn("Разблокировать IP", r.stdout)

    def test_меню_telegram_предлагает_переключение_только_из_бота(self):
        """из бота есть возврат на «только сервис», из сервис-режима - только подключение Telegram"""
        r, _, _ = self._run("telegram_menu", stdin="0\n", mode="bot")
        self.assertIn("Переключить на 'только сервис'", r.stdout)
        r, _, _ = self._run("telegram_menu", stdin="0\n", mode="service")
        self.assertNotIn("Переключить на 'только сервис'", r.stdout)
        self.assertIn("Подключить Telegram", r.stdout)

    def test_переключение_в_сервис_режиме_ничего_не_делает(self):
        """switch_to_service в режиме «только сервис» только предупреждает"""
        r, mode_after, _ = self._run("switch_to_service", mode="service")
        self.assertIn("Уже режим", r.stdout)
        self.assertEqual(mode_after, "service")

    def test_отказ_от_переключения_ничего_не_меняет(self):
        """без подтверждения режим остаётся «bot»"""
        r, mode_after, _ = self._run("switch_to_service", stdin="n\n", mode="bot")
        self.assertIn("Отменено", r.stdout)
        self.assertEqual(mode_after, "bot")

    def test_переносятся_только_бессрочные_блокировки_бота(self):
        """из data/blocked_ips.json берутся записи с нулевым сроком, блокировки на срок - нет"""
        script = (
            'cat > "$INSTALL_DIR/data/blocked_ips.json" <<EOF\n'
            '{\n "ips": {\n  "1.2.3.4": 0.0,\n  "5.6.7.0/24": 0.0,\n  "9.9.9.9": 1893456000.5\n }\n}\nEOF\n'
            '_collect_bot_blocks | sort'
        )
        r, _, _ = self._run(script, mode="bot")
        self.assertEqual(r.stdout.split(), ["1.2.3.4", "5.6.7.0/24"], r.stderr)

    def test_удаление_python_правил_не_трогает_правила_сервис_режима(self):
        """убираются только переходы в SKIPA-BLOCK и сама цепочка; ничего про skipa-scanners не удаляется"""
        _, _, log = self._run("_remove_bot_firewall_rules", mode="bot", fake_ipt=True)
        lines = log.splitlines()
        self.assertIn("-D INPUT -j SKIPA-BLOCK", lines)
        self.assertIn("-F SKIPA-BLOCK", lines)
        self.assertIn("-X SKIPA-BLOCK", lines)
        self.assertFalse([x for x in lines if "skipa-scanners" in x or "skipa-manual" in x], lines)
        self.assertFalse([x for x in lines if x.startswith("-D") and "SKIPA-BLOCK" not in x], lines)

    def test_в_документах_нет_ручной_блокировки_для_сервис_режима(self):
        """справка blockctl.sh не обещает block/unblock"""
        text = (ROOT / "service" / "blockctl.sh").read_text(encoding="utf-8")
        self.assertIn("{list|allow|unallow|allowlist|import-blocks}", text)

    def test_версия_установщика_совпадает_с_VERSION(self):
        """INSTALLER_VERSION не отстаёт от файла VERSION (раньше застряла на 3.0.0)"""
        import re
        text = (ROOT / "install.sh").read_text(encoding="utf-8")
        m = re.search(r'^INSTALLER_VERSION="([^"]+)"', text, re.M)
        self.assertEqual(m.group(1), (ROOT / "VERSION").read_text(encoding="utf-8").strip())

    def test_telegram_ввод_проверяется_до_записи(self):
        """мусор вместо токена, chat_id или admin_ids не попадает в config.yaml"""
        script = 'cp "$INSTALL_DIR/config.example.yaml" "$SERVICE_CONF"; configure_telegram; grep -E "^  (bot_token|chat_id|admin_ids):" "$SERVICE_CONF"'
        r, _, _ = self._run(script, stdin='1"\nmonitoring: x\n')
        self.assertIn("на токен бота", r.stdout + r.stderr)
        r, _, _ = self._run(script, stdin="123456:ABC-def\nabc\n")
        self.assertIn("chat_id", r.stdout + r.stderr)
        r, _, _ = self._run(script, stdin="123456:ABC-def\n-100123\n1,x\n")
        self.assertIn("admin_ids", r.stdout + r.stderr)
        self.assertIn('bot_token: ""', r.stdout)                              # конфиг не изменён
        self.assertNotIn("123456:ABC-def", r.stdout)
