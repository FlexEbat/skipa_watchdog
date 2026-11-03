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
            '_service_conf_get ACTION_MODE\n_set_yaml_scalar "$SERVICE_CONF" telegram.chat_id 123\n'
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
class MigrationAndNotifyMenuTests(unittest.TestCase):
    """переход с Python-бота на bash, меню уведомлений, отсутствие ручной блокировки"""

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


    def _conf_after(self, script, stdin=""):
        r, _, _ = self._run('cp "$INSTALL_DIR/config.example.yaml" "$SERVICE_CONF"\n' + script +
                            '\n_conf_lib; for k in telegram.bot_token telegram.chat_id matrix.homeserver matrix.access_token matrix.room_id; '
                            'do echo "$k=$(yaml_get "$SERVICE_CONF" $k)"; done', stdin=stdin)
        out = dict(line.split("=", 1) for line in r.stdout.splitlines() if "=" in line and line.split("=")[0].count(".") == 1)
        return r, out

    def test_telegram_сохраняется_только_после_проверки(self):
        """мусор вместо токена или chat_id не попадает в config.yaml, нормальные значения - попадают"""
        r, out = self._conf_after("configure_telegram", 'bad"token\n5\n')
        self.assertEqual(out["telegram.bot_token"], "")
        r, out = self._conf_after("configure_telegram", "123456:ABC-def\nabc\n")
        self.assertEqual(out["telegram.bot_token"], "")
        r, out = self._conf_after("configure_telegram", "123456:ABC-def\n-100123\nn\n")
        self.assertEqual((out["telegram.bot_token"], out["telegram.chat_id"]), ("123456:ABC-def", "-100123"))
        r, out = self._conf_after("configure_telegram", "0\n")
        self.assertEqual(out["telegram.bot_token"], "")
        self.assertIn("Отменено", r.stdout)

    def test_matrix_сохраняется_только_после_проверки(self):
        """homeserver только https, room_id - идентификатор; токен не печатается на экран"""
        r, out = self._conf_after("configure_matrix", "http://matrix.example.org\ntok\n!a:example.org\n")
        self.assertEqual(out["matrix.access_token"], "")
        r, out = self._conf_after("configure_matrix", "https://matrix.example.org\ntok\n#alias:example.org\n")
        self.assertEqual(out["matrix.room_id"], "")
        r, out = self._conf_after("configure_matrix", "https://matrix.example.org/\nsyt_secret\n!room:example.org\nn\n")
        self.assertEqual((out["matrix.homeserver"], out["matrix.access_token"], out["matrix.room_id"]),
                         ("https://matrix.example.org", "syt_secret", "!room:example.org"))
        self.assertNotIn("syt_secret", r.stdout.split("telegram.bot_token=")[0])      # ввод токена не показывается на экране

    def test_отключение_канала_очищает_секрет(self):
        """disable_channel убирает токен из config.yaml"""
        r, out = self._conf_after('configure_telegram <<< $\'123456:ABC-def\\n-100123\\nn\\n\'; disable_channel telegram')
        self.assertEqual((out["telegram.bot_token"], out["telegram.chat_id"]), ("", "0"))

    def test_включение_канала_при_режиме_block_предлагает_block_notify(self):
        """в режиме 'block' демон уведомлений не запущен: меню предлагает включить block_notify"""
        r, _, _ = self._run('cp "$INSTALL_DIR/config.example.yaml" "$SERVICE_CONF"; _service_conf_set ACTION_MODE block\n'
                            '_after_notify_change; _service_conf_get ACTION_MODE', stdin="y\nn\n")
        self.assertEqual(r.stdout.strip().splitlines()[-1], "block_notify")
        r, _, _ = self._run('cp "$INSTALL_DIR/config.example.yaml" "$SERVICE_CONF"; _service_conf_set ACTION_MODE block\n'
                            '_after_notify_change; _service_conf_get ACTION_MODE', stdin="n\nn\n")
        self.assertEqual(r.stdout.strip().splitlines()[-1], "block")

    def test_прежний_python_вариант_распознаётся(self):
        """метка bot или юнит skipa-watchdog.service - признак прежнего Python-бота"""
        r, _, _ = self._run('_has_legacy_bot && echo yes || echo no', mode="bot")
        self.assertEqual(r.stdout.strip(), "yes")
        r, _, _ = self._run('SYSTEMD_DIR="$INSTALL_DIR/units"; mkdir -p "$SYSTEMD_DIR"; _has_legacy_bot && echo yes || echo no', mode="service")
        self.assertEqual(r.stdout.strip(), "no")
        r, _, _ = self._run('SYSTEMD_DIR="$INSTALL_DIR/units"; mkdir -p "$SYSTEMD_DIR"; touch "$SYSTEMD_DIR/skipa-watchdog.service"; '
                            '_has_legacy_bot && echo yes || echo no', mode="service")
        self.assertEqual(r.stdout.strip(), "yes")

    def test_остатки_python_убираются(self):
        """venv и каталог bot/ (не из git) удаляются, config.yaml и data/ остаются"""
        r, _, _ = self._run('mkdir -p "$INSTALL_DIR/venv/bin" "$INSTALL_DIR/bot/__pycache__" "$INSTALL_DIR/data"\n'
                            'touch "$INSTALL_DIR/config.yaml" "$INSTALL_DIR/data/blocked_ips.json"\n'
                            '_cleanup_python_leftovers; ls "$INSTALL_DIR" | sort | tr "\\n" " "')
        out = r.stdout.strip().splitlines()[-1]                      # последняя строка - ls каталога
        self.assertNotIn("venv", out.split())
        self.assertNotIn("bot", out.split())
        self.assertIn("config.yaml", out)
        self.assertIn("data", out)

    def test_в_установщике_нет_ссылок_на_python(self):
        """install.sh не вызывает python/pip/venv и не знает про watchdog.py"""
        text = (ROOT / "install.sh").read_text(encoding="utf-8")
        for bad in ("pip install", "python3 -m venv", "ensure_venv", "watchdog.py", "requirements"):
            self.assertNotIn(bad, text, bad)
