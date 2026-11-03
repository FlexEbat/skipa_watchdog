"""Паритет панели, бота и сервиса: общий редактор конфига, белый список, настройки, логи."""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONFCTL = ROOT / "service" / "confctl.sh"
BLOCKCTL = ROOT / "service" / "blockctl.sh"
HAVE_BASH = bool(shutil.which("bash") and shutil.which("awk"))


class _Conf(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.d = Path(self.tmp.name)
        self.conf = self.d / "config.yaml"
        shutil.copy(ROOT / "config.example.yaml", self.conf)

    def ctl(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(["bash", str(CONFCTL), str(self.conf), *args], capture_output=True, text=True, timeout=30)


@unittest.skipUnless(HAVE_BASH, "нужны bash и awk")
class ConfctlTests(_Conf):
    def test_добавление_удаление_и_повторы(self):
        """ignore-add/del: код 3 для дубля и отсутствующего, список ведётся без потерь"""
        self.assertEqual(self.ctl("ignore-add", "203.0.113.5").returncode, 0)
        self.assertEqual(self.ctl("ignore-add", "10.0.0.0/8").returncode, 0)
        self.assertEqual(self.ctl("ignore-add", "203.0.113.5").returncode, 3)
        self.assertEqual(self.ctl("ignore-list").stdout.split(), ["203.0.113.5", "10.0.0.0/8"])
        self.assertEqual(self.ctl("ignore-del", "203.0.113.5").returncode, 0)
        self.assertEqual(self.ctl("ignore-del", "198.51.100.1").returncode, 3)
        self.assertEqual(self.ctl("ignore-del", "10.0.0.0/8").returncode, 0)
        self.assertIn("ignore_ips: []", self.conf.read_text(encoding="utf-8"))

    def test_мусор_отклоняется_и_файл_не_портится(self):
        """некорректные адреса и ключи не доходят до файла"""
        before = self.conf.read_text(encoding="utf-8")
        for bad in ("999.1.1.1", "abc", "1.2.3.4/33", "1.2.3.4; rm -rf /", '"x"'):
            self.assertEqual(self.ctl("ignore-add", bad).returncode, 1, bad)
        self.assertEqual(self.ctl("set", "плохой ключ", "x").returncode, 1)
        self.assertEqual(self.ctl("set", "action.mode", "a\nb").returncode, 1)
        self.assertEqual(self.conf.read_text(encoding="utf-8"), before)

    def test_остальной_файл_и_комментарии_сохраняются(self):
        """правка списка не трогает прочие строки и комментарии"""
        self.ctl("ignore-add", "203.0.113.5")
        norm = lambda t: [l for l in t.splitlines() if "ignore_ips:" not in l]  # noqa: E731
        self.assertEqual(norm(self.conf.read_text(encoding="utf-8")),
                         norm((ROOT / "config.example.yaml").read_text(encoding="utf-8")))

    def test_set_и_get(self):
        """set/get работают с секцией.ключом"""
        self.assertEqual(self.ctl("set", "action.mode", "notify").returncode, 0)
        self.assertEqual(self.ctl("get", "action.mode").stdout.strip(), "notify")


@unittest.skipUnless(HAVE_BASH, "нужны bash и awk")
class BlockctlAllowTests(_Conf):
    def _blockctl(self, *args: str) -> subprocess.CompletedProcess:
        bindir = self.d / "bin"
        bindir.mkdir(exist_ok=True)
        ipset = bindir / "ipset"
        ipset.write_text('#!/usr/bin/env bash\necho "$@" >> "$OUT"\nexit 0\n', encoding="utf-8")
        ipset.chmod(0o755)
        env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}", OUT=str(self.d / "ipset.log"), SKIPA_CONFIG=str(self.conf))
        return subprocess.run(["bash", str(BLOCKCTL), *args], capture_output=True, text=True, env=env, timeout=30)

    def test_allow_пишет_в_конфиг_и_в_ipset(self):
        """allow: monitoring.ignore_ips + ipset skipa-allow; блокировка вручную снимается"""
        r = self._blockctl("allow", "203.0.113.5")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("203.0.113.5", self.ctl("ignore-list").stdout)
        log = (self.d / "ipset.log").read_text(encoding="utf-8")
        self.assertIn("add skipa-allow 203.0.113.5 -exist", log)
        self.assertIn("del skipa-manual 203.0.113.5 -exist", log)

    def test_unallow_и_список(self):
        """unallow убирает из конфига и ядра; allowlist показывает записи"""
        self._blockctl("allow", "203.0.113.5")
        self.assertIn("203.0.113.5", self._blockctl("allowlist").stdout)
        r = self._blockctl("unallow", "203.0.113.5")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("203.0.113.5", self.ctl("ignore-list").stdout)
        self.assertIn("del skipa-allow 203.0.113.5 -exist", (self.d / "ipset.log").read_text(encoding="utf-8"))
        self.assertNotEqual(self._blockctl("unallow", "203.0.113.5").returncode, 0)   # второй раз - такого нет

    def test_allow_некорректный_адрес(self):
        """мусор не попадает ни в конфиг, ни в ipset"""
        self.assertNotEqual(self._blockctl("allow", "не-адрес").returncode, 0)
        self.assertEqual(self.ctl("ignore-list").stdout.strip(), "")


if __name__ == "__main__":
    unittest.main()


STATS = ROOT / "service" / "stats.sh"


@unittest.skipUnless(HAVE_BASH and shutil.which("date"), "нужны bash, awk и GNU date")
class StatsScriptTests(_Conf):
    def _log(self, lines: str) -> None:
        log_dir = self.d / "log"
        log_dir.mkdir(exist_ok=True)
        (log_dir / "detections.log").write_text(lines, encoding="utf-8")
        self.conf.write_text(self.conf.read_text(encoding="utf-8").replace("/var/log/skipa_watchdog", str(log_dir)),
                             encoding="utf-8")

    def _stats(self, days: str = "7") -> str:
        r = subprocess.run(["bash", str(STATS), str(self.conf), days], capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout

    @staticmethod
    def _day(offset: int) -> str:
        import datetime
        return (datetime.date.today() - datetime.timedelta(days=offset)).isoformat()

    def test_оба_формата_журнала_и_период(self):
        """считает записи бота и bash-демона, старые записи за период не попадают"""
        self._log(
            f"===== {self._day(0)} 10:00:00 | IP=203.0.113.5 | match=Skipa: 203.0.113.0/24 =====\nтекст\n\n"
            f"===== {self._day(0)} 10:05:00 | IP=203.0.113.5 | match=Skipa: 203.0.113.0/24 =====\n\n"
            f"===== {self._day(2)} 11:00:00 | IP=198.51.100.7 | proto=tcp port=22 =====\n"
            f"===== {self._day(30)} 11:00:00 | IP=192.0.2.1 | proto=tcp port=22 =====\n"
        )
        out = self._stats("7")
        self.assertIn("3 (уникальных IP: 2)", out)
        self.assertIn("203.0.113.5", out)
        self.assertNotIn("192.0.2.1", out)
        self.assertIn("22", out)                       # топ портов
        self.assertIn("Skipa", out)                    # по спискам
        self.assertIn("4 (уникальных IP: 3)", self._stats("60"))

    def test_пустой_и_отсутствующий_журнал(self):
        """нет журнала или в нём нет записей - внятное сообщение, а не ошибка"""
        self.assertIn("пока пуст", self._stats())
        self._log("")
        self.assertIn("0 (уникальных IP: 0)", self._stats())

    def test_некорректное_число_дней_заменяется_на_7(self):
        """мусор вместо дней не ломает скрипт"""
        self._log(f"===== {self._day(0)} 10:00:00 | IP=203.0.113.5 | proto=tcp port=22 =====\n")
        self.assertIn("последние 7 дн.", self._stats("abc"))


@unittest.skipUnless(HAVE_BASH, "нужен bash")
class PanelMenusTests(_Conf):
    """allowlist_menu и view_stats из install.sh, с вводом через stdin и поддельным ipset."""

    def setUp(self):
        super().setUp()
        self.inst = self.d / "inst"
        shutil.copytree(ROOT / "service", self.inst / "service")
        shutil.copy(self.conf, self.inst / "config.yaml")
        (self.inst / ".install_mode").write_text("service\n", encoding="utf-8")
        bindir = self.d / "bin"
        bindir.mkdir()
        ipset = bindir / "ipset"
        ipset.write_text('#!/usr/bin/env bash\necho "$@" >> "$OUT"\nexit 0\n', encoding="utf-8")
        ipset.chmod(0o755)
        self.env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}", OUT=str(self.d / "ipset.log"),
                        SKIPA_SOURCE_ONLY="1", SKIPA_INSTALL_DIR=str(self.inst), SKIPA_NO_UPDATE_CHECK="1")

    def _panel(self, function: str, user_input: str) -> subprocess.CompletedProcess:
        script = f'source "{ROOT / "install.sh"}"; pause() {{ :; }}; {function}'
        return subprocess.run(["bash", "-c", script], input=user_input, capture_output=True, text=True,
                              env=self.env, timeout=60)

    def test_белый_список_в_сервисном_режиме(self):
        """пункт меню «Белый список»: добавление и удаление пишут в конфиг и в ipset"""
        r = self._panel("allowlist_menu", "1\n203.0.113.5\n2\n203.0.113.5\n0\n")
        self.assertEqual(r.returncode, 0, r.stderr)
        log = (self.d / "ipset.log").read_text(encoding="utf-8")
        self.assertIn("add skipa-allow 203.0.113.5 -exist", log)
        self.assertIn("del skipa-allow 203.0.113.5 -exist", log)
        self.assertIn("203.0.113.5", r.stdout)                     # список показан после добавления
        self.assertIn("ignore_ips: []", (self.inst / "config.yaml").read_text(encoding="utf-8"))

    def test_статистика_из_панели(self):
        """пункт меню «Статистика детектов» вызывает stats.sh с выбранным периодом"""
        import datetime
        log_dir = self.d / "log"
        log_dir.mkdir()
        day = datetime.date.today().isoformat()
        (log_dir / "detections.log").write_text(
            f"===== {day} 10:00:00 | IP=203.0.113.5 | proto=tcp port=22 =====\n", encoding="utf-8")
        cfg = self.inst / "config.yaml"
        cfg.write_text(cfg.read_text(encoding="utf-8").replace("/var/log/skipa_watchdog", str(log_dir)), encoding="utf-8")
        r = self._panel("view_stats", "3\n")
        self.assertIn("последние 3 дн.: 1", r.stdout)
        r = self._panel("view_stats", "abc\n")
        self.assertIn("целое число дней", r.stdout)

    def test_пункты_меню_присутствуют_и_ведут_к_функциям(self):
        """в главном меню есть новые пункты и они связаны с функциями"""
        text = (ROOT / "install.sh").read_text(encoding="utf-8")
        for needle in ('7) allowlist_menu ;;', '8) view_stats ;;', '12) update_project ;;', '13) do_uninstall; pause ;;'):
            self.assertIn(needle, text)


@unittest.skipUnless(HAVE_BASH, "нужен bash")
class ListUpdateCheckUsesConfigTests(_Conf):
    def test_проверка_списков_берёт_адреса_из_конфига(self):
        """check_list_updates качает именно настроенные источники; пустой blacklist_url - не качает"""
        inst = self.d / "inst"
        shutil.copytree(ROOT / "service", inst / "service")
        text = self.conf.read_text(encoding="utf-8")
        import re
        text = re.sub(r'(?m)^  primary_list_url:.*$', '  primary_list_url: "https://example.org/my-list.txt"', text)
        text = re.sub(r'(?m)^  blacklist_url:.*$', '  blacklist_url: ""', text)
        (inst / "config.yaml").write_text(text, encoding="utf-8")
        bindir = self.d / "bin"
        bindir.mkdir()
        for name, body in (("curl", 'echo "$@" >> "$OUT"; echo data'), ("sha256sum", "cat; echo")):
            f = bindir / name
            f.write_text("#!/usr/bin/env bash\n" + body + "\n", encoding="utf-8")
            f.chmod(0o755)
        env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}", OUT=str(self.d / "curl.log"),
                   SKIPA_SOURCE_ONLY="1", SKIPA_INSTALL_DIR=str(inst))
        script = f'source "{ROOT / "install.sh"}"; LIST_HASH_STATE="{self.d}/hashes.env"; check_list_updates'
        r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        calls = (self.d / "curl.log").read_text(encoding="utf-8")
        self.assertIn("https://example.org/my-list.txt", calls)
        self.assertNotIn("gist.githubusercontent.com", calls)
        self.assertEqual(len(calls.strip().splitlines()), 1)
