"""Паритет панели, бота и сервиса: общий редактор конфига, белый список, настройки, логи."""
import asyncio
import importlib.util
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
CONFCTL = ROOT / "service" / "confctl.sh"
BLOCKCTL = ROOT / "service" / "blockctl.sh"
HAVE_PTB = importlib.util.find_spec("telegram") is not None
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


@unittest.skipUnless(HAVE_BASH and HAVE_PTB, "нужны bash и python-telegram-bot")
class BotParityTests(_Conf):
    def setUp(self):
        super().setUp()
        from bot import confedit
        p = mock.patch.object(confedit, "CONFIG_FILE", self.conf)
        p.start()
        self.addCleanup(p.stop)

    def _update(self, args, user_id=555):
        replies = []

        async def reply(text, **kw):
            replies.append((text, kw))

        update = SimpleNamespace(
            effective_user=SimpleNamespace(id=user_id, username="admin"),
            effective_chat=SimpleNamespace(id=555),
            message=SimpleNamespace(reply_text=reply),
        )
        return update, SimpleNamespace(args=args, bot_data={}), replies

    def _cfg(self, **kw):
        from tests.helpers import make_config
        return make_config(bot_token="1:x", chat_id=555, admin_ids=[555], **kw)

    def test_allow_и_unallow_через_бота(self):
        """/allow пишет в конфиг, обновляет живой список и ipset; /unallow откатывает"""
        import ipaddress
        from bot import banning, blocker, telegram_layer
        cfg = self._cfg()
        synced = []
        update, ctx, replies = self._update(["203.0.113.5"])
        ctx.bot_data["config"] = cfg
        with mock.patch.object(blocker, "sync_allowlist", lambda nets: synced.append(list(nets)) or True), \
             mock.patch.object(blocker, "is_blocked", return_value=True), \
             mock.patch.object(banning, "unban_ip", mock.AsyncMock(return_value=True)) as unban:
            asyncio.run(telegram_layer.cmd_allow(update, ctx))
            self.assertIn(ipaddress.ip_network("203.0.113.5/32"), cfg.ignore_networks)
            self.assertIn("203.0.113.5", self.ctl("ignore-list").stdout)
            self.assertTrue(synced and any(str(n) == "203.0.113.5/32" for n in synced[-1]))
            unban.assert_awaited_once()
            self.assertIn("Блокировка снята", replies[-1][0])
            asyncio.run(telegram_layer.cmd_unallow(update, ctx))
        self.assertNotIn(ipaddress.ip_network("203.0.113.5/32"), cfg.ignore_networks)
        self.assertNotIn("203.0.113.5", self.ctl("ignore-list").stdout)

    def test_allow_отклоняет_мусор_и_чужих(self):
        """некорректный адрес и не-администратор ничего не меняют"""
        from bot import telegram_layer
        cfg = self._cfg()
        update, ctx, replies = self._update(["не-ip"])
        ctx.bot_data["config"] = cfg
        asyncio.run(telegram_layer.cmd_allow(update, ctx))
        self.assertIn("Использование", replies[-1][0])
        stranger, ctx2, replies2 = self._update(["203.0.113.5"], user_id=999)
        ctx2.bot_data["config"] = cfg
        asyncio.run(telegram_layer.cmd_allow(stranger, ctx2))
        self.assertEqual(self.ctl("ignore-list").stdout.strip(), "")

    def test_настройки_два_шага_и_перезапуск(self):
        """cfg:ask просит подтверждения, cfg:do пишет значение и перезапускает службу"""
        from bot import confedit, telegram_layer
        cfg = self._cfg()
        replies = []

        async def reply(text, **kw):
            replies.append((text, kw))

        async def answer(*a, **k):
            return None

        def query(data):
            return SimpleNamespace(data=data, from_user=SimpleNamespace(id=555), answer=answer,
                                   message=SimpleNamespace(chat=SimpleNamespace(id=555), reply_text=reply))

        ctx = SimpleNamespace(bot_data={"config": cfg})
        restarted = []

        async def fake_restart():
            restarted.append(1)
            return True, "ok"

        with mock.patch.object(confedit, "restart_service", fake_restart):
            asyncio.run(telegram_layer.on_settings_callback(SimpleNamespace(callback_query=query("cfg:ask:action.mode:notify")), ctx))
            self.assertIn("Изменить", replies[-1][0])
            self.assertEqual(self.ctl("get", "action.mode").stdout.strip(), "block_notify")    # пока без изменений
            asyncio.run(telegram_layer.on_settings_callback(SimpleNamespace(callback_query=query("cfg:do:action.mode:notify")), ctx))
            self.assertEqual(self.ctl("get", "action.mode").stdout.strip(), "notify")
            self.assertEqual(restarted, [1])
            # недопустимое значение и ключ игнорируются
            n = len(replies)
            asyncio.run(telegram_layer.on_settings_callback(SimpleNamespace(callback_query=query("cfg:do:action.mode:rm -rf")), ctx))
            asyncio.run(telegram_layer.on_settings_callback(SimpleNamespace(callback_query=query("cfg:do:telegram.bot_token:x")), ctx))
            self.assertEqual(len(replies), n)
            self.assertEqual(self.ctl("get", "action.mode").stdout.strip(), "notify")

    def test_logs_скрывает_токен_и_ограничивает_длину(self):
        """/logs не выдаёт токен бота и укладывается в лимит сообщения"""
        from bot import telegram_layer
        log_dir = self.d / "log"
        log_dir.mkdir()
        token = "123456789:" + "A" * 35
        (log_dir / "skipa-watchdog.log").write_text(
            "\n".join([f"строка {i} " + "x" * 80 for i in range(200)] + [f"token={token}"]), encoding="utf-8")
        cfg = self._cfg(log_dir=str(log_dir))
        update, ctx, replies = self._update(["100"])
        ctx.bot_data["config"] = cfg
        asyncio.run(telegram_layer.cmd_logs(update, ctx))
        text = replies[-1][0]
        self.assertNotIn(token, text)
        self.assertIn("токен скрыт", text)
        self.assertLessEqual(len(text), 3600)


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


@unittest.skipUnless(HAVE_BASH and HAVE_PTB, "нужны bash и python-telegram-bot")
class CliTests(unittest.TestCase):
    def test_block_проверяет_цель_и_часы(self):
        """bot.cli block: служебные адреса и кривые часы отклоняются, нормальный вызов доходит до blocker"""
        from bot import blocker, cli
        with mock.patch.object(blocker, "block_ip", return_value=True) as block:
            self.assertEqual(cli.cmd_block("10.0.0.5", None), 1)
            self.assertEqual(cli.cmd_block("8.8.8.8", "-1"), 1)
            self.assertEqual(cli.cmd_block("8.8.8.8", "inf"), 1)
            block.assert_not_called()
            self.assertEqual(cli.cmd_block("8.8.8.8", "2"), 0)
            block.assert_called_once_with("8.8.8.8", 7200)
            self.assertEqual(cli.cmd_block("8.8.4.4", None), 0)
            self.assertEqual(block.call_args.args, ("8.8.4.4", 0))

    def test_unblock_идёт_через_banning(self):
        """bot.cli unblock делает то же, что /unblock в боте: unban_ip с jail из конфига"""
        from bot import banning, cli
        from tests.helpers import make_config
        with mock.patch.object(cli, "_config", return_value=make_config(fail2ban_jail="sshd")), \
             mock.patch.object(banning, "unban_ip", mock.AsyncMock(return_value=True)) as unban:
            self.assertEqual(cli.cmd_unblock("8.8.8.8"), 0)
            unban.assert_awaited_once_with("8.8.8.8", fail2ban_jail="sshd", by="panel")

    def test_main_без_аргументов_показывает_справку(self):
        """неизвестная команда - код 1"""
        from bot import cli
        self.assertEqual(cli.main([]), 1)
        self.assertEqual(cli.main(["что-то"]), 1)


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

    def test_белый_список_в_режиме_бота_правит_конфиг(self):
        """в режиме с Python панель правит тот же config.yaml через confctl.sh (без ipset)"""
        (self.inst / ".install_mode").write_text("bot\n", encoding="utf-8")
        script = (f'source "{ROOT / "install.sh"}"; pause() {{ :; }}; restart_if_running() {{ echo RESTART; }}; '
                  'allowlist_menu')
        r = subprocess.run(["bash", "-c", script], input="1\n198.51.100.0/24\n1\n198.51.100.0/24\n0\n",
                           capture_output=True, text=True, env=self.env, timeout=60)
        self.assertIn('ignore_ips: ["198.51.100.0/24"]', (self.inst / "config.yaml").read_text(encoding="utf-8"))
        self.assertEqual(r.stdout.count("RESTART"), 1)             # второй раз - «уже в списке», без перезапуска
        self.assertIn("Уже в белом списке", r.stdout)
        self.assertFalse((self.d / "ipset.log").exists())

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
