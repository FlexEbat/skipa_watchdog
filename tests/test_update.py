"""Проверка обновлений при запуске: bash (панель, сервис), Python (бот), кнопки в Telegram."""
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
LIB_UPDATE = ROOT / "service" / "lib-update.sh"
HAVE_PTB = importlib.util.find_spec("telegram") is not None


def git(cwd: Path, *args: str) -> str:
    env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t", GIT_COMMITTER_NAME="t",
               GIT_COMMITTER_EMAIL="t@t", GIT_CONFIG_GLOBAL="/dev/null")
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=True, env=env).stdout


@unittest.skipUnless(shutil.which("git") and shutil.which("bash"), "нужны git и bash")
class _Repos(unittest.TestCase):
    """Bare-origin + клон (как каталог установки) + второй клон, из которого «выпускаем» версии."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        d = Path(self.tmp.name)
        self.origin, self.install, self.dev = d / "origin.git", d / "install", d / "dev"
        git(d, "init", "-q", "--bare", "-b", "main", str(self.origin))
        git(d, "clone", "-q", str(self.origin), str(self.dev))
        (self.dev / "VERSION").write_text("1.0.0\n")
        (self.dev / "service").mkdir()
        shutil.copy(LIB_UPDATE, self.dev / "service" / "lib-update.sh")
        git(self.dev, "add", "-A")
        git(self.dev, "commit", "-q", "-m", "v1.0.0")
        git(self.dev, "push", "-q", "origin", "main")
        git(d, "clone", "-q", str(self.origin), str(self.install))

    def release(self, version: str, message: str = "новая версия") -> None:
        (self.dev / "VERSION").write_text(version + "\n")
        git(self.dev, "commit", "-q", "-am", f"{message} {version}")
        git(self.dev, "push", "-q", "origin", "main")

    def bash_check(self, directory: Path, extra_env: dict | None = None) -> dict:
        env = dict(os.environ, GIT_CONFIG_GLOBAL="/dev/null")
        env.pop("SKIPA_NO_UPDATE_CHECK", None)
        env.update(extra_env or {})
        script = (f'source "{LIB_UPDATE}"; update_check "{directory}"; '
                  'printf "%s|%s|%s|%s\\n" "$UPD_STATE" "$UPD_LOCAL" "$UPD_REMOTE" "$UPD_BEHIND"; printf "%s" "$UPD_LOG"')
        out = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env, timeout=60).stdout
        head, _, log = out.partition("\n")
        state, local, remote, behind = head.split("|")
        return {"state": state, "local": local, "remote": remote, "behind": int(behind), "log": log}


class BashUpdateCheckTests(_Repos):
    def test_актуальная_версия(self):
        """без новых коммитов состояние none"""
        r = self.bash_check(self.install)
        self.assertEqual((r["state"], r["local"], r["behind"]), ("none", "1.0.0", 0))

    def test_обнаруживает_новую_версию(self):
        """новый коммит в origin: available, версии и список коммитов"""
        self.release("1.1.0", "добавили фичу")
        r = self.bash_check(self.install)
        self.assertEqual((r["state"], r["local"], r["remote"], r["behind"]), ("available", "1.0.0", "1.1.0", 1))
        self.assertIn("добавили фичу", r["log"])

    def test_проверку_можно_отключить(self):
        """SKIPA_NO_UPDATE_CHECK=1 - молча unknown, без обращения к сети"""
        self.release("1.1.0")
        self.assertEqual(self.bash_check(self.install, {"SKIPA_NO_UPDATE_CHECK": "1"})["state"], "unknown")

    def test_не_git_каталог_и_нет_сети_не_ломают(self):
        """каталог без .git и недоступный origin дают unknown, а не ошибку"""
        self.assertEqual(self.bash_check(Path(self.tmp.name))["state"], "unknown")
        git(self.install, "remote", "set-url", "origin", "/нет/такого/репозитория")
        self.assertEqual(self.bash_check(self.install)["state"], "unknown")


class PanelPromptTests(_Repos):
    def _panel(self, answer: str) -> subprocess.CompletedProcess:
        """Запускает offer_project_update из install.sh с подменёнными confirm/do_install."""
        script = (
            f'export SKIPA_SOURCE_ONLY=1 SKIPA_INSTALL_DIR="{self.install}" GIT_CONFIG_GLOBAL=/dev/null\n'
            f'source "{ROOT / "install.sh"}"\n'
            f'confirm() {{ echo "ВОПРОС: $1"; [ "{answer}" = yes ]; }}\n'
            'do_install() { echo "УСТАНОВКА ЗАПУЩЕНА"; return 0; }\n'
            'offer_project_update\n'
            'echo "СОСТОЯНИЕ=$UPD_STATE"\n'
            'print_header\n'
        )
        return subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=60)

    def test_предлагает_установить_и_устанавливает(self):
        """при согласии вызывается установка"""
        self.release("1.2.0")
        r = self._panel("yes")
        self.assertIn("Доступна новая версия", r.stdout)
        self.assertIn("1.0.0 -> 1.2.0", r.stdout)
        self.assertIn("ВОПРОС: Установить обновление сейчас?", r.stdout)
        self.assertIn("УСТАНОВКА ЗАПУЩЕНА", r.stdout)

    def test_отказ_оставляет_напоминание_в_шапке(self):
        """при отказе установка не запускается, а шапка меню напоминает об обновлении"""
        self.release("1.2.0")
        r = self._panel("no")
        self.assertNotIn("УСТАНОВКА ЗАПУЩЕНА", r.stdout)
        self.assertIn("СОСТОЯНИЕ=available", r.stdout)
        self.assertIn("Доступна версия 1.2.0", r.stdout)

    def test_без_обновления_ничего_не_спрашивает(self):
        """актуальная версия: вопроса нет"""
        r = self._panel("yes")
        self.assertNotIn("ВОПРОС", r.stdout)


class PythonUpdaterTests(_Repos):
    def test_check_update(self):
        """check_update возвращает версии и коммиты, а при актуальной версии - None"""
        from bot import updater
        with mock.patch.dict(os.environ, {"GIT_CONFIG_GLOBAL": "/dev/null"}):
            os.environ.pop("SKIPA_NO_UPDATE_CHECK", None)
            self.assertIsNone(asyncio.run(updater.check_update(self.install)))
            self.release("1.3.0", "важное")
            info = asyncio.run(updater.check_update(self.install))
        self.assertEqual((info.local, info.remote, info.behind), ("1.0.0", "1.3.0", 1))
        self.assertTrue(any("важное" in c for c in info.commits))
        self.assertIn("1.0.0", updater.format_update_text(info))

    def test_отключение_и_не_клон(self):
        """SKIPA_NO_UPDATE_CHECK=1 и каталог без .git дают None"""
        from bot import updater
        self.release("1.3.0")
        with mock.patch.dict(os.environ, {"SKIPA_NO_UPDATE_CHECK": "1"}):
            self.assertIsNone(asyncio.run(updater.check_update(self.install)))
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SKIPA_NO_UPDATE_CHECK", None)
            self.assertIsNone(asyncio.run(updater.check_update(Path(self.tmp.name))))

    def test_итог_обновления_после_перезапуска(self):
        """после рестарта бот сообщает: обновилось или версия не изменилась"""
        from bot import updater
        pending = Path(self.tmp.name) / "pending.json"
        info = updater.UpdateInfo(local="1.0.0", remote="1.1.0", behind=1)
        with mock.patch.object(updater, "PENDING_FILE", pending):
            updater.mark_pending(info)
            (self.install / "VERSION").write_text("1.1.0\n")
            self.assertIn("✅", updater.take_pending_result(self.install))
            self.assertIsNone(updater.take_pending_result(self.install))   # отметка снята
            updater.mark_pending(info)
            (self.install / "VERSION").write_text("1.0.0\n")
            self.assertIn("не применилось", updater.take_pending_result(self.install))

    def test_запуск_через_systemd_run(self):
        """обновление уходит отдельным юнитом, а без systemd-run - понятный отказ"""
        from bot import updater
        info = updater.UpdateInfo(local="1.0.0", remote="1.1.0", behind=1)
        pending = Path(self.tmp.name) / "pending.json"
        calls = []

        class FakeProc:
            returncode = 0
            async def communicate(self):
                return b"", b""

        async def fake_exec(*cmd, **kw):
            calls.append(cmd)
            return FakeProc()

        with mock.patch.object(updater, "PENDING_FILE", pending):
            with mock.patch("shutil.which", return_value=None):
                ok, text = asyncio.run(updater.start_update(info, self.install))
                self.assertFalse(ok)
                self.assertIn("sudo skipa-watchdog", text)
                self.assertFalse(pending.exists())
            with mock.patch("shutil.which", return_value="/usr/bin/systemd-run"), \
                 mock.patch("asyncio.create_subprocess_exec", fake_exec):
                ok, _ = asyncio.run(updater.start_update(info, self.install))
        self.assertTrue(ok)
        cmd = calls[0]
        self.assertEqual(cmd[0], "systemd-run")
        self.assertIn("--no-block", cmd)
        self.assertTrue(str(cmd[-2]).endswith("install.sh") and cmd[-1] == "install")
        self.assertTrue(pending.exists())


class StartupNoticeTests(unittest.TestCase):
    def test_без_telegram_только_лог_и_задача_не_завершается(self):
        """без Telegram об обновлении пишется в журнал; задача не должна завершаться (иначе остановится весь процесс)"""
        import watchdog
        from bot import updater
        from tests.helpers import make_config
        info = updater.UpdateInfo(local="1.0.0", remote="1.1.0", behind=2, commits=["abc fix"])

        async def run():
            with mock.patch.object(updater, "check_update", mock.AsyncMock(return_value=info)), \
                 mock.patch.object(updater, "take_pending_result", return_value=None):
                with self.assertLogs("skipa_watchdog", level="WARNING") as cm:
                    task = asyncio.create_task(watchdog._update_notice(make_config(), {}))
                    await asyncio.sleep(0.2)
                    still_running = not task.done()
                    task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass
                return still_running, cm.output

        still_running, out = asyncio.run(run())
        self.assertTrue(still_running)
        self.assertTrue(any("Доступна новая версия" in line for line in out), out)

    def test_с_telegram_без_связи_сообщение_уходит_в_очередь_с_кнопками(self):
        """пока Telegram недоступен, уведомление об обновлении ждёт в очереди вместе с кнопкой «Установить»"""
        import watchdog
        from bot import updater
        from tests.helpers import make_config
        info = updater.UpdateInfo(local="1.0.0", remote="1.1.0", behind=1)
        queued = []

        async def run():
            async def no_sleep(_):
                return None
            real_sleep = asyncio.sleep
            cfg = make_config(bot_token="1:x", chat_id=555)
            with mock.patch.object(updater, "check_update", mock.AsyncMock(return_value=info)), \
                 mock.patch.object(updater, "take_pending_result", return_value=None), \
                 mock.patch.object(watchdog, "queue_pending_alert", lambda *a, **k: queued.append(a)), \
                 mock.patch.object(watchdog.asyncio, "sleep", no_sleep):
                task = asyncio.create_task(watchdog._update_notice(cfg, {"telegram_app": None}))
                await real_sleep(0.3)
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

        asyncio.run(run())
        self.assertEqual(len(queued), 1)
        chat_id, text, markup = queued[0]
        self.assertEqual(chat_id, 555)
        self.assertIn("1.1.0", text)
        self.assertEqual(markup["inline_keyboard"][0][0]["callback_data"], "upd:install")


@unittest.skipUnless(HAVE_PTB, "python-telegram-bot не установлен")
class UpdateButtonsTests(unittest.TestCase):
    def _query(self, data: str, user_id: int = 555):
        replies, edits = [], []

        async def reply(text, **kw):
            replies.append(text)

        async def edit(**kw):
            edits.append(kw)

        async def answer(*a, **k):
            return None

        q = SimpleNamespace(
            data=data, from_user=SimpleNamespace(id=user_id), answer=answer, edit_message_reply_markup=edit,
            message=SimpleNamespace(chat=SimpleNamespace(id=555), reply_text=reply),
        )
        return q, replies, edits

    def _run(self, data: str, user_id: int = 555, info=None, start=(True, "ок")):
        from bot import telegram_layer, updater
        from tests.helpers import make_config
        q, replies, edits = self._query(data, user_id)
        ctx = SimpleNamespace(bot_data={"config": make_config(bot_token="1:x", chat_id=555, admin_ids=[555])})
        started = []

        async def fake_start(i, *a, **k):
            started.append(i)
            return start

        with mock.patch.object(updater, "check_update", mock.AsyncMock(return_value=info)), \
             mock.patch.object(updater, "start_update", fake_start):
            asyncio.run(telegram_layer.on_update_callback(SimpleNamespace(callback_query=q), ctx))
        return replies, edits, started

    def test_установить(self):
        """кнопка «Установить» запускает обновление и убирает кнопки"""
        from bot import updater
        info = updater.UpdateInfo(local="1.0.0", remote="1.1.0", behind=1)
        replies, edits, started = self._run("upd:install", info=info)
        self.assertEqual(started, [info])
        self.assertTrue(edits)
        self.assertTrue(any("1.1.0" in r for r in replies))

    def test_позже_не_устанавливает(self):
        """«Позже» только снимает кнопки"""
        replies, edits, started = self._run("upd:later")
        self.assertEqual(started, [])
        self.assertTrue(edits and replies)

    def test_чужой_пользователь_игнорируется(self):
        """не администратор не может запустить обновление"""
        from bot import updater
        info = updater.UpdateInfo(local="1.0.0", remote="1.1.0", behind=1)
        replies, edits, started = self._run("upd:install", user_id=999, info=info)
        self.assertEqual((replies, edits, started), ([], [], []))

    def test_уже_актуально(self):
        """если за время ожидания обновление исчезло, установка не запускается"""
        replies, _edits, started = self._run("upd:install", info=None)
        self.assertEqual(started, [])
        self.assertTrue(any("актуальная" in r for r in replies))


if __name__ == "__main__":
    unittest.main()
