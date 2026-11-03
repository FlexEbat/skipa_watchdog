"""Проверка обновлений при запуске: bash (панель, сервис), Python (бот), кнопки в Telegram."""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LIB_UPDATE = ROOT / "service" / "lib-update.sh"


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


if __name__ == "__main__":
    unittest.main()
