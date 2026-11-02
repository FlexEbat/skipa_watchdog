"""service/lib-config.sh читает тот же config.yaml, что и Python: значения должны совпадать."""
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
LIB = ROOT / "service" / "lib-config.sh"


def sh(script: str, cwd: Path) -> str:
    r = subprocess.run(["bash", "-c", f'source "{LIB}"\n{script}'], capture_output=True, text=True, cwd=cwd, timeout=20)
    assert r.returncode == 0, r.stderr
    return r.stdout


@unittest.skipUnless(shutil.which("bash") and shutil.which("awk"), "нужны bash и awk")
class LibConfigTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.d = Path(self.tmp.name)
        self.cfg = self.d / "config.yaml"
        shutil.copy(ROOT / "config.example.yaml", self.cfg)

    def test_values_match_python_view_of_the_same_file(self):
        """bash и Python читают из config.yaml одинаковые значения"""
        data = yaml.safe_load(self.cfg.read_text())
        out = sh(
            'load_service_config config.yaml\n'
            'printf "%s\\n" "$ACTION_MODE" "$ACTIVE_LIST" "$PRIMARY_LIST_URL" "$BLACKLIST_URL" '
            '"$UPDATE_INTERVAL_DAYS" "$KERNEL_LOG_PREFIX" "$ALERT_COOLDOWN_MINUTES" "$LOG_LIMIT" "$LOG_BURST" "$LOG_DIR"',
            self.d,
        ).split("\n")
        self.assertEqual(out[0], data["action"]["mode"])
        self.assertEqual(out[1], data["sources"]["active_list"])
        self.assertEqual(out[2], data["sources"]["primary_list_url"])
        self.assertEqual(out[3], data["sources"]["blacklist_url"])
        self.assertEqual(int(out[4]), data["sources"]["update_interval_days"])
        self.assertEqual(out[5], data["monitoring"]["kernel_log_prefix"])
        self.assertEqual(int(out[6]), data["monitoring"]["alert_cooldown_minutes"])
        self.assertEqual(out[7], data["firewall"]["log_limit"])
        self.assertEqual(int(out[8]), data["firewall"]["log_burst"])
        self.assertEqual(out[9], data["logging"]["log_dir"])

    def test_set_changes_only_target_and_python_sees_it(self):
        """запись меняет только целевой ключ"""
        before = yaml.safe_load(self.cfg.read_text())
        sh('yaml_set config.yaml sources.active_list list1\nyaml_set config.yaml action.mode notify', self.d)
        after = yaml.safe_load(self.cfg.read_text())
        self.assertEqual(after["sources"]["active_list"], "list1")
        self.assertEqual(after["action"]["mode"], "notify")
        after["sources"]["active_list"] = before["sources"]["active_list"]
        after["action"]["mode"] = before["action"]["mode"]
        self.assertEqual(after, before)                     # остальное не тронуто
        self.assertEqual(sh("yaml_get config.yaml sources.active_list", self.d).strip(), "list1")

    def test_lists_inline_block_and_set_raw(self):
        """списки в строку и блоком, запись как есть"""
        self.cfg.write_text(
            "monitoring:\n  ignore_ips:\n    - 5.5.5.5   # свой\n    - \"6.6.6.0/24\"\n  poll_interval_seconds: 5\n"
        )
        self.assertEqual(sh("yaml_list config.yaml monitoring.ignore_ips", self.d).split(), ["5.5.5.5", "6.6.6.0/24"])
        sh('yaml_set config.yaml monitoring.ignore_ips \'["7.7.7.7", "8.8.8.0/24"]\' raw', self.d)
        data = yaml.safe_load(self.cfg.read_text())
        self.assertEqual(data["monitoring"]["ignore_ips"], ["7.7.7.7", "8.8.8.0/24"])
        self.assertEqual(data["monitoring"]["poll_interval_seconds"], 5)     # соседний ключ цел
        self.assertEqual(sh("load_service_config config.yaml; echo \"$IGNORE_IPS\"", self.d).strip(), "7.7.7.7 8.8.8.0/24")

    def test_missing_key_is_created_in_section_and_file_mode_kept(self):
        """отсутствующий ключ создаётся в секции, права файла сохраняются"""
        self.cfg.write_text("sources:\n  active_list: \"merged\"\nmonitoring:\n  method: \"both\"\n")
        self.cfg.chmod(0o600)
        sh("yaml_set config.yaml sources.update_interval_days 3 raw", self.d)
        data = yaml.safe_load(self.cfg.read_text())
        self.assertEqual(data["sources"]["update_interval_days"], 3)
        self.assertEqual(data["monitoring"]["method"], "both")
        self.assertEqual(self.cfg.stat().st_mode & 0o777, 0o600)

    def test_defaults_when_keys_absent(self):
        """значения по умолчанию при отсутствии ключей"""
        self.cfg.write_text("telegram:\n  bot_token: \"\"\n")
        out = sh('load_service_config config.yaml; echo "$ACTION_MODE $ACTIVE_LIST $UPDATE_INTERVAL_DAYS $LOG_LIMIT"', self.d)
        self.assertEqual(out.strip(), "block_notify merged 7 30/second")


if __name__ == "__main__":
    unittest.main()


@unittest.skipUnless(shutil.which("bash") and shutil.which("awk"), "нужны bash и awk")
class YamlSetHardeningTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.d = Path(self.tmp.name)
        self.cfg = self.d / "config.yaml"
        shutil.copy(ROOT / "config.example.yaml", self.cfg)

    def _set(self, path: str, value: str, raw: bool = False) -> subprocess.CompletedProcess:
        script = f'source "{LIB}"\nyaml_set "{self.cfg}" "$1" "$2" {"raw" if raw else ""}'
        return subprocess.run(["bash", "-c", script, "x", path, value], capture_output=True, text=True,
                              cwd=self.d, timeout=20)

    def test_обратный_слэш_n_не_превращается_в_перевод_строки(self):
        """`awk -v` раскрывал \\n; значение через окружение остаётся буквальным"""
        before = self.cfg.read_text(encoding="utf-8").count("\n")
        r = self._set("telegram.bot_token", "12:abc\\nmonitoring:\\n  ignore_ips: [evil]", raw=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        text = self.cfg.read_text(encoding="utf-8")
        self.assertEqual(text.count("\n"), before)                 # ни одной лишней строки
        self.assertNotIn("\nmonitoring:\n  ignore_ips: [evil]", text)
        self.assertIn("  bot_token: 12:abc\\nmonitoring:", text)      # осталось буквальным текстом

    def test_перевод_строки_и_кавычки_в_значении_отклоняются(self):
        """значение с \\n, кавычкой или обратным слэшем не пишется, файл не меняется"""
        original = self.cfg.read_bytes()
        for bad in ("a\nb", 'a"b', "a\\b"):
            r = self._set("telegram.bot_token", bad)
            self.assertNotEqual(r.returncode, 0, repr(bad))
        r = self._set("telegram.bot_token", "x\ny", raw=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(self.cfg.read_bytes(), original)

    def test_недопустимый_ключ_отклоняется(self):
        """ключ с пробелом или спецсимволами не попадает в awk-программу"""
        original = self.cfg.read_bytes()
        for bad in ("a b.c", "sec.k$(id)", "sec.k:x"):
            self.assertNotEqual(self._set(bad, "v").returncode, 0, bad)
        self.assertEqual(self.cfg.read_bytes(), original)

    def test_обычное_значение_читается_обратно(self):
        """токен бота записывается и читается как раньше"""
        self.assertEqual(self._set("telegram.bot_token", "123456:ABC-def_ghi").returncode, 0)
        self.assertEqual(sh('yaml_get "%s" telegram.bot_token' % self.cfg, self.d).strip(), "123456:ABC-def_ghi")


class ExampleConfigTests(unittest.TestCase):
    def test_в_примере_конфига_нет_дублирующихся_ключей(self):
        """PyYAML молча берёт последний из дублей: вторая секция firewall: затирала keep_established_tcp"""
        class Strict(yaml.SafeLoader):
            pass

        def construct(loader, node, deep=False):
            seen = set()
            for k, _ in node.value:
                key = loader.construct_object(k)
                assert key not in seen, f"дубль ключа {key!r}"
                seen.add(key)
            return yaml.SafeLoader.construct_mapping(loader, node, deep)

        Strict.add_constructor("tag:yaml.org,2002:map", construct)
        data = yaml.load((ROOT / "config.example.yaml").read_text(encoding="utf-8"), Loader=Strict)
        self.assertEqual(set(data["firewall"]), {"keep_established_tcp", "log_limit", "log_burst"})
