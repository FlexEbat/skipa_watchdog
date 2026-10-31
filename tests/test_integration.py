import asyncio
import ipaddress
import logging
import signal
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parent.parent

try:
    import telegram  # noqa: F401
    HAVE_PTB = True
except ImportError:  # pragma: no cover
    HAVE_PTB = False


class ConfigTests(unittest.TestCase):
    def test_example_config_loads(self):
        """config.example.yaml загружается со значениями по умолчанию"""
        from bot.config import Config
        cfg = Config.load(ROOT / "config.example.yaml")
        self.assertEqual(cfg.action_mode, "block_notify")
        self.assertTrue(cfg.firewall_needed and cfg.drop_enabled and cfg.preload_db)
        self.assertEqual(cfg.block_timeout_hours, 72)
        self.assertFalse(cfg.telegram_enabled)

    def test_null_sections_and_bad_values(self):
        """пустые секции и неверные значения приводятся к допустимым"""
        from bot.config import Config
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "c.yaml"
            p.write_text("alerting:\nmonitoring:\n  poll_interval_seconds: 0\n  method: bogus\n")
            cfg = Config.load(p)
            self.assertEqual(cfg.poll_interval_seconds, 1)
            self.assertEqual(cfg.method, "poll")
            self.assertEqual(cfg.retry_interval_seconds, 300)


@unittest.skipUnless(HAVE_PTB, "python-telegram-bot не установлен")
class TelegramTests(unittest.TestCase):
    def cfg(self, **kw):
        from tests.helpers import make_config
        return make_config(bot_token="1:x", chat_id=-100, **kw)

    def test_admin_gate_fails_closed(self):
        """команды закрыты по умолчанию: пустой admin_ids пускает только личку chat_id"""
        from tests.helpers import make_config
        from bot.telegram_layer import _is_admin
        c = self.cfg(admin_ids=[])                      # chat_id=-100 - это группа
        self.assertFalse(_is_admin(c, 555, 999))        # посторонний, чужой чат
        self.assertFalse(_is_admin(c, 555, -100))       # в группе без admin_ids командовать нельзя
        self.assertFalse(_is_admin(c, None, -100))
        private = make_config(bot_token="1:x", chat_id=555, admin_ids=[])
        self.assertTrue(_is_admin(private, 555, 555))   # личная переписка настроенного пользователя
        self.assertFalse(_is_admin(private, 556, 555))  # чужой пользователь в том же чате
        self.assertFalse(_is_admin(private, 555, 777))  # тот же пользователь, но другой чат
        c2 = self.cfg(admin_ids=[7])
        self.assertTrue(_is_admin(c2, 7, 1))
        self.assertFalse(_is_admin(c2, 8, -100))        # при заданных admin_ids чат не даёт прав

    def test_ip_arg_parsing(self):
        """IP из команды разбирается строго, мусор отклоняется"""
        from bot.telegram_layer import _parse_ip_arg
        self.assertEqual(_parse_ip_arg("1.2.3.4"), "1.2.3.4")
        self.assertEqual(_parse_ip_arg("::ffff:1.2.3.4"), "1.2.3.4")
        for bad in ("1.2.3.4/../x", "evil", "-j ACCEPT", ""):
            self.assertIsNone(_parse_ip_arg(bad))

    def test_application_builds_with_proxy(self):
        """приложение Telegram собирается с прокси"""
        from bot.telegram_layer import build_application
        c = self.cfg(telegram_proxy="http://127.0.0.1:3128")
        app = asyncio.run(build_application(c, {}))
        self.assertGreaterEqual(len(app.handlers[0]), 10)


class HitHandlerTests(unittest.TestCase):
    def make(self, mode="block_notify"):
        import watchdog
        from tests.helpers import make_config
        cfg = make_config(action_mode=mode, enrich_enabled=False)
        q = asyncio.Queue()
        d = Path(tempfile.mkdtemp())
        return watchdog, cfg, q, d / "detections.log"

    def hit(self, ip="185.224.228.5"):
        from bot.monitor import Hit
        return Hit(ip=ip, matched_source="skipa: 185.224.228.0/24", local_port=22, method="kernel_log")

    def test_block_and_notify(self):
        """срабатывание: блокировка, затем уведомление"""
        wd, cfg, q, log = self.make()
        with mock.patch.object(wd.blocker, "block_ip", return_value=True) as b:
            ok = asyncio.run(wd._make_hit_handler(cfg, {}, log, q)(self.hit()))
        self.assertTrue(ok)
        b.assert_called_once_with("185.224.228.5")
        hit, note, blocked = q.get_nowait()
        self.assertTrue(blocked)
        self.assertIn("заблокирован", note)
        self.assertIn("185.224.228.5", log.read_text())

    def test_failed_block_returns_false_for_fast_retry(self):
        """сбой блокировки возвращает False для повтора через минуту"""
        wd, cfg, q, log = self.make()
        with mock.patch.object(wd.blocker, "block_ip", return_value=False):
            self.assertFalse(asyncio.run(wd._make_hit_handler(cfg, {}, log, q)(self.hit())))

    def test_refusal_is_not_an_error(self):
        """отказ validate_target не считается ошибкой и не повторяется"""
        wd, cfg, q, log = self.make()
        with mock.patch.object(wd.blocker, "block_ip") as b:
            ok = asyncio.run(wd._make_hit_handler(cfg, {}, log, q)(self.hit("10.0.0.5")))
        self.assertTrue(ok)                      # не повторять каждую минуту
        b.assert_not_called()
        self.assertIn("Не блокирую", q.get_nowait()[1])

    def test_block_mode_still_writes_audit_log(self):
        """в режиме block журнал обнаружений пишется"""
        wd, cfg, q, log = self.make("block")
        with mock.patch.object(wd.blocker, "block_ip", return_value=True):
            asyncio.run(wd._make_hit_handler(cfg, {}, log, q)(self.hit()))
        self.assertTrue(log.exists())
        self.assertTrue(q.empty())

    def test_notify_mode_does_not_block(self):
        """в режиме notify блокировки нет"""
        wd, cfg, q, log = self.make("notify")
        with mock.patch.object(wd.blocker, "block_ip") as b:
            self.assertTrue(asyncio.run(wd._make_hit_handler(cfg, {}, log, q)(self.hit())))
        b.assert_not_called()


class SmokeTests(unittest.TestCase):
    """Запускает настоящий async_main: оркестрация задач, устойчивость к недоступному
    Telegram, корректная остановка по SIGTERM."""

    def test_runs_without_telegram_and_stops_on_sigterm(self):
        """процесс работает без Telegram и останавливается по SIGTERM"""
        self._run(telegram=False)

    @unittest.skipUnless(HAVE_PTB, "python-telegram-bot не установлен")
    def test_unreachable_telegram_does_not_kill_process(self):
        """недоступный Telegram не останавливает процесс"""
        logs = self._run(telegram=True)
        self.assertIn("Telegram недоступен", logs)
        self.assertIn("Skipa Watchdog остановлен", logs)

    def test_dashboard_healthcheck_and_events_run_in_real_process(self):
        """дашборд и health-check работают в настоящем процессе"""
        import socket
        import urllib.request

        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        seen = {}

        def probe():
            for _ in range(20):
                try:
                    with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/status", timeout=2) as r:
                        seen["status"] = r.status
                        seen["body"] = r.read().decode()
                        return
                except OSError:
                    time.sleep(0.3)

        import threading
        import time
        t = threading.Thread(target=probe)
        t.start()
        logs = self._run(telegram=False, extra={
            "dashboard": {"enabled": True, "port": port},
            "healthcheck": {"enabled": True},
        }, wait=4.0)
        t.join()
        self.assertEqual(seen.get("status"), 200)
        self.assertIn("monitors", seen["body"])
        self.assertIn("Веб-дашборд запущен", logs)

    def _run(self, telegram, extra=None, wait=2.5):
        import watchdog
        from bot import ip_lists
        from bot.ip_lists import NetEntry, ThreatDB

        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            cfg = {
                "action": {"mode": "notify"},
                "monitoring": {"method": "poll", "poll_interval_seconds": 1},
                "enrichment": {"enabled": False},
                "logging": {"log_dir": str(d / "log")},
                "environment": {"docker_scan": False, "k8s_scan": False},
            }
            cfg.update(extra or {})
            if telegram:
                cfg["telegram"] = {"bot_token": "123456:ABC", "chat_id": 1, "admin_ids": [1]}
            (d / "c.yaml").write_text(yaml.safe_dump(cfg))
            db = ThreatDB(networks=[NetEntry(ipaddress.ip_network("1.2.3.0/24"), "skipa")],
                          last_update_ts=__import__("time").time())

            async def fake_get(url, **kw):
                return ""

            async def main():
                task = asyncio.create_task(watchdog.async_main())
                await asyncio.sleep(wait)
                signal.raise_signal(signal.SIGTERM)
                await asyncio.wait_for(task, 15)

            handler_count = len(logging.getLogger().handlers)
            with mock.patch.object(watchdog, "CONFIG_PATH", str(d / "c.yaml")), \
                 mock.patch.object(watchdog, "load_cache", lambda: db), \
                 mock.patch.object(ip_lists.http_client, "get_text", fake_get), \
                 mock.patch("bot.fallback.PENDING_FILE", d / "pending.jsonl"), \
                 mock.patch("bot.fallback.DATA_DIR", d):
                asyncio.run(main())
            text = (d / "log" / "skipa-watchdog.log").read_text()
            # убрать добавленные хендлеры, чтобы не мешать другим тестам
            for h in logging.getLogger().handlers[handler_count:]:
                logging.getLogger().removeHandler(h)
                h.close()
            return text


if __name__ == "__main__":
    unittest.main()


class SecretsInLogsTests(unittest.TestCase):
    def test_bot_token_and_keys_never_reach_the_log_file(self):
        """токен бота и ключи не попадают в файл журнала"""
        import logging
        import watchdog
        from tests.helpers import make_config

        token = "123456789:AAH-secret_token_value_0123456789"
        with tempfile.TemporaryDirectory() as d:
            cfg = make_config(bot_token=token, ipinfo_token="ipinfo_secret_value", log_dir=d, log_level="INFO",
                              extra_sources=[{"api_key": "abuse_secret_value"}])
            root = logging.getLogger()
            before = list(root.handlers)
            try:
                watchdog._setup_logging(cfg)
                log = logging.getLogger("test")
                log.info("HTTP Request: POST https://api.telegram.org/bot%s/getUpdates", token)
                log.warning("ошибка: https://ipinfo.io/1.2.3.4/json?token=ipinfo_secret_value, ключ abuse_secret_value")
                try:
                    raise RuntimeError(f"сбой при обращении к /bot{token}/sendMessage")
                except RuntimeError:
                    log.exception("упало")
                self.assertEqual(logging.getLogger("httpx").level, logging.WARNING)
            finally:
                for h in root.handlers[len(before):]:
                    root.removeHandler(h)
                    h.close()
            text = (Path(d) / "skipa-watchdog.log").read_text()
        for secret in (token, "AAH-secret_token_value", "ipinfo_secret_value", "abuse_secret_value"):
            self.assertNotIn(secret, text)
        self.assertIn("<скрыто>", text)
