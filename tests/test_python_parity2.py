"""Вариант с Python: те же опции, что и в сервис-режиме (минимум записей, TCP-флаги, IPv6 в журнале)."""
import asyncio
import ipaddress
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from bot import blocker, ip_lists
from bot.config import Config
from bot.ip_lists import fetch_threat_db
from tests.helpers import make_config
from tests.test_blocker import BlockerBase


def run(coro):
    return asyncio.run(coro)


class ConfigOptionsTests(unittest.TestCase):
    def _load(self, extra_yaml: str = "") -> Config:
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "config.yaml"
            p.write_text('telegram:\n  bot_token: ""\n  chat_id: 0\n' + extra_yaml, encoding="utf-8")
            return Config.load(str(p))

    def test_значения_по_умолчанию(self):
        """TCP-флаги выключены, минимум записей - 10"""
        cfg = self._load()
        self.assertFalse(cfg.keep_established_tcp)
        self.assertEqual(cfg.min_list_entries, 10)

    def test_чтение_из_конфига(self):
        """firewall.keep_established_tcp и sources.min_entries читаются"""
        cfg = self._load("firewall:\n  keep_established_tcp: true\nsources:\n  min_entries: 3\n")
        self.assertTrue(cfg.keep_established_tcp)
        self.assertEqual(cfg.min_list_entries, 3)

    def test_пример_конфига_содержит_новые_ключи(self):
        """config.example.yaml разбирается и содержит оба ключа с безопасными значениями"""
        cfg = Config.load(str(Path(__file__).resolve().parent.parent / "config.example.yaml"))
        self.assertFalse(cfg.keep_established_tcp)
        self.assertEqual(cfg.min_list_entries, 10)


class KeepEstablishedRulesTests(BlockerBase):
    def _chain(self):
        # в поддельном netfilter правило - кортеж аргументов; для проверок удобнее строка
        return [" ".join(r) for r in self.nf.chains["SKIPA-BLOCK"]]

    def _drops(self):
        return [r for r in self._chain() if "DROP" in r]

    def test_по_умолчанию_один_drop_на_набор(self):
        """без опции правила прежние: по одному DROP на db и dyn"""
        blocker.configure(preload_db=True, drop_enabled=True)
        blocker.ensure_wiring()
        self.assertEqual(len(self._drops()), 2)
        self.assertFalse(any("--syn" in r and "DROP" in r for r in self._chain()))

    def test_с_опцией_пара_drop_и_переключение_туда_и_обратно(self):
        """keep_established: DROP для новых TCP и для не-TCP; после выключения остаётся один DROP на набор"""
        blocker.configure(preload_db=True, drop_enabled=True, keep_established=True)
        blocker.ensure_wiring()
        drops = self._drops()
        self.assertEqual(len(drops), 4)                                   # (nontcp + syn) x (db + dyn)
        self.assertEqual(len([r for r in drops if "--syn" in r]), 2)
        self.assertEqual(len([r for r in drops if r.startswith("! -p tcp")]), 2)
        self.assertFalse(any("RETURN" in r and "skipa-db" in r for r in self._chain()))
        blocker.configure(keep_established=False)
        blocker.ensure_wiring()
        drops = self._drops()
        self.assertEqual(len(drops), 2)
        self.assertFalse(any("--syn" in r for r in drops))
        blocker.configure(keep_established=True)
        blocker.ensure_wiring()
        self.assertEqual(len(self._drops()), 4)

    def test_порядок_allow_log_drop_сохраняется(self):
        """RETURN allowlist первым, затем LOG, затем DROP-правила"""
        blocker.configure(preload_db=True, drop_enabled=True, keep_established=True)
        blocker.ensure_wiring()
        kinds = ["RETURN" if "RETURN" in r else "LOG" if "LOG" in r else "DROP" for r in self._chain()]
        self.assertEqual(kinds[0], "RETURN")
        self.assertEqual(kinds[1], "LOG")
        self.assertTrue(all(k == "DROP" for k in kinds[2:]))

    def test_режим_notify_убирает_оба_вида(self):
        """при drop_enabled=False нет ни простых, ни парных DROP"""
        blocker.configure(preload_db=True, drop_enabled=True, keep_established=True)
        blocker.ensure_wiring()
        blocker.configure(drop_enabled=False)
        blocker.ensure_wiring()
        self.assertEqual(self._drops(), [])


class MinEntriesTests(unittest.TestCase):
    PRIMARY = "\n".join(f"{100 + i}.1.1.0/24" for i in range(1, 13))   # 12 записей (101..112)

    def _fetch(self, texts, previous=None, **kw):
        async def fake_get(url, **_kw):
            return texts.get(url, "")
        with mock.patch.object(ip_lists.http_client, "get_text", fake_get):
            return run(fetch_threat_db("P", kw.pop("blacklist", ""), "bl", "merged", previous=previous, **kw))

    def test_мусор_при_первой_загрузке_отклоняется(self):
        """3 записи при min_entries=10 и без прошлой версии - база пуста"""
        db = self._fetch({"P": "101.1.1.0/24\n102.1.1.0/24\n103.1.1.0/24"}, min_entries=10)
        self.assertEqual(db.source_line_count, 0)
        self.assertFalse(ip_lists.has_data(db))

    def test_нормальный_список_принимается(self):
        """12 записей проходят порог"""
        db = self._fetch({"P": self.PRIMARY}, min_entries=10)
        self.assertEqual(db.source_line_count, 12)

    def test_по_умолчанию_порога_нет(self):
        """на уровне библиотеки порог выключен (его передаёт конфиг): старое поведение сохранено"""
        db = self._fetch({"P": "101.1.1.0/24"})
        self.assertEqual(db.source_line_count, 1)

    def test_с_прошлой_версией_порог_не_применяется(self):
        """после удачной загрузки решает проверка «вдвое», а не минимум"""
        good = self._fetch({"P": self.PRIMARY}, min_entries=10)
        same_size = self._fetch({"P": self.PRIMARY}, previous=good, min_entries=10)
        self.assertEqual(same_size.source_line_count, 12)
        shrunk = self._fetch({"P": "101.1.1.0/24"}, previous=good, min_entries=10)
        self.assertTrue(shrunk.degraded)
        self.assertEqual(shrunk.source_line_count, 12)

    def test_у_доп_источника_свой_порог(self):
        """min_entries в элементе extra переопределяет общий"""
        extra = [{"name": "x", "type": "cidr_list", "url": "X", "enabled": True, "min_entries": 2}]
        db = self._fetch({"P": self.PRIMARY, "X": "7.7.7.0/24\n8.8.8.0/24"}, extra_sources=extra, min_entries=10)
        self.assertIsNotNone(db.match("7.7.7.7"))
        extra[0]["min_entries"] = 5
        db = self._fetch({"P": self.PRIMARY, "X": "7.7.7.0/24\n8.8.8.0/24"}, extra_sources=extra, min_entries=10)
        self.assertIsNone(db.match("7.7.7.7"))

    def test_abuseipdb_ipv6_пропускается_с_записью_в_журнал(self):
        """IPv6 из ответа AbuseIPDB больше не пропадает молча"""
        data = {"data": [{"ipAddress": f"48.1.0.{i}"} for i in range(1, 13)] + [{"ipAddress": "2001:db8::9"}]}

        async def fake_json(url, **kw):
            return data

        async def fake_text(url, **kw):
            return self.PRIMARY

        extra = [{"name": "abuse", "type": "abuseipdb", "api_key": "k", "enabled": True}]
        with mock.patch.object(ip_lists.http_client, "get_json", fake_json), \
             mock.patch.object(ip_lists.http_client, "get_text", fake_text), \
             self.assertLogs("skipa_watchdog", level="INFO") as cm:
            db = run(fetch_threat_db("P", "", "bl", "merged", extra_sources=extra, min_entries=10))
        self.assertIsNotNone(db.match("48.1.0.5"))
        self.assertTrue(any("1 записей IPv6 пропущено" in line for line in cm.output), cm.output)


class WatchdogWiringTests(unittest.TestCase):
    def test_настройки_доходят_до_blocker_и_загрузки_списков(self):
        """watchdog передаёт keep_established и min_entries дальше"""
        import watchdog
        cfg = make_config(keep_established_tcp=True, min_list_entries=7)
        with mock.patch.object(blocker, "configure") as conf:
            watchdog._configure_blocker(cfg)
        self.assertTrue(conf.call_args.kwargs["keep_established"])
        src = Path(watchdog.__file__).read_text(encoding="utf-8")
        self.assertIn("min_entries=config.min_list_entries", src)
        self.assertIn("min_entries=config.min_list_entries", (Path(watchdog.__file__).parent / "bot" / "dbupdate.py").read_text(encoding="utf-8"))
        self.assertIsNotNone(ipaddress)


if __name__ == "__main__":
    unittest.main()
