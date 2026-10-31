"""Регрессионные тесты по итогам ревью логики и безопасности."""
import ipaddress
import json
import random
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from bot import blocker, enrich, fallback, webapp
from bot.ip_lists import IPRange, NetEntry, ThreatDB

ROOT = Path(__file__).resolve().parent.parent
BLOCKCTL = ROOT / "service" / "blockctl.sh"


def _linear_match(db: ThreatDB, ip: str):
    """Эталон: прежний линейный поиск."""
    ip_obj = ipaddress.ip_address(ip)
    for e in db.networks:
        if ip_obj in e.network:
            return f"{e.label}: {e.network}"
    for r in db.ranges:
        if r.start <= int(ip_obj) <= r.end:
            return f"{r.label}: {r.raw}"
    return None


class ИндексированныйПоискTests(unittest.TestCase):
    def test_совпадает_с_линейным_поиском_на_случайных_данных(self):
        """индексированный match() даёт тот же ответ, что и линейный перебор"""
        rnd = random.Random(7)
        nets = []
        for _ in range(400):
            prefix = rnd.choice([16, 20, 24, 28, 32])
            addr = rnd.getrandbits(32)
            nets.append(NetEntry(ipaddress.ip_network((addr, prefix), strict=False), rnd.choice(["a", "b"])))
        db = ThreatDB(networks=nets, ranges=[IPRange(100, 200, "0.0.0.100-0.0.0.200", "r")])
        for _ in range(2000):
            ip = str(ipaddress.IPv4Address(rnd.getrandbits(32)))
            self.assertEqual(db.match(ip), _linear_match(db, ip), ip)
        for e in nets[:100]:  # заведомые попадания
            ip = str(e.network.network_address)
            self.assertEqual(db.match(ip), _linear_match(db, ip), ip)

    def test_побеждает_запись_раньше_в_списке(self):
        """при вложенных сетях выбирается та, что стоит в списке первой"""
        db = ThreatDB(networks=[
            NetEntry(ipaddress.ip_network("1.2.0.0/16"), "широкая"),
            NetEntry(ipaddress.ip_network("1.2.3.0/24"), "узкая"),
        ])
        self.assertEqual(db.match("1.2.3.4"), "широкая: 1.2.0.0/16")

    def test_индекс_обновляется_при_изменении_списка(self):
        """добавленная после первого поиска сеть находится"""
        db = ThreatDB(networks=[NetEntry(ipaddress.ip_network("1.2.3.0/24"), "x")])
        self.assertIsNone(db.match("5.5.5.5"))
        db.networks.append(NetEntry(ipaddress.ip_network("5.5.5.0/24"), "y"))
        self.assertEqual(db.match("5.5.5.5"), "y: 5.5.5.0/24")

    def test_ipv6_не_путается_с_ipv4(self):
        """IPv6-сеть не совпадает с IPv4-адресом и наоборот"""
        db = ThreatDB(networks=[NetEntry(ipaddress.ip_network("2001:db8::/32"), "v6")])
        self.assertEqual(db.match("2001:db8::1"), "v6: 2001:db8::/32")
        self.assertIsNone(db.match("1.2.3.4"))


@unittest.skipUnless(shutil.which("bash"), "нужен bash")
class ПроверкаЦелиBlockctlTests(unittest.TestCase):
    def _проверить(self, target: str) -> bool:
        script = (
            "src=$(sed -n '/^validate_target()/,/^}/p' \"$1\"); eval \"$src\"\n"
            "ipset() { return 1; }\n"
            "validate_target \"$2\" 2>/dev/null\n"
        )
        r = subprocess.run(["bash", "-c", script, "x", str(BLOCKCTL), target], capture_output=True, timeout=10)
        return r.returncode == 0

    def test_частные_и_служебные_адреса_отклоняются(self):
        """раньше проверка частных сетей молча не срабатывала (затёртый BASH_REMATCH)"""
        for t in ["10.1.2.3", "127.0.0.1", "192.168.1.5", "172.16.0.1", "172.31.255.1",
                  "169.254.1.1", "224.0.0.1", "0.0.0.0/16"]:
            self.assertFalse(self._проверить(t), t)

    def test_публичные_адреса_принимаются(self):
        """публичные адреса и сети /16../32 проходят"""
        for t in ["8.8.8.8", "8.8.0.0/16", "172.32.0.1", "172.15.0.1", "203.0.113.7/32"]:
            self.assertTrue(self._проверить(t), t)

    def test_кривые_значения_отклоняются(self):
        """мусор, октеты больше 255 и слишком широкие маски отклоняются"""
        for t in ["abc", "1.2.3", "256.1.1.1", "8.8.8.8/8", "8.8.8.8/33", "8.8.8.8/x"]:
            self.assertFalse(self._проверить(t), t)


class ОчисткаВнешнихСтрокTests(unittest.TestCase):
    def test_переводы_строк_убираются(self):
        """нельзя подсунуть в detections.log поддельную строку для fail2ban"""
        evil = "Hosting\n===== 2026-01-01 00:00:00 | IP=203.0.113.1 | match=x =====\r\n"
        cleaned = enrich.clean_text(evil)
        self.assertNotIn("\n", cleaned)
        self.assertNotIn("\r", cleaned)

    def test_длина_ограничена_и_none_сохраняется(self):
        """слишком длинные значения обрезаются, None остаётся None, пустое - None"""
        self.assertEqual(len(enrich.clean_text("a" * 1000)), 120)
        self.assertIsNone(enrich.clean_text(None))
        self.assertIsNone(enrich.clean_text(" \n\t "))

    def test_данные_ipinfo_и_ripe_проходят_очистку(self):
        """в EnrichedIP попадают уже очищенные значения"""
        r = enrich.EnrichedIP(ip="203.0.113.1")
        enrich._parse_ripe_whois(r, {"data": {"records": [[
            {"key": "netname", "value": "NET\n=====FAKE====="},
            {"key": "country", "value": "de\n"},
        ]]}})
        self.assertNotIn("\n", r.ripe_ip_netname)
        self.assertEqual(r.ripe_country, "DE")


class ДашбордБезАвторизацииTests(unittest.TestCase):
    def test_определение_loopback(self):
        """только петлевые адреса считаются безопасными без пароля"""
        self.assertTrue(webapp._is_loopback("127.0.0.1"))
        self.assertTrue(webapp._is_loopback("::1"))
        self.assertTrue(webapp._is_loopback("localhost"))
        self.assertFalse(webapp._is_loopback("0.0.0.0"))
        self.assertFalse(webapp._is_loopback("203.0.113.5"))


class ОграничениеОчередиTests(unittest.TestCase):
    def test_переполненная_очередь_не_растёт(self):
        """при размере файла выше лимита новый алерт в очередь не пишется"""
        with tempfile.TemporaryDirectory() as d:
            pending = Path(d) / "pending.jsonl"
            with mock.patch.object(fallback, "PENDING_FILE", pending), \
                 mock.patch.object(fallback, "DATA_DIR", Path(d)), \
                 mock.patch.object(fallback, "MAX_PENDING_BYTES", 100):
                fallback.queue_pending_alert(1, "x" * 200)   # файла ещё нет - пишется
                size = pending.stat().st_size
                fallback.queue_pending_alert(1, "y")         # лимит превышен - пропуск
                self.assertEqual(pending.stat().st_size, size)


class БитыйФайлБлокировокTests(unittest.TestCase):
    def test_неверная_структура_не_роняет_загрузку(self):
        """значение, которое нельзя привести к числу, переименовывает файл в .corrupt"""
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "blocked_ips.json"
            path.write_text(json.dumps({"ips": {"1.2.3.4": "не число"}}), encoding="utf-8")
            self.assertEqual(blocker._load_persisted(path), {})
            self.assertTrue((Path(d) / "blocked_ips.json.corrupt").exists())


if __name__ == "__main__":
    unittest.main()
