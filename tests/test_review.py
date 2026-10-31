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


class ЧтениеСобытийTests(unittest.TestCase):
    def _файл(self, d: Path, n: int, step: int = 30):
        import time
        now = time.time()
        f = d / "events.jsonl"
        with f.open("w", encoding="utf-8") as fh:
            for i in range(n):
                fh.write(json.dumps({"ts": now - (n - i) * step, "ip": f"1.2.{i % 250}.{i % 200}"}) + "\n")
        return f, now

    def test_чтение_с_конца_даёт_тот_же_результат_что_полное(self):
        """события за период из хвоста файла совпадают с полной фильтрацией"""
        from bot import events_store as es
        with tempfile.TemporaryDirectory() as d:
            f, now = self._файл(Path(d), 5000)
            with mock.patch.object(es, "EVENTS_FILE", f), mock.patch.object(es, "_TAIL_BLOCK", 4096):
                for hours in (1, 6, 24, 24 * 90):
                    since = now - hours * 3600
                    expected = [e for e in es.load_events() if e["ts"] >= since]
                    self.assertEqual(es.load_events(since_ts=since), expected, hours)

    def test_обрезка_оставляет_последние_записи(self):
        """prune_events оставляет только последние keep_last строк по порядку"""
        from bot import events_store as es
        with tempfile.TemporaryDirectory() as d:
            f, _ = self._файл(Path(d), 100)
            with mock.patch.object(es, "EVENTS_FILE", f):
                before = es.load_events()
                es.prune_events(keep_last=40)
                self.assertEqual(es.load_events(), before[-40:])
                es.prune_events(keep_last=40)   # повторно ничего не меняет
                self.assertEqual(es.load_events(), before[-40:])


class ConntrackTests(unittest.TestCase):
    def test_быстрый_путь_совпадает_с_общим_разбором(self):
        """read_conntrack отдаёт по одной записи на адрес и пропускает не-TCP"""
        from bot import monitor
        lines = [
            "ipv4     2 tcp      6 431999 ESTABLISHED src=203.0.113.5 dst=10.0.0.5 sport=51234 dport=443 "
            "src=10.0.0.5 dst=203.0.113.5 sport=443 dport=51234 [ASSURED] mark=0 use=2",
            "ipv4     2 tcp      6 117 TIME_WAIT src=203.0.113.5 dst=10.0.0.5 sport=51240 dport=22 "
            "src=10.0.0.5 dst=203.0.113.5 sport=22 dport=51240 [ASSURED] mark=0 use=2",
            "ipv4     2 udp      17 25 src=203.0.113.9 dst=10.0.0.5 sport=5353 dport=53 "
            "src=10.0.0.5 dst=203.0.113.9 sport=53 dport=5353 mark=0 use=2",
            "ipv4     2 tcp      6 60 SYN_SENT src=198.51.100.7 dst=10.0.0.5 sport=40000 dport=80 [UNREPLIED] "
            "src=10.0.0.5 dst=198.51.100.7 sport=80 dport=40000 mark=0 use=2",
        ]
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "ct"
            p.write_text("\n".join(lines), encoding="ascii")
            with mock.patch.object(monitor, "_CONNTRACK_PATHS", (str(p),)):
                got = monitor.read_conntrack()
        self.assertEqual(got, [("203.0.113.5", 51234, 443), ("198.51.100.7", 40000, 80)])
        self.assertEqual(monitor.parse_conntrack_line(lines[0]), got[0])


SYNC = ROOT / "service" / "sync-lists.sh"
ALLOW_SSH = ROOT / "service" / "allow-ssh.sh"


class _BashStubs(unittest.TestCase):
    """Окружение с поддельными curl/ipset/ss (без root и без сети)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.d = Path(self.tmp.name)
        self.bin = self.d / "bin"
        self.bin.mkdir()
        self.out = self.d / "out"
        self.out.mkdir()
        self.cfg = self.d / "config.yaml"
        shutil.copy(ROOT / "config.example.yaml", self.cfg)
        text = self.cfg.read_text(encoding="utf-8")
        text = text.replace("/var/log/skipa_watchdog", str(self.d / "log"))
        self.cfg.write_text(text, encoding="utf-8")
        self._fake("curl", 'echo "$@" >> "$OUT/curl-args"\ncat "$OUT/list.txt"')
        self._fake("ss", 'cat "$OUT/ss.txt" 2>/dev/null; true')
        self._fake(
            "ipset",
            'echo "$@" >> "$OUT/ipset-calls"\n'
            'if [ "$1" = restore ]; then n=$(ls "$OUT" | grep -c "^restore-"); cat > "$OUT/restore-$n"; fi\n'
            'if [ "$1" = list ]; then echo "Number of entries: 3"; fi\n'
            'exit 0',
        )

    def _fake(self, name: str, body: str) -> None:
        p = self.bin / name
        p.write_text("#!/usr/bin/env bash\n" + body + "\n", encoding="utf-8")
        p.chmod(0o755)

    def _env(self) -> dict:
        import os
        env = dict(os.environ)
        env.update(PATH=f"{self.bin}:{env['PATH']}", OUT=str(self.out), SKIPA_STATE_DIR=str(self.d / "state"))
        return env

    def _sync(self, listing: str, ss: str = "") -> tuple[str, str]:  # noqa: D401
        (self.out / "list.txt").write_text(listing, encoding="utf-8")
        (self.out / "ss.txt").write_text(ss, encoding="utf-8")
        for f in self.out.glob("restore-*"):
            f.unlink()
        r = subprocess.run(["bash", str(SYNC), str(self.cfg)], capture_output=True, text=True,
                           env=self._env(), timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        restores = sorted(self.out.glob("restore-*"))
        allow = restores[0].read_text(encoding="utf-8") if restores else ""
        scan = restores[1].read_text(encoding="utf-8") if len(restores) > 1 else ""
        return allow, scan


@unittest.skipUnless(shutil.which("bash") and shutil.which("awk"), "нужны bash и awk")
class СинхронизацияСпискаBashTests(_BashStubs):
    """sync-lists.sh целиком."""

    def test_широкие_сети_отбрасываются_а_узкие_остаются(self):
        """/8 и /16 не попадают в набор сканеров при min_prefix по умолчанию (20)"""
        _allow, scan = self._sync("203.0.113.0/24\n8.0.0.0/8\n9.9.0.0/16\n198.51.100.7\n")
        self.assertIn("203.0.113.0/24", scan)
        self.assertIn("198.51.100.7", scan)
        self.assertNotIn("8.0.0.0/8", scan)
        self.assertNotIn("9.9.0.0/16", scan)

    def test_allowlist_содержит_частные_сети_целиком(self):
        """раньше /8 и /12 в allowlist отбрасывались общим фильтром (минимум /16)"""
        allow, _scan = self._sync("203.0.113.0/24\n")
        for net in ("127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"):
            self.assertIn(net, allow)

    def test_ssh_сессии_попадают_в_allowlist(self):
        """адрес администратора с живой SSH-сессией защищён, даже если он есть в списке"""
        ss = "0 0 10.1.1.1:22 198.51.100.50:50123\n0 0 [::ffff:10.1.1.1]:22 [::ffff:192.0.2.9]:41000\n"
        allow, scan = self._sync("198.51.100.50\n203.0.113.0/24\n", ss=ss)
        self.assertIn("198.51.100.50", allow)
        self.assertIn("192.0.2.9", allow)
        self.assertIn("198.51.100.50", scan)   # в списке он остаётся - спасает именно allowlist

    def test_ssh_защита_отключается_настройкой(self):
        """monitoring.auto_allowlist: false отключает добавление SSH-сессий"""
        self.cfg.write_text(self.cfg.read_text(encoding="utf-8").replace(
            "auto_allowlist: true", "auto_allowlist: false"), encoding="utf-8")
        allow, _ = self._sync("203.0.113.0/24\n", ss="0 0 10.1.1.1:22 198.51.100.50:50123\n")
        self.assertNotIn("198.51.100.50", allow)

    def test_min_prefix_из_конфига(self):
        """sources.min_prefix: 16 возвращает /16 в набор"""
        self.cfg.write_text(self.cfg.read_text(encoding="utf-8").replace("min_prefix: 20", "min_prefix: 16"),
                            encoding="utf-8")
        _allow, scan = self._sync("9.9.0.0/16\n8.0.0.0/8\n")
        self.assertIn("9.9.0.0/16", scan)
        self.assertNotIn("8.0.0.0/8", scan)

    def test_curl_только_https(self):
        """curl запускается с ограничением протоколов https (и для редиректов)"""
        self._sync("203.0.113.0/24\n")
        args = (self.out / "curl-args").read_text(encoding="utf-8")
        self.assertIn("--proto =https", args)
        self.assertIn("--proto-redir =https", args)

    def test_источник_с_огромным_охватом_не_принимается(self):
        """список из 1600 сетей /20 (6,5 млн адресов) отклоняется целиком"""
        # 100 * 16 = 1600 сетей /20 по 4096 адресов = 6,5 млн > предела 4 194 304
        listing = "\n".join(f"{a}.{b}.0.0/20" for a in range(20, 120) for b in range(0, 256, 16)) + "\n"
        _allow, scan = self._sync(listing + "203.0.113.0/24\n")
        self.assertEqual(scan, "")   # ничего не загружено: нет предыдущей копии, источник отвергнут


@unittest.skipUnless(shutil.which("bash") and shutil.which("awk"), "нужны bash и awk")
class ПроверкаAllowSshTests(_BashStubs):
    def test_allow_ssh_добавляет_адреса_в_набор(self):
        """allow-ssh.sh вносит текущие SSH-сессии в skipa-allow"""
        (self.out / "ss.txt").write_text("0 0 10.1.1.1:22 198.51.100.50:50123\n", encoding="utf-8")
        r = subprocess.run(["bash", str(ALLOW_SSH), str(self.cfg)], capture_output=True, text=True,
                           env=self._env(), timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        calls = (self.out / "ipset-calls").read_text(encoding="utf-8")
        self.assertIn("add skipa-allow 198.51.100.50 -exist", calls)


import importlib.util

HAVE_PTB = importlib.util.find_spec("telegram") is not None


@unittest.skipUnless(HAVE_PTB, "python-telegram-bot не установлен")
class РазблокировкаЧерезБотаTests(unittest.TestCase):
    def test_unblock_снимает_бан_в_fail2ban_и_пишет_журнал(self):
        """/unblock идёт через banning: unbanip в fail2ban и запись в журнал банов"""
        import asyncio
        from types import SimpleNamespace
        from bot import banning, telegram_layer
        from tests.helpers import make_config

        cfg = make_config(bot_token="1:x", chat_id=555, admin_ids=[555], fail2ban_jail="sshd")
        replies = []

        async def reply(text, **_kw):
            replies.append(text)

        update = SimpleNamespace(
            effective_user=SimpleNamespace(id=555, username="admin"),
            effective_chat=SimpleNamespace(id=555),
            message=SimpleNamespace(reply_text=reply),
        )
        context = SimpleNamespace(bot_data={"config": cfg}, args=["203.0.113.9"])
        f2b_calls = []

        async def fake_run(*cmd):
            f2b_calls.append(cmd)
            return True

        with mock.patch.object(blocker, "unblock_ip", return_value=True), \
             mock.patch.object(blocker, "is_in_db_set", return_value=False), \
             mock.patch.object(banning, "_run", fake_run), \
             mock.patch.object(banning, "_log_ban_action") as journal:
            asyncio.run(telegram_layer.cmd_unblock(update, context))

        self.assertIn(("fail2ban-client", "set", "sshd", "unbanip", "203.0.113.9"), f2b_calls)
        journal.assert_called_once()
        self.assertEqual(journal.call_args.args[0], "unban")
        self.assertTrue(any("разблокирован" in r for r in replies), replies)


class ТолькоHttpsTests(unittest.TestCase):
    def test_http_по_умолчанию_отклоняется(self):
        """URL по обычному http не скачивается, пока это не разрешено в конфиге"""
        from bot import http_client
        with mock.patch.object(http_client, "_opener") as opener:
            self.assertIsNone(http_client._get_bytes("http://example.com/list.txt", 5))
            opener.open.assert_not_called()

    def test_http_разрешается_настройкой(self):
        """sources.allow_insecure_http: true включает http"""
        from bot import http_client
        http_client.configure(allow_insecure_http=True)
        self.addCleanup(http_client.configure, False)
        resp = mock.MagicMock()
        resp.__enter__.return_value.status = 200
        resp.__enter__.return_value.read.return_value = b"1.2.3.0/24"
        with mock.patch.object(http_client, "_opener") as opener:
            opener.open.return_value = resp
            self.assertEqual(http_client._get_bytes("http://example.com/list.txt", 5), b"1.2.3.0/24")

    def test_редирект_на_http_и_ftp_отклоняется(self):
        """https нельзя понизить до http (или уйти на ftp) через редирект"""
        import urllib.error
        import urllib.request
        from bot import http_client
        handler = http_client._NoDowngradeRedirect()
        req = urllib.request.Request("https://example.com/a")
        for target in ("http://evil.example/a", "ftp://evil.example/a", "file:///etc/passwd"):
            with self.assertRaises(urllib.error.URLError, msg=target):
                handler.redirect_request(req, None, 302, "Found", {}, target)


class ЛимитыСписковTests(unittest.TestCase):
    def tearDown(self):
        from bot import ip_lists
        ip_lists.configure_limits(ip_lists.DEFAULT_MIN_PREFIX_V4)

    def test_min_prefix_настраивается(self):
        """по умолчанию /16 отбрасывается, после configure_limits(16) - принимается"""
        from bot import ip_lists
        net = ipaddress.ip_network("9.9.0.0/16")
        self.assertFalse(ip_lists.network_is_acceptable(net))
        ip_lists.configure_limits(16)
        self.assertTrue(ip_lists.network_is_acceptable(net))
        self.assertFalse(ip_lists.network_is_acceptable(ipaddress.ip_network("9.0.0.0/8")))

    def test_охват_считается_грубо_сверху(self):
        """_coverage суммирует адреса сетей и диапазонов"""
        from bot import ip_lists
        nets = [NetEntry(ipaddress.ip_network("1.2.3.0/24"), "x"), NetEntry(ipaddress.ip_network("5.5.5.5/32"), "x")]
        self.assertEqual(ip_lists._coverage(nets, [IPRange(10, 19, "x", "x")]), 256 + 1 + 10)
