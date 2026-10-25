"""Тесты функций, перенесённых из ветки test: доп. источники, события, статистика,
бан, дашборд, health-check."""
import asyncio
import base64
import ipaddress
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from bot import banning, events_store, fallback, healthcheck, ip_lists, stats
from bot.ip_lists import fetch_threat_db
from tests.fakes import FakeNetfilter
from tests.helpers import make_config


def run(coro):
    return asyncio.run(coro)


class ExtraSourceTests(unittest.TestCase):
    DROP = "; Spamhaus DROP\n203.0.113.0/24 ; SBL1\n198.51.100.0/24\nbad line\n0.0.0.0/0 ; SBL2\n"

    def _fetch(self, texts, extra, previous=None, json_data=None):
        async def fake_get(url, **kw):
            return texts.get(url, "")

        async def fake_json(url, **kw):
            return json_data

        with mock.patch.object(ip_lists.http_client, "get_text", fake_get), \
             mock.patch.object(ip_lists.http_client, "get_json", fake_json):
            return run(fetch_threat_db("P", "", "bl", "merged", previous=previous, extra_sources=extra))

    def test_generic_parser_comments_and_sanity(self):
        got = ip_lists._parse_generic_cidr_list(self.DROP, "Spamhaus DROP")
        self.assertEqual(sorted(str(e.network) for e in got), ["198.51.100.0/24", "203.0.113.0/24"])

    def test_extra_source_labelled_and_matches(self):
        extra = [{"name": "drop", "display_name": "Spamhaus DROP", "type": "cidr_list", "url": "D", "enabled": True}]
        db = self._fetch({"P": "101.1.1.0/24", "D": self.DROP}, extra)
        self.assertEqual(db.per_source_counts["Spamhaus DROP"], 2)
        self.assertEqual(db.match("203.0.113.9"), "Spamhaus DROP: 203.0.113.0/24")

    def test_disabled_extra_ignored_and_abuseipdb_needs_key(self):
        extra = [
            {"name": "d", "type": "cidr_list", "url": "D", "enabled": False},
            {"name": "a", "display_name": "AbuseIPDB", "type": "abuseipdb", "api_key": "", "enabled": True},
        ]
        db = self._fetch({"P": "101.1.1.0/24", "D": self.DROP}, extra)
        self.assertEqual(list(db.per_source_counts), ["skipa"])
        self.assertFalse(db.degraded)

    def test_abuseipdb_json(self):
        extra = [{"name": "a", "display_name": "AbuseIPDB", "type": "abuseipdb", "api_key": "k", "enabled": True}]
        db = self._fetch({"P": "101.1.1.0/24"}, extra,
                         json_data={"data": [{"ipAddress": "8.8.4.4"}, {"ipAddress": "oops"}, {}]})
        self.assertEqual(db.match("8.8.4.4"), "AbuseIPDB: 8.8.4.4/32")

    def test_extra_down_uses_previous(self):
        extra = [{"name": "drop", "display_name": "Spamhaus DROP", "type": "cidr_list", "url": "D"}]
        good = self._fetch({"P": "101.1.1.0/24", "D": self.DROP}, extra)
        db = self._fetch({"P": "101.1.1.0/24"}, extra, previous=good)
        self.assertTrue(db.degraded)
        self.assertIsNotNone(db.match("203.0.113.9"))


class EventsAndStatsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        d = Path(self.tmp.name)
        for mod, attrs in ((events_store, {"DATA_DIR": d, "EVENTS_FILE": d / "events.jsonl"}),):
            for k, v in attrs.items():
                p = mock.patch.object(mod, k, v)
                p.start()
                self.addCleanup(p.stop)

    def _enriched(self):
        return mock.Mock(country_code="DE", country_name="Germany", asn="AS1", org_name="Hoster <b>GmbH</b>")

    def test_record_load_prune(self):
        for i in range(5):
            events_store.record_event(f"1.2.3.{i}", "1.2.3.0/24", "skipa", "poll", self._enriched(), 22)
        self.assertEqual(len(events_store.load_events()), 5)
        events_store.prune_events(keep_last=2)
        self.assertEqual([e["ip"] for e in events_store.load_events()], ["1.2.3.3", "1.2.3.4"])
        self.assertEqual(len(events_store.load_events(since_ts=time.time() + 10)), 0)

    def test_summary_text_escapes_html_and_histogram_without_matplotlib(self):
        events_store.record_event("1.2.3.4", "x", "skipa", "poll", self._enriched(), 22)
        events_store.record_event("1.2.3.4", "x", "skipa", "poll", self._enriched(), 80)
        with mock.patch.dict("sys.modules", {"matplotlib": None, "matplotlib.pyplot": None}):
            summary, chart, hist = stats.stats_for_period(7)
        self.assertIsNone(chart)
        self.assertEqual((summary["total_hits"], summary["unique_ips"]), (2, 1))
        text = stats.format_summary_text(summary, "неделю")
        self.assertIn("&lt;b&gt;GmbH", text)          # org_name экранирован
        self.assertIn("█", hist)

    def test_empty_period(self):
        summary, chart, hist = stats.stats_for_period(7)
        self.assertEqual(summary["total_hits"], 0)
        self.assertIsNone(chart)
        self.assertEqual(hist, "")


class BanningTests(unittest.TestCase):
    def setUp(self):
        from bot import blocker
        self.blocker = blocker
        self.nf = FakeNetfilter()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        d = Path(self.tmp.name)
        for target, attr, val in (
            (blocker, "_run", self.nf.run),
            (blocker.shutil, "which", lambda n: "/sbin/" + n),
            (blocker, "BLOCKLIST_FILE_DEFAULT", d / "blocked.json"),
            (banning, "DATA_DIR", d),
            (banning, "BAN_LOG_FILE", d / "bans.jsonl"),
        ):
            p = mock.patch.object(target, attr, val)
            p.start()
            self.addCleanup(p.stop)
        blocker._use_ipset = None
        blocker._allow_nets = []
        blocker._settings = blocker.Settings()
        self.d = d

    def test_ban_unban_history_and_timeout(self):
        ok, _ = run(banning.ban_ip("185.224.228.5", duration_minutes=30, reason="t", by="@admin"))
        self.assertTrue(ok)
        self.assertEqual(self.nf.sets["skipa-dyn"]["185.224.228.5"], 1800)
        self.assertEqual(run(banning.list_banned()), ["185.224.228.5"])
        self.assertTrue(run(banning.unban_ip("185.224.228.5", by="@admin")))
        self.assertEqual(run(banning.list_banned()), [])
        actions = [json.loads(l)["action"] for l in (self.d / "bans.jsonl").read_text().splitlines()]
        self.assertEqual(actions, ["ban", "unban"])

    def test_ban_refuses_unsafe_target(self):
        ok, reason = run(banning.ban_ip("10.0.0.5"))
        self.assertFalse(ok)
        self.assertTrue(reason)
        self.assertFalse((self.d / "bans.jsonl").exists())

    def test_fail2ban_mirror_called(self):
        calls = []

        async def fake_run(*args):
            calls.append(args)
            return 0, "", ""
        with mock.patch.object(banning, "_run", fake_run):
            run(banning.ban_ip("185.224.228.5", fail2ban_jail="sshd"))
            run(banning.unban_ip("185.224.228.5", fail2ban_jail="sshd"))
        self.assertEqual([c[3] for c in calls], ["banip", "unbanip"])


class PendingMarkupTests(unittest.TestCase):
    def test_markup_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            with mock.patch.object(fallback, "DATA_DIR", d), mock.patch.object(fallback, "PENDING_FILE", d / "p.jsonl"):
                fallback.queue_pending_alert(1, "t", {"inline_keyboard": [[{"text": "x", "callback_data": "ban:1.2.3.4"}]]})
                rec = fallback.drain_pending()[0]
                self.assertEqual(rec["reply_markup"]["inline_keyboard"][0][0]["callback_data"], "ban:1.2.3.4")


class HealthcheckTests(unittest.TestCase):
    def test_heartbeat(self):
        self.assertIsNone(healthcheck.seconds_since_last("nope"))
        healthcheck.heartbeat("x")
        self.assertLess(healthcheck.seconds_since_last("x"), 1)
        self.assertIn("x", healthcheck.snapshot())


class ConfigTests(unittest.TestCase):
    def test_new_sections_and_derived_flags(self):
        from bot.config import Config
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "c.yaml"
            p.write_text(
                "action: {mode: notify}\n"
                "monitoring: {method: poll}\n"
                "banning: {enabled: true, auto_ban_new_hits: true, auto_ban_duration_minutes: 15}\n"
                "dashboard: {enabled: true, port: 9000}\n"
                "digest: {weekday: 9, hour: 99}\n"
                "sources: {extra: [{name: a, url: u}, 'junk']}\n"
            )
            c = Config.load(p)
        self.assertTrue(c.drop_enabled and c.firewall_needed)      # автобан включает блокировку
        self.assertEqual(c.auto_block_timeout_s, 900)
        self.assertEqual((c.dashboard_port, c.digest_weekday, c.digest_hour), (9000, 6, 23))
        self.assertEqual(len(c.extra_sources), 1)

    def test_ban_button_alone_needs_firewall_but_not_auto_drop(self):
        c = make_config(action_mode="notify", method="poll", ban_enabled=True)
        self.assertTrue(c.firewall_needed)
        self.assertFalse(c.drop_enabled)


class DashboardTests(unittest.TestCase):
    def _request(self, config, path, auth=None, method="GET"):
        from bot import webapp

        async def go():
            db = ip_lists.ThreatDB(networks=[ip_lists.NetEntry(ipaddress.ip_network("1.2.3.0/24"), "skipa")],
                                   per_source_counts={"skipa": 1}, source_line_count=1, last_update_ts=time.time())
            server = await asyncio.start_server(
                lambda r, w: webapp._handle(r, w, lambda: db, config), "127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]
            r, w = await asyncio.open_connection("127.0.0.1", port)
            hdr = f"{method} {path} HTTP/1.1\r\nHost: x\r\n" + (f"Authorization: {auth}\r\n" if auth else "") + "\r\n"
            w.write(hdr.encode())
            await w.drain()
            data = await asyncio.wait_for(r.read(), 5)
            w.close()
            server.close()
            await server.wait_closed()
            return data.decode()

        return run(go())

    def test_auth_and_routes(self):
        cfg = make_config(dashboard_username="u", dashboard_password="p")
        self.assertIn("401", self._request(cfg, "/api/status").split("\r\n")[0])
        bad = "Basic " + base64.b64encode(b"u:wrong").decode()
        self.assertIn("401", self._request(cfg, "/api/status", bad).split("\r\n")[0])
        good = "Basic " + base64.b64encode(b"u:p").decode()
        with mock.patch("bot.blocker.list_blocked_ips", return_value=["9.9.9.9"]):
            out = self._request(cfg, "/api/status", good)
        self.assertIn("200 OK", out.split("\r\n")[0])
        body = json.loads(out.split("\r\n\r\n", 1)[1])
        self.assertEqual((body["total_records"], body["banned_ips"]), (1, ["9.9.9.9"]))
        self.assertIn("Skipa Watchdog", self._request(cfg, "/", good))
        self.assertIn("404", self._request(cfg, "/nope", good).split("\r\n")[0])
        self.assertIn("405", self._request(cfg, "/", good, method="POST").split("\r\n")[0])

    def test_open_when_no_credentials_configured(self):
        cfg = make_config()
        with mock.patch("bot.blocker.list_blocked_ips", return_value=[]):
            self.assertIn("200 OK", self._request(cfg, "/api/status").split("\r\n")[0])

    def test_html_escapes_external_fields(self):
        from bot import webapp
        self.assertIn("esc(e.org_name)", webapp.DASHBOARD_HTML)
        self.assertNotIn("${e.org_name", webapp.DASHBOARD_HTML)


if __name__ == "__main__":
    unittest.main()


class ConntrackTests(unittest.TestCase):
    LINES = (
        "ipv4     2 tcp      6 431999 ESTABLISHED src=185.224.228.5 dst=203.0.113.7 sport=51234 dport=443 "
        "src=172.17.0.2 dst=185.224.228.5 sport=443 dport=51234 [ASSURED] mark=0 use=1\n"
        "ipv4     2 tcp      6 59 SYN_SENT src=185.224.228.9 dst=203.0.113.7 sport=40000 dport=3306 [UNREPLIED] "
        "src=203.0.113.7 dst=185.224.228.9 sport=3306 dport=40000 mark=0 use=1\n"
        "ipv4     2 udp      17 29 src=1.1.1.1 dst=203.0.113.7 sport=53 dport=53 src=203.0.113.7 dst=1.1.1.1 sport=53 dport=53 use=1\n"
        "ipv6     10 tcp     6 100 TIME_WAIT src=::ffff:185.224.228.7 dst=2001:db8::1 sport=1 dport=22 src=2001:db8::1 dst=::ffff:185.224.228.7 sport=22 dport=1 use=1\n"
        "garbage\n"
    )

    def test_parse_lines(self):
        from bot import monitor
        got = [monitor.parse_conntrack_line(l) for l in self.LINES.splitlines()]
        self.assertEqual(got[0], ("185.224.228.5", 51234, 443))      # DNAT на контейнер: видим клиента
        self.assertEqual(got[1], ("185.224.228.9", 40000, 3306))     # одиночный SYN без ответа
        self.assertIsNone(got[2])                                    # udp пропущен
        self.assertEqual(got[3][0], "185.224.228.7")                 # ::ffff: нормализован
        self.assertIsNone(got[4])

    def test_poll_finds_docker_published_port_via_conntrack(self):
        from bot import monitor
        db = ip_lists.ThreatDB(networks=[ip_lists.NetEntry(ipaddress.ip_network("185.224.228.0/24"), "skipa")])
        hits = []

        async def on_hit(h):
            hits.append(h)
            return True

        async def go():
            task = asyncio.create_task(monitor.poll_connections_loop(
                lambda: db, [], 1, monitor.Deduper(60), on_hit, use_conntrack=True))
            await asyncio.sleep(0.5)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        parsed = [monitor.parse_conntrack_line(l) for l in self.LINES.splitlines()]
        with mock.patch.object(monitor, "read_conntrack", lambda: [p for p in parsed if p]), \
             mock.patch.object(monitor, "read_tcp_table", lambda: []):
            run(go())
        self.assertEqual(sorted(h.ip for h in hits), ["185.224.228.5", "185.224.228.7", "185.224.228.9"])
        self.assertTrue(all(h.method == "poll" for h in hits))
