import asyncio
import ipaddress
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from bot import fallback, ip_lists, monitor
from bot.ip_lists import NetEntry, ThreatDB, fetch_threat_db, has_data, needs_update, normalize_ip


def run(coro):
    return asyncio.run(coro)


class ParseTests(unittest.TestCase):
    def test_too_wide_networks_dropped(self):
        got = ip_lists._parse_cidr_list("0.0.0.0/0\n8.0.0.0/8\n1.2.3.0/24\n5.5.5.5\nbad\n# c\n")
        self.assertEqual(sorted(str(e.network) for e in got), ["1.2.3.0/24", "5.5.5.5/32"])

    def test_mixed_list_sanity(self):
        nets, ranges = ip_lists._parse_mixed_list(
            "0.0.0.0/0\n1.1.1.0/24\n2.2.2.2-2.2.2.9\n9.9.9.9-1.1.1.1\n0.0.0.0-255.255.255.255\n", "x"
        )
        self.assertEqual([str(n.network) for n in nets], ["1.1.1.0/24"])
        self.assertEqual(len(ranges), 1)

    def test_ipv4_mapped_matches(self):
        db = ThreatDB(networks=[NetEntry(ipaddress.ip_network("1.2.3.0/24"), "skipa")])
        self.assertIsNotNone(db.match("1.2.3.4"))
        self.assertIsNotNone(db.match("::ffff:1.2.3.4"))
        self.assertIsNone(db.match("::ffff:9.9.9.9"))
        self.assertEqual(str(normalize_ip("::ffff:1.2.3.4")), "1.2.3.4")

    def test_ipset_entries_expand_ranges(self):
        nets, ranges = ip_lists._parse_mixed_list("2.2.2.0-2.2.2.130\n1.1.1.0/24\n", "x")
        db = ThreatDB(networks=nets, ranges=ranges)
        self.assertEqual(sorted(db.ipset_entries()), ["1.1.1.0/24", "2.2.2.0/25", "2.2.2.128/31", "2.2.2.130/32"])


class FetchTests(unittest.TestCase):
    PRIMARY = "\n".join(f"10{i}.1.1.0/24" for i in range(1, 6))  # 101..105 -> публичные
    BL = "7.7.7.0/24\n8.8.8.8\n"

    def _fetch(self, texts, previous=None, active="merged"):
        async def fake_get(url, **kw):
            return texts.get(url, "")
        with mock.patch.object(ip_lists.http_client, "get_text", fake_get):
            return run(fetch_threat_db("P", "B", "bl", active, previous=previous))

    def test_full_success(self):
        db = self._fetch({"P": self.PRIMARY, "B": self.BL})
        self.assertFalse(db.degraded)
        self.assertEqual(db.source_line_count, 7)

    def test_one_source_down_keeps_previous_and_marks_degraded(self):
        good = self._fetch({"P": self.PRIMARY, "B": self.BL})
        db = self._fetch({"P": self.PRIMARY, "B": ""}, previous=good)
        self.assertTrue(db.degraded)
        self.assertEqual(db.source_line_count, 7)          # blacklist сохранён из прошлой версии
        self.assertIsNotNone(db.match("7.7.7.7"))

    def test_shrunk_source_rejected(self):
        good = self._fetch({"P": self.PRIMARY, "B": self.BL})
        db = self._fetch({"P": "101.1.1.0/24", "B": self.BL}, previous=good)   # 1 из 5 < 50%
        self.assertTrue(db.degraded)
        self.assertEqual(db.per_source_counts["skipa"], 5)

    def test_everything_down_without_previous_is_empty(self):
        db = self._fetch({})
        self.assertFalse(has_data(db))

    def test_degraded_retried_within_hour(self):
        db = ThreatDB(networks=[NetEntry(ipaddress.ip_network("1.2.3.0/24"), "s")],
                      last_update_ts=time.time() - 3700, degraded=True)
        self.assertTrue(needs_update(db, 7))
        db.degraded = False
        self.assertFalse(needs_update(db, 7))

    def test_cache_roundtrip_keeps_degraded(self):
        db = ThreatDB(networks=[NetEntry(ipaddress.ip_network("1.2.3.0/24"), "s")], degraded=True)
        self.assertTrue(ThreatDB.from_json(json.loads(json.dumps(db.to_json()))).degraded)


class DbUpdateTests(unittest.TestCase):
    def test_refresh_keeps_old_data_when_sources_down(self):
        from bot import dbupdate
        old = ThreatDB(networks=[NetEntry(ipaddress.ip_network("1.2.3.0/24"), "skipa")])
        state = {"db": old}
        cfg = mock.Mock(primary_list_url="P", blacklist_url="B", blacklist_name="bl", active_list="merged", extra_sources=[])
        async def fake_get(url, **kw):
            return ""
        with mock.patch.object(ip_lists.http_client, "get_text", fake_get):
            msg = run(dbupdate.refresh_db(cfg, state))
        # защита не пропала: старые записи сохранены, база помечена неполной
        self.assertIsNotNone(state["db"].match("1.2.3.4"))
        self.assertTrue(state["db"].degraded)
        self.assertIn("недоступна", msg)

    def test_refresh_without_any_data_leaves_state_alone(self):
        from bot import dbupdate
        state = {"db": None}
        cfg = mock.Mock(primary_list_url="P", blacklist_url="B", blacklist_name="bl", active_list="merged", extra_sources=[])
        async def fake_get(url, **kw):
            return ""
        with mock.patch.object(ip_lists.http_client, "get_text", fake_get):
            msg = run(dbupdate.refresh_db(cfg, state))
        self.assertIsNone(state["db"])
        self.assertIn("оставил старую", msg)


class MonitorTests(unittest.TestCase):
    def test_hex_decode_ipv4_and_mapped(self):
        self.assertEqual(monitor._hex_to_ip_port("0100A8C0:0050", False), ("192.168.0.1", 80))
        # 1.2.3.4 как ::ffff:1.2.3.4 в /proc/net/tcp6
        self.assertEqual(monitor._hex_to_ip_port("0000000000000000FFFF000004030201:01BB", True), ("1.2.3.4", 443))

    def test_only_inbound_connections(self):
        table = [
            ("0A", "0.0.0.0", 0, 443),             # LISTEN :443
            ("01", "1.2.3.4", 55000, 443),         # входящее -> да
            ("03", "5.6.7.8", 40000, 443),         # SYN_RECV -> да
            ("02", "9.9.9.9", 443, 51000),         # SYN_SENT: исходящее -> нет
            ("01", "9.9.9.9", 443, 51001),         # исходящее установленное (локальный порт не слушается) -> нет
        ]
        got = {ip for ip, _rp, _lp in monitor._inbound_connections(table)}
        self.assertEqual(got, {"1.2.3.4", "5.6.7.8"})

    def test_established_peers(self):
        with mock.patch.object(monitor, "read_tcp_table", lambda: [("01", "7.7.7.7", 5000, 22), ("01", "8.8.8.8", 5000, 80)]):
            self.assertEqual(monitor.established_peers({22}), {"7.7.7.7"})

    def test_dedup_retry_after_failure(self):
        d = monitor.Deduper(60)
        self.assertTrue(d.should_alert("1.2.3.4"))
        self.assertFalse(d.should_alert("1.2.3.4"))
        d.penalize_retry("1.2.3.4", 60)
        self.assertFalse(d.should_alert("1.2.3.4"))
        d._last_alert["1.2.3.4"] -= 61            # прошла минута
        self.assertTrue(d.should_alert("1.2.3.4"))

    def test_dispatch_survives_handler_error_and_penalizes(self):
        d = monitor.Deduper(60)
        hit = monitor.Hit(ip="1.2.3.4", matched_source="x", local_port=1, method="poll")
        async def boom(h):
            raise RuntimeError("x")
        d.should_alert(hit.ip)
        run(monitor._dispatch(boom, d, hit))       # не должно бросить
        d._last_alert[hit.ip] -= 61
        self.assertTrue(d.should_alert(hit.ip))


class FallbackTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        d = Path(self.tmp.name)
        for name, val in (("DATA_DIR", d), ("PENDING_FILE", d / "pending.jsonl")):
            p = mock.patch.object(fallback, name, val)
            p.start()
            self.addCleanup(p.stop)

    def test_drain_then_requeue_keeps_alerts_added_meanwhile(self):
        fallback.queue_pending_alert(1, "a")
        fallback.queue_pending_alert(1, "b")
        records = fallback.drain_pending()
        self.assertEqual([r["text"] for r in records], ["a", "b"])
        fallback.queue_pending_alert(1, "c")              # пришёл, пока "отправляли"
        fallback.requeue(records[1:])                     # b не отправился
        self.assertEqual([r["text"] for r in fallback.load_pending()], ["c", "b"])

    def test_ttl_and_cap(self):
        old = time.time() - fallback.PENDING_TTL_SECONDS - 10
        fallback.queue_pending_alert(1, "old", ts=old)
        for i in range(fallback.MAX_PENDING + 5):
            fallback.queue_pending_alert(1, f"n{i}")
        got = fallback.drain_pending()
        self.assertEqual(len(got), fallback.MAX_PENDING)
        self.assertNotIn("old", [r["text"] for r in got])

    def test_strip_html_unescapes(self):
        self.assertEqual(fallback._strip_html("<b>A &amp; B</b>"), "A & B")


if __name__ == "__main__":
    unittest.main()
