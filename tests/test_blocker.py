import ipaddress
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from bot import blocker
from tests.fakes import FakeNetfilter


class BlockerBase(unittest.TestCase):
    ipset = True

    def setUp(self):
        self.nf = FakeNetfilter(ipset=self.ipset)
        self.tmp = tempfile.TemporaryDirectory()
        self.file = Path(self.tmp.name) / "blocked.json"
        patches = [
            mock.patch.object(blocker, "_run", self.nf.run),
            mock.patch.object(blocker.shutil, "which", lambda n: "/sbin/" + n if (n != "ipset" or self.ipset) else None),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        blocker._use_ipset = None
        blocker._allow_nets = []
        blocker._wired_seen = set()
        blocker._settings = blocker.Settings()
        self.addCleanup(self.tmp.cleanup)


class ValidateTests(BlockerBase):
    def test_rejects_dangerous_targets(self):
        """отказ для опасных целей: широкие сети, служебные и частные адреса, мусор, IPv6"""
        for bad in ["0.0.0.0/0", "8.0.0.0/8", "127.0.0.1", "10.1.2.3", "192.168.1.5",
                    "garbage", "", "1.2.3.4/33", "2001:db8::1", "224.0.0.1"]:
            net, reason = blocker.validate_target(bad)
            self.assertIsNone(net, bad)
            self.assertTrue(reason)

    def test_accepts_public(self):
        """публичный IP и сеть /24 принимаются"""
        net, _ = blocker.validate_target("185.224.228.5")
        self.assertEqual(str(net), "185.224.228.5/32")
        net, _ = blocker.validate_target("185.224.228.0/24")
        self.assertEqual(net.prefixlen, 24)

    def test_ipv4_mapped_is_normalized(self):
        """адрес ::ffff:a.b.c.d приводится к IPv4"""
        net, _ = blocker.validate_target("::ffff:185.224.228.5")
        self.assertEqual(str(net), "185.224.228.5/32")

    def test_allowlist_overlap_refused(self):
        """цель, пересекающаяся с allowlist, отклоняется"""
        blocker.set_allowlist([ipaddress.ip_network("185.224.228.7/32")])
        self.assertIsNone(blocker.validate_target("185.224.228.0/24")[0])
        self.assertIsNone(blocker.validate_target("185.224.228.7")[0])
        self.assertIsNotNone(blocker.validate_target("185.224.229.7")[0])


class IpsetModeTests(BlockerBase):
    def test_chain_rules_and_wiring(self):
        """переходы в SKIPA-BLOCK и порядок правил в цепочке (allow, LOG, DROP)"""
        blocker.configure(preload_db=True, drop_enabled=True)
        res = blocker.ensure_wiring()
        self.assertEqual(res, {"INPUT": "fixed", "DOCKER-USER": "fixed"})
        for c in ("INPUT", "DOCKER-USER"):
            self.assertEqual(self.nf.chains[c][0], ("-j", "SKIPA-BLOCK"))
        chain = self.nf.chains["SKIPA-BLOCK"]
        # allowlist RETURN первым, LOG строго перед DROP базы
        self.assertIn("RETURN", chain[0])
        kinds = ["LOG" if "LOG" in r else "DROP" if "DROP" in r else "RETURN" for r in chain]
        self.assertEqual(kinds, ["RETURN", "LOG", "DROP", "DROP"])
        # повторный вызов ничего не меняет
        self.assertEqual(blocker.ensure_wiring(), {"INPUT": "ok", "DOCKER-USER": "ok"})

    def test_wiring_self_heals_after_flush(self):
        """сброшенный переход восстанавливается"""
        blocker.ensure_wiring()
        self.nf.chains["INPUT"].clear()            # ufw reload и т.п.
        self.assertEqual(blocker.ensure_wiring()["INPUT"], "fixed")
        self.assertTrue(blocker.wiring_status()["INPUT"])

    def test_docker_user_appears_later(self):
        """DOCKER-USER, появившийся позже, подключается"""
        del self.nf.chains["DOCKER-USER"]
        self.assertEqual(list(blocker.ensure_wiring()), ["INPUT"])
        self.nf.chains["DOCKER-USER"] = []
        self.assertEqual(blocker.ensure_wiring()["DOCKER-USER"], "fixed")

    def test_notify_mode_has_no_drop(self):
        """в режиме notify правил DROP нет, LOG есть"""
        blocker.configure(preload_db=True, drop_enabled=False)
        blocker.ensure_wiring()
        self.assertFalse(any("DROP" in r for r in self.nf.chains["SKIPA-BLOCK"]))
        self.assertTrue(any("LOG" in r for r in self.nf.chains["SKIPA-BLOCK"]))

    def test_legacy_global_log_removed_when_preload(self):
        """при предзагрузке старый общий LOG удаляется"""
        blocker.configure(preload_db=True)
        blocker.ensure_chain()
        self.nf.chains["INPUT"] = [tuple(["-p", "tcp", "--syn"] + blocker._log_args())]
        blocker.ensure_wiring()
        self.assertNotIn(tuple(["-p", "tcp", "--syn"] + blocker._log_args()), self.nf.chains["INPUT"])

    def test_global_log_kept_without_preload(self):
        """без предзагрузки общий LOG остаётся"""
        blocker.configure(preload_db=False)
        blocker.ensure_wiring()
        self.assertIn(tuple(["-p", "tcp", "--syn"] + blocker._log_args()), self.nf.chains["INPUT"])
        self.assertTrue(blocker.log_rule_present())

    def test_block_with_timeout_and_persist(self):
        """блокировка с таймаутом сохраняется в файл, ручная бессрочная"""
        blocker.configure(auto_timeout_s=3600)
        self.assertTrue(blocker.block_ip("185.224.228.5", blocklist_file=self.file))
        self.assertEqual(self.nf.sets["skipa-dyn"]["185.224.228.5"], 3600)
        data = json.loads(self.file.read_text())["ips"]
        self.assertGreater(data["185.224.228.5"], time.time())
        # ручная блокировка - бессрочно
        self.assertTrue(blocker.block_ip("185.224.229.0/24", 0, blocklist_file=self.file))
        self.assertIsNone(self.nf.sets["skipa-dyn"]["185.224.229.0/24"])
        self.assertEqual(json.loads(self.file.read_text())["ips"]["185.224.229.0/24"], 0)

    def test_block_refused_for_unsafe(self):
        """небезопасная цель не блокируется и не пишется в файл"""
        self.assertFalse(blocker.block_ip("0.0.0.0/0", blocklist_file=self.file))
        self.assertFalse(self.file.exists())

    def test_unblock_in_fresh_process(self):
        """разблокировка работает в новом процессе"""
        blocker.block_ip("185.224.228.5", 0, blocklist_file=self.file)
        blocker._use_ipset = None                   # как в отдельном процессе CLI
        self.assertTrue(blocker.unblock_ip("185.224.228.5", blocklist_file=self.file))
        self.assertNotIn("185.224.228.5", self.nf.sets["skipa-dyn"])
        self.assertEqual(json.loads(self.file.read_text())["ips"], {})

    def test_list_blocked_in_fresh_process(self):
        """список блокировок читается в новом процессе"""
        blocker.block_ip("185.224.228.5", 0, blocklist_file=self.file)
        blocker._use_ipset = None
        self.assertEqual(blocker.list_blocked_ips(), ["185.224.228.5"])

    def test_restore_respects_expiry(self):
        """восстановление учитывает остаток таймаута и отбрасывает просроченные"""
        now = time.time()
        self.file.write_text(json.dumps({"ips": {
            "185.224.228.5": 0, "185.224.228.6": now + 600, "185.224.228.7": now - 10,
        }}))
        self.assertEqual(blocker.restore_persisted_blocks(self.file), 2)
        s = self.nf.sets["skipa-dyn"]
        self.assertIn("185.224.228.5", s)
        self.assertLessEqual(s["185.224.228.6"], 600)
        self.assertNotIn("185.224.228.7", s)
        self.assertNotIn("185.224.228.7", json.loads(self.file.read_text())["ips"])

    def test_restore_old_list_format(self):
        """восстановление читает старый формат файла (список)"""
        self.file.write_text(json.dumps(["185.224.228.5"]))
        self.assertEqual(blocker.restore_persisted_blocks(self.file), 1)

    def test_corrupt_file_is_kept_aside(self):
        """повреждённый файл блокировок переименовывается в .corrupt"""
        self.file.write_text("{broken")
        self.assertEqual(blocker.restore_persisted_blocks(self.file), 0)
        self.assertTrue(self.file.with_name("blocked.json.corrupt").exists())

    def test_preload_and_allowlist_replace_atomically(self):
        """база и allowlist подменяются атомарно через временный набор"""
        self.assertEqual(blocker.preload_db(["1.2.3.0/24", "5.6.7.8/32"]), 2)
        self.assertEqual(set(self.nf.sets["skipa-db"]), {"1.2.3.0/24", "5.6.7.8/32"})
        self.assertNotIn("skipa-db-tmp", self.nf.sets)
        blocker.sync_allowlist([ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("::1/128")])
        self.assertEqual(set(self.nf.sets["skipa-allow"]), {"10.0.0.0/8"})
        self.assertEqual(blocker.db_set_size(), 2)


class LegacyModeTests(BlockerBase):
    ipset = False

    def test_per_ip_rules(self):
        """без ipset: правило на каждый IP, повтор не создаёт дубль"""
        self.assertTrue(blocker.block_ip("185.224.228.5", blocklist_file=self.file))
        self.assertFalse(blocker.using_ipset())
        self.assertIn(("-s", "185.224.228.5", "-j", "DROP"), self.nf.chains["SKIPA-BLOCK"])
        # идемпотентность
        self.assertTrue(blocker.block_ip("185.224.228.5", blocklist_file=self.file))
        self.assertEqual(self.nf.chains["SKIPA-BLOCK"].count(("-s", "185.224.228.5", "-j", "DROP")), 1)
        self.assertEqual(blocker.list_blocked_ips(), ["185.224.228.5"])
        self.assertTrue(blocker.unblock_ip("185.224.228.5", blocklist_file=self.file))
        self.assertEqual(blocker.list_blocked_ips(), [])

    def test_wiring_adds_global_log(self):
        """без ipset: общий LOG ставится после перехода"""
        blocker.ensure_wiring()
        self.assertTrue(blocker.log_rule_present())
        self.assertEqual(self.nf.chains["INPUT"][0], ("-j", "SKIPA-BLOCK"))

    def test_preload_is_noop(self):
        """без ipset предзагрузка ничего не делает"""
        self.assertEqual(blocker.preload_db(["1.2.3.0/24"]), 0)

    def test_restore_legacy(self):
        """без ipset: блокировки восстанавливаются правилами"""
        self.file.write_text(json.dumps({"ips": {"185.224.228.5": 0}}))
        self.assertEqual(blocker.restore_persisted_blocks(self.file), 1)
        self.assertIn(("-s", "185.224.228.5", "-j", "DROP"), self.nf.chains["SKIPA-BLOCK"])


if __name__ == "__main__":
    unittest.main()


class ПорядокПравилTests(BlockerBase):
    def test_пропавшее_log_правило_встаёт_перед_drop(self):
        """восстановленное LOG-правило занимает своё место, а не дописывается после DROP"""
        blocker.configure(preload_db=True, drop_enabled=True)
        blocker.ensure_wiring()
        chain = self.nf.chains["SKIPA-BLOCK"]
        log_rule = next(r for r in chain if "LOG" in r)
        chain.remove(log_rule)                      # правило потеряно (ручной сброс и т.п.)
        blocker.ensure_wiring()
        kinds = ["LOG" if "LOG" in r else "DROP" if "DROP" in r else "RETURN" for r in chain]
        self.assertEqual(kinds, ["RETURN", "LOG", "DROP", "DROP"])

    def test_пропавшее_allow_правило_встаёт_первым(self):
        """восстановленный RETURN для allowlist снова первый"""
        blocker.configure(preload_db=True, drop_enabled=True)
        blocker.ensure_wiring()
        chain = self.nf.chains["SKIPA-BLOCK"]
        chain.remove(next(r for r in chain if "RETURN" in r))
        blocker.ensure_wiring()
        self.assertIn("RETURN", chain[0])
