"""Проверки безопасности: канонизация целей разблокировки, аргументы fail2ban, лимиты дашборда."""
import asyncio
import unittest
from unittest import mock

from bot import banning, blocker, webapp


class CanonicalTargetTests(unittest.TestCase):
    def test_нормальные_формы(self):
        """одиночный адрес и сеть приводятся к каноническому виду"""
        self.assertEqual(blocker.canonical_target("1.2.3.4"), "1.2.3.4")
        self.assertEqual(blocker.canonical_target("1.2.3.4/32"), "1.2.3.4")
        self.assertEqual(blocker.canonical_target("1.2.3.4/24"), "1.2.3.0/24")
        self.assertEqual(blocker.canonical_target("::ffff:1.2.3.4"), "1.2.3.4")

    def test_мусор_отбрасывается(self):
        """опции, пробелы, хвост после маски и IPv6 не доходят до ipset и fail2ban-client"""
        for bad in ("", "--all", "1.2.3.4 --all", "1.2.3.4/", "1.2.3.4/24/x", "1.2.3.4/33", "1.2.3.4/abc",
                    "-x", "1.2.3.4;id", "2001:db8::1", "not-an-ip", "1.2.3.4\n5.6.7.8"):
            self.assertIsNone(blocker.canonical_target(bad), repr(bad))

    def test_unblock_не_передаёт_мусор_в_ipset(self):
        """unblock_ip отказывает до любого вызова ipset/iptables"""
        with mock.patch.object(blocker, "_run") as run, mock.patch.object(blocker, "_ipt") as ipt:
            self.assertFalse(blocker.unblock_ip("1.2.3.4/24/--all"))
            self.assertFalse(blocker.unblock_ip("--all"))
        run.assert_not_called()
        ipt.assert_not_called()


class Fail2banArgsTests(unittest.TestCase):
    def test_в_fail2ban_уходит_каноническая_форма(self):
        """и бан, и разбан передают в fail2ban-client только IPv4/сеть"""
        calls = []

        async def fake_run(*args):
            calls.append(args)
            return 0, "", ""

        with mock.patch.object(banning, "_run", fake_run), \
                mock.patch.object(blocker, "block_ip", return_value=True), \
                mock.patch.object(blocker, "unblock_ip", return_value=True), \
                mock.patch.object(banning, "_log_ban_action"):
            self.assertTrue(asyncio.run(banning.ban_ip("8.8.8.8/32", fail2ban_jail="sshd"))[0])
            self.assertEqual(calls[-1], ("fail2ban-client", "set", "sshd", "banip", "8.8.8.8"))
            self.assertTrue(asyncio.run(banning.unban_ip("8.8.8.8/32", fail2ban_jail="sshd")))
        self.assertEqual(calls[-1], ("fail2ban-client", "set", "sshd", "unbanip", "8.8.8.8"))


class DashboardLimitsTests(unittest.TestCase):
    def test_соединения_сверх_лимита_закрываются(self):
        """при занятых слотах новое соединение закрывается без разбора запроса"""
        async def go():
            slots = asyncio.Semaphore(1)
            await slots.acquire()
            writer = mock.Mock()
            await webapp._handle(mock.Mock(), writer, lambda: None, mock.Mock(), slots)
            writer.close.assert_called_once()

        asyncio.run(go())

    def test_лимит_и_пауза_заданы(self):
        """константы защиты от перебора пароля и исчерпания соединений на месте"""
        self.assertGreaterEqual(webapp.AUTH_FAIL_DELAY, 0.5)
        self.assertLessEqual(webapp.MAX_CONNECTIONS, 100)


if __name__ == "__main__":
    unittest.main()
