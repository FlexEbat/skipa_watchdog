"""Пакет тестов.

Защита хоста: ни один тест не должен менять НАСТОЯЩИЕ iptables/ipset. Если запустить набор от
root на машине с установленными ipset/iptables, неподменённые вызовы bot.blocker создавали бы
реальные наборы и цепочку SKIPA-BLOCK прямо в боевом фаерволе. Поэтому по умолчанию _run для
этих команд отказывает так же, как при отсутствии программ; тесты, которым нужен netfilter,
подменяют _run своей моделью (tests.fakes.FakeNetfilter) через mock.patch.object.
Сквозной сценарий на настоящем ядре вынесен в tests/test_real_netfilter.py и включается явно.
"""
from bot import blocker

_original_run = blocker._run
_NETFILTER_TOOLS = ("iptables", "ip6tables", "ipset", "iptables-save", "iptables-restore")


def _guarded_run(cmd, timeout=15, input_text=None):
    if cmd and str(cmd[0]).split("/")[-1] in _NETFILTER_TOOLS:
        return False, "tests: обращение к настоящему netfilter заблокировано (подмените bot.blocker._run)"
    return _original_run(cmd, timeout=timeout, input_text=input_text)


blocker._run = _guarded_run
