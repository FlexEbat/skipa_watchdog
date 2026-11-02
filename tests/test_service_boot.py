"""Режим «только сервис»: сохранение наборов после перезагрузки, flock, минимум записей,
дополнительные источники, проверка правил, TCP-флаги. Без root: поддельные ipset/iptables."""
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from tests import netfake

ROOT = Path(__file__).resolve().parent.parent
SVC = ROOT / "service"
HAVE = bool(shutil.which("bash") and shutil.which("awk") and shutil.which("flock"))


@unittest.skipUnless(HAVE, "нужны bash, awk и flock")
class _Env(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.d = Path(self.tmp.name)
        self.bin = self.d / "bin"
        netfake.install(self.bin)
        self.env = netfake.env_for(dict(os.environ), self.d, self.bin)
        self.env["FAKE"] = str(self.d / "fake")
        (self.d / "fake").mkdir()
        self.conf = self.d / "config.yaml"
        text = (ROOT / "config.example.yaml").read_text(encoding="utf-8")
        self.conf.write_text(text.replace("/var/log/skipa_watchdog", str(self.d / "log")), encoding="utf-8")
        # curl отдаёт файлы из $FAKE по подстроке URL; тело stdin (-K -) сохраняет
        self._script(self.bin / "curl", r'''
for a in "$@"; do case "$a" in http*) url="$a";; esac; done
echo "$@" >> "$FAKE/curl-args"
case "$url" in
  *skipa_cidr*) cat "$FAKE/primary" 2>/dev/null;;
  *blacklist.txt*) cat "$FAKE/blacklist" 2>/dev/null;;
  *spamhaus*) cat "$FAKE/spamhaus" 2>/dev/null;;
  *abuseipdb*) cat > "$FAKE/abuse-stdin"; cat "$FAKE/abuse" 2>/dev/null;;
esac''')
        self.set_list("primary", [f"45.{i}.0.0/24" for i in range(1, 13)])
        self.set_list("blacklist", [])

    @staticmethod
    def _script(path: Path, body: str) -> None:
        path.write_text("#!/usr/bin/env bash\n" + body + "\n", encoding="utf-8")
        path.chmod(0o755)

    def set_list(self, name: str, lines: list[str]) -> None:
        (self.d / "fake" / name).write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")

    def edit_conf(self, old: str, new: str, count: int = 1) -> None:
        s = self.conf.read_text(encoding="utf-8")
        assert old in s, old
        self.conf.write_text(s.replace(old, new, count), encoding="utf-8")

    def run_script(self, name: str, *args: str, env: dict | None = None) -> subprocess.CompletedProcess:
        return subprocess.run(["bash", str(SVC / name), *args], capture_output=True, text=True,
                              env={**self.env, **(env or {})}, timeout=60)

    def sync(self) -> subprocess.CompletedProcess:
        return self.run_script("sync-lists.sh", str(self.conf))

    def import_blocks(self, *nets: str) -> subprocess.CompletedProcess:
        """перенос бессрочных блокировок из варианта с ботом (единственный путь в skipa-manual)"""
        f = self.d / f"carry-{abs(hash(nets))}.txt"
        f.write_text("\n".join(nets) + "\n", encoding="utf-8")
        return self.run_script("blockctl.sh", "import-blocks", str(f))

    def members(self, name: str) -> list[str]:
        p = self.d / "ipsets" / name
        return [x for x in p.read_text(encoding="utf-8").split() if x] if p.exists() else []

    @property
    def save_file(self) -> Path:
        return self.d / "state" / "ipsets.save"


class SaveAndRestoreTests(_Env):
    def test_после_синхронизации_наборы_сохранены(self):
        """sync-lists пишет файл для восстановления: права 600, наборы scanners и allow внутри"""
        r = self.sync()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(oct(self.save_file.stat().st_mode & 0o777), "0o600")
        text = self.save_file.read_text(encoding="utf-8")
        self.assertIn("add skipa-scanners 45.5.0.0/24", text)
        self.assertIn("create skipa-allow", text)

    def test_перенесённые_блокировки_и_белый_список_сохраняются(self):
        """import-blocks/allow/unallow обновляют файл сохранения; allow снимает перенесённую блокировку"""
        self.sync()
        r = self.import_blocks("8.8.8.0/24")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip().splitlines()[-1], "1")
        self.assertIn("add skipa-manual 8.8.8.0/24", self.save_file.read_text(encoding="utf-8"))
        env = {"SKIPA_CONFIG": str(self.conf)}
        self.assertEqual(self.run_script("blockctl.sh", "allow", "8.8.8.0/24", env=env).returncode, 0)
        self.assertNotIn("add skipa-manual 8.8.8.0/24", self.save_file.read_text(encoding="utf-8"))
        self.assertEqual(self.run_script("blockctl.sh", "allow", "203.0.113.5", env=env).returncode, 0)
        self.assertIn("add skipa-allow 203.0.113.5", self.save_file.read_text(encoding="utf-8"))
        self.assertEqual(self.run_script("blockctl.sh", "unallow", "203.0.113.5", env=env).returncode, 0)
        self.assertNotIn("add skipa-allow 203.0.113.5", self.save_file.read_text(encoding="utf-8"))

    def test_команд_block_и_unblock_в_сервис_режиме_нет(self):
        """block/unblock удалены совсем: это неизвестные команды, набор не меняется"""
        self.sync()
        text = (SVC / "blockctl.sh").read_text(encoding="utf-8")
        self.assertNotIn("block)", text.replace("import-blocks)", ""))
        for cmd in ("block", "unblock"):
            r = self.run_script("blockctl.sh", cmd, "8.8.8.0/24")
            self.assertNotEqual(r.returncode, 0, cmd)
            self.assertIn("Использование", r.stderr)
        self.assertEqual(self.members("skipa-manual"), [])

    def test_перенос_отбрасывает_частные_и_слишком_широкие_сети(self):
        """import-blocks проходит ту же проверку целей, что и раньше блокировка: мусор не попадает в набор"""
        self.sync()
        r = self.import_blocks("10.0.0.0/8", "0.0.0.0/0", "192.168.1.5", "не-адрес", "8.8.4.0/24")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip().splitlines()[-1], "1")
        self.assertEqual(self.members("skipa-manual"), ["8.8.4.0/24"])

    def test_после_перезагрузки_наборы_возвращаются(self):
        """boot.sh sets восстанавливает базу и ручные блокировки из файла"""
        self.sync()
        self.import_blocks("8.8.8.0/24")
        shutil.rmtree(self.d / "ipsets")                      # «перезагрузка»: память ядра пуста
        self.assertEqual(self.members("skipa-scanners"), [])
        r = self.run_script("boot.sh", "sets", str(self.conf))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("восстановлены", r.stdout)
        self.assertIn("45.5.0.0/24", self.members("skipa-scanners"))
        self.assertIn("8.8.8.0/24", self.members("skipa-manual"))

    def test_без_файла_создаются_пустые_наборы(self):
        """первая загрузка после обновления: файла нет, но наборы обязаны существовать для чужих правил"""
        r = self.run_script("boot.sh", "sets", str(self.conf))
        self.assertEqual(r.returncode, 0, r.stderr)
        for name in ("skipa-scanners", "skipa-manual", "skipa-allow"):
            self.assertTrue((self.d / "ipsets" / name).exists(), name)

    def test_сбой_восстановления_не_оставляет_без_наборов(self):
        """если restore упал, наборы всё равно создаются (иначе iptables-restore отвергнет весь файл правил)"""
        self.sync()
        shutil.rmtree(self.d / "ipsets")
        r = self.run_script("boot.sh", "sets", str(self.conf), env={"FAKE_IPSET_RESTORE_FAIL": "1"})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("ошибкой", r.stdout)
        self.assertTrue((self.d / "ipsets" / "skipa-manual").exists())

    def test_неизвестная_команда_boot(self):
        """boot.sh без допустимого аргумента - код 1 и справка"""
        self.assertNotEqual(self.run_script("boot.sh", "что-то", str(self.conf)).returncode, 0)

    def test_пустой_набор_не_затирает_прежний_файл(self):
        """если сохранять нечего (наборов нет), прошлый файл остаётся"""
        self.sync()
        before = self.save_file.read_text(encoding="utf-8")
        shutil.rmtree(self.d / "ipsets")
        script = f'source "{SVC / "lib-ipset.sh"}"; save_ipsets'
        self.assertEqual(subprocess.run(["bash", "-c", script], env=self.env, capture_output=True).returncode, 0)
        self.assertEqual(self.save_file.read_text(encoding="utf-8"), before)


class LockTests(_Env):
    def test_второй_претендент_ждёт_и_получает_отказ(self):
        """flock: пока блокировка занята, вторая операция выходит по таймауту"""
        holder = subprocess.Popen(
            ["bash", "-c", f'source "{SVC / "lib-ipset.sh"}"; acquire_ipset_lock 5 && echo held && sleep 4'],
            env=self.env, stdout=subprocess.PIPE, text=True)
        self.assertEqual(holder.stdout.readline().strip(), "held")
        env = dict(self.env)
        env.pop("SKIPA_IPSET_LOCKED", None)
        r = subprocess.run(["bash", "-c", f'source "{SVC / "lib-ipset.sh"}"; acquire_ipset_lock 1'],
                           env=env, capture_output=True, text=True)
        holder.kill()
        holder.wait()
        holder.stdout.close()
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("не завершилась", r.stderr)

    def test_вложенный_вызов_не_ждёт_сам_себя(self):
        """дочерний скрипт видит SKIPA_IPSET_LOCKED и не блокируется на блокировке родителя"""
        script = (f'source "{SVC / "lib-ipset.sh"}"; acquire_ipset_lock 2 || exit 3; '
                  f'bash -c \'source "{SVC / "lib-ipset.sh"}"; acquire_ipset_lock 1\'')
        r = subprocess.run(["bash", "-c", script], env=self.env, capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_параллельные_blockctl_не_теряют_записи(self):
        """два одновременных переноса обе попадают в файл сохранения"""
        self.sync()
        files = []
        for net in ("9.9.9.0/24", "9.9.8.0/24"):
            f = self.d / f"par-{net.split('/')[0]}.txt"
            f.write_text(net + "\n", encoding="utf-8")
            files.append(f)
        procs = [subprocess.Popen(["bash", str(SVC / "blockctl.sh"), "import-blocks", str(f)], env=self.env,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                 for f in files]
        for p in procs:
            self.assertEqual(p.wait(timeout=60), 0)
        text = self.save_file.read_text(encoding="utf-8")
        self.assertIn("add skipa-manual 9.9.9.0/24", text)
        self.assertIn("add skipa-manual 9.9.8.0/24", text)

    def test_все_изменяющие_скрипты_берут_блокировку(self):
        """регрессия: ни один скрипт, меняющий наборы, не должен остаться без flock"""
        for name in ("sync-lists.sh", "blockctl.sh", "setup-ipset-rules.sh", "allow-ssh.sh", "boot.sh"):
            self.assertIn("acquire_ipset_lock", (SVC / name).read_text(encoding="utf-8"), name)


class MinEntriesTests(_Env):
    def test_мусор_при_первой_загрузке_отклоняется(self):
        """3 строки вместо списка: источник не принят, ipset пуст"""
        self.set_list("primary", ["1.1.1.1", "2.2.2.2", "3.3.3.3"])
        r = self.sync()
        self.assertIn("минимум для первой загрузки", r.stdout + r.stderr)
        self.assertEqual(self.members("skipa-scanners"), [])

    def test_порог_настраивается(self):
        """sources.min_entries: 1 разрешает короткий список"""
        self.edit_conf("min_entries: 10", "min_entries: 2")
        self.set_list("primary", ["1.1.1.1", "2.2.2.2", "3.3.3.3"])
        self.sync()
        self.assertIn("1.1.1.1/32", self.members("skipa-scanners"))

    def test_с_копией_работает_прежняя_проверка(self):
        """после удачной загрузки порог не применяется, а резкое похудение ловится «вдвое»"""
        self.sync()
        self.set_list("primary", ["45.1.0.0/24", "45.2.0.0/24", "45.3.0.0/24"])     # 3 из 12
        r = self.sync()
        self.assertIn("вместо ~", r.stdout + r.stderr)
        self.assertIn("45.12.0.0/24", self.members("skipa-scanners"))               # прежнее осталось

    def test_у_доп_источника_свой_порог(self):
        """min_entries внутри элемента extra переопределяет общий"""
        self.edit_conf("      enabled: false", "      enabled: true\n      min_entries: 2")
        self.set_list("spamhaus", ["47.1.0.0/22 ; SBL1", "47.2.0.0/22 ; SBL2"])
        self.sync()
        self.assertIn("47.1.0.0/22", self.members("skipa-scanners"))


class ExtraSourcesTests(_Env):
    def enable_first_extra(self):
        self.edit_conf("      enabled: false", "      enabled: true")

    def test_выключенные_источники_не_качаются(self):
        """в примере конфига все extra выключены: ни одного обращения к их URL"""
        self.sync()
        calls = (self.d / "fake" / "curl-args").read_text(encoding="utf-8")
        self.assertNotIn("spamhaus", calls)
        self.assertNotIn("firehol", calls)

    def test_spamhaus_с_комментариями_точка_с_запятой(self):
        """включённый cidr_list попадает в набор; '; SBLnnn' и строки-комментарии не мешают"""
        self.enable_first_extra()
        self.set_list("spamhaus", ["; Spamhaus DROP List"] + [f"47.{i}.0.0/22 ; SBL{i}" for i in range(1, 13)])
        r = self.sync()
        self.assertIn("доп. источников: 1", r.stdout + r.stderr)
        mem = self.members("skipa-scanners")
        self.assertIn("47.3.0.0/22", mem)
        self.assertTrue(all(";" not in m for m in mem))

    def test_доп_источник_участвует_при_любом_active_list(self):
        """как у бота: sources.extra не зависит от active_list"""
        self.enable_first_extra()
        self.edit_conf('active_list: "merged"', 'active_list: "list2"')
        self.set_list("spamhaus", [f"47.{i}.0.0/22" for i in range(1, 13)])
        self.sync()
        mem = self.members("skipa-scanners")
        self.assertIn("47.5.0.0/22", mem)
        self.assertNotIn("45.5.0.0/24", mem)      # primary при list2 не используется

    def test_небезопасное_имя_и_неизвестный_тип_пропускаются(self):
        """name с лишними символами и незнакомый type не ломают синхронизацию"""
        self.edit_conf('name: "spamhaus_drop"', 'name: "../etc/passwd"')
        self.edit_conf('      type: "cidr_list"', '      type: "magic"', 2)
        self.edit_conf("      enabled: false", "      enabled: true", 2)
        r = self.sync()
        out = r.stdout + r.stderr
        self.assertEqual(r.returncode, 0)
        self.assertIn("допустимы только буквы", out)
        self.assertIn("неизвестный тип", out)

    def test_abuseipdb_ключ_не_в_аргументах_и_ipv6_пропускается(self):
        """ключ уходит через stdin curl (-K -), а не в argv; IPv6 из ответа пропускается с записью в журнал"""
        self.edit_conf('api_key: ""', 'api_key: "SeCr3tKey123"')
        self.edit_conf("      enabled: false", "      enabled: true", 3)       # все три; cidr_list ниже пустые
        self.set_list("spamhaus", [])
        (self.d / "fake" / "abuse").write_text(
            json.dumps({"data": [{"ipAddress": f"48.1.0.{i}"} for i in range(1, 13)] + [{"ipAddress": "2001:db8::9"}]}),
            encoding="utf-8")
        r = self.sync()
        out = r.stdout + r.stderr
        self.assertIn("48.1.0.5/32", self.members("skipa-scanners"))
        self.assertNotIn("2001:db8::9", "\n".join(self.members("skipa-scanners")))
        self.assertIn("IPv6 пропущено", out)
        self.assertNotIn("SeCr3tKey123", (self.d / "fake" / "curl-args").read_text(encoding="utf-8"))
        self.assertIn("Key: SeCr3tKey123", (self.d / "fake" / "abuse-stdin").read_text(encoding="utf-8"))
        self.assertNotIn("SeCr3tKey123", out)

    def test_abuseipdb_без_ключа_пропускается(self):
        """пустой api_key: понятное сообщение, обращения к API нет"""
        self.edit_conf("      enabled: false", "      enabled: true", 3)
        self.set_list("spamhaus", [])
        r = self.sync()
        self.assertIn("api_key", r.stdout + r.stderr)
        self.assertFalse((self.d / "fake" / "abuse-stdin").exists())

    def test_ipv6_в_основном_списке_пишется_в_журнал(self):
        """IPv6 больше не пропадает молча"""
        self.set_list("primary", [f"45.{i}.0.0/24" for i in range(1, 13)] + ["2001:db8::/32", "2001:db8:1::1"])
        r = self.sync()
        self.assertIn("2 записей IPv6 пропущено", r.stdout + r.stderr)

    def test_парсер_блочных_и_однострочных_элементов(self):
        """yaml_extra_sources: оба стиля, кавычки, запятая внутри кавычек, enabled по умолчанию true"""
        yaml = self.d / "x.yaml"
        yaml.write_text(
            'sources:\n  extra:\n    - name: a\n      url: "https://a/x"   # комм\n      enabled: false\n'
            '    - {name: b, type: abuseipdb, api_key: "K1", display_name: "Abuse, DB"}\n'
            'other:\n  x: 1\n', encoding="utf-8")
        out = subprocess.run(["bash", "-c", f'source "{SVC / "lib-config.sh"}"; yaml_extra_sources "{yaml}"'],
                             capture_output=True, text=True).stdout.splitlines()
        rows = [line.split("\x1f") for line in out]
        self.assertEqual(rows[0][:4], ["a", "", "https://a/x", "false"])
        self.assertEqual((rows[1][0], rows[1][1], rows[1][3], rows[1][4], rows[1][7]),
                         ("b", "abuseipdb", "true", "K1", "Abuse, DB"))
        self.assertEqual(len(rows), 2)


class RulesAndVerificationTests(_Env):
    def setUp(self):
        super().setUp()
        (self.d / "ipt").mkdir()
        (self.d / "ipt" / "state.json").write_text(json.dumps({"INPUT": [], "DOCKER-USER": []}), encoding="utf-8")

    def rules(self, chain: str = "INPUT") -> list[str]:
        return json.loads((self.d / "ipt" / "state.json").read_text(encoding="utf-8"))[chain]

    def apply(self, env: dict | None = None) -> subprocess.CompletedProcess:
        return self.run_script("setup-ipset-rules.sh", str(self.conf), env=env)

    def test_применение_и_проверка_результата(self):
        """правила встали в INPUT и DOCKER-USER, скрипт сообщает OK и сохраняет наборы"""
        r = self.apply()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("OK: наборы и правила на месте", r.stdout)
        self.assertIn("✓ в цепочке DOCKER-USER", r.stdout)
        self.assertEqual(len([x for x in self.rules() if x.endswith("-j DROP")]), 2)    # scanners + manual
        self.assertTrue(self.save_file.exists())

    def test_повторное_применение_не_дублирует(self):
        """идемпотентность: второй запуск не добавляет правил"""
        self.apply()
        before = self.rules()
        self.assertEqual(self.apply().returncode, 0)
        self.assertEqual(self.rules(), before)

    def test_сбой_постановки_правил_виден_и_даёт_ошибку(self):
        """если правила фактически не встали, скрипт завершается с ошибкой и показывает ✗"""
        r = self.apply(env={"FAKE_IPT_BROKEN": "1"})
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("✗ в цепочке INPUT НЕТ правил", r.stdout)

    def test_keep_established_ставит_пару_правил_и_откатывается(self):
        """firewall.keep_established_tcp: DROP только для новых TCP и не-TCP, без RETURN; обратно - один DROP"""
        self.edit_conf("keep_established_tcp: false", "keep_established_tcp: true")
        self.assertEqual(self.apply().returncode, 0)
        drops = [x for x in self.rules() if "match-set skipa-scanners" in x and x.endswith("-j DROP")]
        self.assertEqual(len(drops), 2)
        self.assertTrue(any(x.startswith("-p tcp --syn") for x in drops))
        self.assertTrue(any(x.startswith("! -p tcp") for x in drops))
        self.assertFalse(any("RETURN" in x for x in self.rules()))
        self.edit_conf("keep_established_tcp: true", "keep_established_tcp: false")
        self.assertEqual(self.apply().returncode, 0)
        drops = [x for x in self.rules() if "match-set skipa-scanners" in x and x.endswith("-j DROP")]
        self.assertEqual(len(drops), 1)
        self.assertFalse(drops[0].startswith(("-p tcp", "! -p")))

    def test_режим_notify_убирает_все_виды_drop(self):
        """в режиме notify остаётся только LOG, DROP любого вида убирается"""
        self.edit_conf("keep_established_tcp: false", "keep_established_tcp: true")
        self.apply()
        self.edit_conf('mode: "block_notify"', 'mode: "notify"')
        self.apply()
        self.assertFalse(any(x.endswith("-j DROP") for x in self.rules()))
        self.assertTrue(any("-j LOG" in x for x in self.rules()))

    def test_boot_rules_создаёт_наборы_и_ставит_правила(self):
        """поздний юнит сам обеспечивает наборы (на случай, если ранний не отработал)"""
        r = self.run_script("boot.sh", "rules", str(self.conf))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertTrue((self.d / "ipsets" / "skipa-scanners").exists())


class UnitFilesTests(unittest.TestCase):
    """Регрессия по порядку запуска: один юнит с After=docker и Before=netfilter-persistent даёт цикл."""

    def text(self, name: str) -> str:
        return (SVC / name).read_text(encoding="utf-8")

    def test_ранний_юнит_до_netfilter_persistent_и_без_docker(self):
        t = self.text("skipa-watchdog-ipset.service")
        self.assertRegex(t, r"(?m)^Before=.*netfilter-persistent\.service")
        self.assertNotRegex(t, r"(?m)^(After|Wants|Requires)=.*docker")
        self.assertIn("DefaultDependencies=no", t)

    def test_поздний_юнит_после_docker_и_kubelet_без_before_netfilter(self):
        t = self.text("skipa-watchdog-rules.service")
        self.assertRegex(t, r"(?m)^After=.*docker\.service")
        self.assertRegex(t, r"(?m)^After=.*kubelet\.service")
        self.assertNotRegex(t, r"(?m)^Before=.*netfilter-persistent")
        self.assertNotRegex(t, r"(?m)^(Wants|Requires)=.*docker", "наш юнит не должен запускать выключенный Docker")

    @unittest.skipUnless(shutil.which("systemd-analyze"), "нужен systemd-analyze")
    def test_нет_цикла_упорядочивания_в_эмуляции_загрузки(self):
        """эмуляция: Docker + netfilter-persistent + сетевой менеджер; у наших юнитов цикла нет,
        а у «единого юнита» из исходной идеи - есть (проверка самого теста)"""
        u = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, u, True)

        def unit(name: str, body: str) -> None:
            (u / name).write_text(body + "\n[Service]\nExecStart=/bin/true\n", encoding="utf-8")

        unit("docker.service", "[Unit]\nAfter=network-online.target\nWants=network-online.target")
        unit("kubelet.service", "[Unit]\nAfter=network-online.target\nWants=network-online.target")
        unit("netfilter-persistent.service",
             "[Unit]\nDefaultDependencies=no\nWants=network-pre.target\nBefore=network-pre.target shutdown.target\nConflicts=shutdown.target")
        unit("netmgr.service", "[Unit]\nWants=network.target\nAfter=network-pre.target\nBefore=network.target")
        unit("netmgr-wait.service", "[Unit]\nAfter=netmgr.service\nBefore=network-online.target")
        unit("single.service", "[Unit]\nDefaultDependencies=no\nAfter=local-fs.target docker.service kubelet.service\nBefore=netfilter-persistent.service")
        for name in ("skipa-watchdog-ipset.service", "skipa-watchdog-rules.service"):
            shutil.copy(SVC / name, u / name)
        common = "docker.service kubelet.service netfilter-persistent.service netmgr.service netmgr-wait.service"
        unit("good.target", f"[Unit]\nWants=skipa-watchdog-ipset.service skipa-watchdog-rules.service {common}\n"
                            f"After=skipa-watchdog-ipset.service skipa-watchdog-rules.service {common}")
        unit("bad.target", f"[Unit]\nWants=single.service {common}\nAfter=single.service {common}")
        env = dict(os.environ, SYSTEMD_UNIT_PATH=f"{u}:/lib/systemd/system:/usr/lib/systemd/system")

        def verify(target: str) -> str:
            r = subprocess.run(["systemd-analyze", "verify", "--man=no", str(u / target)], capture_output=True,
                               text=True, env=env)
            return r.stdout + r.stderr

        if "ordering cycle" not in verify("bad.target"):
            self.skipTest("эта версия systemd-analyze не находит цикл в контрольном примере")
        self.assertNotIn("ordering cycle", verify("good.target"))


class InstallWiringTests(unittest.TestCase):
    """install.sh ставит и убирает оба юнита и проверяет результат применения правил."""

    def setUp(self):
        self.text = (ROOT / "install.sh").read_text(encoding="utf-8")

    def test_юниты_ставятся_включаются_и_удаляются(self):
        for needle in ('SETS_UNIT="skipa-watchdog-ipset"', 'RULES_UNIT="skipa-watchdog-rules"',
                       'systemctl enable "$SETS_UNIT" "$RULES_UNIT"',
                       '"$SYSTEMD_DIR/${SETS_UNIT}.service" "$SYSTEMD_DIR/${RULES_UNIT}.service"'):
            self.assertIn(needle, self.text, needle)
        self.assertGreaterEqual(self.text.count("$SETS_UNIT"), 5)

    @unittest.skipUnless(HAVE, "нужен bash")
    def test_проверка_правил_варианта_с_ботом(self):
        """_verify_bot_firewall_rules: ✓ при наличии перехода в SKIPA-BLOCK, ✗ и код 1 без него"""
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        bindir = d / "bin"
        netfake.install(bindir)
        env = netfake.env_for(dict(os.environ), d, bindir)
        env.update(SKIPA_SOURCE_ONLY="1", SKIPA_INSTALL_DIR=str(d / "inst"))
        (d / "ipt").mkdir()
        (d / "ipt" / "state.json").write_text(json.dumps({"INPUT": [], "SKIPA-BLOCK": []}), encoding="utf-8")
        script = f'source "{ROOT / "install.sh"}"; _verify_bot_firewall_rules; echo "rc=$?"'
        bad = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env)
        self.assertIn("✗ в INPUT НЕТ перехода", bad.stdout)
        self.assertIn("rc=1", bad.stdout)
        (d / "ipt" / "state.json").write_text(json.dumps({"INPUT": ["-j SKIPA-BLOCK"], "SKIPA-BLOCK": []}), encoding="utf-8")
        good = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env)
        self.assertIn("✓ INPUT -> SKIPA-BLOCK", good.stdout)
        self.assertIn("rc=0", good.stdout)


if __name__ == "__main__":
    unittest.main()
