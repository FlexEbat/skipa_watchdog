"""Уведомления из bash (Telegram, Matrix): формат запросов, очередь, повторы, секреты вне argv."""
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SVC = ROOT / "service"
HAVE = bool(shutil.which("bash") and shutil.which("awk") and shutil.which("flock") and shutil.which("find"))

FAKE_CURL = r'''#!/usr/bin/env bash
# поддельный curl: пишет вызов в $FAKE, отдаёт код из очереди $FAKE/codes (по одному за вызов)
n=$(cat "$FAKE/count" 2>/dev/null || echo 0); n=$((n + 1)); echo "$n" > "$FAKE/count"
printf '%s\n' "$@" > "$FAKE/args-$n"
out=""; prev=""
for a in "$@"; do [ "$prev" = "-o" ] && out="$a"; prev="$a"; done
cat > "$FAKE/stdin-$n"
code=200
if [ -s "$FAKE/codes" ]; then code=$(head -n1 "$FAKE/codes"); sed -i 1d "$FAKE/codes"; fi
body='{"ok":true}'
[ -f "$FAKE/body-$code" ] && body=$(cat "$FAKE/body-$code")
[ -n "$out" ] && printf '%s' "$body" > "$out"
printf '%s' "$code"
[ "$code" = 000 ] && exit 7
exit 0
'''

CONF_TEMPLATE = """telegram:
  bot_token: "{tg_token}"
  chat_id: {tg_chat}
matrix:
  homeserver: "{mx_hs}"
  access_token: "{mx_token}"
  room_id: "{mx_room}"
notifications:
  batch_seconds: {batch}
  batch_max: 20
  language: "{lang}"
action:
  mode: "block_notify"
monitoring:
  alert_cooldown_minutes: 60
  kernel_log_prefix: "CONN: "
logging:
  log_dir: "{log}"
"""


@unittest.skipUnless(HAVE, "нужны bash, awk, flock и find")
class NotifyBase(unittest.TestCase):
    TG = ("123456:ABC-def_ghi", "-1001234")
    MX = ("https://matrix.example.org", "syt_secretTOKEN123", "!room:example.org")

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.d = Path(self.tmp.name)
        self.bin = self.d / "bin"; self.bin.mkdir()
        self.fake = self.d / "fake"; self.fake.mkdir()
        self.state = self.d / "state"; self.state.mkdir()
        self.log = self.d / "log"
        self._script("curl", FAKE_CURL)
        self._script("sleep", 'echo "$@" >> "$FAKE/sleeps"')        # ожидание retry_after не тормозит тесты
        self.env = {**os.environ, "PATH": f"{self.bin}:{os.environ['PATH']}", "FAKE": str(self.fake),
                    "SKIPA_STATE_DIR": str(self.state)}
        self.conf = self.d / "config.yaml"

    def _script(self, name, body):
        p = self.bin / name
        p.write_text(body if body.startswith("#!") else "#!/usr/bin/env bash\n" + body + "\n", encoding="utf-8")
        p.chmod(0o755)

    def write_conf(self, telegram=True, matrix=True, batch=0, lang="ru"):
        tg = self.TG if telegram else ("", "0")
        mx = self.MX if matrix else ("", "", "")
        self.conf.write_text(CONF_TEMPLATE.format(
            tg_token=tg[0], tg_chat=tg[1], mx_hs=mx[0], mx_token=mx[1], mx_room=mx[2], log=self.log, batch=batch, lang=lang), encoding="utf-8")

    def sh(self, script, timeout=30):
        pre = (f'source "{SVC}/lib-config.sh"; source "{SVC}/lib-notify.sh"; '
               f'load_service_config "{self.conf}"; STATE_DIR="{self.state}"; load_notify_config "{self.conf}"\n')
        return subprocess.run(["bash", "-c", pre + script], capture_output=True, text=True, env=self.env, timeout=timeout)

    def codes(self, *codes):
        (self.fake / "codes").write_text("\n".join(map(str, codes)) + "\n", encoding="utf-8")

    def calls(self):
        return sorted(self.fake.glob("args-*"), key=lambda p: int(p.name.split("-")[1]))

    def spool(self):
        d = self.state / "notify-spool"
        return sorted(p.name for p in d.iterdir() if p.name != ".lock") if d.exists() else []


class ValidationTests(NotifyBase):
    def test_telegram_формат(self):
        """токен и chat_id проверяются до записи в конфиг"""
        ok = self.sh('notify_validate_telegram "123:abc-D_1" "-100500" && echo OK')
        self.assertEqual(ok.stdout.strip(), "OK")
        for tok, chat in (('x"y', "1"), ("abc", "1"), ("1:a b", "1"), ("1:abc", "0"), ("1:abc", "x1"), ("1:abc", "")):
            r = self.sh(f'notify_validate_telegram "{tok}" "{chat}" 2>/dev/null && echo OK')
            self.assertNotEqual(r.stdout.strip(), "OK", (tok, chat))

    def test_matrix_формат(self):
        """homeserver только https (http - для localhost), room_id - идентификатор, а не алиас"""
        good = ("https://matrix.example.org", "syt_abc.DEF-1", "!abc:example.org")
        self.assertEqual(self.sh('notify_validate_matrix "%s" "%s" "%s" && echo OK' % good).stdout.strip(), "OK")
        self.assertEqual(self.sh('notify_validate_matrix "http://localhost:8008" "t" "!a:b" && echo OK').stdout.strip(), "OK")
        for hs, tok, room in (("http://matrix.example.org", "t", "!a:b"), ("https://x y", "t", "!a:b"),
                              ("https://m.org", 't"x', "!a:b"), ("https://m.org", "t", "#alias:m.org"),
                              ("https://m.org", "t", "!a b:m.org"), ("ftp://m.org", "t", "!a:b")):
            r = self.sh(f'notify_validate_matrix "{hs}" "{tok}" "{room}" 2>/dev/null && echo OK')
            self.assertNotEqual(r.stdout.strip(), "OK", (hs, tok, room))

    def test_неверные_значения_выключают_канал(self):
        """мусор в config.yaml не ломает отправку: канал просто считается выключенным"""
        self.conf.write_text(CONF_TEMPLATE.format(tg_token="bad token", tg_chat=5, mx_hs="http://evil.example",
                                                  mx_token="t", mx_room="!a:b", log=self.log, batch=0, lang="ru"), encoding="utf-8")
        self.assertEqual(self.sh("notify_channels").stdout.strip(), "")


class SendTests(NotifyBase):
    def test_telegram_секрет_только_через_stdin(self):
        """адрес с токеном уходит в curl через -K -, в argv его нет; текст читается из файла"""
        self.write_conf(matrix=False)
        r = self.sh('notify_enqueue "привет"; notify_drain; echo rc=$?')
        self.assertIn("rc=0", r.stdout, r.stderr)
        self.assertEqual(len(self.calls()), 1)
        args = self.calls()[0].read_text(encoding="utf-8")
        stdin = (self.fake / "stdin-1").read_text(encoding="utf-8")
        self.assertIn('url = "https://api.telegram.org/bot123456:ABC-def_ghi/sendMessage"', stdin)
        self.assertNotIn("ABC-def_ghi", args)
        self.assertIn("chat_id=-1001234", args)
        self.assertIn("text@", args)
        self.assertIn("-K", args)
        self.assertIn("=https", args)
        self.assertEqual(self.spool(), [])

    def test_matrix_запрос_и_json(self):
        """PUT с Bearer-токеном в stdin, room_id закодирован, тело - валидный JSON со всеми спецсимволами"""
        self.write_conf(telegram=False)
        text = 'строка "в кавычках" \\ слэш\nвторая\tстрока 🛡'
        (self.d / "msg.txt").write_text(text, encoding="utf-8")
        r = self.sh(f'notify_enqueue "$(cat {self.d}/msg.txt)"; notify_drain; echo rc=$?')
        self.assertIn("rc=0", r.stdout, r.stderr)
        args = self.calls()[0].read_text(encoding="utf-8").splitlines()
        stdin = (self.fake / "stdin-1").read_text(encoding="utf-8")
        self.assertIn("/_matrix/client/v3/rooms/%21room%3Aexample.org/send/m.room.message/", stdin)
        self.assertIn('header = "Authorization: Bearer syt_secretTOKEN123"', stdin)
        self.assertNotIn("syt_secretTOKEN123", "\n".join(args))
        self.assertEqual(args[args.index("-X") + 1], "PUT")
        payload = json.loads(args[args.index("--data-binary") + 1])
        self.assertEqual(payload["msgtype"], "m.text")
        self.assertEqual(payload["body"], text)

    def test_оба_канала_и_отдельные_файлы_очереди(self):
        """сообщение ставится в очередь по файлу на канал, оба доходят"""
        self.write_conf()
        r = self.sh("notify_enqueue привет; notify_spool_size")
        self.assertEqual(r.stdout.strip(), "2")
        self.assertEqual(sorted(n.rsplit(".", 1)[1] for n in self.spool()), ["matrix", "telegram"])
        self.sh("notify_drain")
        self.assertEqual(len(self.calls()), 2)
        self.assertEqual(self.spool(), [])

    def test_без_настроенных_каналов_очередь_не_создаётся(self):
        """нет токенов - нет файлов и нет сетевых вызовов"""
        self.write_conf(telegram=False, matrix=False)
        self.sh("notify_enqueue привет; notify_drain")
        self.assertEqual(self.spool(), [])
        self.assertEqual(self.calls(), [])

    def test_сетевой_сбой_оставляет_сообщение_и_порядок(self):
        """нет связи - файлы остаются, потом уходят в том же порядке, ровно по разу"""
        self.write_conf(matrix=False)
        self.codes(000)
        r = self.sh('notify_enqueue первое; sleep 1; notify_enqueue второе; notify_drain; echo rc=$?')
        self.assertIn("rc=1", r.stdout)
        self.assertEqual(len(self.spool()), 2)
        self.assertEqual(len(self.calls()), 1)              # на первом же сбое дальше не идём
        self.sh("notify_drain")
        sent = [(self.fake / f"args-{i}").read_text(encoding="utf-8") for i in (2, 3)]
        self.assertEqual(self.spool(), [])
        texts = [Path(l.split("@", 1)[1]).name for a in sent for l in a.splitlines() if l.startswith("text@")]
        self.assertEqual(len(texts), 2)

    def test_429_ждёт_retry_after_и_повторяет(self):
        """429 - пауза из retry_after (не дольше 60 с) и повторная отправка"""
        self.write_conf(matrix=False)
        self.codes(429, 200)
        (self.fake / "body-429").write_text('{"ok":false,"parameters":{"retry_after":17}}', encoding="utf-8")
        self.sh("notify_enqueue привет; notify_drain")
        self.assertEqual((self.fake / "sleeps").read_text().split(), ["17"])
        self.assertEqual(len(self.calls()), 2)
        self.assertEqual(self.spool(), [])
        (self.fake / "count").unlink(); self.codes(429, 200)
        (self.fake / "body-429").write_text('{"parameters":{"retry_after":9999}}', encoding="utf-8")
        (self.fake / "sleeps").unlink()
        self.sh("notify_enqueue ещё; notify_drain")
        self.assertEqual((self.fake / "sleeps").read_text().split(), ["60"])

    def test_неверный_токен_сообщение_выбрасывается(self):
        """401/403/400 повторять бессмысленно: файл удаляется, причина в журнале, очередь не растёт"""
        self.write_conf(matrix=False)
        self.codes(401)
        r = self.sh("notify_enqueue привет; notify_drain; echo rc=$?")
        self.assertIn("rc=0", r.stdout)
        self.assertEqual(self.spool(), [])
        self.assertIn("отклонил", (self.log / "skipa-watchdog.log").read_text(encoding="utf-8"))

    def test_старые_сообщения_и_переполнение(self):
        """старше суток и сверх 200 файлов выбрасываются, не отправляясь"""
        self.write_conf(matrix=False)
        sp = self.state / "notify-spool"; sp.mkdir(parents=True)
        (sp / "1000-00001.telegram").write_text("древнее\n")
        self.sh("notify_drain")
        self.assertEqual(self.spool(), [])
        self.assertEqual(self.calls(), [])
        self.sh('for i in $(seq 1 230); do notify_enqueue "m$i"; done')
        self.assertLessEqual(len(self.spool()), 200)
        self.assertGreater(len(self.spool()), 150)

    def test_тест_уведомления_сообщает_по_каналам(self):
        """notify_test отправляет мимо очереди и называет итог по каждому каналу"""
        self.write_conf()
        r = self.sh("notify_test; echo rc=$?")
        self.assertIn("telegram: доставлено", r.stdout)
        self.assertIn("matrix: доставлено", r.stdout)
        self.assertIn("rc=0", r.stdout)
        (self.fake / "count").unlink(); self.codes(403, 000)
        r = self.sh("notify_test; echo rc=$?")
        self.assertIn("telegram: сервер отклонил", r.stdout)
        self.assertIn("matrix: нет связи", r.stdout)
        self.assertIn("rc=1", r.stdout)

    def test_urlencode_и_json_escape(self):
        """служебные функции корректно обрабатывают спецсимволы"""
        r = self.sh('_urlencode "!a:b/c d"; echo; _json_escape $\'a"b\\\\c\\n\\x01\'')
        enc, esc = r.stdout.splitlines()[:2]
        self.assertEqual(enc, "%21a%3Ab%2Fc%20d")
        self.assertEqual(json.loads(f'"{esc}"'), 'a"b\\c\n\x01')


class NotifyTailTests(NotifyBase):
    def run_tail(self, lines):
        feed = self.d / "journal.txt"
        feed.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self._script("journalctl", f'cat "{feed}"')
        return subprocess.run(["bash", str(SVC / "notify-tail.sh"), str(self.conf)], capture_output=True, text=True,
                              env=self.env, timeout=60)

    def kern(self, ip, port=22):
        return f"CONN: IN=eth0 OUT= SRC={ip} DST=1.1.1.1 LEN=60 PROTO=TCP SPT=4444 DPT={port} SYN"

    def test_волна_сканов_одно_сообщение(self):
        """несколько адресов и повтор одного из них: одно сообщение, повтор не дублируется, лог на каждый адрес"""
        self.write_conf(matrix=False, batch=30)
        r = self.run_tail([self.kern("45.1.1.1"), self.kern("45.1.1.2", 443), self.kern("45.1.1.1"), "посторонняя строка"])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(len(self.calls()), 1)
        self.assertIn("-K", (self.fake / "args-1").read_text(encoding="utf-8"))
        det = (self.log / "detections.log").read_text(encoding="utf-8")
        self.assertEqual(det.count("IP=45.1.1.1"), 1)
        self.assertEqual(det.count("IP=45.1.1.2"), 1)
        self.assertEqual(self.spool(), [])

    def test_без_накопления_каждое_обнаружение_уходит_и_очередь_пустеет(self):
        """batch_seconds=0: два адреса - два сообщения, и ни одно не застревает из-за блокировки отправителя"""
        self.write_conf(matrix=False, batch=0)
        r = self.run_tail([self.kern("45.3.3.3"), self.kern("45.3.3.4")])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(len(self.calls()), 2)
        self.assertEqual(self.spool(), [])

    def test_язык_сообщения_en(self):
        """notifications.language: en - текст на английском (в том числе тестовое сообщение)"""
        self.write_conf(matrix=True, telegram=False, batch=30, lang="en")
        self.run_tail([self.kern("45.4.4.4")])
        payload = json.loads((self.fake / "args-1").read_text(encoding="utf-8").splitlines()[
            (self.fake / "args-1").read_text(encoding="utf-8").splitlines().index("--data-binary") + 1])
        self.assertIn("Scanners detected: 1 (blocked by the kernel)", payload["body"])
        self.assertIn("45.4.4.4", payload["body"])

    def test_без_каналов_только_лог(self):
        """без Telegram/Matrix работает как раньше: detections.log есть, сети нет"""
        self.write_conf(telegram=False, matrix=False)
        r = self.run_tail([self.kern("45.2.2.2")])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.calls(), [])
        self.assertIn("IP=45.2.2.2", (self.log / "detections.log").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
