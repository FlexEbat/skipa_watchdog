#!/usr/bin/env bash
# Сквозная проверка режима "только сервис" на РЕАЛЬНЫХ ipset/iptables.
#
# ВНИМАНИЕ: сценарий создаёт и УДАЛЯЕТ наборы skipa-* и правила skipa-* в INPUT/DOCKER-USER
# хоста. Запускать только в одноразовой среде (контейнер/VM), от root, и только явно:
#     SKIPA_REAL_NETFILTER_TESTS=1 python3 -m unittest tests.test_real_netfilter
# или напрямую: sudo bash tests/e2e_service_real.sh
#
# Что проверяет: синхронизацию с доп. источником, сохранение наборов, "перезагрузку"
# (наборы и правила исчезают), воспроизводит отказ iptables-restore без наборов и то, что
# ранний этап (boot.sh sets) его устраняет, применение и проверку правил, TCP-флаги, flock
# при одновременных запусках и порог первой загрузки. Сеть не нужна: curl подменён.
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1
W=$(mktemp -d); export SKIPA_STATE_DIR="$W/state" SKIPA_NO_UPDATE_CHECK=1 FAKE="$W/fake"
mkdir -p "$FAKE" "$W/bin" "$W/log"
PASS=0; FAIL=0
chk() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then echo "  PASS  $d"; PASS=$((PASS+1)); else echo "  FAIL  $d"; FAIL=$((FAIL+1)); fi; }
clean() { for c in INPUT DOCKER-USER; do while iptables -w 5 -S $c 2>/dev/null | grep -q skipa; do n=$(iptables -w 5 -L $c -n --line-numbers | grep -E 'skipa' | head -1 | awk '{print $1}'); iptables -w 5 -D $c "$n" 2>/dev/null || break; done; done
          for s in skipa-scanners skipa-manual skipa-allow skipa-scanners-tmp skipa-allow-tmp; do ipset flush $s 2>/dev/null; ipset destroy $s 2>/dev/null; done; }
clean

# --- поддельный curl (сеть недоступна): отдаёт списки по URL
seq 1 30 | sed 's#.*#45.&.0.0/24#' > "$FAKE/primary"
{ seq 1 15 | sed 's#.*#46.&.0.1#'; echo "2001:db8::1"; echo "2001:db8::/32"; } > "$FAKE/blacklist"
{ echo "; Spamhaus DROP List"; seq 1 12 | sed 's#.*#47.&.0.0/22 ; SBL&#'; } > "$FAKE/spamhaus"
cat > "$W/bin/curl" <<'EOF'
#!/usr/bin/env bash
for a in "$@"; do case "$a" in http*) url="$a";; esac; done
echo "$@" >> "$FAKE/curl-args"
case "$url" in
  *skipa_cidr*) cat "$FAKE/primary";; *blacklist.txt*) cat "$FAKE/blacklist";; *spamhaus*) cat "$FAKE/spamhaus";;
  *abuseipdb*) cat > "$FAKE/abuse-stdin"; echo '{"data":[{"ipAddress":"48.1.0.1","abuseConfidenceScore":100},{"ipAddress":"2001:db8::9"}]}';;
esac
EOF
chmod +x "$W/bin/curl"; export PATH="$W/bin:$PATH"

# --- конфиг: включаем spamhaus_drop (первый enabled: false в файле)
CONF="$W/config.yaml"; sed "s#/var/log/skipa_watchdog#$W/log#" config.example.yaml > "$CONF"
python3 - "$CONF" <<'EOF'
import sys,re
p=sys.argv[1]; s=open(p).read(); s=s.replace("enabled: false","enabled: true",1); open(p,"w").write(s)
EOF

echo "== 1. sync-lists: источники, доп. источник, IPv6, сохранение"
bash service/sync-lists.sh "$CONF" > "$W/sync1.out" 2>&1; echo "  rc=$?"
chk "primary в наборе (45.5.0.0/24)"        ipset test skipa-scanners 45.5.0.77
chk "blacklist в наборе (46.3.0.1)"          ipset test skipa-scanners 46.3.0.1
chk "ДОП. источник spamhaus_drop в наборе (47.2.0.9)" ipset test skipa-scanners 47.2.1.9
chk "';'-комментарии Spamhaus не мешают разбору"      ipset test skipa-scanners 47.12.2.2
chk "IPv6 не попал в набор IPv4 (в Members нет ':')"  test "$(ipset list skipa-scanners | sed -n '/^Members:/,$p' | tail -n +2 | grep -c ':')" = 0
chk "журнал: IPv6 пропущен ЯВНО, а не молча"          grep -q "записей IPv6 пропущено" "$W/sync1.out"
chk "журнал: доп. источников 1"                       grep -q "доп. источников: 1" "$W/sync1.out"
chk "файл сохранения создан, права 600"               test "$(stat -c %a "$SKIPA_STATE_DIR/ipsets.save")" = 600
chk "в сохранении есть scanners и allow"              bash -c "grep -q '^create skipa-scanners' $SKIPA_STATE_DIR/ipsets.save && grep -q '^create skipa-allow' $SKIPA_STATE_DIR/ipsets.save"

echo "== 2. ручная блокировка сохраняется"
bash service/blockctl.sh block 8.8.8.0/24 >/dev/null 2>&1
chk "8.8.8.8 в skipa-manual"                   ipset test skipa-manual 8.8.8.8
chk "блокировка записана в файл сохранения"    grep -q "add skipa-manual 8.8.8.0/24" "$SKIPA_STATE_DIR/ipsets.save"

echo "== 3. правила применяются и проверяются"
bash service/setup-ipset-rules.sh "$CONF" > "$W/rules1.out" 2>&1; echo "  rc=$?"
chk "в INPUT есть DROP по skipa-scanners"      bash -c "iptables -S INPUT | grep -q 'match-set skipa-scanners src.*-j DROP'"
chk "вывод содержит итог проверки OK"          grep -q "OK: наборы и правила на месте" "$W/rules1.out"
iptables-save > "$W/rules.v4"      # то, что сохранил бы netfilter-persistent

echo "== 4. «перезагрузка»: наборы и правила исчезают"
clean
chk "после «перезагрузки» наборов сервис-режима нет" test -z "$(ipset list -n | grep -E '^skipa-(scanners|manual|allow)$')"
echo "  --- опасность: iptables-restore из сохранённого файла БЕЗ наборов"
if iptables-restore < "$W/rules.v4" 2>"$W/restore.err"; then echo "  (!) restore неожиданно прошёл"; FAIL=$((FAIL+1)); else echo "  PASS  (воспроизведено) iptables-restore отверг файл целиком: $(head -c 100 "$W/restore.err" | tr '\n' ' ')"; PASS=$((PASS+1)); fi
echo "  --- boot.sh sets (ранний юнит)"
bash service/boot.sh sets "$CONF" 2>&1 | sed 's/^/  /'
chk "наборы восстановлены: scanners (45.5.0.77)"          ipset test skipa-scanners 45.5.0.77
chk "наборы восстановлены: spamhaus (47.2.1.9)"           ipset test skipa-scanners 47.2.1.9
chk "РУЧНАЯ блокировка пережила перезагрузку (8.8.8.8)"   ipset test skipa-manual 8.8.8.8
chk "теперь iptables-restore из сохранённого файла проходит" iptables-restore < "$W/rules.v4"
chk "правила из netfilter-persistent встали в INPUT"      bash -c "iptables -S INPUT | grep -q 'match-set skipa-scanners'"

echo "== 5. boot.sh rules (поздний юнит) идемпотентен и проверяет результат"
clean; bash service/boot.sh sets "$CONF" >/dev/null 2>&1
bash service/boot.sh rules "$CONF" > "$W/rules2.out" 2>&1; echo "  rc=$?"
bash service/boot.sh rules "$CONF" > "$W/rules3.out" 2>&1; echo "  повторный rc=$?"
chk "правил не задвоилось (1 DROP scanners в INPUT)" test "$(iptables -S INPUT | grep -c 'match-set skipa-scanners src.*-j DROP')" = 1

echo "== 6. keep_established_tcp"
python3 - "$CONF" <<'EOF'
import sys; p=sys.argv[1]; s=open(p).read(); open(p,"w").write(s.replace("keep_established_tcp: false","keep_established_tcp: true"))
EOF
bash service/setup-ipset-rules.sh "$CONF" >/dev/null 2>&1; echo "  rc=$?"
chk "включено: есть DROP только для новых TCP (--syn)"  bash -c "iptables -S INPUT | grep 'match-set skipa-scanners' | grep -q -- '-p tcp.*--tcp-flags FIN,SYN,RST,ACK SYN.*-j DROP'"
chk "включено: есть DROP для не-TCP (! -p tcp)"          bash -c "iptables -S INPUT | grep 'match-set skipa-scanners' | grep -q -- '! -p tcp.*-j DROP'"
chk "включено: прежнего «DROP на всё» нет"              test "$(iptables -S INPUT | grep 'match-set skipa-scanners' | grep -c -- '-j DROP' )" = 2
chk "RETURN в INPUT не используется"                     bash -c "! iptables -S INPUT | grep -q 'skipa.*-j RETURN'"
python3 - "$CONF" <<'EOF'
import sys; p=sys.argv[1]; s=open(p).read(); open(p,"w").write(s.replace("keep_established_tcp: true","keep_established_tcp: false"))
EOF
bash service/setup-ipset-rules.sh "$CONF" >/dev/null 2>&1
chk "выключено обратно: снова один DROP на всё, варианты убраны" test "$(iptables -S INPUT | grep 'match-set skipa-scanners' | grep -c -- '-j DROP')" = 1

echo "== 7. flock: одновременные операции не пересекаются"
( source service/lib-ipset.sh; acquire_ipset_lock 5; sleep 3 ) &
sleep 0.5
t0=$(date +%s); ( source service/lib-ipset.sh; unset SKIPA_IPSET_LOCKED; acquire_ipset_lock 1 ) 2>"$W/lock.err"; rc=$?
chk "второй претендент ждал и получил отказ по таймауту (rc!=0)" test "$rc" -ne 0
chk "сообщение о занятой блокировке"                             grep -q "не завершилась" "$W/lock.err"
wait
echo "  --- два sync-lists одновременно (реальные наборы, общие *-tmp)"
( bash service/sync-lists.sh "$CONF" > "$W/pa.out" 2>&1; echo $? > "$W/pa.rc" ) &
( bash service/sync-lists.sh "$CONF" > "$W/pb.out" 2>&1; echo $? > "$W/pb.rc" ) &
wait
chk "оба прошли успешно"                  test "$(cat "$W/pa.rc")$(cat "$W/pb.rc")" = "00"
chk "набор цел после гонки (45.5.0.77, 47.2.1.9)" bash -c "ipset test skipa-scanners 45.5.0.77 && ipset test skipa-scanners 47.2.1.9"
chk "временных *-tmp наборов не осталось"  test -z "$(ipset list -n | grep -- '-tmp')"
( bash service/blockctl.sh block 9.9.9.0/24 > /dev/null 2>&1 ) & ( bash service/blockctl.sh block 9.9.8.0/24 >/dev/null 2>&1 ) & wait
chk "параллельные blockctl: обе блокировки в файле сохранения" bash -c "grep -q 'add skipa-manual 9.9.9.0/24' $SKIPA_STATE_DIR/ipsets.save && grep -q 'add skipa-manual 9.9.8.0/24' $SKIPA_STATE_DIR/ipsets.save"

echo "== 8. минимум записей при ПЕРВОЙ загрузке"
rm -rf "$SKIPA_STATE_DIR"; clean
printf '1.1.1.1\n2.2.2.2\n3.3.3.3\n' > "$FAKE/primary"; : > "$FAKE/blacklist"; : > "$FAKE/spamhaus"
bash service/sync-lists.sh "$CONF" > "$W/min1.out" 2>&1
chk "список из 3 строк при первой загрузке ОТКЛОНЁН"  grep -q "минимум для первой загрузки" "$W/min1.out"
chk "мусор не попал в ipset"                           bash -c "! ipset test skipa-scanners 1.1.1.1"
seq 1 12 | sed 's#.*#45.&.0.0/24#' > "$FAKE/primary"
bash service/sync-lists.sh "$CONF" > "$W/min2.out" 2>&1
chk "нормальный список (12) принят"                    ipset test skipa-scanners 45.3.0.5
printf '45.1.0.0/24\n' > "$FAKE/primary"
bash service/sync-lists.sh "$CONF" > "$W/min3.out" 2>&1
chk "при наличии копии работает прежняя проверка «похудел вдвое»" grep -q "вместо ~" "$W/min3.out"
chk "прежнее содержимое осталось"                      ipset test skipa-scanners 45.3.0.5

echo; echo "ИТОГО: PASS=$PASS FAIL=$FAIL"; clean; rm -rf "$W"
