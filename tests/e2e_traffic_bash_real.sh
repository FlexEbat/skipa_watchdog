#!/usr/bin/env bash
# Поведение на РЕАЛЬНЫХ пакетах (netns + veth): режим «только сервис» (setup-ipset-rules.sh)
#
# ВНИМАНИЕ: меняет наборы/правила skipa-* и SKIPA-BLOCK на хосте и создаёт сетевое пространство
# имён "cli" с veth "vs". Только от root, только в одноразовой среде, только явно:
#     SKIPA_REAL_NETFILTER_TESTS=1 python3 -m unittest tests.test_real_netfilter
# Нужны: ip (iproute2), ipset, iptables, python3. Сеть не нужна.
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1
W=$(mktemp -d); export SKIPA_STATE_DIR="$W/state" SKIPA_NO_UPDATE_CHECK=1
PASS=0; FAIL=0
chk() { local d="$1"; shift; if "$@"; then echo "  PASS  $d"; PASS=$((PASS+1)); else echo "  FAIL  $d"; FAIL=$((FAIL+1)); fi; }
cleanup() { pkill -f "srv.py $W" 2>/dev/null; pkill -f "sess.py" 2>/dev/null
  for c in INPUT; do while n=$(iptables -L $c -n --line-numbers 2>/dev/null | grep -E 'skipa' | head -1 | awk '{print $1}'); [ -n "$n" ]; do iptables -D $c "$n" || break; done; done
  for s in skipa-scanners skipa-manual skipa-allow; do ipset flush $s 2>/dev/null; ipset destroy $s 2>/dev/null; done
  ip netns del cli 2>/dev/null; ip link del vs 2>/dev/null; rm -rf "$W"; }
trap cleanup EXIT
cleanup_pre() { ip netns del cli 2>/dev/null; ip link del vs 2>/dev/null; }; cleanup_pre

ip netns add cli && ip link add vs type veth peer name vc && ip link set vc netns cli || { echo "netns/veth недоступны"; exit 2; }
ip addr add 10.200.0.1/24 dev vs && ip link set vs up
ip netns exec cli ip addr add 10.200.0.2/24 dev vc && ip netns exec cli ip link set vc up && ip netns exec cli ip link set lo up

cat > "$W/srv.py" <<'EOF'
import socket, threading, sys
def tcp():
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("10.200.0.1", 9000)); s.listen(16)
    def h(c):
        try:
            while True:
                d = c.recv(64)
                if not d: break
                c.sendall(d)
        except OSError: pass
    while True:
        c, _ = s.accept(); threading.Thread(target=h, args=(c,), daemon=True).start()
def udp():
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.bind(("10.200.0.1", 9001))
    while True:
        d, a = u.recvfrom(64); u.sendto(d, a)
threading.Thread(target=udp, daemon=True).start(); tcp()
EOF
cat > "$W/new.py" <<'EOF'
import socket, sys
s = socket.socket(); s.settimeout(2)
try:
    s.connect(("10.200.0.1", 9000)); s.sendall(b"x"); print("OK" if s.recv(8) == b"x" else "BAD")
except OSError: print("FAIL")
EOF
cat > "$W/udp.py" <<'EOF'
import socket
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.settimeout(1.5)
u.sendto(b"u", ("10.200.0.1", 9001))
try: print("OK" if u.recv(8) == b"u" else "BAD")
except OSError: print("FAIL")
EOF
# долгая сессия: раз в 0.2 с шлёт байт и считает эхо; печатает счётчик по сигналу через файл
cat > "$W/sess.py" <<'EOF'
import socket, sys, time
out = sys.argv[1]; s = socket.socket(); s.settimeout(0.5); s.connect(("10.200.0.1", 9000)); n = 0
while True:
    try:
        s.sendall(b"p"); 
        if s.recv(8) == b"p": n += 1
    except OSError: pass
    open(out, "w").write(str(n)); time.sleep(0.2)
EOF
python3 "$W/srv.py" "$W" & sleep 0.5
tryc() { ip netns exec cli python3 "$W/$1.py"; }

echo "== 0. без правил: всё проходит"
chk "новое TCP-соединение проходит" test "$(tryc new)" = OK
chk "UDP проходит"                    test "$(tryc udp)" = OK

source service/lib-ipset.sh; create_base_sets        # наборы с теми же параметрами, что создаёт сам проект
ipset add skipa-scanners 10.200.0.2 -exist     # «сканер» - адрес клиента в другом netns
cfg() { sed "s#/var/log/skipa_watchdog#$W/log#" config.example.yaml | sed "s#keep_established_tcp: false#keep_established_tcp: $1#"; }
clear_rules() { while n=$(iptables -L INPUT -n --line-numbers | grep -E 'skipa' | head -1 | awk '{print $1}'); [ -n "$n" ]; do iptables -D INPUT "$n"; done; }
sess_count() { cat "$W/count" 2>/dev/null || echo 0; }

echo "== 1. keep_established_tcp = false (по умолчанию): блокируется ВСЁ, включая установленную сессию"
rm -f "$W/count"; ip netns exec cli python3 "$W/sess.py" "$W/count" & SP=$!; sleep 1
c0=$(sess_count); chk "до блокировки сессия живая (эхо идёт, счётчик $c0 > 0)" test "$c0" -gt 0
cfg false > "$W/c.yaml"; bash service/setup-ipset-rules.sh "$W/c.yaml" >/dev/null 2>&1
sleep 1; c1=$(sess_count); sleep 1.5; c2=$(sess_count)
chk "установленная сессия ОБОРВАНА (счётчик встал: $c1 -> $c2)" test "$c2" = "$c1"
chk "новое соединение блокируется"  test "$(tryc new)" = FAIL
chk "UDP блокируется"                test "$(tryc udp)" = FAIL
kill $SP 2>/dev/null; wait $SP 2>/dev/null; clear_rules

echo "== 2. keep_established_tcp = true: новые TCP и не-TCP блокируются, установленная сессия ЖИВЁТ"
rm -f "$W/count"; ip netns exec cli python3 "$W/sess.py" "$W/count" & SP=$!; sleep 1
c0=$(sess_count); chk "до блокировки сессия живая (счётчик $c0 > 0)" test "$c0" -gt 0
cfg true > "$W/c.yaml"; bash service/setup-ipset-rules.sh "$W/c.yaml" >/dev/null 2>&1
sleep 1; c1=$(sess_count); sleep 1.5; c2=$(sess_count)
chk "установленная сессия ПРОДОЛЖАЕТ работать ($c1 -> $c2)"  test "$c2" -gt "$c1"
chk "НОВОЕ TCP-соединение блокируется (SYN отброшен)"        test "$(tryc new)" = FAIL
chk "UDP блокируется"                                         test "$(tryc udp)" = FAIL
chk "в INPUT нет RETURN-правил skipa (хостовые правила не обходятся)" bash -c "! iptables -S INPUT | grep -E 'skipa.*-j RETURN'"
echo "  --- возврат к false на лету: правила прежнего вида заменяются, сессия теперь рвётся"
cfg false > "$W/c.yaml"; bash service/setup-ipset-rules.sh "$W/c.yaml" >/dev/null 2>&1
sleep 1; c1=$(sess_count); sleep 1.5; c2=$(sess_count)
chk "после выключения опции сессия оборвана ($c1 -> $c2)"    test "$c2" = "$c1"
chk "правил прежнего вида не осталось (ровно 1 DROP по scanners)" test "$(iptables -S INPUT | grep 'match-set skipa-scanners' | grep -c -- '-j DROP')" = 1
kill $SP 2>/dev/null; wait $SP 2>/dev/null

echo "== 3. адрес из allowlist не блокируется даже в списке"
ipset add skipa-allow 10.200.0.2 -exist
chk "новое соединение из allowlist проходит" test "$(tryc new)" = OK
echo; echo "ИТОГО: PASS=$PASS FAIL=$FAIL"
