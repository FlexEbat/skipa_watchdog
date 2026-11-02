#!/usr/bin/env bash
# Общие функции режима "только сервис": блокировка от одновременного запуска,
# сохранение/восстановление ipset-наборов и проверка применённых правил.
# Подключается через `source` (set -u совместим).
#
#   acquire_ipset_lock [сек]  эксклюзивная блокировка на все операции с наборами
#   create_base_sets          создаёт (если нет) наборы skipa-scanners/-manual/-allow
#   save_ipsets               сохраняет наборы в $STATE_DIR/ipsets.save (атомарно)
#   restore_ipsets            восстанавливает наборы из этого файла
#   verify_service_rules      проверяет, что наборы и правила на месте (код 1 - нет)

# shellcheck disable=SC2034  # константы читают скрипты, подключающие библиотеку
SET_SCANNERS="skipa-scanners"
SET_MANUAL="skipa-manual"
SET_ALLOW="skipa-allow"
MAXELEM_SCANNERS=200000
MAXELEM_MANUAL=65536
MAXELEM_ALLOW=4096

ipset_state_dir() { echo "${SKIPA_STATE_DIR:-/var/lib/skipa_watchdog}"; }

# Таймер sync-lists, пункт меню «обновить базу», blockctl, setup-ipset-rules.sh и
# загрузочный скрипт работают с одними и теми же наборами, включая временные *-tmp
# (restore + swap). Одновременный запуск двух из них мог бы затереть чужой *-tmp или
# сохранить наполовину собранное состояние, поэтому всё идёт через один flock.
# Вложенные вызовы (sync-lists -> save_ipsets, boot -> setup-ipset-rules) не ждут сами
# себя: владелец блокировки выставляет SKIPA_IPSET_LOCKED=1, и дочерние процессы
# считают блокировку уже полученной.
acquire_ipset_lock() {
    local wait="${1:-120}" dir
    [ "${SKIPA_IPSET_LOCKED:-}" = "1" ] && return 0
    command -v flock >/dev/null 2>&1 || return 0          # нет flock - работаем как раньше
    dir="$(ipset_state_dir)"
    mkdir -p "$dir" 2>/dev/null || return 0
    exec 9>"$dir/ipset.lock" || return 0
    if ! flock -w "$wait" 9; then
        echo "Другая операция с ipset не завершилась за ${wait} с (блокировка $dir/ipset.lock) - выходим" >&2
        return 1
    fi
    export SKIPA_IPSET_LOCKED=1
}

create_base_sets() {
    ipset create "$SET_SCANNERS" hash:net maxelem "$MAXELEM_SCANNERS" -exist || return 1
    ipset create "$SET_MANUAL" hash:net maxelem "$MAXELEM_MANUAL" -exist || return 1
    ipset create "$SET_ALLOW" hash:net maxelem "$MAXELEM_ALLOW" -exist || return 1
}

# Наборы живут только в памяти ядра: после перезагрузки они пусты, а ручные блокировки
# (skipa-manual) без сохранения теряются безвозвратно. Файл пишется во временный и
# переименовывается, чтобы сбой посреди записи не оставил обрезанный файл.
save_ipsets() {
    local dir file tmp s any=0
    command -v ipset >/dev/null 2>&1 || return 0
    dir="$(ipset_state_dir)"; file="$dir/ipsets.save"
    mkdir -p "$dir" 2>/dev/null || return 1
    tmp="$(mktemp "$file.XXXXXX")" || return 1
    for s in "$SET_SCANNERS" "$SET_MANUAL" "$SET_ALLOW"; do
        if ipset list -n "$s" 2>/dev/null | grep -qx "$s"; then
            ipset save "$s" >> "$tmp" 2>/dev/null || { rm -f "$tmp"; return 1; }
            any=1
        fi
    done
    if [ "$any" -eq 0 ]; then rm -f "$tmp"; return 0; fi    # нечего сохранять - прежний файл не трогаем
    chmod 600 "$tmp"
    mv -f "$tmp" "$file"
}

restore_ipsets() {
    local file
    file="$(ipset_state_dir)/ipsets.save"
    [ -s "$file" ] || return 2                               # файла нет - это не ошибка, просто нечего восстанавливать
    ipset restore -exist < "$file"
}

# Проверка результата применения правил (по аналогии с проверкой после миграции):
# наборы существуют, в INPUT (и в DOCKER-USER, если он есть и не отключён) стоят правила
# с нашими наборами. Печатает построчный итог; код 1, если нет защиты хоста (INPUT).
verify_service_rules() {
    local rc=0 s chain rules
    for s in "$SET_SCANNERS" "$SET_MANUAL" "$SET_ALLOW"; do
        if ipset list -n "$s" 2>/dev/null | grep -qx "$s"; then
            echo "  ✓ ipset $s существует"
        else
            echo "  ✗ ipset $s НЕ существует"; rc=1
        fi
    done
    rules="$(iptables -w 5 -S INPUT 2>/dev/null)" || rules=""
    if grep -q -- "--match-set $SET_SCANNERS src" <<<"$rules" && grep -q -- "--match-set $SET_MANUAL src" <<<"$rules"; then
        echo "  ✓ в цепочке INPUT есть правила с $SET_SCANNERS и $SET_MANUAL"
    else
        echo "  ✗ в цепочке INPUT НЕТ правил skipa-*: хост не защищён (запустите пункт «Docker/Kubernetes → применить правила»)"
        rc=1
    fi
    if [ "${SKIP_DOCKER:-0}" != "1" ] && iptables -w 5 -L DOCKER-USER -n >/dev/null 2>&1; then
        rules="$(iptables -w 5 -S DOCKER-USER 2>/dev/null)" || rules=""
        if grep -q -- "--match-set $SET_SCANNERS src" <<<"$rules"; then
            echo "  ✓ в цепочке DOCKER-USER есть правила skipa-*"
        else
            echo "  ✗ в цепочке DOCKER-USER нет правил skipa-* (Docker-контейнеры не защищены)"; rc=1
        fi
    fi
    for chain in KUBE-EXTERNAL-SERVICES KUBE-NODEPORTS; do
        [ "${SKIP_K8S:-0}" = "1" ] && break
        iptables -w 5 -L "$chain" -n >/dev/null 2>&1 || continue
        rules="$(iptables -w 5 -S "$chain" 2>/dev/null)" || rules=""
        if grep -q -- "--match-set $SET_SCANNERS src" <<<"$rules"; then
            echo "  ✓ в цепочке $chain есть правила skipa-*"
        else
            echo "  ✗ в цепочке $chain нет правил skipa-*"; rc=1
        fi
    done
    return "$rc"
}
