#!/usr/bin/env bash
# Скачивает и объединяет списки IP-сканеров и атомарно загружает их в ipset
# "skipa-scanners" - никакого Python, только curl/wget + ipset + awk.
#
# Запускается install.sh при установке и дальше периодически через
# skipa-watchdog-sync-lists.timer (systemd). Можно и вручную:
#   sudo bash sync-lists.sh /opt/skipa_watchdog/service.conf
set -uo pipefail

CONF="${1:-/opt/skipa_watchdog/service.conf}"
if [ ! -f "$CONF" ]; then
    echo "Конфиг $CONF не найден" >&2
    exit 1
fi
# shellcheck disable=SC1090
source "$CONF"

LOG_DIR="${LOG_DIR:-/var/log/skipa_watchdog}"
STATE_DIR="/var/lib/skipa_watchdog"
mkdir -p "$LOG_DIR" "$STATE_DIR"

SETNAME="skipa-scanners"
TMPSET="skipa-scanners-tmp"
MAXELEM=200000
RANGE_CAP=65536

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [sync-lists] $*" | tee -a "$LOG_DIR/skipa-watchdog.log" >&2
}

fetch() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --max-time 30 "$1" 2>/dev/null
    elif command -v wget >/dev/null 2>&1; then
        wget -qO- --timeout=30 "$1" 2>/dev/null
    fi
}

# Раскладывает диапазон A-B на отдельные записи /32 (с ограничением по
# размеру - предохранитель от случайно огромного диапазона в источнике).
expand_range() {
    local start="$1" end="$2"
    awk -v start="$start" -v end="$end" -v cap="$RANGE_CAP" '
    function ip2int(ip,   a,n) {
        n = split(ip, a, ".")
        if (n != 4) return -1
        return (a[1]*16777216)+(a[2]*65536)+(a[3]*256)+a[4]
    }
    function int2ip(n,   o1,o2,o3,o4) {
        o1 = int(n/16777216); n = n % 16777216
        o2 = int(n/65536); n = n % 65536
        o3 = int(n/256); o4 = n % 256
        return o1"."o2"."o3"."o4
    }
    BEGIN {
        s = ip2int(start); e = ip2int(end)
        if (s < 0 || e < 0 || e < s) { exit 0 }
        if (e - s + 1 > cap) { exit 0 }
        for (i = s; i <= e; i++) print int2ip(i) "/32"
    }'
}

# Построчно нормализует источник (CIDR / диапазон "A-B" / одиночный IP) в
# записи вида "IP/MASK".
normalize_list() {
    while IFS= read -r line; do
        line="${line%%#*}"
        line="$(echo "$line" | tr -d '[:space:]')"
        [ -z "$line" ] && continue
        case "$line" in
            */*) echo "$line" ;;
            *-*) expand_range "${line%-*}" "${line#*-}" ;;
            *) echo "${line}/32" ;;
        esac
    done
}

use_list1=0
use_list2=0
case "${ACTIVE_LIST:-merged}" in
    list1) use_list1=1 ;;
    list2) use_list2=1 ;;
    *) use_list1=1; use_list2=1 ;;
esac

RAW_FILE="$(mktemp)"
trap 'rm -f "$RAW_FILE"' EXIT

# Оба источника скачиваются всегда, независимо от ACTIVE_LIST - чтобы данные
# по обоим листам оставались свежими (и было с чем сравнивать при смене
# активного списка), а не протухали, пока не выбраны. ACTIVE_LIST влияет
# только на то, какие из скачанных записей реально попадают в ipset ниже.
PRIMARY_NORMALIZED=""
BLACKLIST_NORMALIZED=""
if [ -n "${PRIMARY_LIST_URL:-}" ]; then
    PRIMARY_NORMALIZED="$(fetch "$PRIMARY_LIST_URL" | normalize_list)"
fi
if [ -n "${BLACKLIST_URL:-}" ]; then
    BLACKLIST_NORMALIZED="$(fetch "$BLACKLIST_URL" | normalize_list)"
fi

if [ "$use_list1" = "1" ] && [ -n "$PRIMARY_NORMALIZED" ]; then
    printf '%s\n' "$PRIMARY_NORMALIZED" >> "$RAW_FILE"
fi
if [ "$use_list2" = "1" ] && [ -n "$BLACKLIST_NORMALIZED" ]; then
    printf '%s\n' "$BLACKLIST_NORMALIZED" >> "$RAW_FILE"
fi

# Исключения (IGNORE_IPS) - точное построчное совпадение, см. комментарий в
# service.conf.example про ограничение этого подхода.
if [ -n "${IGNORE_IPS:-}" ]; then
    for ign in $IGNORE_IPS; do
        [[ "$ign" == */* ]] || ign="${ign}/32"
        grep -vxF "$ign" "$RAW_FILE" > "$RAW_FILE.f" 2>/dev/null && mv "$RAW_FILE.f" "$RAW_FILE"
    done
fi

sort -u "$RAW_FILE" -o "$RAW_FILE"
COUNT=$(wc -l < "$RAW_FILE" | tr -d ' ')

if [ "$COUNT" -eq 0 ]; then
    log "Не удалось получить ни одной записи (сеть недоступна или оба источника пусты) -" \
        "оставляю текущий ipset без изменений."
    exit 0
fi

# Собираем новый набор во временном ipset и подменяем им боевой атомарно
# (ipset swap) - без окна, когда список пуст или наполовину загружен.
ipset create "$TMPSET" hash:net maxelem "$MAXELEM" -exist
ipset flush "$TMPSET"
{
    echo "create $TMPSET hash:net maxelem $MAXELEM -exist"
    while IFS= read -r net; do
        echo "add $TMPSET $net -exist"
    done < "$RAW_FILE"
} | ipset restore -exist

ipset create "$SETNAME" hash:net maxelem "$MAXELEM" -exist
ipset swap "$TMPSET" "$SETNAME"
ipset destroy "$TMPSET" 2>/dev/null || true

date +%s > "$STATE_DIR/last-sync"
log "Обновлено: $COUNT записей в ipset $SETNAME (active_list=${ACTIVE_LIST:-merged})"
