#!/usr/bin/env bash
# Скачивает и объединяет списки IP-сканеров и атомарно загружает их в ipset
# "skipa-scanners" - никакого Python, только curl/wget + ipset + awk.
#
# Запускается install.sh при установке и дальше периодически через
# skipa-watchdog-sync-lists.timer (systemd). Можно и вручную:
#   sudo bash sync-lists.sh /opt/skipa_watchdog/config.yaml
#
# Защита от сбоев источников:
#   - слишком широкие сети (короче sources.min_prefix, по умолчанию /20) и битые
#     строки отбрасываются; источник, покрывающий больше ~4 млн адресов, не принимается;
#   - скачивание только по https (sources.allow_insecure_http: true разрешает http);
#   - текущие SSH-сессии администратора попадают в allowlist (monitoring.auto_allowlist);
#   - если источник не скачался - используется его последняя удачная копия;
#   - если источник внезапно "похудел" больше чем вдвое - тоже;
#   - ipset подменяется (swap) только если restore прошёл без ошибок.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONF="${1:-$HERE/../config.yaml}"
if [ ! -f "$CONF" ]; then
    echo "Конфиг $CONF не найден" >&2
    exit 1
fi
# shellcheck source=lib-config.sh
source "$HERE/lib-config.sh"
load_service_config "$CONF"   # единый config.yaml, тот же, что читает watchdog.py
STATE_DIR="${SKIPA_STATE_DIR:-/var/lib/skipa_watchdog}"
mkdir -p "$LOG_DIR" "$STATE_DIR"

SETNAME="skipa-scanners"
TMPSET="skipa-scanners-tmp"
ALLOWSET="skipa-allow"
MAXELEM=200000
MAXELEM_ALLOW=4096
# MIN_PREFIX приходит из config.yaml (sources.min_prefix) через load_service_config
MAX_RANGE=1048576
MAX_COVERAGE=4194304   # столько адресов (~0,1% IPv4) максимум может покрывать один источник

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [sync-lists] $*" | tee -a "$LOG_DIR/skipa-watchdog.log" >&2
}

fetch() {
    # --max-filesize: источник не должен отдавать десятки мегабайт. Только https: списки
    # блокируются автоматически, подмена по пути равна управлению блокировками.
    local protos="https"
    [ "${ALLOW_INSECURE_HTTP:-false}" = "true" ] && protos="http,https"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --proto "=$protos" --proto-redir "=$protos" \
            --max-time 30 --max-filesize 20971520 "$1" 2>/dev/null
    elif command -v wget >/dev/null 2>&1; then
        if [ "$protos" = "https" ] && [[ "$1" != https://* ]]; then
            return 0
        fi
        wget -qO- --timeout=30 "$1" 2>/dev/null | head -c 20971520
    fi
}

# Нормализует источник в записи, которые ipset (hash:net) принимает как есть:
# "IP/MASK", диапазон "A-B" (ipset сам разложит его на сети - вручную
# раскладывать не нужно и лимитов на размер диапазона больше нет) или
# одиночный IP (-> /32). Битые строки, обратные диапазоны и сети короче
# /MIN_PREFIX отбрасываются.
normalize_list() {
    awk -v minp="$MIN_PREFIX" -v maxr="$MAX_RANGE" '
    function ip2int(ip,   a, n, k) {
        n = split(ip, a, ".")
        if (n != 4) return -1
        for (k = 1; k <= 4; k++) if (a[k] !~ /^[0-9]+$/ || a[k] + 0 > 255) return -1
        return a[1]*16777216 + a[2]*65536 + a[3]*256 + a[4]
    }
    {
        sub(/#.*/, ""); gsub(/[ \t\r]/, "")
        if ($0 == "") next
        if (index($0, "/")) {
            split($0, p, "/")
            if (ip2int(p[1]) < 0 || p[2] !~ /^[0-9]+$/ || p[2] + 0 > 32 || p[2] + 0 < minp) next
            print $0
        } else if (index($0, "-")) {
            split($0, p, "-")
            s = ip2int(p[1]); e = ip2int(p[2])
            if (s < 0 || e < s || e - s + 1 > maxr) next
            print p[1] "-" p[2]
        } else {
            if (ip2int($0) < 0) next
            print $0 "/32"
        }
    }'
}

# Сколько IPv4-адресов покрывает нормализованный список (грубая верхняя оценка).
coverage() {
    awk '
        index($0, "/") { split($0, p, "/"); total += 2 ^ (32 - p[2]); next }
        index($0, "-") { split($0, p, "-"); split(p[1], a, "."); split(p[2], b, ".")
                         total += (b[1]*16777216 + b[2]*65536 + b[3]*256 + b[4]) - (a[1]*16777216 + a[2]*65536 + a[3]*256 + a[4]) + 1 }
        END { printf "%d\n", total }'
}

# Скачивает один источник с откатом на последнюю удачную копию.
# $1 - имя (для файла кэша и лога), $2 - URL. Результат - в stdout.
get_source() {
    local name="$1" url="$2" cache="$STATE_DIR/$1.last" fresh="" n_new n_old=0
    [ -z "$url" ] && return 0
    fresh="$(fetch "$url" | normalize_list)"
    n_new=$(printf '%s' "$fresh" | grep -c . || true)
    [ -f "$cache" ] && n_old=$(grep -c . "$cache" || true)

    if [ "$n_new" -eq 0 ]; then
        if [ "$n_old" -gt 0 ]; then
            log "Источник $name недоступен - использую последнюю удачную копию ($n_old записей)"
            cat "$cache"
        else
            log "Источник $name недоступен, копии нет"
        fi
        return 0
    fi
    if [ "$(printf '%s\n' "$fresh" | coverage)" -gt "$MAX_COVERAGE" ]; then
        log "Источник $name покрывает больше $MAX_COVERAGE адресов - похоже на подмену, использую прошлую копию"
        [ "$n_old" -gt 0 ] && cat "$cache"
        return 0
    fi
    if [ "$n_old" -gt 0 ] && [ $((n_new * 2)) -lt "$n_old" ]; then
        log "Источник $name вернул $n_new записей вместо ~$n_old - похоже на сбой, использую прошлую копию"
        cat "$cache"
        return 0
    fi
    printf '%s\n' "$fresh" > "$cache"
    printf '%s\n' "$fresh"
}

# Атомарно подменяет содержимое набора: restore во временный + swap. Подмена
# выполняется ТОЛЬКО если restore прошёл без ошибок (раньше недозагруженный
# набор мог попасть в бой). $1 - боевой набор, $2 - временный, $3 - maxelem,
# $4 - файл с записями.
replace_set() {
    local live="$1" tmp="$2" maxelem="$3" file="$4"
    ipset create "$tmp" hash:net maxelem "$maxelem" -exist || return 1
    ipset flush "$tmp" || return 1
    {
        echo "create $tmp hash:net maxelem $maxelem -exist"
        while IFS= read -r net; do
            echo "add $tmp $net -exist"
        done < "$file"
    } | ipset restore -exist
    if [ "${PIPESTATUS[1]}" -ne 0 ]; then
        ipset destroy "$tmp" 2>/dev/null || true
        return 1
    fi
    ipset create "$live" hash:net maxelem "$maxelem" -exist || return 1
    ipset swap "$tmp" "$live" || { ipset destroy "$tmp" 2>/dev/null; return 1; }
    ipset destroy "$tmp" 2>/dev/null || true
}

use_list1=0
use_list2=0
case "${ACTIVE_LIST:-merged}" in
    list1) use_list1=1 ;;
    list2) use_list2=1 ;;
    *) use_list1=1; use_list2=1 ;;
esac

RAW_FILE="$(mktemp)"
ALLOW_FILE="$(mktemp)"
trap 'rm -f "$RAW_FILE" "$ALLOW_FILE"' EXIT

# Оба источника скачиваются всегда, независимо от ACTIVE_LIST - чтобы данные
# по обоим листам оставались свежими, а не протухали, пока не выбраны.
# ACTIVE_LIST влияет только на то, какие записи реально попадают в ipset.
PRIMARY_NORMALIZED="$(get_source primary "${PRIMARY_LIST_URL:-}")"
BLACKLIST_NORMALIZED="$(get_source blacklist "${BLACKLIST_URL:-}")"

[ "$use_list1" = "1" ] && [ -n "$PRIMARY_NORMALIZED" ] && printf '%s\n' "$PRIMARY_NORMALIZED" >> "$RAW_FILE"
[ "$use_list2" = "1" ] && [ -n "$BLACKLIST_NORMALIZED" ] && printf '%s\n' "$BLACKLIST_NORMALIZED" >> "$RAW_FILE"

sort -u "$RAW_FILE" -o "$RAW_FILE"
COUNT=$(grep -c . "$RAW_FILE" || true)

if [ "$COUNT" -eq 0 ]; then
    log "Не удалось получить ни одной записи (сеть недоступна или оба источника пусты) -" \
        "оставляю текущий ipset без изменений."
    exit 0
fi

# allowlist: частные/служебные сети + monitoring.ignore_ips (IP или CIDR). Это именно набор,
# а не вычёркивание строк из списка: так исключение работает и для адреса,
# лежащего ВНУТРИ большой сети из списка. DROP-правило проверяет его первым
# (см. setup-ipset-rules.sh).
{
    printf '%s\n' 127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16
    for ign in ${IGNORE_IPS:-}; do
        [[ "$ign" == */* ]] || ign="${ign}/32"
        echo "$ign"
    done
    # текущие SSH-сессии: свой адрес, попавший во внешний список, не должен отрезать от сервера
    if [ "${AUTO_ALLOWLIST:-true}" != "false" ]; then
        # shellcheck disable=SC2086
        ssh_peers ${SSH_PORTS:-22} | sed 's#$#/32#'
    fi
} | MIN_PREFIX=1 normalize_list | sort -u > "$ALLOW_FILE"

if ! replace_set "$ALLOWSET" "$ALLOWSET-tmp" "$MAXELEM_ALLOW" "$ALLOW_FILE"; then
    log "Не удалось обновить ipset $ALLOWSET - список сканеров НЕ обновляю, чтобы не заблокировать своих"
    exit 1
fi

if ! replace_set "$SETNAME" "$TMPSET" "$MAXELEM" "$RAW_FILE"; then
    log "ОШИБКА: не удалось загрузить список в ipset (возможно, превышен maxelem=$MAXELEM) -" \
        "прежнее содержимое $SETNAME оставлено без изменений"
    exit 1
fi

date +%s > "$STATE_DIR/last-sync"
log "Обновлено: $COUNT записей в ipset $SETNAME (active_list=${ACTIVE_LIST:-merged})"
