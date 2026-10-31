#!/usr/bin/env bash
# Статистика детектов за период по detections.log. Работает в обоих вариантах (журнал
# пишут и Python-бот, и bash-демон), поэтому панель показывает одно и то же везде.
# Использование: stats.sh [config.yaml] [дней]   (по умолчанию config.yaml рядом, 7 дней)
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONF="${1:-$HERE/../config.yaml}"
DAYS="${2:-7}"
[[ "$DAYS" =~ ^[0-9]+$ ]] && [ "$DAYS" -ge 1 ] || DAYS=7

# shellcheck source=lib-config.sh
source "$HERE/lib-config.sh"
load_service_config "$CONF"
LOG="${LOG_DIR:-/var/log/skipa_watchdog}/detections.log"
[ -f "$LOG" ] || { echo "Журнал детектов пока пуст ($LOG не найден)."; exit 0; }

cutoff="$(date -d "-$((DAYS - 1)) days" +%F 2>/dev/null)" || cutoff="0000-00-00"

# Заголовок записи: "===== 2026-10-30 12:00:00 | IP=1.2.3.4 | match=... =====" (бот)
# или "... | IP=1.2.3.4 | proto=tcp port=22 =====" (bash-демон)
awk -v cutoff="$cutoff" -v days="$DAYS" '
    /^===== [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9] / {
        day = substr($2, 1, 10)
        if (day < cutoff) next
        ip = ""; port = ""; src = ""
        n = split($0, parts, " \\| ")
        for (i = 1; i <= n; i++) {
            if (parts[i] ~ /^IP=/) ip = substr(parts[i], 4)
            if (parts[i] ~ /port=[0-9]+/) { p = parts[i]; sub(/.*port=/, "", p); sub(/[^0-9].*/, "", p); port = p }
            if (parts[i] ~ /^match=/) { src = parts[i]; sub(/^match=/, "", src); sub(/ *=====$/, "", src); sub(/:.*/, "", src) }
        }
        if (ip == "") next
        total++; perday[day]++
        if (!(ip in seen)) { seen[ip] = 1; uniq++ }
        byip[ip]++
        if (port != "") byport[port]++
        if (src != "") bysrc[src]++
    }
    function top(arr, limit, label,    k, best, bestk, shown, used) {
        for (shown = 0; shown < limit; shown++) {
            best = 0; bestk = ""
            for (k in arr) if (!(k in used) && arr[k] > best) { best = arr[k]; bestk = k }
            if (bestk == "") break
            used[bestk] = 1
            printf "  %-40s %d\n", bestk, best
        }
    }
    END {
        printf "Детекты за последние %d дн.: %d (уникальных IP: %d)\n", days, total + 0, uniq + 0
        if (!total) exit
        print "\nТоп IP:";           top(byip, 10)
        if (length(byport)) { print "\nТоп портов:";    top(byport, 5) }
        if (length(bysrc))  { print "\nПо спискам:";    top(bysrc, 5) }
        print "\nПо дням:"
        for (d in perday) printf "  %s %d\n", d, perday[d] | "sort"
    }
' "$LOG"
