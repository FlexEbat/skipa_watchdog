#!/usr/bin/env bash
# Хвостует journalctl -k и пишет обнаружения в detections.log. Нужен только
# если ACTION_MODE включает notify ("notify"/"block_notify") - при чистом
# "block" блокировка идёт целиком в ядре (ipset+iptables), этот процесс не
# нужен вообще, и install.sh его не запускает.
set -uo pipefail

CONF="${1:-/opt/skipa_watchdog/service.conf}"
if [ ! -f "$CONF" ]; then
    echo "Конфиг $CONF не найден" >&2
    exit 1
fi
# shellcheck disable=SC1090
source "$CONF"

LOG_DIR="${LOG_DIR:-/var/log/skipa_watchdog}"
PREFIX="${KERNEL_LOG_PREFIX:-CONN: }"
mkdir -p "$LOG_DIR"
DETECTIONS_LOG="$LOG_DIR/detections.log"
PROCESS_LOG="$LOG_DIR/skipa-watchdog.log"

echo "$(date '+%Y-%m-%d %H:%M:%S') [notify-tail] Запущен, слежу за journalctl -k (префикс '$PREFIX')" \
    >> "$PROCESS_LOG"

# Антиспам: один и тот же IP пишется в detections.log не чаще раза в
# ALERT_COOLDOWN_MINUTES (иначе сканер, бьющий по портам, давал бы до 30
# записей в секунду - лимит LOG-правила).
COOLDOWN=$(( ${ALERT_COOLDOWN_MINUTES:-60} * 60 ))
SRC_RE='SRC=([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)'
DPT_RE='DPT=([0-9]+)'

journalctl -k -f -n 0 --output=cat 2>/dev/null | grep --line-buffered -F "$PREFIX" | {
    declare -A last_seen=()
    while IFS= read -r line; do
        [[ $line =~ $SRC_RE ]] || continue
        src="${BASH_REMATCH[1]}"
        dpt="?"
        [[ $line =~ $DPT_RE ]] && dpt="${BASH_REMATCH[1]}"

        now=$(date +%s)
        prev="${last_seen[$src]:-0}"
        if [ $((now - prev)) -lt "$COOLDOWN" ]; then
            continue
        fi
        last_seen[$src]=$now
        # не даём массиву расти бесконечно
        if [ "${#last_seen[@]}" -gt 20000 ]; then
            last_seen=()
        fi

        ts="$(date '+%Y-%m-%d %H:%M:%S')"
        {
            echo "===== $ts | IP=$src | port=$dpt ====="
            echo "$line"
            echo
        } >> "$DETECTIONS_LOG"
        echo "$ts [notify-tail] СКАНЕР ОБНАРУЖЕН: $src (порт $dpt)" >> "$PROCESS_LOG"
    done
}
