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

journalctl -k -f -n 0 --output=cat 2>/dev/null | grep --line-buffered -F "$PREFIX" | while IFS= read -r line; do
    src="$(echo "$line" | grep -oP 'SRC=\K[0-9.]+' || true)"
    dpt="$(echo "$line" | grep -oP 'DPT=\K[0-9]+' || true)"
    [ -z "$src" ] && continue
    ts="$(date '+%Y-%m-%d %H:%M:%S')"
    {
        echo "===== $ts | IP=$src | port=${dpt:-?} ====="
        echo "$line"
        echo
    } >> "$DETECTIONS_LOG"
    echo "$ts [notify-tail] СКАНЕР ОБНАРУЖЕН: $src (порт ${dpt:-?})" >> "$PROCESS_LOG"
done
