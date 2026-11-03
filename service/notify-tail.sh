#!/usr/bin/env bash
# Хвостует journalctl -k: пишет обнаружения в detections.log и, если настроен Telegram или
# Matrix, отправляет уведомления (service/lib-notify.sh). Нужен только если action.mode
# включает notify ("notify"/"block_notify"): при чистом "block" всё идёт в ядре и этот
# процесс не запускается.
#
# Сообщения копятся notifications.batch_seconds секунд и уходят одним сообщением (до
# notifications.batch_max адресов), поэтому волна сканов не превращается в поток алертов.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONF="${1:-$HERE/../config.yaml}"
if [ ! -f "$CONF" ]; then
    echo "Конфиг $CONF не найден" >&2
    exit 1
fi
# shellcheck source=lib-config.sh
source "$HERE/lib-config.sh"
# shellcheck source=lib-notify.sh
source "$HERE/lib-notify.sh"
load_service_config "$CONF"
# shellcheck disable=SC2034  # STATE_DIR читает load_notify_config (lib-notify.sh)
STATE_DIR="${SKIPA_STATE_DIR:-/var/lib/skipa_watchdog}"
load_notify_config "$CONF"
PREFIX="$KERNEL_LOG_PREFIX"
mkdir -p "$LOG_DIR"
DETECTIONS_LOG="$LOG_DIR/detections.log"
PROCESS_LOG="$LOG_DIR/skipa-watchdog.log"
HOST="$(hostname 2>/dev/null || echo host)"

CHANNELS="$(notify_channels | tr '\n' ' ')"
echo "$(date '+%Y-%m-%d %H:%M:%S') [notify-tail] Запущен, слежу за journalctl -k (префикс '$PREFIX'), уведомления: ${CHANNELS:-нет}" \
    >> "$PROCESS_LOG"

# Антиспам: один и тот же IP пишется в detections.log и уведомления не чаще раза в
# monitoring.alert_cooldown_minutes (иначе сканер, бьющий по портам, давал бы до 30
# записей в секунду - лимит LOG-правила).
COOLDOWN=$(( ${ALERT_COOLDOWN_MINUTES:-60} * 60 ))
SRC_RE='SRC=([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)'
DPT_RE='DPT=([0-9]+)'
PROTO_RE='PROTO=([A-Za-z0-9]+)'
if [ "$NOTIFY_LANG" = "en" ]; then
    MSG_HEAD="Scanners detected"; MSG_MORE="and"; MSG_MORE_END="more"
    case "${ACTION_MODE:-block_notify}" in
        *block*) VERDICT="blocked by the kernel" ;;
        *)       VERDICT="notify only, not blocked" ;;
    esac
else
    MSG_HEAD="Обнаружено сканеров"; MSG_MORE="и ещё"; MSG_MORE_END=""
    case "${ACTION_MODE:-block_notify}" in
        *block*) VERDICT="заблокирован ядром" ;;
        *)       VERDICT="только уведомление, не блокируется" ;;
    esac
fi

# Собирает сообщение из накопленных строк "ip proto port" и ставит в очередь
flush_batch() {
    local n="${#pending[@]}" shown i text ip proto port
    [ "$n" -gt 0 ] || return 0
    if [ -n "$CHANNELS" ]; then
        shown=$n; [ "$shown" -gt "$NOTIFY_BATCH_MAX" ] && shown="$NOTIFY_BATCH_MAX"
        text="Skipa Watchdog @ ${HOST}"$'\n'"${MSG_HEAD}: ${n} (${VERDICT})"
        for ((i = 0; i < shown; i++)); do
            read -r ip proto port <<< "${pending[i]}"
            text+=$'\n'"• ${ip}  ${proto}/${port}"
        done
        [ "$n" -gt "$shown" ] && text+=$'\n'"… ${MSG_MORE} $((n - shown))${MSG_MORE_END:+ $MSG_MORE_END}"
        # лимит Telegram - 4096 символов; строки короткие, но страхуемся
        notify_enqueue "${text:0:3900}"
        ( notify_drain ) &
    fi
    pending=()
    batch_started=0
}

pending=()
batch_started=0
last_retry=0

journalctl -k -f -n 0 --output=cat 2>/dev/null | grep --line-buffered -F "$PREFIX" | {
    declare -A last_seen=()
    while true; do
        # read -t: без новых строк просыпаемся раз в 5 секунд, чтобы отправить накопленное
        # и повторить неудавшуюся очередь
        IFS= read -r -t 5 line
        rc=$?
        now=$(date +%s)
        if [ "$rc" -gt 128 ]; then
            line=""
        elif [ "$rc" -ne 0 ]; then
            flush_batch; break          # journalctl завершился
        fi

        if [ -n "$line" ] && [[ $line =~ $SRC_RE ]]; then
            src="${BASH_REMATCH[1]}"
            dpt="-"
            [[ $line =~ $DPT_RE ]] && dpt="${BASH_REMATCH[1]}"
            proto="?"
            [[ $line =~ $PROTO_RE ]] && proto="${BASH_REMATCH[1]}"

            prev="${last_seen[$src]:-0}"
            if [ $((now - prev)) -ge "$COOLDOWN" ]; then
                last_seen[$src]=$now
                # не даём массиву расти бесконечно
                if [ "${#last_seen[@]}" -gt 20000 ]; then
                    last_seen=()
                fi
                ts="$(date '+%Y-%m-%d %H:%M:%S')"
                # в журнал ядра может попасть что угодно между нашими полями: оставляем печатаемый ASCII,
                # иначе управляющие символы/переводы строк позволили бы подделать соседние записи
                line="${line//[^[:print:]]/ }"
                {
                    echo "===== $ts | IP=$src | proto=$proto port=$dpt ====="
                    echo "$line"
                    echo
                } >> "$DETECTIONS_LOG"
                echo "$ts [notify-tail] СКАНЕР ОБНАРУЖЕН: $src ($proto, порт $dpt)" >> "$PROCESS_LOG"
                [ "${#pending[@]}" -eq 0 ] && batch_started=$now
                pending+=("$src $proto $dpt")
            fi
        fi

        if [ "${#pending[@]}" -gt 0 ] \
           && { [ $((now - batch_started)) -ge "$NOTIFY_BATCH_SECONDS" ] || [ "${#pending[@]}" -ge $((NOTIFY_BATCH_MAX * 5)) ]; }; then
            flush_batch
        fi
        # очередь не пуста (не было связи) - пробуем снова не чаще раза в минуту
        if [ -n "$CHANNELS" ] && [ $((now - last_retry)) -ge 60 ] && [ "$(notify_spool_size)" -gt 0 ]; then
            last_retry=$now
            ( notify_drain ) &
        fi
    done
    wait        # фоновые отправки должны закончиться до выхода (journalctl завершился / остановка юнита)
}
