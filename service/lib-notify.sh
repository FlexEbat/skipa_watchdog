#!/usr/bin/env bash
# Уведомления из bash: Telegram и Matrix через curl, без Python и без постоянного бота.
# Только отправка - команд в чате нет: управление остаётся в меню `sudo skipa-watchdog`.
#
# Подключение:  source lib-config.sh; source lib-notify.sh; load_service_config <config.yaml>
#               load_notify_config <config.yaml>
#
#   notify_channels                  включённые каналы по одному в строке (telegram, matrix)
#   notify_enqueue <текст>           положить сообщение в очередь по файлу на канал (быстро, без сети)
#   notify_drain                     отправить очередь: по порядку, с повтором при сбое сети
#   notify_test                      отправить пробное сообщение сразу, код возврата 0 - все каналы ок
#   notify_validate_telegram <token> <chat_id>      проверка формата перед записью в config.yaml
#   notify_validate_matrix <homeserver> <token> <room_id>
#
# Секреты (токен Telegram, access token Matrix) никогда не попадают в аргументы процессов:
# адрес и заголовки передаются curl через `-K -` (stdin). Сообщения - обычный текст, без
# HTML/Markdown, поэтому экранировать нечего, а адрес сканера из журнала ядра безопасен.
#
# Очередь ($STATE_DIR/notify-spool, имя файла: <секунды>-<номер>.<канал>):
#   - сообщение старше 24 часов и всё, что сверх 200 файлов, выбрасывается;
#   - сетевая ошибка и 5xx - повтор позже, порядок сохраняется;
#   - 429 - ждём retry_after (не дольше 60 с);
#   - 400/401/403/404 (неверный токен, чат, комната) - повторять бессмысленно, сообщение
#     выбрасывается с записью в журнал, чтобы очередь не росла вечно.

NOTIFY_MAX_AGE=86400
NOTIFY_MAX_FILES=200
NOTIFY_CURL_TIMEOUT=20

_notify_log() {
    local dir="${LOG_DIR:-/var/log/skipa_watchdog}"
    mkdir -p "$dir" 2>/dev/null
    echo "$(date '+%Y-%m-%d %H:%M:%S') [notify] $*" >> "$dir/skipa-watchdog.log" 2>/dev/null
}

# --- проверка формата -------------------------------------------------------------------------

notify_validate_telegram() {
    [[ "${1:-}" =~ ^[0-9]+:[A-Za-z0-9_-]+$ ]] || { echo "токен бота должен выглядеть как 123456:ABC-def" >&2; return 1; }
    [[ "${2:-}" =~ ^-?[0-9]+$ ]] && [ "${2:-0}" != "0" ] || { echo "chat_id - целое число, не 0 (у групп оно отрицательное)" >&2; return 1; }
}

notify_validate_matrix() {
    local hs="${1:-}" token="${2:-}" room="${3:-}"
    if ! [[ "$hs" =~ ^https://[A-Za-z0-9.-]+(:[0-9]+)?(/[A-Za-z0-9._~/-]*)?$ \
         || "$hs" =~ ^http://(localhost|127\.0\.0\.1)(:[0-9]+)?(/[A-Za-z0-9._~/-]*)?$ ]]; then
        echo "homeserver - адрес вида https://matrix.example.org (http допускается только для localhost)" >&2; return 1
    fi
    [[ "$token" =~ ^[A-Za-z0-9_.~+/=-]+$ ]] || { echo "access_token содержит недопустимые символы" >&2; return 1; }
    [[ "$room" =~ ^![A-Za-z0-9._=/+-]+:[A-Za-z0-9.-]+(:[0-9]+)?$ ]] \
        || { echo "room_id - идентификатор вида !abcdef:example.org (не алиас #комната)" >&2; return 1; }
}

# --- настройки --------------------------------------------------------------------------------

# Выставляет TG_TOKEN TG_CHAT TG_PROXY MX_HOMESERVER MX_TOKEN MX_ROOM NOTIFY_BATCH_SECONDS NOTIFY_BATCH_MAX NOTIFY_LANG.
# shellcheck disable=SC2034  # переменные читают notify-tail.sh и install.sh
# Значение, не прошедшее проверку формата, считается пустым: канал просто выключен.
load_notify_config() {
    local file="$1" v
    TG_TOKEN="$(yaml_get "$file" telegram.bot_token)"
    TG_CHAT="$(yaml_get "$file" telegram.chat_id)"
    TG_PROXY="$(yaml_get "$file" telegram.proxy)"
    notify_validate_telegram "$TG_TOKEN" "$TG_CHAT" 2>/dev/null || { TG_TOKEN=""; TG_CHAT=""; }
    [[ "$TG_PROXY" =~ ^(https?|socks5h?)://[A-Za-z0-9._:@%+-]+$ ]] || TG_PROXY=""
    MX_HOMESERVER="$(yaml_get "$file" matrix.homeserver)"; MX_HOMESERVER="${MX_HOMESERVER%/}"
    MX_TOKEN="$(yaml_get "$file" matrix.access_token)"
    MX_ROOM="$(yaml_get "$file" matrix.room_id)"
    notify_validate_matrix "$MX_HOMESERVER" "$MX_TOKEN" "$MX_ROOM" 2>/dev/null \
        || { MX_HOMESERVER=""; MX_TOKEN=""; MX_ROOM=""; }
    v="$(yaml_get "$file" notifications.batch_seconds)"
    [[ "$v" =~ ^[0-9]+$ ]] || v=30
    [ "$v" -gt 3600 ] && v=3600
    NOTIFY_BATCH_SECONDS="$v"
    v="$(yaml_get "$file" notifications.batch_max)"
    [[ "$v" =~ ^[0-9]+$ ]] && [ "$v" -ge 1 ] || v=20
    NOTIFY_BATCH_MAX="$v"
    NOTIFY_LANG="$(yaml_get "$file" notifications.language)"
    [ "$NOTIFY_LANG" = "en" ] || NOTIFY_LANG="ru"
    NOTIFY_SPOOL="${STATE_DIR:-${SKIPA_STATE_DIR:-/var/lib/skipa_watchdog}}/notify-spool"
}

notify_channels() {
    [ -n "${TG_TOKEN:-}" ] && echo telegram
    [ -n "${MX_TOKEN:-}" ] && echo matrix
    return 0
}

# --- отправка одного сообщения ----------------------------------------------------------------

# Перекодирование в %XX: нужно для room_id в пути запроса Matrix (! и :)
_urlencode() {
    local s="$1" out="" i c
    for ((i = 0; i < ${#s}; i++)); do
        c="${s:i:1}"
        case "$c" in
            [A-Za-z0-9._~-]) out+="$c" ;;
            *) out+="$(printf '%%%02X' "'$c")" ;;
        esac
    done
    printf '%s' "$out"
}

# Текст -> содержимое JSON-строки (без внешних кавычек)
_json_escape() {
    local s="$1" out="" i c
    for ((i = 0; i < ${#s}; i++)); do
        c="${s:i:1}"
        case "$c" in
            '\') out+='\\' ;;
            '"') out+='\"' ;;
            $'\n') out+='\n' ;;
            $'\r') out+='\r' ;;
            $'\t') out+='\t' ;;
            [[:cntrl:]]) out+="$(printf '\\u%04x' "'$c")" ;;
            *) out+="$c" ;;
        esac
    done
    printf '%s' "$out"
}

# Итог запроса: 0 - доставлено; 1 - повторить позже; 2 - повторять бессмысленно; 3 - 429, ждать
# NOTIFY_RETRY_AFTER секунд. $1 - код HTTP ("000" - сети нет), $2 - файл с телом ответа.
_notify_classify() {
    local code="$1" body="$2"
    NOTIFY_RETRY_AFTER=0
    case "$code" in
        2??) return 0 ;;
        429)
            NOTIFY_RETRY_AFTER="$(grep -o '"retry_after"[[:space:]]*:[[:space:]]*[0-9]*' "$body" 2>/dev/null | grep -o '[0-9]*$' | head -n1)"
            [[ "$NOTIFY_RETRY_AFTER" =~ ^[0-9]+$ ]] || NOTIFY_RETRY_AFTER=5
            [ "$NOTIFY_RETRY_AFTER" -gt 60 ] && NOTIFY_RETRY_AFTER=60
            return 3 ;;
        400|401|403|404) return 2 ;;
        *) return 1 ;;
    esac
}

# $1 - файл с текстом. Токен и адрес идут в curl через stdin (-K -).
_send_telegram() {
    local file="$1" body code
    body="$(mktemp)" || return 1
    code="$({
        printf 'url = "https://api.telegram.org/bot%s/sendMessage"\n' "$TG_TOKEN"
        [ -n "$TG_PROXY" ] && printf 'proxy = "%s"\n' "$TG_PROXY"
    } | curl -sS -K - --proto '=https' --proto-redir '=https' --max-time "$NOTIFY_CURL_TIMEOUT" \
            -o "$body" -w '%{http_code}' \
            --data-urlencode "chat_id=$TG_CHAT" --data-urlencode "text@$file" \
            --data-urlencode "disable_web_page_preview=true" 2>/dev/null)"
    _notify_classify "${code:-000}" "$body"
    local rc=$?
    rm -f "$body"
    return $rc
}

# $1 - файл с текстом, $2 - идентификатор транзакции: при повторе того же сообщения сервер
# Matrix увидит тот же txnId и не создаст дубль.
_send_matrix() {
    local file="$1" txn="$2" body code text payload
    text="$(cat "$file")"
    payload="{\"msgtype\":\"m.text\",\"body\":\"$(_json_escape "$text")\"}"
    body="$(mktemp)" || return 1
    code="$({
        printf 'url = "%s/_matrix/client/v3/rooms/%s/send/m.room.message/%s"\n' \
            "$MX_HOMESERVER" "$(_urlencode "$MX_ROOM")" "$(_urlencode "$txn")"
        printf 'header = "Authorization: Bearer %s"\n' "$MX_TOKEN"
        printf 'header = "Content-Type: application/json"\n'
    } | curl -sS -K - -X PUT --max-time "$NOTIFY_CURL_TIMEOUT" -o "$body" -w '%{http_code}' \
            --data-binary "$payload" 2>/dev/null)"
    _notify_classify "${code:-000}" "$body"
    local rc=$?
    rm -f "$body"
    return $rc
}

# --- очередь ----------------------------------------------------------------------------------

notify_enqueue() {
    local text="$1" ch id n
    [ -n "$(notify_channels)" ] || return 0
    mkdir -p "$NOTIFY_SPOOL" 2>/dev/null || return 1
    chmod 700 "$NOTIFY_SPOOL" 2>/dev/null
    n="$(find "$NOTIFY_SPOOL" -maxdepth 1 -type f 2>/dev/null | wc -l)"
    if [ "$n" -ge "$NOTIFY_MAX_FILES" ]; then
        # очередь забита (долго нет связи): выбрасываем самые старые, новое важнее
        find "$NOTIFY_SPOOL" -maxdepth 1 -type f -printf '%f\n' | sort | head -n $((n - NOTIFY_MAX_FILES + 2)) \
            | while IFS= read -r old; do rm -f "$NOTIFY_SPOOL/$old"; done
        _notify_log "очередь уведомлений переполнена - старые сообщения выброшены"
    fi
    id="$(date +%s)-$(printf '%05d' $((RANDOM % 100000)))$$"
    while IFS= read -r ch; do
        ( umask 077; printf '%s\n' "$text" > "$NOTIFY_SPOOL/$id.$ch" )
    done < <(notify_channels)
}

# Один проход по очереди. Код: 0 - всё отправлено или выброшено, 1 - сбой связи (остальное не трогаем:
# порядок важнее). NOTIFY_DRAINED - сколько файлов обработано за проход.
_notify_drain_pass() {
    local f name ch now ts rc tries
    now="$(date +%s)"; NOTIFY_DRAINED=0
    while IFS= read -r name; do
        f="$NOTIFY_SPOOL/$name"; [ -f "$f" ] || continue
        ch="${name##*.}"; ts="${name%%-*}"
        NOTIFY_DRAINED=$((NOTIFY_DRAINED + 1))
        if [[ "$ts" =~ ^[0-9]+$ ]] && [ $((now - ts)) -gt "$NOTIFY_MAX_AGE" ]; then
            rm -f "$f"; _notify_log "сообщение $name старше суток - выброшено"; continue
        fi
        tries=0
        while :; do
            case "$ch" in
                telegram) [ -n "${TG_TOKEN:-}" ] && _send_telegram "$f"; rc=$? ;;
                matrix)   [ -n "${MX_TOKEN:-}" ] && _send_matrix "$f" "${name%.*}"; rc=$? ;;
                *)        rc=2 ;;
            esac
            # канал выключили в конфиге после постановки в очередь: сообщение уже не нужно
            { [ "$ch" = telegram ] && [ -z "${TG_TOKEN:-}" ]; } || { [ "$ch" = matrix ] && [ -z "${MX_TOKEN:-}" ]; } && rc=2
            if [ "$rc" -eq 3 ] && [ "$tries" -lt 2 ]; then
                tries=$((tries + 1)); sleep "${NOTIFY_RETRY_AFTER:-5}"; continue
            fi
            break
        done
        case "$rc" in
            0) rm -f "$f" ;;
            2) rm -f "$f"; _notify_log "$ch: сервер отклонил сообщение (проверьте токен, chat_id/комнату) - выброшено" ;;
            *) _notify_log "$ch: не удалось отправить, повторю позже"; return 1 ;;
        esac
    done < <(find "$NOTIFY_SPOOL" -maxdepth 1 -type f -name '*-*.*' -printf '%f\n' | sort)
    return 0
}

notify_drain() {
    [ -d "$NOTIFY_SPOOL" ] || return 0
    command -v curl >/dev/null 2>&1 || { _notify_log "curl не найден - уведомления не отправляются"; return 1; }
    # одна очередь - один отправитель: иначе тот же файл уйдёт дважды
    exec 8>"$NOTIFY_SPOOL/.lock"
    if command -v flock >/dev/null 2>&1; then flock -n 8 || return 0; fi
    local _
    # пока шёл проход, мог появиться новый файл (второй отправитель отказался из-за блокировки)
    for _ in 1 2 3 4 5; do
        _notify_drain_pass || return 1
        [ "${NOTIFY_DRAINED:-0}" -gt 0 ] || return 0
    done
    return 0
}

notify_spool_size() {
    find "${NOTIFY_SPOOL:-/nonexistent}" -maxdepth 1 -type f -name '*-*.*' 2>/dev/null | wc -l
}

# Пробное сообщение: сразу, мимо очереди, с подробным итогом по каналам.
notify_test() {
    local f ch rc=0 host out
    host="$(hostname 2>/dev/null || echo host)"
    f="$(mktemp)" || return 1
    if [ "${NOTIFY_LANG:-ru}" = "en" ]; then
        printf 'Skipa Watchdog (%s): test notification, everything works.\n' "$host" > "$f"
    else
        printf 'Skipa Watchdog (%s): тестовое уведомление, всё работает.\n' "$host" > "$f"
    fi
    if [ -z "$(notify_channels)" ]; then
        echo "Ни один канал не настроен." >&2; rm -f "$f"; return 1
    fi
    while IFS= read -r ch; do
        case "$ch" in
            telegram) _send_telegram "$f"; out=$? ;;
            matrix)   _send_matrix "$f" "test-$(date +%s)-$$"; out=$? ;;
        esac
        case "$out" in
            0) echo "$ch: доставлено" ;;
            2) echo "$ch: сервер отклонил запрос - проверьте токен и chat_id/комнату"; rc=1 ;;
            3) echo "$ch: слишком частые запросы (429), попробуйте через минуту"; rc=1 ;;
            *) echo "$ch: нет связи с сервером"; rc=1 ;;
        esac
    done < <(notify_channels)
    rm -f "$f"
    return $rc
}
