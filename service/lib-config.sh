#!/usr/bin/env bash
# Чтение и запись config.yaml из bash - единственный конфиг проекта для обоих
# вариантов (только сервис / сервис + бот). Python в варианте «только сервис»
# не нужен, поэтому парсер написан на awk и понимает ровно тот подмножество
# YAML, которое использует config.example.yaml: секция верхнего уровня,
# ключи с отступом в 2 пробела, скаляры (в кавычках или без) и списки
# (`[a, b]` в одну строку или блоком `- a` на отступе 4).
#
# Подключение:   source "$(dirname "$0")/lib-config.sh"
#   yaml_get  <файл> <секция.ключ>            скаляр (пусто, если нет)
#   yaml_list <файл> <секция.ключ>            элементы списка, по одному в строке
#   yaml_set  <файл> <секция.ключ> <значение> [raw]
#                                             заменить значение (ключ создаётся); без
#                                             raw значение берётся в кавычки, с raw
#                                             пишется как есть (например "[a, b]")
#   load_service_config <файл>                выставить переменные для скриптов:
#       ACTION_MODE PRIMARY_LIST_URL BLACKLIST_URL ACTIVE_LIST UPDATE_INTERVAL_DAYS
#       LOG_DIR KERNEL_LOG_PREFIX ALERT_COOLDOWN_MINUTES IGNORE_IPS (через пробел)
#       LOG_LIMIT LOG_BURST SKIP_DOCKER SKIP_K8S

yaml_get() {
    local file="$1" path="$2" sec key
    sec="${path%%.*}"; key="${path#*.}"
    [ -f "$file" ] || return 0
    awk -v want_sec="$sec" -v want_key="$key" '
    function value_of(line,   v, q) {
        v = line
        sub(/^[^:]*:[ \t]*/, "", v)
        if (v ~ /^"/) { sub(/^"/, "", v); q = index(v, "\""); return q ? substr(v, 1, q - 1) : v }
        if (v ~ /^\047/) { sub(/^\047/, "", v); q = index(v, "\047"); return q ? substr(v, 1, q - 1) : v }
        sub(/[ \t]+#.*$/, "", v); sub(/[ \t]+$/, "", v)
        return v
    }
    /^[ \t]*#/ || /^[ \t]*$/ { next }
    /^[A-Za-z_][A-Za-z0-9_]*:/ { sec = $0; sub(/:.*/, "", sec); next }
    sec == want_sec && $0 ~ ("^  " want_key ":") { print value_of($0); exit }
    ' "$file"
}

yaml_list() {
    local file="$1" path="$2" sec key
    sec="${path%%.*}"; key="${path#*.}"
    [ -f "$file" ] || return 0
    awk -v want_sec="$sec" -v want_key="$key" '
    function clean(s) { gsub(/^[ \t"\047]+|[ \t"\047]+$/, "", s); return s }
    BEGIN { in_key = 0 }
    /^[ \t]*#/ || /^[ \t]*$/ { next }
    /^[A-Za-z_][A-Za-z0-9_]*:/ { sec = $0; sub(/:.*/, "", sec); in_key = 0; next }
    sec != want_sec { next }
    $0 ~ ("^  " want_key ":") {
        in_key = 1
        v = $0; sub(/^[^:]*:[ \t]*/, "", v); sub(/[ \t]+#.*$/, "", v)
        if (v ~ /^\[/) {
            sub(/^\[/, "", v); sub(/\].*$/, "", v)
            n = split(v, parts, ",")
            for (i = 1; i <= n; i++) { p = clean(parts[i]); if (p != "") print p }
            in_key = 0
        }
        next
    }
    in_key && /^    -/ { v = $0; sub(/^    -[ \t]*/, "", v); sub(/[ \t]+#.*$/, "", v); v = clean(v); if (v != "") print v; next }
    in_key && /^  [A-Za-z_]/ { in_key = 0 }
    ' "$file"
}

yaml_set() {
    local file="$1" path="$2" value="$3" raw="${4:-}" sec key tmp
    sec="${path%%.*}"; key="${path#*.}"
    [ -f "$file" ] || { echo "yaml_set: нет файла $file" >&2; return 1; }
    tmp="$(mktemp "${file}.XXXXXX")" || return 1
    awk -v want_sec="$sec" -v want_key="$key" -v val="$value" -v raw="$raw" '
    function emit_key() {
        if (raw != "") printf "  %s: %s\n", want_key, val
        else printf "  %s: \"%s\"\n", want_key, val
        done = 1
    }
    BEGIN { done = 0; in_sec = 0; skipping_list = 0 }
    {
        if (skipping_list) {
            if ($0 ~ /^    -/ || $0 ~ /^[ \t]*$/) next
            skipping_list = 0
        }
        if ($0 ~ /^[A-Za-z_][A-Za-z0-9_]*:/) {
            if (in_sec && !done) emit_key()          # ключа в секции не было - добавляем в конец
            s = $0; sub(/:.*/, "", s); in_sec = (s == want_sec)
            print; next
        }
        if (in_sec && !done && $0 ~ ("^  " want_key ":")) {
            emit_key()
            v = $0; sub(/^[^:]*:[ \t]*/, "", v)
            if (v == "" || v ~ /^#/) skipping_list = 1   # был блочный список - его строки заменяем
            next
        }
        print
    }
    END {
        if (in_sec && !done) emit_key()
        if (!done && !in_sec) { printf "%s:\n", want_sec; emit_key() }
    }
    ' "$file" > "$tmp" || { rm -f "$tmp"; return 1; }
    chmod --reference="$file" "$tmp" 2>/dev/null || true
    mv "$tmp" "$file"
}

# Значения по умолчанию совпадают с config.example.yaml
load_service_config() {
    local file="$1" v
    ACTION_MODE="$(yaml_get "$file" action.mode)";                      ACTION_MODE="${ACTION_MODE:-block_notify}"
    PRIMARY_LIST_URL="$(yaml_get "$file" sources.primary_list_url)"
    BLACKLIST_URL="$(yaml_get "$file" sources.blacklist_url)"
    ACTIVE_LIST="$(yaml_get "$file" sources.active_list)";              ACTIVE_LIST="${ACTIVE_LIST:-merged}"
    UPDATE_INTERVAL_DAYS="$(yaml_get "$file" sources.update_interval_days)"; UPDATE_INTERVAL_DAYS="${UPDATE_INTERVAL_DAYS:-7}"
    LOG_DIR="$(yaml_get "$file" logging.log_dir)";                      LOG_DIR="${LOG_DIR:-/var/log/skipa_watchdog}"
    KERNEL_LOG_PREFIX="$(yaml_get "$file" monitoring.kernel_log_prefix)"; KERNEL_LOG_PREFIX="${KERNEL_LOG_PREFIX:-CONN: }"
    ALERT_COOLDOWN_MINUTES="$(yaml_get "$file" monitoring.alert_cooldown_minutes)"; ALERT_COOLDOWN_MINUTES="${ALERT_COOLDOWN_MINUTES:-60}"
    IGNORE_IPS="$(yaml_list "$file" monitoring.ignore_ips | tr '\n' ' ' | sed 's/ *$//')"
    LOG_LIMIT="$(yaml_get "$file" firewall.log_limit)";                 LOG_LIMIT="${LOG_LIMIT:-30/second}"
    LOG_BURST="$(yaml_get "$file" firewall.log_burst)";                 LOG_BURST="${LOG_BURST:-40}"
    SKIP_DOCKER=0; SKIP_K8S=0
    v="$(yaml_get "$file" environment.docker_scan)"; [ "$v" = "false" ] && SKIP_DOCKER=1
    v="$(yaml_get "$file" environment.k8s_scan)";    [ "$v" = "false" ] && SKIP_K8S=1
    export ACTION_MODE PRIMARY_LIST_URL BLACKLIST_URL ACTIVE_LIST UPDATE_INTERVAL_DAYS LOG_DIR \
        KERNEL_LOG_PREFIX ALERT_COOLDOWN_MINUTES IGNORE_IPS LOG_LIMIT LOG_BURST SKIP_DOCKER SKIP_K8S
}
