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
#       LOG_LIMIT LOG_BURST SKIP_DOCKER SKIP_K8S MIN_PREFIX ALLOW_INSECURE_HTTP
#       AUTO_ALLOWLIST SSH_PORTS (через пробел) MIN_ENTRIES KEEP_ESTABLISHED
#   yaml_extra_sources <config.yaml>          sources.extra: по записи на строку, поля через \037:
#                                             name type url enabled api_key min_confidence min_entries display_name
#   ssh_peers <порт>...                       IPv4-адреса, с которых сейчас открыты
#                                             SSH-сессии на этих портах (по одному в строке)

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
    # перевод строки в значении дописал бы в конфиг чужие ключи; ключ - только из безопасного набора
    case "$value" in *$'\n'*|*$'\r'*) echo "yaml_set: значение не должно содержать переводов строк" >&2; return 1 ;; esac
    # парсер значений в кавычках (yaml_get) не понимает экранирования, поэтому кавычку и \
    # в значении, которое мы сами берём в кавычки, не принимаем, а не портим молча
    if [ -z "$raw" ]; then
        case "$value" in *\"*|*\\*) echo "yaml_set: в значении нельзя использовать двойную кавычку и обратный слэш" >&2; return 1 ;; esac
    fi
    [[ "$sec" =~ ^[A-Za-z_][A-Za-z0-9_]*$ && "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] \
        || { echo "yaml_set: недопустимый ключ $path" >&2; return 1; }
    tmp="$(mktemp "${file}.XXXXXX")" || return 1
    # значение передаётся через окружение: `awk -v` обрабатывает обратные слэши (\n стал бы переводом строки)
    YS_VAL="$value" YS_RAW="$raw" awk -v want_sec="$sec" -v want_key="$key" '
    function emit_key() {
        if (raw != "") printf "  %s: %s\n", want_key, val
        else printf "  %s: \"%s\"\n", want_key, val
        done = 1
    }
    BEGIN { done = 0; in_sec = 0; skipping_list = 0; val = ENVIRON["YS_VAL"]; raw = ENVIRON["YS_RAW"] }
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
    MIN_PREFIX="$(yaml_get "$file" sources.min_prefix)";                 MIN_PREFIX="${MIN_PREFIX:-20}"
    [[ "$MIN_PREFIX" =~ ^[0-9]+$ ]] || MIN_PREFIX=20
    [ "$MIN_PREFIX" -lt 8 ] && MIN_PREFIX=8
    [ "$MIN_PREFIX" -gt 32 ] && MIN_PREFIX=32
    ALLOW_INSECURE_HTTP="$(yaml_get "$file" sources.allow_insecure_http)"; ALLOW_INSECURE_HTTP="${ALLOW_INSECURE_HTTP:-false}"
    # минимум записей в источнике при ПЕРВОЙ загрузке (когда сравнить с прошлой копией нечем)
    MIN_ENTRIES="$(yaml_get "$file" sources.min_entries)";               MIN_ENTRIES="${MIN_ENTRIES:-10}"
    [[ "$MIN_ENTRIES" =~ ^[0-9]+$ ]] || MIN_ENTRIES=10
    # не трогать установленные TCP-сессии (блокировать только новые соединения и не-TCP)
    KEEP_ESTABLISHED="$(yaml_get "$file" firewall.keep_established_tcp)"; KEEP_ESTABLISHED="${KEEP_ESTABLISHED:-false}"
    AUTO_ALLOWLIST="$(yaml_get "$file" monitoring.auto_allowlist)";      AUTO_ALLOWLIST="${AUTO_ALLOWLIST:-true}"
    SSH_PORTS="$(yaml_list "$file" monitoring.ssh_ports | grep -E '^[0-9]+$' | tr '\n' ' ' | sed 's/ *$//')"
    SSH_PORTS="${SSH_PORTS:-22}"
    SKIP_DOCKER=0; SKIP_K8S=0
    v="$(yaml_get "$file" environment.docker_scan)"; [ "$v" = "false" ] && SKIP_DOCKER=1
    v="$(yaml_get "$file" environment.k8s_scan)";    [ "$v" = "false" ] && SKIP_K8S=1
    export ACTION_MODE PRIMARY_LIST_URL BLACKLIST_URL ACTIVE_LIST UPDATE_INTERVAL_DAYS LOG_DIR \
        KERNEL_LOG_PREFIX ALERT_COOLDOWN_MINUTES IGNORE_IPS LOG_LIMIT LOG_BURST SKIP_DOCKER SKIP_K8S \
        MIN_PREFIX ALLOW_INSECURE_HTTP AUTO_ALLOWLIST SSH_PORTS MIN_ENTRIES KEEP_ESTABLISHED
}

# IPv4-адреса администраторов с живыми SSH-сессиями: их нельзя блокировать, даже если
# адрес попал во внешний список (так же работает allowlist в Python-варианте).
ssh_peers() {
    local p
    command -v ss >/dev/null 2>&1 || return 0
    for p in "$@"; do
        [[ "$p" =~ ^[0-9]+$ ]] || continue
        ss -Htn state established "( sport = :$p )" 2>/dev/null
    done | awk '
        { peer = $4; sub(/:[0-9]+$/, "", peer); gsub(/[\[\]]/, "", peer); sub(/^::ffff:/, "", peer)
          if (peer ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) print peer }' | sort -u
}

# sources.extra: список источников (Spamhaus DROP, FireHOL, AbuseIPDB...). Читается тем же
# config.yaml, что и у бота, без Python и без YAML-библиотек: поддерживаются блочные
# элементы ("- name: x" + ключи ниже) и однострочные ("- {name: x, url: y}").
# Вывод - по записи на источник, поля через \037 (в порядке):
#   name type url enabled api_key min_confidence min_entries display_name
# enabled: true, если ключа нет (как у бота); false/no/off/0 - выключен.
yaml_extra_sources() {
    awk '
    function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t\r]+$/, "", s); return s }
    function unq(v,    q, rest, e) {
        v = trim(v); q = substr(v, 1, 1)
        if (q == "\"" || q == "\047") {
            rest = substr(v, 2); e = index(rest, q)
            return e ? substr(rest, 1, e - 1) : rest
        }
        sub(/[ \t]+#.*$/, "", v)
        return trim(v)
    }
    function setkv(kv,    p, k) {
        p = index(kv, ":"); if (!p) return
        k = trim(substr(kv, 1, p - 1))
        cur[k] = unq(substr(kv, p + 1)); seen[k] = 1
    }
    function flow(s,    i, c, q, part, n) {      # {a: 1, b: "x,y"} - запятые внутри кавычек не делят
        s = trim(s); sub(/^\{/, "", s); sub(/\}[ \t]*(#.*)?$/, "", s)
        part = ""; q = ""
        n = length(s)
        for (i = 1; i <= n; i++) {
            c = substr(s, i, 1)
            if (q != "") { part = part c; if (c == q) q = ""; continue }
            if (c == "\"" || c == "\047") { q = c; part = part c; continue }
            if (c == ",") { setkv(part); part = ""; continue }
            part = part c
        }
        if (trim(part) != "") setkv(part)
    }
    function flush(    en) {
        if (!active) return
        en = ("enabled" in seen) ? tolower(cur["enabled"]) : "true"
        en = (en == "false" || en == "no" || en == "off" || en == "0") ? "false" : "true"
        printf "%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\n", cur["name"], cur["type"], cur["url"], en, \
            cur["api_key"], cur["min_confidence"], cur["min_entries"], cur["display_name"]
        split("", cur); split("", seen); active = 0
    }
    { line = $0; sub(/\r$/, "", line) }
    line ~ /^[ \t]*(#.*)?$/ { next }
    {
        match(line, /^ */); ind = RLENGTH; body = substr(line, ind + 1)
    }
    ind == 0 { flush(); insrc = (body ~ /^sources:/); inextra = 0; next }
    !insrc { next }
    !inextra {
        if (body ~ /^extra:[ \t]*(#.*)?$/) { inextra = 1; extra_ind = ind }
        next
    }
    body ~ /^-([ \t]|$)/ {
        flush(); active = 1
        rest = trim(substr(body, 2))
        if (substr(rest, 1, 1) == "{") flow(rest); else if (rest != "") setkv(rest)
        next
    }
    ind <= extra_ind { flush(); inextra = 0; next }
    active { setkv(body) }
    END { flush() }
    ' "$1"
}
