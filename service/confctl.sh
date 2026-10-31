#!/usr/bin/env bash
# Единая точка правки config.yaml для панели (install.sh), бота и сервисных скриптов:
# все три пишут конфиг одним и тем же кодом (awk из lib-config.sh), поэтому формат файла,
# комментарии и блочные списки обрабатываются одинаково, где бы ни была сделана правка.
#
# Использование: confctl.sh <config.yaml> <команда> [аргументы]
#   get <секция.ключ>                    прочитать значение
#   set <секция.ключ> <значение> [raw]   записать (raw - значение уже оформлено как YAML)
#   ignore-list                          monitoring.ignore_ips, по адресу в строке
#   ignore-add <ip|сеть>                 добавить в monitoring.ignore_ips (дубли пропускаются)
#   ignore-del <ip|сеть>                 удалить из monitoring.ignore_ips
# Коды возврата: 0 - выполнено, 1 - ошибка/некорректные данные, 3 - нечего делать
# (ignore-add: уже есть; ignore-del: такого нет).
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib-config.sh
source "$HERE/lib-config.sh"

CONF="${1:-}"; CMD="${2:-}"
[ -f "$CONF" ] && [ -n "$CMD" ] || { sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 1; }
shift 2

# Два одновременных изменения (панель и бот) не должны затереть друг друга.
lock() {
    command -v flock >/dev/null 2>&1 || return 0
    exec 9>"$(dirname "$CONF")/.$(basename "$CONF").lock" && flock -w 10 -x 9
}

valid_key() { [[ "$1" =~ ^[a-z_]+\.[a-z_0-9]+$ ]]; }

# IPv4/CIDR целиком или IPv6 (форма): для allowlist ширина сети не ограничивается -
# свои адреса защищать можно любыми диапазонами.
valid_net() {
    local t="$1" ip mask o
    ip="${t%%/*}"; mask=""
    [[ "$t" == */* ]] && mask="${t#*/}"
    if [[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]]; then
        for o in "${BASH_REMATCH[@]:1}"; do [ "$((10#$o))" -le 255 ] || return 1; done
        [ -z "$mask" ] || { [[ "$mask" =~ ^[0-9]+$ ]] && [ "$mask" -le 32 ]; }
    elif [[ "$ip" =~ ^[0-9A-Fa-f:]+$ ]] && [[ "$ip" == *:*:* ]]; then
        [ -z "$mask" ] || { [[ "$mask" =~ ^[0-9]+$ ]] && [ "$mask" -le 128 ]; }
    else
        return 1
    fi
}

write_ignore_list() {   # аргументы - элементы списка
    local out="" ip
    for ip in "$@"; do out="${out:+$out, }\"$ip\""; done
    yaml_set "$CONF" monitoring.ignore_ips "[$out]" raw
}

case "$CMD" in
    get)
        valid_key "${1:-}" || { echo "Некорректный ключ: ${1:-}" >&2; exit 1; }
        yaml_get "$CONF" "$1"
        ;;
    set)
        valid_key "${1:-}" || { echo "Некорректный ключ: ${1:-}" >&2; exit 1; }
        [ "$#" -ge 2 ] || { echo "Нужно значение" >&2; exit 1; }
        case "$2" in *$'\n'*|*$'\r'*) echo "Значение не должно содержать переводов строк" >&2; exit 1 ;; esac
        lock || { echo "Не удалось получить блокировку конфига" >&2; exit 1; }
        yaml_set "$CONF" "$1" "$2" "${3:-}"
        ;;
    ignore-list)
        yaml_list "$CONF" monitoring.ignore_ips
        ;;
    ignore-add)
        net="${1:-}"
        valid_net "$net" || { echo "Некорректный IP/сеть: $net" >&2; exit 1; }
        lock || { echo "Не удалось получить блокировку конфига" >&2; exit 1; }
        mapfile -t cur < <(yaml_list "$CONF" monitoring.ignore_ips)
        for x in ${cur[@]+"${cur[@]}"}; do [ "$x" = "$net" ] && exit 3; done
        write_ignore_list ${cur[@]+"${cur[@]}"} "$net"
        ;;
    ignore-del)
        net="${1:-}"
        [ -n "$net" ] || { echo "Нужен IP/сеть" >&2; exit 1; }
        lock || { echo "Не удалось получить блокировку конфига" >&2; exit 1; }
        mapfile -t cur < <(yaml_list "$CONF" monitoring.ignore_ips)
        keep=(); found=0
        for x in ${cur[@]+"${cur[@]}"}; do
            if [ "$x" = "$net" ]; then found=1; else keep+=("$x"); fi
        done
        [ "$found" -eq 1 ] || exit 3
        write_ignore_list ${keep[@]+"${keep[@]}"}
        ;;
    *)
        echo "Неизвестная команда: $CMD" >&2; exit 1
        ;;
esac
