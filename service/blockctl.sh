#!/usr/bin/env bash
# Ручное управление блокировками для режима "только сервис" (bash).
# Работает с отдельным ipset "skipa-manual" - НЕ с автообновляемым
# "skipa-scanners" (тот целиком пересобирается при каждом обновлении списка,
# поэтому ручные блокировки хранятся отдельно и не теряются при sync).
# Использование: blockctl.sh {block|unblock|list} [ip]
set -uo pipefail

MANUAL_SET="skipa-manual"
SCANNERS_SET="skipa-scanners"
ERR_LOG="$(mktemp)"

# Проверка цели: только IPv4/CIDR, не шире /16, не частная/служебная сеть.
# Защита от `blockctl.sh block 0.0.0.0/0`, который отрезал бы и администратора.
validate_target() {
    local t="$1" ip mask
    ip="${t%%/*}"
    mask=32
    [[ "$t" == */* ]] && mask="${t#*/}"
    if ! [[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]]; then
        echo "Некорректный IPv4-адрес: $t" >&2; return 1
    fi
    # октеты сохраняем сразу: следующая проверка [[ =~ ]] затирает BASH_REMATCH, и
    # раньше проверка частных/служебных сетей ниже молча не срабатывала никогда
    local a="${BASH_REMATCH[1]}" b="${BASH_REMATCH[2]}" o
    for o in "${BASH_REMATCH[@]:1}"; do
        [ "$((10#$o))" -le 255 ] || { echo "Некорректный IPv4-адрес: $t" >&2; return 1; }
    done
    a=$((10#$a)); b=$((10#$b))
    if ! [[ "$mask" =~ ^[0-9]+$ ]] || [ "$mask" -gt 32 ] || [ "$mask" -lt 16 ]; then
        echo "Маска должна быть от /16 до /32 (получено: $t)" >&2; return 1
    fi
    if [ "$a" -eq 0 ] || [ "$a" -eq 10 ] || [ "$a" -eq 127 ] \
        || { [ "$a" -eq 172 ] && [ "$b" -ge 16 ] && [ "$b" -le 31 ]; } \
        || { [ "$a" -eq 192 ] && [ "$b" -eq 168 ]; } \
        || { [ "$a" -eq 169 ] && [ "$b" -eq 254 ]; } || [ "$a" -ge 224 ]; then
        echo "Служебный или частный адрес - не блокирую: $t" >&2; return 1
    fi
    if ipset test skipa-allow "$ip" >/dev/null 2>&1; then
        echo "Адрес в allowlist (monitoring.ignore_ips) - не блокирую: $t" >&2; return 1
    fi
}
trap 'rm -f "$ERR_LOG"' EXIT

case "${1:-}" in
    block)
        [ -n "${2:-}" ] || { echo "Использование: $0 block <ip>" >&2; exit 1; }
        validate_target "$2" || exit 1
        ipset create "$MANUAL_SET" hash:net maxelem 65536 -exist
        if ipset add "$MANUAL_SET" "$2" -exist 2>"$ERR_LOG"; then
            echo "OK"
        else
            cat "$ERR_LOG" >&2
            echo "FAIL"
            exit 1
        fi
        ;;
    unblock)
        [ -n "${2:-}" ] || { echo "Использование: $0 unblock <ip>" >&2; exit 1; }
        # Разблокировать можно только то, что заблокировали вручную. Если IP
        # пришёл из базового списка (skipa-scanners) - он вернётся при
        # следующем обновлении; чтобы исключить его насовсем, впишите в
        # monitoring.ignore_ips в config.yaml.
        if ipset del "$MANUAL_SET" "$2" -exist 2>"$ERR_LOG"; then
            echo "OK"
        else
            cat "$ERR_LOG" >&2
            echo "FAIL"
            exit 1
        fi
        if ipset test "$SCANNERS_SET" "$2" >/dev/null 2>&1; then
            echo "ПРИМЕЧАНИЕ: $2 также входит в автообновляемый список skipa-scanners -" \
                 "останется заблокирован через него. Чтобы исключить насовсем, добавьте" \
                 "IP в monitoring.ignore_ips в config.yaml." >&2
        fi
        ;;
    list)
        echo "# Ручные блокировки (skipa-manual):"
        ipset list "$MANUAL_SET" 2>/dev/null | awk '/^[0-9]/{print}'
        echo "# Из базового списка (skipa-scanners), всего:"
        ipset list "$SCANNERS_SET" 2>/dev/null | awk '/^Number of entries:/{print $NF}'
        ;;
    *)
        echo "Использование: $0 {block|unblock|list} [ip]" >&2
        exit 1
        ;;
esac
