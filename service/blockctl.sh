#!/usr/bin/env bash
# Управление наборами в режиме "только сервис" (bash). Блокировка в этом режиме полностью
# автоматическая: сканеры из списка (skipa-scanners) режет ядро, список обновляет таймер.
# Ручной блокировки и разблокировки здесь НЕТ - единственный ручной рычаг - белый список.
# Набор "skipa-manual" остаётся только для бессрочных блокировок, перенесённых из варианта
# с Telegram при переключении режима (import-blocks); отдельно от skipa-scanners, потому что
# тот целиком пересобирается при каждом обновлении списка.
# Использование: blockctl.sh {list|allow|unallow|allowlist|import-blocks} [аргумент]
#   allow / unallow / allowlist - белый список (monitoring.ignore_ips): запись в
#   config.yaml (общий для панели и бота код confctl.sh) и сразу в ipset skipa-allow.
#   import-blocks <файл> - внутренняя команда переключения режима: по адресу в строке.
set -uo pipefail

MANUAL_SET="skipa-manual"
SCANNERS_SET="skipa-scanners"
ALLOW_SET="skipa-allow"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONF="${SKIPA_CONFIG:-$HERE/../config.yaml}"
# shellcheck source=lib-ipset.sh
source "$HERE/lib-ipset.sh"
ERR_LOG="$(mktemp)"

# Проверка цели: только IPv4/CIDR, не шире /16, не частная/служебная сеть.
# Защита от переноса 0.0.0.0/0 и подобного, что отрезало бы и администратора.
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

# Изменения наборов не должны пересекаться с sync-lists.sh/setup-ipset-rules.sh (общий flock);
# просмотр (list/allowlist) блокировки не требует
case "${1:-}" in
    allow|unallow|import-blocks) acquire_ipset_lock 60 || exit 1 ;;
esac

case "${1:-}" in
    block|unblock)
        echo "В режиме 'только сервис' ручной блокировки и разблокировки нет: всё работает автоматически." >&2
        echo "Чтобы адрес не блокировался - blockctl.sh allow <ip> (белый список)." >&2
        echo "Ручная блокировка есть в варианте с Telegram (/block, /unblock)." >&2
        exit 1
        ;;
    import-blocks)
        [ -f "${2:-}" ] || { echo "Использование: $0 import-blocks <файл>" >&2; exit 1; }
        create_base_sets || exit 1
        added=0
        while IFS= read -r target; do
            [ -n "$target" ] || continue
            validate_target "$target" 2>/dev/null || continue
            ipset add "$MANUAL_SET" "$target" -exist 2>/dev/null && added=$((added + 1))
        done < "$2"
        save_ipsets || echo "ВНИМАНИЕ: блокировки действуют, но не сохранены для перезагрузки" >&2
        echo "$added"
        ;;
    list)
        echo "# Ручные блокировки (skipa-manual):"
        ipset list "$MANUAL_SET" 2>/dev/null | awk '/^[0-9]/{print}'
        echo "# Из базового списка (skipa-scanners), всего:"
        ipset list "$SCANNERS_SET" 2>/dev/null | awk '/^Number of entries:/{print $NF}'
        ;;
    allow)
        [ -n "${2:-}" ] || { echo "Использование: $0 allow <ip|сеть>" >&2; exit 1; }
        bash "$HERE/confctl.sh" "$CONF" ignore-add "$2"
        rc=$?
        [ "$rc" -eq 3 ] && echo "Уже в белом списке: $2" && rc=0
        [ "$rc" -eq 0 ] || { echo "FAIL" >&2; exit 1; }
        # сразу в ядро: без ожидания следующей синхронизации списков. Если адрес уже заблокирован
        # вручную - снимаем эту блокировку: иначе ручная блокировка и allowlist спорят.
        if ipset add "$ALLOW_SET" "$2" -exist 2>"$ERR_LOG"; then
            ipset del "$MANUAL_SET" "$2" -exist 2>/dev/null
            save_ipsets || echo "ВНИМАНИЕ: изменение действует, но не сохранено для перезагрузки" >&2
            echo "OK"
        else
            echo "Записано в config.yaml, но в ipset добавить не удалось (набор $ALLOW_SET создаётся при" \
                 "первой синхронизации): $(cat "$ERR_LOG")" >&2
        fi
        ;;
    unallow)
        [ -n "${2:-}" ] || { echo "Использование: $0 unallow <ip|сеть>" >&2; exit 1; }
        bash "$HERE/confctl.sh" "$CONF" ignore-del "$2"
        rc=$?
        if [ "$rc" -eq 3 ]; then echo "Такого адреса нет в monitoring.ignore_ips: $2" >&2; exit 1; fi
        [ "$rc" -eq 0 ] || { echo "FAIL" >&2; exit 1; }
        # из ядра убираем только записи, добавленные из конфига; частные сети и SSH-сессии
        # вернутся при ближайшей синхронизации allowlist
        ipset del "$ALLOW_SET" "$2" -exist 2>/dev/null
        save_ipsets || echo "ВНИМАНИЕ: изменение действует, но не сохранено для перезагрузки" >&2
        echo "OK"
        ;;
    allowlist)
        echo "# Белый список (monitoring.ignore_ips):"
        bash "$HERE/confctl.sh" "$CONF" ignore-list
        ;;
    *)
        echo "Использование: $0 {list|allow|unallow|allowlist|import-blocks} [аргумент]" >&2
        exit 1
        ;;
esac
