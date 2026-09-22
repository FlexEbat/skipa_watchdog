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
trap 'rm -f "$ERR_LOG"' EXIT

case "${1:-}" in
    block)
        [ -n "${2:-}" ] || { echo "Использование: $0 block <ip>" >&2; exit 1; }
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
        # IGNORE_IPS в service.conf.
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
                 "IP в IGNORE_IPS в service.conf." >&2
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
