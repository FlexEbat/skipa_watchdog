#!/usr/bin/env bash
# Проверка обновлений проекта (общая для панели install.sh и сервисных скриптов).
# Подключается через `source`. Каталог установки - git-клон репозитория, поэтому
# достаточно сравнить локальную ветку с её upstream.
#
#   update_check [каталог]   выставляет переменные:
#       UPD_STATE   available | none | unknown (нет git/сети/upstream - молча пропускаем)
#       UPD_LOCAL   установленная версия (файл VERSION)
#       UPD_REMOTE  версия в репозитории
#       UPD_BEHIND  сколько новых коммитов в репозитории
#       UPD_LOG     последние новые коммиты (по строке на коммит)
#
# SKIPA_NO_UPDATE_CHECK=1 отключает проверку (офлайн-серверы, тесты, повторный
# запуск панели сразу после обновления).

# shellcheck disable=SC2034  # UPD_* - результат функции, их читает вызывающий скрипт

update_check() {
    local dir="${1:-${INSTALL_DIR:-/opt/skipa_watchdog}}" up
    UPD_STATE=unknown; UPD_LOCAL=""; UPD_REMOTE=""; UPD_BEHIND=0; UPD_LOG=""
    [ "${SKIPA_NO_UPDATE_CHECK:-0}" = "1" ] && return 0
    command -v git >/dev/null 2>&1 || return 0
    [ -d "$dir/.git" ] || return 0

    UPD_LOCAL="$(head -n1 "$dir/VERSION" 2>/dev/null | tr -d '[:space:]')"
    # fetch не должен ни зависнуть на запросе пароля, ни висеть при недоступной сети
    local -a wrap=()
    command -v timeout >/dev/null 2>&1 && wrap=(timeout 20)
    GIT_TERMINAL_PROMPT=0 "${wrap[@]}" git -C "$dir" fetch --quiet origin 2>/dev/null || return 0

    up="$(git -C "$dir" rev-parse --abbrev-ref --symbolic-full-name '@{u}' 2>/dev/null)" || return 0
    [ -n "$up" ] || return 0
    UPD_BEHIND="$(git -C "$dir" rev-list --count 'HEAD..@{u}' 2>/dev/null || echo 0)"
    [[ "$UPD_BEHIND" =~ ^[0-9]+$ ]] || UPD_BEHIND=0
    UPD_REMOTE="$(git -C "$dir" show '@{u}:VERSION' 2>/dev/null | head -n1 | tr -d '[:space:]')"
    if [ "$UPD_BEHIND" -gt 0 ]; then
        UPD_STATE=available
        UPD_LOG="$(git -C "$dir" log --format='  %h %s' -n 5 'HEAD..@{u}' 2>/dev/null)"
    else
        UPD_STATE=none
    fi
}
