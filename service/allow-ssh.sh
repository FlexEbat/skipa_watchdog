#!/usr/bin/env bash
# Добавляет в ipset "skipa-allow" адреса, с которых прямо сейчас открыты SSH-сессии
# (monitoring.ssh_ports), чтобы свой адрес, попавший во внешний список, не отрезал
# администратора от сервера. Запускается раз в минуту таймером
# skipa-watchdog-allow-ssh.timer. Устаревшие адреса удаляются при следующей пересборке
# allowlist (sync-lists.sh), так что набор не растёт бесконечно.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONF="${1:-$HERE/../config.yaml}"
[ -f "$CONF" ] || exit 0
# shellcheck source=lib-config.sh
source "$HERE/lib-config.sh"
# shellcheck source=lib-ipset.sh
source "$HERE/lib-ipset.sh"
load_service_config "$CONF"

[ "$AUTO_ALLOWLIST" = "false" ] && exit 0
command -v ipset >/dev/null 2>&1 || exit 0
ipset list skipa-allow -terse >/dev/null 2>&1 || exit 0   # набора ещё нет - sync-lists.sh не запускался

# Раз в минуту этот скрипт не должен мешать идущей синхронизации (sync-lists.sh пересобирает
# skipa-allow через swap): занято - просто пропускаем такт, следующий через минуту.
acquire_ipset_lock 5 || exit 0

# Запас до maxelem (4096): не даём вечным SSH-сканерам раздуть набор
size="$(ipset list skipa-allow -terse 2>/dev/null | awk -F': ' '/^Number of entries/{print $2}')"
[ "${size:-0}" -ge 4000 ] && exit 0

# shellcheck disable=SC2086
ssh_peers $SSH_PORTS | while IFS= read -r ip; do
    ipset add skipa-allow "$ip" -exist 2>/dev/null
done
exit 0
