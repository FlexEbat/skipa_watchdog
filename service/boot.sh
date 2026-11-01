#!/usr/bin/env bash
# Загрузочный скрипт режима "только сервис" (вызывается systemd-юнитами):
#
#   boot.sh sets    skipa-watchdog-ipset.service  - ранний этап: восстановить ipset-наборы из
#                   файла сохранения (или создать пустые). Выполняется ДО netfilter-persistent:
#                   если на сервере сохранены правила с `--match-set skipa-*`, а наборов ещё нет,
#                   iptables-restore отвергает ВЕСЬ файл правил целиком - сервер остаётся без
#                   фаервола вообще.
#   boot.sh rules   skipa-watchdog-rules.service - поздний этап: поставить iptables-правила
#                   (после Docker/kubelet, иначе DOCKER-USER/KUBE-* ещё не существуют) и
#                   проверить результат.
#
# Почему два юнита, а не один: правила должны идти ПОСЛЕ docker.service, а наборы - ДО
# netfilter-persistent.service; но netfilter-persistent стартует до network-pre.target, а
# Docker - после network-online.target, и один юнит с обоими условиями образует цикл
# упорядочивания, который systemd разрывает, удаляя случайное задание.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONF="${2:-$HERE/../config.yaml}"
# shellcheck source=lib-config.sh
source "$HERE/lib-config.sh"
# shellcheck source=lib-ipset.sh
source "$HERE/lib-ipset.sh"
load_service_config "$CONF"

log() { echo "[skipa-watchdog boot] $*"; }
acquire_ipset_lock 300 || exit 1

case "${1:-}" in
    sets)
        restore_ipsets; rc=$?
        case "$rc" in
            0) log "наборы восстановлены из $(ipset_state_dir)/ipsets.save" ;;
            2) log "файла сохранения ещё нет - создаю пустые наборы (первый запуск или обновление со старой версии)" ;;
            *) log "ВНИМАНИЕ: восстановление наборов завершилось с ошибкой (код $rc), создаю недостающие пустыми" ;;
        esac
        # Даже если восстановить не удалось, наборы обязаны существовать: на них ссылаются
        # правила (в том числе сохранённые в netfilter-persistent).
        create_base_sets || { log "ОШИБКА: не удалось создать ipset-наборы"; exit 1; }
        ;;
    rules)
        create_base_sets || { log "ОШИБКА: не удалось создать ipset-наборы"; exit 1; }
        bash "$HERE/setup-ipset-rules.sh" "$CONF" || { log "ОШИБКА: setup-ipset-rules.sh завершился с ошибкой"; exit 1; }
        ;;
    *)
        echo "Использование: $0 {sets|rules} [config.yaml]" >&2
        exit 1
        ;;
esac
