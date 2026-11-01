#!/usr/bin/env bash
# Ставит iptables-правила для режима "только сервис": матчинг и блокировка
# идут через ДВА независимых ipset:
#   - skipa-scanners - автообновляемый базовый список (пересобирается
#     sync-lists.sh целиком при каждом обновлении - см. ipset swap там же)
#   - skipa-manual    - ручные блокировки администратора (blockctl.sh),
#     отдельно от базового списка, чтобы обновление списка их не стирало
#
# Ядро само отсеивает трафик по обоим сразу, без единого демона в userspace.
#
# Опция firewall.keep_established_tcp (по умолчанию false): вместо одного DROP на всё
# ставится пара правил "-p tcp --syn -> DROP" и "! -p tcp -> DROP": новые TCP-соединения
# и весь не-TCP трафик блокируются, а уже установленные TCP-сессии не рвутся. Намеренно
# НЕ используется `-p tcp ! --syn -j RETURN`: RETURN во встроенной цепочке INPUT прекращает
# её обход и пропускает все остальные правила хоста (в том числе чужие DROP). Смена
# опции требует повторно применить правила (старый вариант убирается автоматически).
#
# Применяется к INPUT (хост) и, если есть, DOCKER-USER и
# KUBE-EXTERNAL-SERVICES/KUBE-NODEPORTS (Docker/Kubernetes) - как и
# install-firewall-rules.sh для режима с ботом, только здесь вместо
# динамической цепочки SKIPA-BLOCK используется статичный ipset-матчинг.
#
# Использование:
#   sudo bash setup-ipset-rules.sh [config.yaml | notify|block|block_notify]
# Настройки (режим действия, префикс LOG, лимит, пропуск Docker/K8s) берутся из
# единого config.yaml; режим можно передать и явно третьим вариантом.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ARG="${1:-$HERE/../config.yaml}"
# shellcheck source=lib-config.sh
source "$HERE/lib-config.sh"
# shellcheck source=lib-ipset.sh
source "$HERE/lib-ipset.sh"
if [ -f "$ARG" ]; then
    load_service_config "$ARG"
else
    load_service_config "$HERE/../config.yaml"
    ACTION_MODE="$ARG"
fi

SETS=("$SET_SCANNERS" "$SET_MANUAL")
LOG_PREFIX="$KERNEL_LOG_PREFIX"
LIMIT="$LOG_LIMIT"
BURST="$LOG_BURST"

ipt() { iptables -w 5 "$@"; }

# Никто другой не должен менять наборы, пока ставятся правила (sync-lists.sh, blockctl.sh)
acquire_ipset_lock 120 || exit 1

# allowlist (частные сети + monitoring.ignore_ips) наполняет sync-lists.sh. Каждое правило
# ниже содержит условие "src НЕ в skipa-allow", поэтому свои адреса не
# блокируются, даже если попали внутрь большой сети из списка.
create_base_sets

# Хвост условия, общий для LOG и DROP
ALLOW_COND=(-m set ! --match-set skipa-allow src)

ensure_log_rule() {
    local chain="$1" set="$2"
    if ipt -C "$chain" -m set --match-set "$set" src "${ALLOW_COND[@]}" -m limit --limit "$LIMIT" \
        --limit-burst "$BURST" -j LOG --log-prefix "$LOG_PREFIX" --log-level 4 2>/dev/null; then
        echo "[skipa-watchdog] LOG-правило ($set) в $chain уже стоит"
    else
        ipt -I "$chain" 1 -m set --match-set "$set" src "${ALLOW_COND[@]}" -m limit --limit "$LIMIT" \
            --limit-burst "$BURST" -j LOG --log-prefix "$LOG_PREFIX" --log-level 4
        echo "[skipa-watchdog] LOG-правило ($set) добавлено в $chain"
    fi
}

remove_log_rule() {
    local chain="$1" set="$2"
    ipt -D "$chain" -m set --match-set "$set" src "${ALLOW_COND[@]}" -m limit --limit "$LIMIT" \
        --limit-burst "$BURST" -j LOG --log-prefix "$LOG_PREFIX" --log-level 4 2>/dev/null || true
}

# Варианты DROP-правила: plain - одно правило на всё; syn + nontcp - пара для
# keep_established_tcp (новые TCP-соединения и весь не-TCP трафик, без установленных сессий).
drop_spec() {   # $1 - набор, $2 - вариант; результат в массиве DSPEC
    case "$2" in
        plain)  DSPEC=(-m set --match-set "$1" src "${ALLOW_COND[@]}" -j DROP) ;;
        syn)    DSPEC=(-p tcp --syn -m set --match-set "$1" src "${ALLOW_COND[@]}" -j DROP) ;;
        nontcp) DSPEC=(! -p tcp -m set --match-set "$1" src "${ALLOW_COND[@]}" -j DROP) ;;
    esac
}

ensure_drop_variant() {
    local chain="$1" set="$2" variant="$3"
    drop_spec "$set" "$variant"
    if ipt -C "$chain" "${DSPEC[@]}" 2>/dev/null; then
        echo "[skipa-watchdog] DROP-правило ($set, $variant) в $chain уже стоит"
    else
        ipt -I "$chain" 1 "${DSPEC[@]}"
        echo "[skipa-watchdog] DROP-правило ($set, $variant) добавлено в $chain"
    fi
}

remove_drop_variant() {
    local chain="$1" set="$2" variant="$3"
    drop_spec "$set" "$variant"
    ipt -D "$chain" "${DSPEC[@]}" 2>/dev/null || true
}

# Ставит нужный вид DROP и убирает остальные (после смены keep_established_tcp
# в цепочке не должно остаться правил прежнего вида)
ensure_drop_rule() {
    local chain="$1" set="$2"
    if [ "${KEEP_ESTABLISHED:-false}" = "true" ]; then
        remove_drop_variant "$chain" "$set" plain
        ensure_drop_variant "$chain" "$set" nontcp
        ensure_drop_variant "$chain" "$set" syn
    else
        remove_drop_variant "$chain" "$set" syn
        remove_drop_variant "$chain" "$set" nontcp
        ensure_drop_variant "$chain" "$set" plain
    fi
}

remove_drop_rule() {
    local chain="$1" set="$2" v
    for v in plain syn nontcp; do remove_drop_variant "$chain" "$set" "$v"; done
}

# Правила прошлых версий (без проверки allowlist) - убираем, иначе они продолжат
# блокировать адреса из allowlist
remove_legacy_rules() {
    local chain="$1" set
    for set in "${SETS[@]}"; do
        ipt -D "$chain" -m set --match-set "$set" src -j DROP 2>/dev/null || true
        ipt -D "$chain" -m set --match-set "$set" src -m limit --limit "$LIMIT" \
            --limit-burst "$BURST" -j LOG --log-prefix "$LOG_PREFIX" --log-level 4 2>/dev/null || true
    done
}

# Порядок вставки важен: чтобы LOG успел сработать ДО того, как пакет
# дропнется, DROP нужно вставить первым (он окажется ниже), а LOG - вторым
# (окажется выше и не прерывает цепочку, в отличие от DROP).
apply_to_chain() {
    local chain="$1"
    local set
    remove_legacy_rules "$chain"
    for set in "${SETS[@]}"; do
        case "$ACTION_MODE" in
            notify)
                remove_drop_rule "$chain" "$set"
                ensure_log_rule "$chain" "$set"
                ;;
            block)
                remove_log_rule "$chain" "$set"
                ensure_drop_rule "$chain" "$set"
                ;;
            *)
                ensure_drop_rule "$chain" "$set"
                ensure_log_rule "$chain" "$set"
                ;;
        esac
    done
}

apply_to_chain INPUT

if [ "$SKIP_DOCKER" = "1" ]; then
    echo "[skipa-watchdog] environment.docker_scan: false - пропускаю DOCKER-USER"
elif ipt -L DOCKER-USER -n >/dev/null 2>&1; then
    apply_to_chain DOCKER-USER
else
    echo "[skipa-watchdog] Цепочка DOCKER-USER не найдена - Docker не запущен или не установлен. Пропускаю."
fi

if [ "$SKIP_K8S" = "1" ]; then
    echo "[skipa-watchdog] environment.k8s_scan: false - пропускаю KUBE-* цепочки"
elif command -v ipvsadm >/dev/null 2>&1 && ipvsadm -L -n 2>/dev/null | grep -q .; then
    echo "[skipa-watchdog] kube-proxy работает в режиме ipvs - цепочек KUBE-* в iptables нет," \
         "автоматическое логирование/блокировка NodePort-трафика недоступны."
else
    found=0
    for chain in KUBE-EXTERNAL-SERVICES KUBE-NODEPORTS; do
        if ipt -L "$chain" -n >/dev/null 2>&1; then
            apply_to_chain "$chain"
            found=1
        fi
    done
    [ "$found" = "0" ] && echo "[skipa-watchdog] Цепочки KUBE-EXTERNAL-SERVICES/KUBE-NODEPORTS не найдены - пропускаю."
fi


# Результат нужно проверить, а не считать успешным по факту запуска: если правила не
# встали (нет ipset-модуля, чужой фаервол пересоздал цепочки), защита молча не работает.
echo
echo "[skipa-watchdog] Проверка применённых правил:"
if verify_service_rules; then
    echo "[skipa-watchdog] OK: наборы и правила на месте."
    save_ipsets || echo "[skipa-watchdog] ВНИМАНИЕ: не удалось сохранить наборы для восстановления после перезагрузки" >&2
else
    echo "[skipa-watchdog] ОШИБКА: защита применена не полностью (см. ✗ выше)." >&2
    exit 1
fi
