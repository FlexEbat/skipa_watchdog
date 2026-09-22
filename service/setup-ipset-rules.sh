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
# Применяется к INPUT (хост) и, если есть, DOCKER-USER и
# KUBE-EXTERNAL-SERVICES/KUBE-NODEPORTS (Docker/Kubernetes) - как и
# install-firewall-rules.sh для режима с ботом, только здесь вместо
# динамической цепочки SKIPA-BLOCK используется статичный ipset-матчинг.
#
# Использование:
#   sudo bash setup-ipset-rules.sh <action_mode>
#   action_mode: notify | block | block_notify (по умолчанию block_notify)
set -euo pipefail

SETS=("skipa-scanners" "skipa-manual")
MAXELEM_SCANNERS=200000
MAXELEM_MANUAL=65536
LOG_PREFIX="${SKIPA_LOG_PREFIX:-CONN: }"
LIMIT="${SKIPA_LIMIT:-30/second}"
BURST="${SKIPA_BURST:-40}"
ACTION_MODE="${1:-block_notify}"

SKIP_DOCKER="${SKIPA_SKIP_DOCKER:-0}"
SKIP_K8S="${SKIPA_SKIP_K8S:-0}"

ipset create skipa-scanners hash:net maxelem "$MAXELEM_SCANNERS" -exist
ipset create skipa-manual hash:net maxelem "$MAXELEM_MANUAL" -exist

ensure_log_rule() {
    local chain="$1" set="$2"
    if iptables -C "$chain" -m set --match-set "$set" src -m limit --limit "$LIMIT" \
        --limit-burst "$BURST" -j LOG --log-prefix "$LOG_PREFIX" --log-level 4 2>/dev/null; then
        echo "[skipa-watchdog] LOG-правило ($set) в $chain уже стоит"
    else
        iptables -I "$chain" 1 -m set --match-set "$set" src -m limit --limit "$LIMIT" \
            --limit-burst "$BURST" -j LOG --log-prefix "$LOG_PREFIX" --log-level 4
        echo "[skipa-watchdog] LOG-правило ($set) добавлено в $chain"
    fi
}

remove_log_rule() {
    local chain="$1" set="$2"
    iptables -D "$chain" -m set --match-set "$set" src -m limit --limit "$LIMIT" \
        --limit-burst "$BURST" -j LOG --log-prefix "$LOG_PREFIX" --log-level 4 2>/dev/null || true
}

ensure_drop_rule() {
    local chain="$1" set="$2"
    if iptables -C "$chain" -m set --match-set "$set" src -j DROP 2>/dev/null; then
        echo "[skipa-watchdog] DROP-правило ($set) в $chain уже стоит"
    else
        iptables -I "$chain" 1 -m set --match-set "$set" src -j DROP
        echo "[skipa-watchdog] DROP-правило ($set) добавлено в $chain"
    fi
}

remove_drop_rule() {
    local chain="$1" set="$2"
    iptables -D "$chain" -m set --match-set "$set" src -j DROP 2>/dev/null || true
}

# Порядок вставки важен: чтобы LOG успел сработать ДО того, как пакет
# дропнется, DROP нужно вставить первым (он окажется ниже), а LOG - вторым
# (окажется выше и не прерывает цепочку, в отличие от DROP).
apply_to_chain() {
    local chain="$1"
    local set
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
    echo "[skipa-watchdog] SKIPA_SKIP_DOCKER=1 - пропускаю DOCKER-USER"
elif iptables -L DOCKER-USER -n >/dev/null 2>&1; then
    apply_to_chain DOCKER-USER
else
    echo "[skipa-watchdog] Цепочка DOCKER-USER не найдена - Docker не запущен или не установлен. Пропускаю."
fi

if [ "$SKIP_K8S" = "1" ]; then
    echo "[skipa-watchdog] SKIPA_SKIP_K8S=1 - пропускаю KUBE-* цепочки"
elif command -v ipvsadm >/dev/null 2>&1 && ipvsadm -L -n 2>/dev/null | grep -q .; then
    echo "[skipa-watchdog] kube-proxy работает в режиме ipvs - цепочек KUBE-* в iptables нет," \
         "автоматическое логирование/блокировка NodePort-трафика недоступны."
else
    found=0
    for chain in KUBE-EXTERNAL-SERVICES KUBE-NODEPORTS; do
        if iptables -L "$chain" -n >/dev/null 2>&1; then
            apply_to_chain "$chain"
            found=1
        fi
    done
    [ "$found" = "0" ] && echo "[skipa-watchdog] Цепочки KUBE-EXTERNAL-SERVICES/KUBE-NODEPORTS не найдены - пропускаю."
fi

