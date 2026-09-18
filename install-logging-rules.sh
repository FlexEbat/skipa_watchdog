#!/usr/bin/env bash
# Ставит правила логирования "CONN: " для skipa-watchdog на всех
# релевантных цепочках iptables:
#   - INPUT                      - хостовые сервисы (SSH и всё, что слушает не через Docker)
#   - DOCKER-USER                 - всё, что опубликовано через Docker (docker run -p / compose ports:)
#   - KUBE-EXTERNAL-SERVICES      - NodePort/LoadBalancer-трафик k8s (iptables-режим kube-proxy)
#   - KUBE-NODEPORTS               - то же самое в более старых версиях k8s
#
# Идемпотентно: если правило уже стоит - не дублирует его.
# DOCKER-USER/KUBE-* нужно применять ПОСЛЕ старта Docker/kubelet (см.
# skipa-watchdog-fw-rules.service), т.к. они пересоздают свои цепочки при
# своём старте.
#
# Переменные окружения (все необязательны):
#   SKIPA_SKIP_DOCKER=1   - не трогать DOCKER-USER, даже если цепочка есть
#   SKIPA_SKIP_K8S=1      - не трогать KUBE-* цепочки, даже если они есть

set -euo pipefail

LOG_PREFIX="${SKIPA_LOG_PREFIX:-CONN: }"
LIMIT="${SKIPA_LIMIT:-30/second}"
BURST="${SKIPA_BURST:-40}"

SKIP_DOCKER="${SKIPA_SKIP_DOCKER:-0}"
SKIP_K8S="${SKIPA_SKIP_K8S:-0}"

add_rule_if_missing() {
    local chain="$1"
    if iptables -C "$chain" -p tcp --syn -m limit --limit "$LIMIT" --limit-burst "$BURST" \
        -j LOG --log-prefix "$LOG_PREFIX" --log-level 4 2>/dev/null; then
        echo "[skipa-watchdog] Правило в $chain уже стоит, пропускаю"
    else
        iptables -I "$chain" -p tcp --syn -m limit --limit "$LIMIT" --limit-burst "$BURST" \
            -j LOG --log-prefix "$LOG_PREFIX" --log-level 4
        echo "[skipa-watchdog] Правило добавлено в $chain"
    fi
}

# ---------------------------------------------------------------------------
# 1. Хостовые сервисы
# ---------------------------------------------------------------------------
add_rule_if_missing INPUT

# ---------------------------------------------------------------------------
# 2. Docker (всё, что опубликовано через -p / ports:)
# ---------------------------------------------------------------------------
if [ "$SKIP_DOCKER" = "1" ]; then
    echo "[skipa-watchdog] SKIPA_SKIP_DOCKER=1 - пропускаю DOCKER-USER"
elif iptables -L DOCKER-USER -n >/dev/null 2>&1; then
    add_rule_if_missing DOCKER-USER
else
    echo "[skipa-watchdog] Цепочка DOCKER-USER не найдена - Docker не запущен или не установлен. Пропускаю."
fi

# ---------------------------------------------------------------------------
# 3. Kubernetes (NodePort/LoadBalancer, только iptables-режим kube-proxy)
# ---------------------------------------------------------------------------
if [ "$SKIP_K8S" = "1" ]; then
    echo "[skipa-watchdog] SKIPA_SKIP_K8S=1 - пропускаю KUBE-* цепочки"
elif command -v ipvsadm >/dev/null 2>&1 && ipvsadm -L -n 2>/dev/null | grep -q .; then
    echo "[skipa-watchdog] kube-proxy работает в режиме ipvs - цепочек KUBE-* в iptables нет," \
         "автоматическое логирование NodePort-трафика недоступно (см. README)."
else
    found_k8s_chain=0
    for chain in KUBE-EXTERNAL-SERVICES KUBE-NODEPORTS; do
        if iptables -L "$chain" -n >/dev/null 2>&1; then
            add_rule_if_missing "$chain"
            found_k8s_chain=1
        fi
    done
    if [ "$found_k8s_chain" = "0" ]; then
        echo "[skipa-watchdog] Цепочки KUBE-EXTERNAL-SERVICES/KUBE-NODEPORTS не найдены -" \
             "Kubernetes не обнаружен или ещё не запущен. Пропускаю."
    fi
fi
