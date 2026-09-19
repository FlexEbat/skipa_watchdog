#!/usr/bin/env bash
# Настраивает iptables для skipa-watchdog на всех релевантных цепочках:
#   - INPUT                      - хостовые сервисы (SSH и всё, что слушает не через Docker)
#   - DOCKER-USER                 - всё, что опубликовано через Docker (docker run -p / compose ports:)
#   - KUBE-EXTERNAL-SERVICES      - NodePort/LoadBalancer-трафик k8s (iptables-режим kube-proxy)
#   - KUBE-NODEPORTS               - то же самое в более старых версиях k8s
#
# Для каждой найденной цепочки ставится:
#   1) переход в самом начале -j SKIPA-BLOCK - общая цепочка динамической
#      блокировки: watchdog.py добавляет туда `-s <ip> -j DROP` при
#      обнаружении (action.mode = block/block_notify). Т.к. цепочка одна и
#      та же для INPUT/DOCKER-USER/KUBE-*, одна блокировка сразу закрывает
#      IP и на хосте, и в Docker, и в Kubernetes.
#   2) правило логирования "CONN: " сразу после перехода - нужно для
#      monitoring.method = kernel_log/both (без него psutil-режим работает
#      и без этих правил).
#
# Идемпотентно: повторный запуск ничего не дублирует.
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
BLOCK_CHAIN="SKIPA-BLOCK"

SKIP_DOCKER="${SKIPA_SKIP_DOCKER:-0}"
SKIP_K8S="${SKIPA_SKIP_K8S:-0}"

ensure_block_chain() {
    if iptables -L "$BLOCK_CHAIN" -n >/dev/null 2>&1; then
        echo "[skipa-watchdog] Цепочка $BLOCK_CHAIN уже существует"
    else
        iptables -N "$BLOCK_CHAIN"
        echo "[skipa-watchdog] Создана цепочка $BLOCK_CHAIN (динамические блокировки watchdog.py)"
    fi
}

ensure_jump_to_block() {
    local chain="$1"
    if iptables -C "$chain" -j "$BLOCK_CHAIN" 2>/dev/null; then
        echo "[skipa-watchdog] Переход $chain -> $BLOCK_CHAIN уже стоит"
    else
        iptables -I "$chain" 1 -j "$BLOCK_CHAIN"
        echo "[skipa-watchdog] Добавлен переход $chain -> $BLOCK_CHAIN (позиция 1)"
    fi
}

ensure_log_rule() {
    local chain="$1"
    if iptables -C "$chain" -p tcp --syn -m limit --limit "$LIMIT" --limit-burst "$BURST" \
        -j LOG --log-prefix "$LOG_PREFIX" --log-level 4 2>/dev/null; then
        echo "[skipa-watchdog] Правило LOG в $chain уже стоит"
    else
        iptables -I "$chain" 2 -p tcp --syn -m limit --limit "$LIMIT" --limit-burst "$BURST" \
            -j LOG --log-prefix "$LOG_PREFIX" --log-level 4
        echo "[skipa-watchdog] Правило LOG добавлено в $chain (позиция 2, после перехода в $BLOCK_CHAIN)"
    fi
}

apply_to_chain() {
    local chain="$1"
    ensure_jump_to_block "$chain"
    ensure_log_rule "$chain"
}

# ---------------------------------------------------------------------------
# 0. Общая цепочка блокировки
# ---------------------------------------------------------------------------
ensure_block_chain

# ---------------------------------------------------------------------------
# 1. Хостовые сервисы
# ---------------------------------------------------------------------------
apply_to_chain INPUT

# ---------------------------------------------------------------------------
# 2. Docker (всё, что опубликовано через -p / ports:)
# ---------------------------------------------------------------------------
if [ "$SKIP_DOCKER" = "1" ]; then
    echo "[skipa-watchdog] SKIPA_SKIP_DOCKER=1 - пропускаю DOCKER-USER"
elif iptables -L DOCKER-USER -n >/dev/null 2>&1; then
    apply_to_chain DOCKER-USER
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
         "автоматическое логирование/блокировка NodePort-трафика недоступны (см. README)."
else
    found_k8s_chain=0
    for chain in KUBE-EXTERNAL-SERVICES KUBE-NODEPORTS; do
        if iptables -L "$chain" -n >/dev/null 2>&1; then
            apply_to_chain "$chain"
            found_k8s_chain=1
        fi
    done
    if [ "$found_k8s_chain" = "0" ]; then
        echo "[skipa-watchdog] Цепочки KUBE-EXTERNAL-SERVICES/KUBE-NODEPORTS не найдены -" \
             "Kubernetes не обнаружен или ещё не запущен. Пропускаю."
    fi
fi
