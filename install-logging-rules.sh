#!/usr/bin/env bash
# Ставит для skipa-watchdog:
#   1) ipset-набор для бана (используется функцией "Автобан"/кнопкой "Забанить")
#   2) DROP-правило по этому ipset-набору (ставится ПЕРВЫМ, чтобы забаненные
#      IP резались сразу и не долетали даже до правила логирования)
#   3) правило логирования "CONN: " (для kernel_log-метода мониторинга)
#
# Идемпотентно: безопасно перезапускать сколько угодно раз, дубли не создаются.
# Нужно применять ПОСЛЕ старта Docker (см. skipa-watchdog-fw-rules.service),
# т.к. Docker при своём старте пересоздаёт цепочку DOCKER-USER.

set -euo pipefail

LOG_PREFIX="CONN: "
LIMIT="30/second"
BURST="40"
IPSET_NAME="${SKIPA_IPSET_NAME:-skipa_watchdog_ban}"

# ---------------------------------------------------------------------------
# 1. ipset-набор для бана (нужен пакет ipset: apt install ipset)
# ---------------------------------------------------------------------------
if ! command -v ipset >/dev/null 2>&1; then
    echo "[skipa-watchdog] Команда 'ipset' не найдена. Функции бана (кнопка/автобан) работать не будут,"
    echo "[skipa-watchdog] пока не установите пакет: sudo apt install ipset"
else
    ipset create "$IPSET_NAME" hash:ip timeout 0 -exist
    echo "[skipa-watchdog] ipset-набор '$IPSET_NAME' готов"
fi

# ---------------------------------------------------------------------------
# 2 и 3. Правила в iptables: сначала DROP по ipset (в самый верх), затем LOG
# ---------------------------------------------------------------------------

add_log_rule_if_missing() {
    local chain="$1"
    if iptables -C "$chain" -p tcp --syn -m limit --limit "$LIMIT" --limit-burst "$BURST" \
        -j LOG --log-prefix "$LOG_PREFIX" --log-level 4 2>/dev/null; then
        echo "[skipa-watchdog] LOG-правило в $chain уже стоит, пропускаю"
    else
        iptables -I "$chain" -p tcp --syn -m limit --limit "$LIMIT" --limit-burst "$BURST" \
            -j LOG --log-prefix "$LOG_PREFIX" --log-level 4
        echo "[skipa-watchdog] LOG-правило добавлено в $chain"
    fi
}

add_drop_rule_if_missing() {
    local chain="$1"
    if ! command -v ipset >/dev/null 2>&1; then
        return
    fi
    if iptables -C "$chain" -m set --match-set "$IPSET_NAME" src -j DROP 2>/dev/null; then
        echo "[skipa-watchdog] DROP-правило (ipset) в $chain уже стоит, пропускаю"
    else
        # -I <chain> 1 - ставим строго первым правилом в цепочке, чтобы забаненные
        # IP резались сразу, до правила логирования и до всего остального
        iptables -I "$chain" 1 -m set --match-set "$IPSET_NAME" src -j DROP
        echo "[skipa-watchdog] DROP-правило (ipset) добавлено в $chain (первым)"
    fi
}

setup_chain() {
    local chain="$1"
    add_log_rule_if_missing "$chain"
    add_drop_rule_if_missing "$chain"
}

# Хостовые сервисы (SSH и всё, что слушает не через Docker)
setup_chain INPUT

# Всё, что опубликовано через Docker (-p / -P у docker run, ports: у docker-compose)
if iptables -L DOCKER-USER -n >/dev/null 2>&1; then
    setup_chain DOCKER-USER
else
    echo "[skipa-watchdog] Цепочка DOCKER-USER не найдена - Docker ещё не запущен? Пропускаю."
fi
