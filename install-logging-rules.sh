#!/usr/bin/env bash
# Ставит правила логирования "CONN: " для skipa-watchdog.
# Идемпотентно: если правило уже стоит - не дублирует его.
# Нужно применять ПОСЛЕ старта Docker (см. skipa-watchdog-fw-rules.service),
# т.к. Docker при своём старте пересоздаёт цепочку DOCKER-USER.

set -euo pipefail

LOG_PREFIX="CONN: "
LIMIT="30/second"
BURST="40"

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

# Хостовые сервисы (SSH и всё, что слушает не через Docker)
add_rule_if_missing INPUT

# Всё, что опубликовано через Docker (-p / -P у docker run, ports: у docker-compose)
if iptables -L DOCKER-USER -n >/dev/null 2>&1; then
    add_rule_if_missing DOCKER-USER
else
    echo "[skipa-watchdog] Цепочка DOCKER-USER не найдена - Docker ещё не запущен? Пропускаю."
fi
