#!/usr/bin/env bash
# Skipa Watchdog - установщик и менеджер.
#
# Поддерживает два независимых режима, которые могут стоять на одном
# сервере одновременно:
#   bot     - полноценный Telegram-бот (main.py), качается через git clone,
#             свой venv-bot с python-telegram-bot.
#   service - лёгкий режим без Telegram (watchdog_service.py), просто
#             пишет обнаруженные сканы в /var/log/skipa_watchdog/, свой
#             venv-svc без python-telegram-bot.
#
# Запуск:  sudo bash install.sh          -> интерактивное меню
#          sudo bash install.sh <команда> -> неинтерактивный режим, см. usage()
#
set -uo pipefail

REPO_URL="${SKIPA_REPO_URL:-https://github.com/FlexEbat/skipa_watchdog.git}"
INSTALL_DIR="${SKIPA_INSTALL_DIR:-/opt/skipa_watchdog}"
LOG_DIR="${SKIPA_LOG_DIR:-/var/log/skipa_watchdog}"
SYSTEMD_DIR="/etc/systemd/system"

BOT_UNIT="skipa-watchdog-bot"
SVC_UNIT="skipa-watchdog-svc"
FW_UNIT="skipa-watchdog-fw-rules"

INSTALLER_VERSION="2.0.0"

# ---------------------------------------------------------------------------
# Вывод
# ---------------------------------------------------------------------------
C_RESET="\033[0m"; C_GREEN="\033[32m"; C_YELLOW="\033[33m"; C_RED="\033[31m"; C_BLUE="\033[34m"
info()  { echo -e "${C_BLUE}[i]${C_RESET} $*"; }
ok()    { echo -e "${C_GREEN}[+]${C_RESET} $*"; }
warn()  { echo -e "${C_YELLOW}[!]${C_RESET} $*"; }
err()   { echo -e "${C_RED}[x]${C_RESET} $*" >&2; }
pause() { read -rp "Нажмите Enter, чтобы продолжить..." _; }

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        err "Нужны права root (systemctl/iptables/${INSTALL_DIR}/${LOG_DIR}). Запустите через sudo."
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# Определение окружения: Docker / Kubernetes (упрощённая bash-версия
# bot/env_detect.py - нужна ДО того, как поставлен python-код проекта)
# ---------------------------------------------------------------------------
detect_docker() {
    [ -S /var/run/docker.sock ] && return 0
    command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 && return 0
    return 1
}

detect_k8s() {
    [ -d /var/run/secrets/kubernetes.io/serviceaccount ] && return 0
    [ -n "${KUBERNETES_SERVICE_HOST:-}" ] && return 0
    if command -v systemctl >/dev/null 2>&1; then
        systemctl is-active --quiet kubelet 2>/dev/null && return 0
    fi
    command -v kubectl >/dev/null 2>&1 && [ -f "${KUBECONFIG:-$HOME/.kube/config}" ] && return 0
    return 1
}

logging_rules_applied() {
    # Грубая проверка: хотя бы одно правило с нашим log-prefix уже стоит где угодно
    command -v iptables >/dev/null 2>&1 || return 1
    iptables -S 2>/dev/null | grep -q -- '--log-prefix "CONN: "'
}

# При каждом запуске install.sh: смотрим на систему и, если есть
# Docker/K8s без нашего логирования - предлагаем это исправить.
env_check_and_offer() {
    local has_docker=0 has_k8s=0
    detect_docker && has_docker=1
    detect_k8s && has_k8s=1

    if [ "$has_docker" -eq 0 ] && [ "$has_k8s" -eq 0 ]; then
        return 0
    fi

    echo
    info "Анализ системы:"
    [ "$has_docker" -eq 1 ] && echo "   🐳 Обнаружен Docker"
    [ "$has_k8s" -eq 1 ] && echo "   ☸️  Обнаружен Kubernetes (kubelet/kubectl)"

    local default_yes=1
    if logging_rules_applied; then
        ok "Правила логирования сканов (CONN:) уже где-то стоят."
        echo "   Хотите проверить/дополнить их для Docker/K8s-цепочек ещё раз? [y/N]"
        default_yes=0
    else
        warn "По умолчанию мониторится только хост (INPUT). Трафик на порты," \
             "опубликованные через Docker/Kubernetes, идёт другими цепочками и" \
             "сейчас НЕ логируется."
        echo "   Поставить правила логирования также для Docker/K8s сейчас? [Y/n]"
    fi
    read -rp "> " answer
    if [ -z "$answer" ]; then
        [ "$default_yes" -eq 1 ] && answer="y" || answer="n"
    fi
    case "$answer" in
        [Yy]*) apply_container_logging_rules ;;
        *) info "Пропускаю (можно сделать позже из меню: пункт 6)." ;;
    esac
}

apply_container_logging_rules() {
    local script="$INSTALL_DIR/install-logging-rules.sh"
    if [ ! -f "$script" ]; then
        # Скрипт ещё не скачан (проект не установлен) - берём временную копию из репо
        if [ ! -d "$INSTALL_DIR/.git" ]; then
            warn "Проект ещё не установлен, качаю install-logging-rules.sh во временную папку..."
            local tmp
            tmp="$(mktemp -d)"
            if git clone --depth 1 "$REPO_URL" "$tmp" >/dev/null 2>&1; then
                script="$tmp/install-logging-rules.sh"
            else
                err "Не удалось скачать репозиторий, пропускаю установку правил."
                return 1
            fi
        fi
    fi
    if [ ! -f "$script" ]; then
        err "install-logging-rules.sh не найден."
        return 1
    fi
    chmod +x "$script"
    bash "$script"
    ok "Готово. Правила применены (см. вывод выше)."
}

# ---------------------------------------------------------------------------
# Репозиторий / установка
# ---------------------------------------------------------------------------
ensure_repo() {
    if [ -d "$INSTALL_DIR/.git" ]; then
        info "Репозиторий уже есть в $INSTALL_DIR, обновляю (git pull)..."
        git -C "$INSTALL_DIR" pull --ff-only || warn "git pull не удался, продолжаю с текущей версией на диске"
    else
        info "Клонирую $REPO_URL в $INSTALL_DIR..."
        mkdir -p "$(dirname "$INSTALL_DIR")"
        git clone "$REPO_URL" "$INSTALL_DIR"
    fi
}

install_bot() {
    require_root
    command -v git >/dev/null 2>&1 || { err "Нужен git"; return 1; }
    command -v python3 >/dev/null 2>&1 || { err "Нужен python3"; return 1; }

    ensure_repo
    [ -f "$INSTALL_DIR/requirements.txt" ] || { err "requirements.txt не найден в $INSTALL_DIR - установка прервана."; return 1; }

    info "Создаю venv-bot и ставлю зависимости..."
    python3 -m venv "$INSTALL_DIR/venv-bot" || { err "Не удалось создать venv-bot."; return 1; }
    "$INSTALL_DIR/venv-bot/bin/pip" install -q --upgrade pip
    "$INSTALL_DIR/venv-bot/bin/pip" install -q -r "$INSTALL_DIR/requirements.txt" \
        || { err "Не удалось поставить зависимости из requirements.txt."; return 1; }

    if [ ! -f "$INSTALL_DIR/config.yaml" ]; then
        cp "$INSTALL_DIR/config.example.yaml" "$INSTALL_DIR/config.yaml" \
            || { err "Не удалось создать config.yaml (нет config.example.yaml?)."; return 1; }
        warn "Создан $INSTALL_DIR/config.yaml из шаблона - ОБЯЗАТЕЛЬНО заполните" \
             "telegram.bot_token и telegram.chat_id перед запуском:"
        echo "   nano $INSTALL_DIR/config.yaml"
    else
        info "config.yaml уже существует, не трогаю."
    fi

    [ -f "$INSTALL_DIR/skipa-watchdog-bot.service" ] || { err "skipa-watchdog-bot.service не найден в репозитории."; return 1; }
    cp "$INSTALL_DIR/skipa-watchdog-bot.service" "$SYSTEMD_DIR/${BOT_UNIT}.service"
    sed -i "s#/opt/skipa_watchdog#$INSTALL_DIR#g" "$SYSTEMD_DIR/${BOT_UNIT}.service"
    systemctl daemon-reload || { err "systemctl daemon-reload не удался."; return 1; }
    systemctl enable "$BOT_UNIT" >/dev/null 2>&1

    ok "Бот установлен как systemd-юнит $BOT_UNIT."
    if grep -q "your-bot-token-here" "$INSTALL_DIR/config.yaml" 2>/dev/null; then
        warn "config.yaml ещё не заполнен - сервис НЕ запускаю автоматически."
        echo "   После заполнения: sudo systemctl start $BOT_UNIT"
    else
        systemctl restart "$BOT_UNIT"
        ok "Сервис $BOT_UNIT запущен."
    fi
}

uninstall_bot() {
    require_root
    systemctl stop "$BOT_UNIT" 2>/dev/null
    systemctl disable "$BOT_UNIT" 2>/dev/null
    rm -f "$SYSTEMD_DIR/${BOT_UNIT}.service"
    systemctl daemon-reload
    rm -rf "$INSTALL_DIR/venv-bot"
    ok "Бот остановлен и удалён (venv-bot, systemd-юнит)."
    read -rp "Удалить также $INSTALL_DIR/config.yaml с токеном? [y/N] " a
    [[ "$a" =~ ^[Yy] ]] && rm -f "$INSTALL_DIR/config.yaml" && ok "config.yaml удалён."
    if [ ! -d "$INSTALL_DIR/venv-svc" ]; then
        read -rp "Сервис-режим тоже не установлен - удалить весь $INSTALL_DIR (код, кэш, логи)? [y/N] " a
        [[ "$a" =~ ^[Yy] ]] && rm -rf "$INSTALL_DIR" && ok "$INSTALL_DIR удалён."
    fi
}

install_svc() {
    require_root
    command -v git >/dev/null 2>&1 || { err "Нужен git"; return 1; }
    command -v python3 >/dev/null 2>&1 || { err "Нужен python3"; return 1; }

    ensure_repo
    [ -f "$INSTALL_DIR/requirements-service.txt" ] || { err "requirements-service.txt не найден в $INSTALL_DIR - установка прервана."; return 1; }
    mkdir -p "$LOG_DIR"

    info "Создаю venv-svc и ставлю зависимости (без python-telegram-bot)..."
    python3 -m venv "$INSTALL_DIR/venv-svc" || { err "Не удалось создать venv-svc."; return 1; }
    "$INSTALL_DIR/venv-svc/bin/pip" install -q --upgrade pip
    "$INSTALL_DIR/venv-svc/bin/pip" install -q -r "$INSTALL_DIR/requirements-service.txt" \
        || { err "Не удалось поставить зависимости из requirements-service.txt."; return 1; }

    if [ ! -f "$INSTALL_DIR/service.yaml" ]; then
        cp "$INSTALL_DIR/service.example.yaml" "$INSTALL_DIR/service.yaml" \
            || { err "Не удалось создать service.yaml (нет service.example.yaml?)."; return 1; }
        info "Создан $INSTALL_DIR/service.yaml (значения по умолчанию уже рабочие)."
    fi

    [ -f "$INSTALL_DIR/skipa-watchdog-svc.service" ] || { err "skipa-watchdog-svc.service не найден в репозитории."; return 1; }
    cp "$INSTALL_DIR/skipa-watchdog-svc.service" "$SYSTEMD_DIR/${SVC_UNIT}.service"
    sed -i "s#/opt/skipa_watchdog#$INSTALL_DIR#g" "$SYSTEMD_DIR/${SVC_UNIT}.service"
    systemctl daemon-reload || { err "systemctl daemon-reload не удался."; return 1; }
    systemctl enable --now "$SVC_UNIT" || { err "Не удалось запустить $SVC_UNIT (см. journalctl -u $SVC_UNIT)."; return 1; }

    ok "Лёгкий сервис установлен и запущен как $SVC_UNIT."
    echo "   Логи: $LOG_DIR/skipa-watchdog-svc.log, обнаружения: $LOG_DIR/detections.log"
}

uninstall_svc() {
    require_root
    systemctl stop "$SVC_UNIT" 2>/dev/null
    systemctl disable "$SVC_UNIT" 2>/dev/null
    rm -f "$SYSTEMD_DIR/${SVC_UNIT}.service"
    systemctl daemon-reload
    rm -rf "$INSTALL_DIR/venv-svc"
    ok "Сервис остановлен и удалён (venv-svc, systemd-юнит)."
    read -rp "Удалить также логи в $LOG_DIR? [y/N] " a
    [[ "$a" =~ ^[Yy] ]] && rm -rf "$LOG_DIR" && ok "$LOG_DIR удалён."
    if [ ! -d "$INSTALL_DIR/venv-bot" ]; then
        read -rp "Бот тоже не установлен - удалить весь $INSTALL_DIR (код, кэш)? [y/N] " a
        [[ "$a" =~ ^[Yy] ]] && rm -rf "$INSTALL_DIR" && ok "$INSTALL_DIR удалён."
    fi
}

full_uninstall() {
    require_root
    warn "Это остановит и удалит ОБА режима, конфиги, кэш и (по желанию) логи."
    read -rp "Точно продолжить? [y/N] " a
    [[ "$a" =~ ^[Yy] ]] || { info "Отменено."; return; }

    systemctl stop "$BOT_UNIT" "$SVC_UNIT" "$FW_UNIT" 2>/dev/null
    systemctl disable "$BOT_UNIT" "$SVC_UNIT" "$FW_UNIT" 2>/dev/null
    rm -f "$SYSTEMD_DIR/${BOT_UNIT}.service" "$SYSTEMD_DIR/${SVC_UNIT}.service" "$SYSTEMD_DIR/${FW_UNIT}.service"
    systemctl daemon-reload
    rm -rf "$INSTALL_DIR"
    read -rp "Удалить также логи в $LOG_DIR? [y/N] " a
    [[ "$a" =~ ^[Yy] ]] && rm -rf "$LOG_DIR"
    ok "Skipa Watchdog полностью удалён. Правила iptables/nftables (CONN:) не трогал -" \
       "уберите их вручную при необходимости (iptables -D ... / nft delete rule ...)."
}

# ---------------------------------------------------------------------------
# Статус / версия / управление
# ---------------------------------------------------------------------------
unit_line() {
    local unit="$1" label="$2"
    if systemctl list-unit-files "${unit}.service" >/dev/null 2>&1 && \
       [ -f "$SYSTEMD_DIR/${unit}.service" ]; then
        local active enabled
        active="$(systemctl is-active "$unit" 2>/dev/null || echo "inactive")"
        enabled="$(systemctl is-enabled "$unit" 2>/dev/null || echo "disabled")"
        echo "   $label: установлен, active=$active, enabled=$enabled"
    else
        echo "   $label: не установлен"
    fi
}

show_version() {
    echo
    info "Skipa Watchdog - install.sh v$INSTALLER_VERSION"
    if [ -f "$INSTALL_DIR/VERSION" ]; then
        echo "   Версия проекта: $(cat "$INSTALL_DIR/VERSION")"
    else
        echo "   Проект не установлен ($INSTALL_DIR отсутствует)"
    fi
    if [ -d "$INSTALL_DIR/.git" ]; then
        echo "   Git commit: $(git -C "$INSTALL_DIR" rev-parse --short HEAD 2>/dev/null || echo '?')"
    fi
    unit_line "$BOT_UNIT" "Бот (Telegram)"
    unit_line "$SVC_UNIT" "Сервис (без Telegram)"
    unit_line "$FW_UNIT" "Правила логирования при старте Docker"
    pause
}

health_check() {
    echo
    info "Проверка работоспособности:"

    unit_line "$BOT_UNIT" "Бот"
    unit_line "$SVC_UNIT" "Сервис"

    if [ -f "$SYSTEMD_DIR/${BOT_UNIT}.service" ]; then
        if [ -f "$INSTALL_DIR/config.yaml" ] && grep -q "your-bot-token-here" "$INSTALL_DIR/config.yaml"; then
            warn "config.yaml бота ещё не заполнен (bot_token по умолчанию)."
        fi
        echo "   Последние строки лога бота:"
        journalctl -u "$BOT_UNIT" -n 5 --no-pager 2>/dev/null | sed 's/^/     /'
    fi

    if [ -f "$SYSTEMD_DIR/${SVC_UNIT}.service" ]; then
        if [ -w "$LOG_DIR" ] || [ "$(id -u)" -eq 0 ]; then
            ok "Директория логов $LOG_DIR доступна для записи."
        else
            err "Нет прав на запись в $LOG_DIR."
        fi
        echo "   Последние строки лога сервиса:"
        journalctl -u "$SVC_UNIT" -n 5 --no-pager 2>/dev/null | sed 's/^/     /'
        if [ -f "$LOG_DIR/detections.log" ]; then
            local n
            n=$(grep -c '^=====' "$LOG_DIR/detections.log" 2>/dev/null || echo 0)
            echo "   Всего зафиксировано детектов в detections.log: $n"
        fi
    fi

    if command -v iptables >/dev/null 2>&1; then
        if logging_rules_applied; then
            ok "Правило логирования CONN: стоит хотя бы на одной цепочке."
        else
            warn "Правило логирования CONN: нигде не найдено (нужно для method: kernel_log/both)."
        fi
    fi

    if [ ! -f "$SYSTEMD_DIR/${BOT_UNIT}.service" ] && [ ! -f "$SYSTEMD_DIR/${SVC_UNIT}.service" ]; then
        warn "Ничего не установлено."
    fi
    pause
}

manage_services() {
    echo
    echo "Что настраиваем?"
    echo "  1) Бот ($BOT_UNIT)"
    echo "  2) Сервис ($SVC_UNIT)"
    echo "  3) Оба"
    echo "  0) Назад"
    read -rp "> " which
    local units=()
    case "$which" in
        1) units=("$BOT_UNIT") ;;
        2) units=("$SVC_UNIT") ;;
        3) units=("$BOT_UNIT" "$SVC_UNIT") ;;
        *) return ;;
    esac

    echo "Действие: 1) start  2) stop  3) restart  4) статус"
    read -rp "> " action
    for u in "${units[@]}"; do
        if [ ! -f "$SYSTEMD_DIR/${u}.service" ]; then
            warn "$u не установлен, пропускаю."
            continue
        fi
        case "$action" in
            1) systemctl start "$u" && ok "$u запущен" ;;
            2) systemctl stop "$u" && ok "$u остановлен" ;;
            3) systemctl restart "$u" && ok "$u перезапущен" ;;
            4) systemctl status "$u" --no-pager -l | head -n 15 ;;
            *) warn "Неизвестное действие" ;;
        esac
    done
    pause
}

view_logs() {
    echo
    echo "Какие логи посмотреть?"
    echo "  1) journalctl бота (последние 50 строк)"
    echo "  2) journalctl сервиса (последние 50 строк)"
    echo "  3) $LOG_DIR/detections.log (последние 30 строк)"
    echo "  4) $INSTALL_DIR/data/alerts.log (бот, последние 30 строк)"
    echo "  0) Назад"
    read -rp "> " c
    case "$c" in
        1) journalctl -u "$BOT_UNIT" -n 50 --no-pager ;;
        2) journalctl -u "$SVC_UNIT" -n 50 --no-pager ;;
        3) tail -n 30 "$LOG_DIR/detections.log" 2>/dev/null || warn "Файл не найден" ;;
        4) tail -n 30 "$INSTALL_DIR/data/alerts.log" 2>/dev/null || warn "Файл не найден" ;;
        *) return ;;
    esac
    pause
}

force_update_db() {
    local venv=""
    [ -x "$INSTALL_DIR/venv-bot/bin/python" ] && venv="$INSTALL_DIR/venv-bot/bin/python"
    [ -z "$venv" ] && [ -x "$INSTALL_DIR/venv-svc/bin/python" ] && venv="$INSTALL_DIR/venv-svc/bin/python"
    if [ -z "$venv" ]; then
        err "Ни бот, ни сервис не установлены - нечем обновлять базу."
        pause
        return
    fi
    info "Принудительно обновляю базу IP-адресов..."
    (cd "$INSTALL_DIR" && "$venv" - <<'PYEOF'
import asyncio
from bot.config import Config
from bot.ip_lists import fetch_threat_db, save_cache
import os

cfg_path = "config.yaml" if os.path.exists("config.yaml") else "service.yaml"
cfg = Config.load(cfg_path, require_telegram=False)
db = asyncio.run(fetch_threat_db(cfg.cidr_list_url, cfg.range_list_url, cfg.blacklist_url, cfg.blacklist_name))
save_cache(db)
print(f"Готово: {db.source_line_count} записей ({db.per_source_counts})")
PYEOF
    )
    pause
}

edit_config() {
    echo "Что редактировать?"
    echo "  1) config.yaml (бот)"
    echo "  2) service.yaml (сервис)"
    read -rp "> " c
    local target=""
    [ "$c" = "1" ] && target="$INSTALL_DIR/config.yaml"
    [ "$c" = "2" ] && target="$INSTALL_DIR/service.yaml"
    if [ -z "$target" ] || [ ! -f "$target" ]; then
        err "Файл не найден."
        pause
        return
    fi
    "${EDITOR:-nano}" "$target"
    echo "Перезапустить сервис, чтобы применить изменения? [y/N]"
    read -rp "> " a
    if [[ "$a" =~ ^[Yy] ]]; then
        [ "$c" = "1" ] && systemctl restart "$BOT_UNIT" 2>/dev/null
        [ "$c" = "2" ] && systemctl restart "$SVC_UNIT" 2>/dev/null
        ok "Перезапущено."
    fi
}

# ---------------------------------------------------------------------------
# Меню
# ---------------------------------------------------------------------------
main_menu() {
    while true; do
        echo
        echo "======================================"
        echo " Skipa Watchdog - управление (v$INSTALLER_VERSION)"
        echo "======================================"
        echo " 1) Версия"
        echo " 2) Проверка работоспособности"
        echo " 3) Управление сервисами (start/stop/restart)"
        echo " 4) Установка/удаление бота (Telegram)"
        echo " 5) Установка/удаление сервиса (лёгкий режим, без Telegram)"
        echo " 6) Логирование Docker/Kubernetes (DOCKER-USER / KUBE-*)"
        echo " 7) Принудительно обновить базу IP"
        echo " 8) Просмотр логов"
        echo " 9) Редактировать конфиг"
        echo "10) Полное удаление (бот + сервис + конфиги)"
        echo " 0) Выход"
        read -rp "> " choice
        case "$choice" in
            1) show_version ;;
            2) health_check ;;
            3) manage_services ;;
            4)
                echo "  1) Установить/обновить бота  2) Удалить бота  0) Назад"
                read -rp "> " a
                case "$a" in 1) install_bot; pause ;; 2) uninstall_bot; pause ;; esac
                ;;
            5)
                echo "  1) Установить/обновить сервис  2) Удалить сервис  0) Назад"
                read -rp "> " a
                case "$a" in 1) install_svc; pause ;; 2) uninstall_svc; pause ;; esac
                ;;
            6) apply_container_logging_rules; pause ;;
            7) force_update_db ;;
            8) view_logs ;;
            9) edit_config ;;
            10) full_uninstall; pause ;;
            0) exit 0 ;;
            *) warn "Неизвестный пункт" ;;
        esac
    done
}

usage() {
    cat <<EOF
Использование:
  sudo bash install.sh                  интерактивное меню
  sudo bash install.sh install-bot      установить/обновить бота (неинтерактивно)
  sudo bash install.sh install-svc      установить/обновить лёгкий сервис
  sudo bash install.sh uninstall-bot    удалить бота
  sudo bash install.sh uninstall-svc    удалить сервис
  sudo bash install.sh status           краткий статус (без меню)
  sudo bash install.sh fw-rules         поставить правила логирования docker/k8s
EOF
}

main() {
    if [ "$#" -gt 0 ]; then
        require_root
        case "$1" in
            install-bot) install_bot ;;
            install-svc) install_svc ;;
            uninstall-bot) uninstall_bot ;;
            uninstall-svc) uninstall_svc ;;
            status) show_version ;;
            fw-rules) apply_container_logging_rules ;;
            -h|--help) usage ;;
            *) usage; exit 1 ;;
        esac
        exit 0
    fi

    require_root
    env_check_and_offer
    main_menu
}

main "$@"
