#!/usr/bin/env bash
# Skipa Watchdog - установщик и менеджер.
#
# Skipa Watchdog - ОДИН процесс (watchdog.py): мониторит соединения, при
# обнаружении сканера логирует / блокирует через iptables (для хоста,
# Docker и Kubernetes сразу), и, если настроен Telegram, дополнительно
# присылает уведомления и даёт команды/меню в чате. Telegram - надстройка
# поверх того же процесса, а не отдельный режим.
#
# Первый запуск: sudo bash install.sh - покажет только описание и
# предложит установить. После установки регистрируется команда
# `skipa-watchdog`, и дальше управлять можно ей: sudo skipa-watchdog.
#
set -uo pipefail

REPO_URL="${SKIPA_REPO_URL:-https://github.com/FlexEbat/skipa_watchdog.git}"
INSTALL_DIR="${SKIPA_INSTALL_DIR:-/opt/skipa_watchdog}"
LOG_DIR="${SKIPA_LOG_DIR:-/var/log/skipa_watchdog}"
SYSTEMD_DIR="/etc/systemd/system"
CLI_LINK="/usr/local/bin/skipa-watchdog"

UNIT="skipa-watchdog"
FW_UNIT="skipa-watchdog-fw-rules"

INSTALLER_VERSION="3.0.0"

DESCRIPTION="Skipa Watchdog постоянно следит за сетевыми подключениями к серверу и
сверяет источник с базой IP-адресов сканеров (CyberOK/Skipa, ГРЧЦ, НКЦКИ +
доп. списки). При обнаружении, в зависимости от настроенного режима, он
блокирует IP через iptables (сразу для хоста, Docker и Kubernetes),
присылает уведомление, или делает и то, и другое. Telegram - необязательная
надстройка поверх того же процесса: без него всё работает через локальные
логи в /var/log/skipa_watchdog/, с ним - ещё и уведомления/команды в чате."

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

print_header() {
    echo
    echo "======================================"
    echo " Skipa Watchdog"
    if [ -f "$INSTALL_DIR/VERSION" ]; then
        echo " Версия: $(cat "$INSTALL_DIR/VERSION")"
    else
        echo " Версия установщика: $INSTALLER_VERSION (проект ещё не установлен)"
    fi
    echo "======================================"
}

is_installed() {
    [ -f "$SYSTEMD_DIR/${UNIT}.service" ] && [ -f "$INSTALL_DIR/config.yaml" ]
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

firewall_rules_applied() {
    command -v iptables >/dev/null 2>&1 || return 1
    iptables -L SKIPA-BLOCK -n >/dev/null 2>&1
}

# При каждом запуске install.sh: смотрим на систему и, если есть
# Docker/K8s без наших правил - предлагаем это исправить.
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
    if firewall_rules_applied; then
        ok "Правила логирования/блокировки уже стоят (цепочка SKIPA-BLOCK найдена)."
        echo "   Хотите проверить/дополнить их для Docker/K8s-цепочек ещё раз? [y/N]"
        default_yes=0
    else
        warn "По умолчанию мониторится и блокируется только хост (INPUT). Трафик на порты," \
             "опубликованные через Docker/Kubernetes, идёт другими цепочками и" \
             "сейчас НЕ покрыт."
        echo "   Настроить логирование и блокировку также для Docker/K8s сейчас? [Y/n]"
    fi
    read -rp "> " answer
    if [ -z "$answer" ]; then
        [ "$default_yes" -eq 1 ] && answer="y" || answer="n"
    fi
    case "$answer" in
        [Yy]*) apply_firewall_rules ;;
        *) info "Пропускаю (можно сделать позже из меню)." ;;
    esac
}

apply_firewall_rules() {
    local script="$INSTALL_DIR/install-firewall-rules.sh"
    if [ ! -f "$script" ]; then
        if [ ! -d "$INSTALL_DIR/.git" ]; then
            warn "Проект ещё не установлен, качаю install-firewall-rules.sh во временную папку..."
            local tmp
            tmp="$(mktemp -d)"
            if git clone --depth 1 "$REPO_URL" "$tmp" >/dev/null 2>&1; then
                script="$tmp/install-firewall-rules.sh"
            else
                err "Не удалось скачать репозиторий, пропускаю установку правил."
                return 1
            fi
        fi
    fi
    if [ ! -f "$script" ]; then
        err "install-firewall-rules.sh не найден."
        return 1
    fi
    chmod +x "$script"
    bash "$script"
    ok "Готово. Правила применены (см. вывод выше)."
}

# При каждом запуске: проверяем, не вышла ли новая версия одного из листов
# (даже если update_interval_days ещё не наступил - чтобы узнать заранее).
LIST_HASH_STATE="/var/lib/skipa_watchdog/list-hashes.env"

url_hash() {
    command -v curl >/dev/null 2>&1 || return 1
    curl -fsSL --max-time 15 "$1" 2>/dev/null | sha256sum 2>/dev/null | awk '{print $1}'
}

check_list_updates() {
    command -v curl >/dev/null 2>&1 || return 0
    command -v sha256sum >/dev/null 2>&1 || return 0

    mkdir -p "$(dirname "$LIST_HASH_STATE")"
    HASH_PRIMARY=""; HASH_BLACKLIST=""
    # shellcheck disable=SC1090
    [ -f "$LIST_HASH_STATE" ] && source "$LIST_HASH_STATE"

    local primary_url="https://raw.githubusercontent.com/tread-lightly/CyberOK_Skipa_ips/main/lists/skipa_cidr.txt"
    local blacklist_url="https://gist.githubusercontent.com/sngvy/07cee7ac810c9d222fbebddff8c1d1b8/raw/37cde2b27a560c647d0e8eb9d274e3409082d3e7/blacklist.txt"

    info "Проверяю обновления списков IP..."
    local new_primary new_blacklist
    new_primary="$(url_hash "$primary_url")"
    new_blacklist="$(url_hash "$blacklist_url")"

    local any_new=0
    if [ -n "${HASH_PRIMARY:-}" ] && [ -n "$new_primary" ] && [ "$HASH_PRIMARY" != "$new_primary" ]; then
        warn "Лист 1 (основной, skipa_cidr) обновился с прошлой проверки."
        any_new=1
    fi
    if [ -n "${HASH_BLACKLIST:-}" ] && [ -n "$new_blacklist" ] && [ "$HASH_BLACKLIST" != "$new_blacklist" ]; then
        warn "Лист 2 (blacklist) обновился с прошлой проверки."
        any_new=1
    fi
    if [ "$any_new" -eq 1 ]; then
        echo "   Рекомендуется обновить базу: меню -> \"Принудительно обновить базу IP\"."
    fi

    {
        echo "HASH_PRIMARY=${new_primary}"
        echo "HASH_BLACKLIST=${new_blacklist}"
    } > "$LIST_HASH_STATE"
}

# ---------------------------------------------------------------------------
# Установка / обновление / удаление
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

install_cli_link() {
    cat > "$CLI_LINK" <<EOF
#!/usr/bin/env bash
exec bash "$INSTALL_DIR/install.sh" "\$@"
EOF
    chmod +x "$CLI_LINK"
}

_try_install_venv_pkg() {
    command -v apt-get >/dev/null 2>&1 || return 1
    info "Пробую автоматически поставить python3-venv через apt..."
    apt-get update -qq >/dev/null 2>&1
    apt-get install -y python3-venv >/tmp/skipa_apt_venv.log 2>&1
    local pyver
    pyver="$(python3 -c 'import sys; print(f"{sys.version_info[0]}.{sys.version_info[1]}")' 2>/dev/null)"
    if [ -n "$pyver" ]; then
        apt-get install -y "python${pyver}-venv" >>/tmp/skipa_apt_venv.log 2>&1
    fi
}

ensure_venv() {
    if [ -x "$INSTALL_DIR/venv/bin/python" ] && [ -x "$INSTALL_DIR/venv/bin/pip" ]; then
        return 0
    fi
    if [ -d "$INSTALL_DIR/venv" ]; then
        warn "Обнаружен неполный/битый venv (например, от прошлой неудачной попытки) - пересоздаю."
        rm -rf "$INSTALL_DIR/venv"
    fi
    local err_log
    err_log="$(mktemp)"
    if python3 -m venv "$INSTALL_DIR/venv" 2>"$err_log" && [ -x "$INSTALL_DIR/venv/bin/pip" ]; then
        rm -f "$err_log"
        return 0
    fi
    if grep -qiE "ensurepip|No module named venv|python3-venv|python3-full" "$err_log" \
        || [ ! -x "$INSTALL_DIR/venv/bin/pip" ]; then
        warn "На сервере не установлен python3-venv (или ensurepip недоступен) - пробую поставить автоматически..."
        rm -rf "$INSTALL_DIR/venv"
        _try_install_venv_pkg
        if python3 -m venv "$INSTALL_DIR/venv" 2>"$err_log" && [ -x "$INSTALL_DIR/venv/bin/pip" ]; then
            ok "python3-venv поставлен, venv создан."
            rm -f "$err_log"
            return 0
        fi
    fi
    err "Не удалось создать рабочий venv (с pip). Поставьте пакет python3-venv вручную" \
        "(например: sudo apt install python3-venv) и запустите установку снова."
    cat "$err_log" >&2
    rm -rf "$INSTALL_DIR/venv"
    rm -f "$err_log"
    return 1
}

install_telegram_deps() {
    if [ ! -x "$INSTALL_DIR/venv/bin/pip" ]; then
        err "venv не найден - сначала выполните установку."
        return 1
    fi
    if "$INSTALL_DIR/venv/bin/python" -c "import telegram" >/dev/null 2>&1; then
        return 0
    fi
    [ -f "$INSTALL_DIR/requirements-telegram.txt" ] || { err "requirements-telegram.txt не найден."; return 1; }
    info "Ставлю python-telegram-bot..."
    "$INSTALL_DIR/venv/bin/pip" install -q -r "$INSTALL_DIR/requirements-telegram.txt" \
        || { err "Не удалось поставить python-telegram-bot."; return 1; }
    ok "python-telegram-bot установлен."
}

do_install() {
    require_root
    command -v git >/dev/null 2>&1 || { err "Нужен git"; return 1; }
    command -v python3 >/dev/null 2>&1 || { err "Нужен python3"; return 1; }

    ensure_repo
    [ -f "$INSTALL_DIR/requirements.txt" ] || { err "requirements.txt не найден в $INSTALL_DIR - установка прервана."; return 1; }
    mkdir -p "$LOG_DIR"

    info "Создаю venv и ставлю базовые зависимости (мониторинг, блокировка, локальный лог)..."
    ensure_venv || return 1
    "$INSTALL_DIR/venv/bin/pip" install -q --upgrade pip
    "$INSTALL_DIR/venv/bin/pip" install -q -r "$INSTALL_DIR/requirements.txt" \
        || { err "Не удалось поставить зависимости из requirements.txt."; return 1; }
    # На старых установках могли остаться aiohttp/psutil (использовались до
    # перехода на stdlib-only реализацию) - тихо подчищаем, если код их уже
    # не использует, ради минимального веса установки.
    "$INSTALL_DIR/venv/bin/pip" uninstall -y aiohttp psutil >/dev/null 2>&1 || true

    local want_telegram=""
    if [ ! -f "$INSTALL_DIR/config.yaml" ]; then
        cp "$INSTALL_DIR/config.example.yaml" "$INSTALL_DIR/config.yaml" \
            || { err "Не удалось создать config.yaml (нет config.example.yaml?)."; return 1; }
        info "Создан $INSTALL_DIR/config.yaml из шаблона."
        echo
        echo "Как установить?"
        echo "  1) Только сервис - мониторинг + блокировка через iptables, всё пишется"
        echo "     локально в $LOG_DIR. Ничего лишнего не ставится."
        echo "  2) Сервис + Telegram-бот - то же самое, и дополнительно уведомления и"
        echo "     команды/меню в чате (ставится доп. пакет python-telegram-bot)."
        read -rp "> [1] " install_choice
        install_choice="${install_choice:-1}"
        [ "$install_choice" = "2" ] && want_telegram="y"
    else
        info "config.yaml уже существует, не трогаю."
        if ! grep -q '^\s*bot_token: ""' "$INSTALL_DIR/config.yaml" 2>/dev/null; then
            want_telegram="y"  # telegram уже настроен раньше - пакет должен быть на месте
        fi
    fi

    if [[ "$want_telegram" =~ ^[Yy] ]]; then
        install_telegram_deps || return 1
        if grep -q '^\s*bot_token: ""' "$INSTALL_DIR/config.yaml" 2>/dev/null; then
            configure_telegram
        fi
    else
        info "Ставлю только сервис (без python-telegram-bot). Подключить Telegram можно" \
             "в любой момент из меню (пункт 4), тогда пакет доустановится сам."
    fi

    [ -f "$INSTALL_DIR/skipa-watchdog.service" ] || { err "skipa-watchdog.service не найден в репозитории."; return 1; }
    cp "$INSTALL_DIR/skipa-watchdog.service" "$SYSTEMD_DIR/${UNIT}.service"
    sed -i "s#/opt/skipa_watchdog#$INSTALL_DIR#g" "$SYSTEMD_DIR/${UNIT}.service"
    systemctl daemon-reload || { err "systemctl daemon-reload не удался."; return 1; }
    systemctl enable "$UNIT" >/dev/null 2>&1

    install_cli_link

    systemctl restart "$UNIT" 2>/dev/null
    if systemctl is-active --quiet "$UNIT" 2>/dev/null; then
        ok "Skipa Watchdog установлен и запущен как systemd-юнит $UNIT."
    else
        ok "Skipa Watchdog установлен (юнит $UNIT)."
        warn "Сервис пока не запущен/не смог стартовать - проверьте: journalctl -u $UNIT -n 30"
    fi
    echo
    ok "Дальше управлять можно командой: sudo skipa-watchdog"
}

do_uninstall() {
    require_root
    warn "Это остановит и удалит Skipa Watchdog: код, venv, конфиг, кэш."
    read -rp "Точно продолжить? [y/N] " a
    [[ "$a" =~ ^[Yy] ]] || { info "Отменено."; return; }

    systemctl stop "$UNIT" "$FW_UNIT" 2>/dev/null
    systemctl disable "$UNIT" "$FW_UNIT" 2>/dev/null
    rm -f "$SYSTEMD_DIR/${UNIT}.service" "$SYSTEMD_DIR/${FW_UNIT}.service"
    systemctl daemon-reload
    rm -f "$CLI_LINK"
    rm -rf "$INSTALL_DIR"
    read -rp "Удалить также логи в $LOG_DIR? [y/N] " a
    [[ "$a" =~ ^[Yy] ]] && rm -rf "$LOG_DIR"
    ok "Skipa Watchdog полностью удалён. Правила iptables (SKIPA-BLOCK и переходы" \
       "в INPUT/DOCKER-USER/KUBE-*) не трогал - уберите вручную при необходимости:"
    echo "   iptables -D INPUT -j SKIPA-BLOCK ; iptables -F SKIPA-BLOCK ; iptables -X SKIPA-BLOCK"
}

# ---------------------------------------------------------------------------
# Статус / здоровье / управление сервисом
# ---------------------------------------------------------------------------
health_check() {
    echo
    info "Проверка работоспособности:"

    if [ ! -f "$SYSTEMD_DIR/${UNIT}.service" ]; then
        warn "Не установлен."
        pause
        return
    fi

    local active enabled
    active="$(systemctl is-active "$UNIT" 2>/dev/null || echo inactive)"
    enabled="$(systemctl is-enabled "$UNIT" 2>/dev/null || echo disabled)"
    echo "   Юнит: $UNIT, active=$active, enabled=$enabled"

    if grep -q '^\s*bot_token: ""' "$INSTALL_DIR/config.yaml" 2>/dev/null; then
        info "Telegram не настроен - работает только локальный лог/блокировка (это нормально)."
    else
        ok "Telegram настроен."
    fi

    echo "   Последние строки лога:"
    journalctl -u "$UNIT" -n 8 --no-pager 2>/dev/null | sed 's/^/     /'

    if [ -f "$LOG_DIR/detections.log" ]; then
        local n
        n=$(grep -c '^=====' "$LOG_DIR/detections.log" 2>/dev/null || echo 0)
        echo "   Всего зафиксировано детектов в detections.log: $n"
    fi

    if command -v iptables >/dev/null 2>&1; then
        if firewall_rules_applied; then
            ok "Цепочка SKIPA-BLOCK существует."
            if iptables -C INPUT -j SKIPA-BLOCK >/dev/null 2>&1; then
                ok "INPUT подключён к SKIPA-BLOCK (блокировка/логирование хоста работает)."
            else
                warn "INPUT НЕ подключён к SKIPA-BLOCK - запустите пункт про Docker/Kubernetes в меню."
            fi
        else
            warn "Цепочка SKIPA-BLOCK не найдена - блокировка/логирование ещё не настроены."
        fi
    fi
    pause
}

manage_service() {
    echo
    if [ ! -f "$SYSTEMD_DIR/${UNIT}.service" ]; then
        warn "Не установлен."
        pause
        return
    fi
    echo "Действие: 1) start  2) stop  3) restart  4) статус"
    read -rp "> " action
    case "$action" in
        1) systemctl start "$UNIT" && ok "Запущен" ;;
        2) systemctl stop "$UNIT" && ok "Остановлен" ;;
        3) systemctl restart "$UNIT" && ok "Перезапущен" ;;
        4) systemctl status "$UNIT" --no-pager -l | head -n 15 ;;
        *) warn "Неизвестное действие" ;;
    esac
    pause
}

# ---------------------------------------------------------------------------
# Настройки обнаружения: список IP / режим действия
# ---------------------------------------------------------------------------
_venv_python() {
    if [ -x "$INSTALL_DIR/venv/bin/python" ]; then
        echo "$INSTALL_DIR/venv/bin/python"
    fi
}

_set_yaml_scalar() {
    # Обновляет "key: значение" внутри секции (простая эвристика через grep/sed,
    # без внешних yaml-парсеров - конфиг у нас плоский и предсказуемый).
    local file="$1" key="$2" value="$3"
    if grep -q "^\(\s*${key}:\).*" "$file"; then
        sed -i "s#^\(\s*${key}:\).*#\1 ${value}#" "$file"
    else
        warn "Ключ $key не найден в $file - допишите вручную."
    fi
}

detection_settings_menu() {
    echo
    echo "Настройки обнаружения:"
    echo "  1) Источник IP-листов (сейчас: $(grep -oP '(?<=active_list: ").*(?=")' "$INSTALL_DIR/config.yaml" 2>/dev/null || echo '?'))"
    echo "  2) Режим действия (сейчас: $(grep -oP '(?<=mode: ").*(?=")' "$INSTALL_DIR/config.yaml" 2>/dev/null || echo '?'))"
    echo "  0) Назад"
    read -rp "> " c
    case "$c" in
        1) select_active_list ;;
        2) select_action_mode ;;
        *) return ;;
    esac
}

select_active_list() {
    if [ ! -f "$INSTALL_DIR/config.yaml" ]; then
        warn "Сначала установите Skipa Watchdog."; pause; return
    fi
    echo
    echo "Источник списка IP-адресов сканеров:"
    echo "  1) Лист 1 (текущий) - основной список skipa_cidr (tread-lightly/CyberOK_Skipa_ips)"
    echo "  2) Лист 2 (новый) - доп. blacklist (sngvy gist)"
    echo "  3) Объединить оба списка (без повторов)"
    echo "  0) Назад"
    read -rp "> " c
    local value=""
    case "$c" in
        1) value="list1" ;;
        2) value="list2" ;;
        3) value="merged" ;;
        *) return ;;
    esac
    _set_yaml_scalar "$INSTALL_DIR/config.yaml" "active_list" "\"$value\""
    ok "active_list -> $value"
    restart_if_running
    pause
}

select_action_mode() {
    if [ ! -f "$INSTALL_DIR/config.yaml" ]; then
        warn "Сначала установите Skipa Watchdog."; pause; return
    fi
    echo
    echo "Что делать при обнаружении скана:"
    echo "  1) Блокировать + уведомлять (по умолчанию, рекомендуется)"
    echo "  2) Только блокировать"
    echo "  3) Только уведомлять"
    echo "  0) Назад"
    read -rp "> " c
    local value=""
    case "$c" in
        1) value="block_notify" ;;
        2) value="block" ;;
        3) value="notify" ;;
        *) return ;;
    esac
    _set_yaml_scalar "$INSTALL_DIR/config.yaml" "mode" "\"$value\""
    ok "action.mode -> $value"
    if [ "$value" != "notify" ] && ! firewall_rules_applied; then
        warn "Блокировка выбрана, но правила SKIPA-BLOCK ещё не настроены - зайдите в пункт" \
             "про Docker/Kubernetes в меню (он же настраивает блокировку и для обычного хоста)."
    fi
    restart_if_running
    pause
}

restart_if_running() {
    if systemctl is-active --quiet "$UNIT" 2>/dev/null; then
        echo "Перезапустить сервис, чтобы применить изменения? [y/N]"
        read -rp "> " a
        [[ "$a" =~ ^[Yy] ]] && systemctl restart "$UNIT" && ok "Перезапущено."
    fi
}

# ---------------------------------------------------------------------------
# Telegram
# ---------------------------------------------------------------------------
configure_telegram() {
    if [ ! -f "$INSTALL_DIR/config.yaml" ]; then
        warn "Сначала установите Skipa Watchdog."; pause; return
    fi
    install_telegram_deps || return 1
    echo
    read -rp "Telegram bot_token (от @BotFather): " token
    read -rp "chat_id (куда слать уведомления): " chat_id
    read -rp "admin_ids через запятую (можно оставить пустым): " admins

    [ -z "$token" ] && { warn "Токен не введён, отменено."; return; }

    _set_yaml_scalar "$INSTALL_DIR/config.yaml" "bot_token" "\"$token\""
    _set_yaml_scalar "$INSTALL_DIR/config.yaml" "chat_id" "$chat_id"
    if [ -n "$admins" ]; then
        local formatted
        formatted="[$(echo "$admins" | tr -d ' ')]"
        _set_yaml_scalar "$INSTALL_DIR/config.yaml" "admin_ids" "$formatted"
    fi
    ok "Telegram настроен."
}

disable_telegram() {
    if [ ! -f "$INSTALL_DIR/config.yaml" ]; then
        warn "Сначала установите Skipa Watchdog."; pause; return
    fi
    _set_yaml_scalar "$INSTALL_DIR/config.yaml" "bot_token" '""'
    ok "Telegram отключён (bot_token очищен)."
}

telegram_menu() {
    echo
    echo "Telegram:"
    echo "  1) Подключить/перенастроить"
    echo "  2) Отключить"
    echo "  0) Назад"
    read -rp "> " c
    case "$c" in
        1) configure_telegram; restart_if_running; pause ;;
        2) disable_telegram; restart_if_running; pause ;;
        *) return ;;
    esac
}

# ---------------------------------------------------------------------------
# Блокировки
# ---------------------------------------------------------------------------
blocklist_menu() {
    local py
    py="$(_venv_python)"
    if [ -z "$py" ]; then
        err "Сначала установите Skipa Watchdog."; pause; return
    fi
    echo
    echo "Заблокированные IP:"
    (cd "$INSTALL_DIR" && "$py" -c "
from bot import blocker
ips = blocker.list_blocked_ips()
print('  (никто не заблокирован)' if not ips else '\n'.join(f'  {ip}' for ip in ips))
")
    echo
    echo "  1) Заблокировать IP вручную"
    echo "  2) Разблокировать IP"
    echo "  0) Назад"
    read -rp "> " c
    case "$c" in
        1)
            read -rp "IP для блокировки: " ip
            (cd "$INSTALL_DIR" && "$py" -c "
from bot import blocker
print('OK' if blocker.block_ip('$ip') else 'FAIL')
")
            ;;
        2)
            read -rp "IP для разблокировки: " ip
            (cd "$INSTALL_DIR" && "$py" -c "
from bot import blocker
print('OK' if blocker.unblock_ip('$ip') else 'FAIL')
")
            ;;
        *) return ;;
    esac
    pause
}

# ---------------------------------------------------------------------------
# Прочее: логи, конфиг, обновление базы, обновление проекта
# ---------------------------------------------------------------------------
view_logs() {
    echo
    echo "Какие логи посмотреть?"
    echo "  1) journalctl (последние 50 строк)"
    echo "  2) $LOG_DIR/detections.log (последние 30 строк)"
    echo "  3) $LOG_DIR/skipa-watchdog.log (последние 30 строк)"
    echo "  0) Назад"
    read -rp "> " c
    case "$c" in
        1) journalctl -u "$UNIT" -n 50 --no-pager ;;
        2) tail -n 30 "$LOG_DIR/detections.log" 2>/dev/null || warn "Файл не найден" ;;
        3) tail -n 30 "$LOG_DIR/skipa-watchdog.log" 2>/dev/null || warn "Файл не найден" ;;
        *) return ;;
    esac
    pause
}

force_update_db() {
    local py
    py="$(_venv_python)"
    if [ -z "$py" ]; then
        err "Skipa Watchdog не установлен - нечем обновлять базу."
        pause
        return
    fi
    info "Принудительно обновляю базу IP-адресов..."
    (cd "$INSTALL_DIR" && "$py" - <<'PYEOF'
import asyncio
from bot.config import Config
from bot.ip_lists import fetch_threat_db, save_cache

cfg = Config.load("config.yaml")
db = asyncio.run(fetch_threat_db(cfg.primary_list_url, cfg.blacklist_url, cfg.blacklist_name, cfg.active_list))
save_cache(db)
print(f"Готово: {db.source_line_count} записей ({db.per_source_counts})")
PYEOF
    )
    pause
}

edit_config() {
    if [ ! -f "$INSTALL_DIR/config.yaml" ]; then
        err "Файл не найден."
        pause
        return
    fi
    "${EDITOR:-nano}" "$INSTALL_DIR/config.yaml"
    restart_if_running
}

update_project() {
    info "Обновляю Skipa Watchdog (git pull + зависимости)..."
    do_install
    pause
}

# ---------------------------------------------------------------------------
# Меню
# ---------------------------------------------------------------------------
main_menu() {
    while true; do
        print_header
        echo " 1) Проверка работоспособности"
        echo " 2) Управление сервисом (start/stop/restart/статус)"
        echo " 3) Настройки обнаружения (список IP / режим действия)"
        echo " 4) Telegram (подключить/отключить)"
        echo " 5) Docker/Kubernetes (логирование + блокировка)"
        echo " 6) Заблокированные IP"
        echo " 7) Принудительно обновить базу IP"
        echo " 8) Просмотр логов"
        echo " 9) Редактировать конфиг вручную"
        echo "10) Обновить Skipa Watchdog"
        echo "11) Удалить полностью"
        echo " 0) Выход"
        read -rp "> " choice || { echo; info "Ввод завершён, выхожу."; exit 0; }
        case "$choice" in
            1) health_check ;;
            2) manage_service ;;
            3) detection_settings_menu ;;
            4) telegram_menu ;;
            5) apply_firewall_rules; pause ;;
            6) blocklist_menu ;;
            7) force_update_db ;;
            8) view_logs ;;
            9) edit_config ;;
            10) update_project ;;
            11) do_uninstall; pause ;;
            0) exit 0 ;;
            *) warn "Неизвестный пункт" ;;
        esac
    done
}

first_run_flow() {
    print_header
    echo
    echo "$DESCRIPTION"
    echo
    read -rp "Установить Skipa Watchdog сейчас? [Y/n] " a
    a="${a:-y}"
    if [[ "$a" =~ ^[Yy] ]]; then
        if do_install; then
            # Docker/Kubernetes проверяются и донастраиваются только один раз,
            # при первичной установке. Дальше это можно повторить вручную из
            # меню (пункт "Docker/Kubernetes"), само по себе больше не
            # спрашивается при каждом запуске.
            env_check_and_offer
            check_list_updates
        fi
    else
        info "Ок, ничего не меняю. Запустите install.sh снова, когда будете готовы."
    fi
}

usage() {
    cat <<EOF
Использование:
  sudo bash install.sh          интерактивное меню (или первичная установка)
  sudo bash install.sh install  установить/обновить (неинтерактивно)
  sudo bash install.sh uninstall удалить полностью
  sudo bash install.sh status    краткий статус (без меню)
  sudo bash install.sh fw-rules  поставить правила логирования/блокировки docker/k8s
  sudo bash install.sh check-lists  проверить обновления листов прямо сейчас
EOF
}

main() {
    if [ "$#" -gt 0 ]; then
        require_root
        case "$1" in
            install) do_install ;;
            uninstall) do_uninstall ;;
            status) print_header; health_check ;;
            fw-rules) apply_firewall_rules ;;
            check-lists) check_list_updates ;;
            -h|--help) usage ;;
            *) usage; exit 1 ;;
        esac
        exit 0
    fi

    require_root

    if ! is_installed; then
        first_run_flow
        exit 0
    fi

    # Docker/Kubernetes проверяются один раз, при первичной установке (см.
    # first_run_flow) - здесь, при обычном запуске уже установленного
    # Skipa Watchdog, это не повторяется. Донастроить вручную можно из
    # меню (пункт "Docker/Kubernetes") или командой `install.sh fw-rules`.
    check_list_updates
    main_menu
}

main "$@"
