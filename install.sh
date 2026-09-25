#!/usr/bin/env bash
# Skipa Watchdog - установщик и менеджер.
#
# Два режима, полностью независимые по зависимостям:
#   1) Только сервис - мониторинг/блокировка целиком на bash + iptables/ipset.
#      Python НЕ используется вообще: ни для установки, ни для работы.
#   2) Сервис + Telegram-бот - то же самое плюс уведомления/команды в чате
#      (watchdog.py, venv, python-telegram-bot) - единственное, что зависит
#      от Python во всём проекте.
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

UNIT="skipa-watchdog"                       # systemd-юнит python-бота (режим "bot")
FW_UNIT="skipa-watchdog-fw-rules"           # применяет правила python-режима после старта Docker
SYNC_UNIT="skipa-watchdog-sync-lists"       # bash-режим: таймер обновления ipset
NOTIFY_UNIT="skipa-watchdog-notify"         # bash-режим: демон записи detections.log
SERVICE_CONF="$INSTALL_DIR/service.conf"    # конфиг bash-режима (не YAML - обычный bash source)

# Содержит "service" (чистый bash + ipset/iptables, без Python вообще) или
# "bot" (venv + python-telegram-bot) - определяет, какой из двух полностью
# независимых путей установлен и как им управлять из меню.
INSTALL_MODE_FILE="$INSTALL_DIR/.install_mode"

INSTALLER_VERSION="3.0.0"

DESCRIPTION="Skipa Watchdog постоянно следит за сетевыми подключениями к серверу и
сверяет источник с базой IP-адресов сканеров (CyberOK/Skipa, ГРЧЦ, НКЦКИ +
доп. списки). При обнаружении, в зависимости от настроенного режима, он
блокирует IP через iptables/ipset (сразу для хоста, Docker и Kubernetes),
присылает уведомление, или делает и то, и другое. Всё это - включая базовый
режим - реализовано на bash, без единой строчки Python. Telegram - отдельный,
целиком необязательный вариант поверх той же защиты: без него всё работает
через локальные логи в /var/log/skipa_watchdog/, с ним - ещё и уведомления и
команды в чате (для этого одного варианта и только для него ставится Python)."

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
    [ -f "$INSTALL_MODE_FILE" ]
}

# Возвращает "service" или "bot". Если маркер почему-то потерялся (ручное
# вмешательство/старая установка), определяет по факту наличия venv.
_current_mode() {
    if [ -f "$INSTALL_MODE_FILE" ]; then
        cat "$INSTALL_MODE_FILE"
    elif [ -x "$INSTALL_DIR/venv/bin/python" ]; then
        echo "bot"
    else
        echo "service"
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

firewall_rules_applied() {
    command -v iptables >/dev/null 2>&1 || return 1
    if [ "$(_current_mode)" = "bot" ]; then
        iptables -L SKIPA-BLOCK -n >/dev/null 2>&1
    else
        ipset list skipa-scanners >/dev/null 2>&1
    fi
}

# Ставится один раз, сразу после первой установки: без этого шага защита
# (блокировка/логирование сканов) физически не работает. Всегда выполняется
# безусловно (не только когда обнаружен Docker/K8s), потому что защита хоста
# (INPUT) нужна в любом случае - Docker/K8s лишь расширяют её.
setup_firewall_after_install() {
    local has_docker=0 has_k8s=0
    detect_docker && has_docker=1
    detect_k8s && has_k8s=1

    echo
    info "Настраиваю логирование и блокировку..."
    [ "$has_docker" -eq 1 ] && echo "   🐳 Обнаружен Docker - подключаю также DOCKER-USER"
    [ "$has_k8s" -eq 1 ] && echo "   ☸️  Обнаружен Kubernetes - подключаю также KUBE-*"
    apply_firewall_rules
}

# Ставит правила под ТЕКУЩИЙ установленный режим (bot - динамическая цепочка
# SKIPA-BLOCK через watchdog.py; service - статический ipset skipa-scanners,
# без единого процесса в userspace для самой блокировки).
apply_firewall_rules() {
    if [ "$(_current_mode)" = "bot" ]; then
        _apply_bot_firewall_rules
    else
        _apply_service_firewall_rules
    fi
}

_apply_bot_firewall_rules() {
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

_apply_service_firewall_rules() {
    local script="$INSTALL_DIR/service/setup-ipset-rules.sh"
    if [ ! -f "$script" ]; then
        err "service/setup-ipset-rules.sh не найден - переустановите (пункт 10)."
        return 1
    fi
    local mode
    mode="$(_service_conf_get ACTION_MODE)"
    chmod +x "$script"
    bash "$script" "${mode:-block_notify}"
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

# Без этого detections.log/skipa-watchdog.log растут неограниченно - актуально
# для обоих режимов (только один из них, python-бот, ротирует свой
# skipa-watchdog.log сам изнутри, detections.log не ротирует никто).
install_logrotate() {
    [ -f "$INSTALL_DIR/skipa-watchdog.logrotate" ] || return 0
    cp "$INSTALL_DIR/skipa-watchdog.logrotate" /etc/logrotate.d/skipa-watchdog 2>/dev/null \
        && info "Настроена ротация логов (/etc/logrotate.d/skipa-watchdog)."
}

# Определяет, каким python запускать watchdog.py в режиме "bot" - там всегда
# есть venv (создаётся при установке/подключении Telegram). Системный python3
# как запасной вариант - защита на случай ручного вмешательства в установку.
_python_bin() {
    if [ -x "$INSTALL_DIR/venv/bin/python" ]; then
        echo "$INSTALL_DIR/venv/bin/python"
    else
        command -v python3
    fi
}

# Переписывает ExecStart в уже установленном systemd-юните на нужный python
# (вызывается и при первой установке, и когда сервис-режим апгрейдится до
# бота из меню - см. install_telegram_deps).
_write_unit_exec_start() {
    [ -f "$SYSTEMD_DIR/${UNIT}.service" ] || return 0
    local python_bin
    python_bin="$(_python_bin)"
    sed -i "s#^ExecStart=.*#ExecStart=$python_bin $INSTALL_DIR/watchdog.py $INSTALL_DIR/config.yaml#" \
        "$SYSTEMD_DIR/${UNIT}.service"
    systemctl daemon-reload 2>/dev/null
}

_try_install_venv_pkg() {
    local pyver
    pyver="$(python3 -c 'import sys; print(f"{sys.version_info[0]}.{sys.version_info[1]}")' 2>/dev/null)"
    info "Пробую автоматически поставить пакет для venv..."
    # На большинстве дистрибутивов (dnf/yum/apk/zypper/pacman) venv уже входит
    # в сам пакет python3 - проблема почти всегда специфична для Debian/Ubuntu,
    # где apt разносит его в отдельный пакет python3-venv / python3.NN-venv.
    _pkg_install python3-venv >/dev/null 2>&1
    [ -n "$pyver" ] && _pkg_install "python${pyver}-venv" >/dev/null 2>&1
    return 0
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
        info "Для Telegram нужен отдельный venv (python-telegram-bot надёжно ставится" \
             "только через pip) - создаю и переношу туда базовые зависимости..."
        ensure_venv || return 1
        "$INSTALL_DIR/venv/bin/pip" install -q --upgrade pip
        "$INSTALL_DIR/venv/bin/pip" install -q -r "$INSTALL_DIR/requirements.txt" \
            || { err "Не удалось поставить базовые зависимости в новый venv."; return 1; }
        _write_unit_exec_start
        echo "bot" > "$INSTALL_MODE_FILE"
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

# ---------------------------------------------------------------------------
# Автоустановка системных пакетов (git, python3, python3-venv), если их нет.
# Работает на apt/dnf/yum/apk/zypper/pacman - чего нет, то просто пропускаем.
# ---------------------------------------------------------------------------
_detect_pkg_manager() {
    command -v apt-get >/dev/null 2>&1 && { echo "apt"; return; }
    command -v dnf >/dev/null 2>&1 && { echo "dnf"; return; }
    command -v yum >/dev/null 2>&1 && { echo "yum"; return; }
    command -v apk >/dev/null 2>&1 && { echo "apk"; return; }
    command -v zypper >/dev/null 2>&1 && { echo "zypper"; return; }
    command -v pacman >/dev/null 2>&1 && { echo "pacman"; return; }
    echo ""
}

_pkg_install() {
    local mgr log
    mgr="$(_detect_pkg_manager)"
    log="$(mktemp)"
    case "$mgr" in
        apt)    apt-get update -qq >"$log" 2>&1; apt-get install -y "$@" >>"$log" 2>&1 ;;
        dnf)    dnf install -y "$@" >"$log" 2>&1 ;;
        yum)    yum install -y "$@" >"$log" 2>&1 ;;
        apk)    apk add --no-cache "$@" >"$log" 2>&1 ;;
        zypper) zypper --non-interactive install "$@" >"$log" 2>&1 ;;
        pacman) pacman -Sy --noconfirm "$@" >"$log" 2>&1 ;;
        *) rm -f "$log"; return 1 ;;
    esac
    local rc=$?
    rm -f "$log"
    return $rc
}

# ensure_command <команда> <кандидат-пакета> [ещё кандидаты...]
# Если команда уже есть - молча выходит. Если нет - определяет пакетный
# менеджер и пробует поставить по очереди каждый кандидат (имена пакетов
# отличаются между дистрибутивами, например python3 vs python), пока
# команда не появится.
ensure_command() {
    local cmd="$1"
    shift
    command -v "$cmd" >/dev/null 2>&1 && return 0

    local mgr
    mgr="$(_detect_pkg_manager)"
    if [ -z "$mgr" ]; then
        warn "Не нашёл известный пакетный менеджер (apt/dnf/yum/apk/zypper/pacman) -" \
             "поставьте '$cmd' вручную."
        return 1
    fi

    info "Команда '$cmd' не найдена - пробую поставить автоматически (через $mgr)..."
    local pkg
    for pkg in "$@"; do
        if _pkg_install "$pkg" && command -v "$cmd" >/dev/null 2>&1; then
            ok "'$cmd' установлен (пакет $pkg)."
            return 0
        fi
    done
    return 1
}

_sync_notify_service_state() {
    # Демон записи detections.log нужен только если ACTION_MODE включает
    # notify - при чистом "block" вся защита в ядре, процесс не нужен вовсе.
    local action_mode="${1:-$(_service_conf_get ACTION_MODE)}"
    if [ "$action_mode" = "block" ]; then
        systemctl stop "$NOTIFY_UNIT" 2>/dev/null
        systemctl disable "$NOTIFY_UNIT" 2>/dev/null
    else
        systemctl enable --now "$NOTIFY_UNIT" >/dev/null 2>&1
    fi
}

do_install() {
    require_root
    ensure_command git git \
        || { err "Нужен git, не удалось поставить автоматически - поставьте вручную и повторите."; return 1; }

    ensure_repo
    mkdir -p "$LOG_DIR"

    local mode=""
    if [ -f "$INSTALL_MODE_FILE" ]; then
        mode="$(cat "$INSTALL_MODE_FILE")"
        info "Обновляю существующую установку (режим: $mode)..."
    else
        echo
        echo "Как установить?"
        echo "  1) Только сервис - мониторинг + блокировка на bash + iptables/ipset."
        echo "  2) Сервис + Telegram-бот - то же самое, и дополнительно уведомления и"
        echo "     команды/меню в чате (venv + python-telegram-bot)."
        read -rp "> [1] " install_choice
        install_choice="${install_choice:-1}"
        [ "$install_choice" = "2" ] && mode="bot" || mode="service"
    fi

    if [ "$mode" = "bot" ]; then
        _do_install_bot
    else
        _do_install_service
    fi
}

_do_install_bot() {
    ensure_command python3 python3 python3.12 python3.11 python3.10 python \
        || { err "Нужен python3, не удалось поставить автоматически - поставьте вручную и повторите."; return 1; }
    [ -f "$INSTALL_DIR/requirements.txt" ] || { err "requirements.txt не найден в $INSTALL_DIR - установка прервана."; return 1; }

    if [ ! -f "$INSTALL_DIR/config.yaml" ]; then
        cp "$INSTALL_DIR/config.example.yaml" "$INSTALL_DIR/config.yaml" \
            || { err "Не удалось создать config.yaml (нет config.example.yaml?)."; return 1; }
        info "Создан $INSTALL_DIR/config.yaml из шаблона."
    fi

    info "Ставлю venv и зависимости (включая python-telegram-bot)..."
    ensure_venv || return 1
    "$INSTALL_DIR/venv/bin/pip" install -q --upgrade pip
    "$INSTALL_DIR/venv/bin/pip" install -q -r "$INSTALL_DIR/requirements.txt" \
        || { err "Не удалось поставить зависимости из requirements.txt."; return 1; }
    # На старых установках могли остаться aiohttp/psutil (до перехода на
    # stdlib-only реализацию) - тихо подчищаем.
    "$INSTALL_DIR/venv/bin/pip" uninstall -y aiohttp psutil >/dev/null 2>&1 || true
    install_telegram_deps || return 1

    echo "bot" > "$INSTALL_MODE_FILE"
    if grep -q '^\s*bot_token: ""' "$INSTALL_DIR/config.yaml" 2>/dev/null; then
        configure_telegram
    fi

    [ -f "$INSTALL_DIR/skipa-watchdog.service" ] || { err "skipa-watchdog.service не найден в репозитории."; return 1; }
    cp "$INSTALL_DIR/skipa-watchdog.service" "$SYSTEMD_DIR/${UNIT}.service"
    sed -i "s#/opt/skipa_watchdog#$INSTALL_DIR#g" "$SYSTEMD_DIR/${UNIT}.service"
    _write_unit_exec_start
    systemctl daemon-reload || { err "systemctl daemon-reload не удался."; return 1; }
    systemctl enable "$UNIT" >/dev/null 2>&1

    install_cli_link
    install_logrotate

    systemctl restart "$UNIT" 2>/dev/null
    if systemctl is-active --quiet "$UNIT" 2>/dev/null; then
        ok "Skipa Watchdog (сервис + бот) установлен и запущен как systemd-юнит $UNIT."
    else
        ok "Skipa Watchdog установлен (юнит $UNIT)."
        warn "Сервис пока не запущен/не смог стартовать - проверьте: journalctl -u $UNIT -n 30"
    fi
    echo
    ok "Дальше управлять можно командой: sudo skipa-watchdog"
}

_do_install_service() {
    ensure_command iptables iptables >/dev/null 2>&1
    ensure_command ipset ipset \
        || { err "Нужен ipset, не удалось поставить автоматически - поставьте вручную и повторите."; return 1; }
    if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
        ensure_command curl curl \
            || warn "Не удалось поставить ни curl, ни wget - скачивание списков IP работать не будет."
    fi

    [ -f "$INSTALL_DIR/service/sync-lists.sh" ] \
        || { err "service/sync-lists.sh не найден в репозитории - установка прервана."; return 1; }
    chmod +x "$INSTALL_DIR"/service/*.sh

    if [ ! -f "$SERVICE_CONF" ]; then
        cp "$INSTALL_DIR/service/service.conf.example" "$SERVICE_CONF" \
            || { err "Не удалось создать service.conf."; return 1; }
        info "Создан $SERVICE_CONF из шаблона (значения по умолчанию уже рабочие)."
    fi

    echo "service" > "$INSTALL_MODE_FILE"

    info "Скачиваю списки IP и собираю ipset..."
    bash "$INSTALL_DIR/service/sync-lists.sh" "$SERVICE_CONF"

    local interval
    interval="$(_service_conf_get UPDATE_INTERVAL_DAYS)"
    [ -z "$interval" ] && interval=7

    cp "$INSTALL_DIR/service/skipa-watchdog-sync-lists.service" "$SYSTEMD_DIR/${SYNC_UNIT}.service"
    sed -i "s#/opt/skipa_watchdog#$INSTALL_DIR#g" "$SYSTEMD_DIR/${SYNC_UNIT}.service"
    cp "$INSTALL_DIR/service/skipa-watchdog-sync-lists.timer" "$SYSTEMD_DIR/${SYNC_UNIT}.timer"
    sed -i "s#^OnUnitActiveSec=.*#OnUnitActiveSec=${interval}d#" "$SYSTEMD_DIR/${SYNC_UNIT}.timer"

    cp "$INSTALL_DIR/service/skipa-watchdog-notify.service" "$SYSTEMD_DIR/${NOTIFY_UNIT}.service"
    sed -i "s#/opt/skipa_watchdog#$INSTALL_DIR#g" "$SYSTEMD_DIR/${NOTIFY_UNIT}.service"

    systemctl daemon-reload || { err "systemctl daemon-reload не удался."; return 1; }
    systemctl enable --now "${SYNC_UNIT}.timer" >/dev/null 2>&1
    _sync_notify_service_state

    install_cli_link
    install_logrotate

    ok "Skipa Watchdog (только сервис) установлен - без единой зависимости от Python."
    echo
    ok "Дальше управлять можно командой: sudo skipa-watchdog"
}

do_uninstall() {
    require_root
    warn "Это остановит и удалит Skipa Watchdog: код, конфиг, кэш, все связанные юниты."
    read -rp "Точно продолжить? [y/N] " a
    [[ "$a" =~ ^[Yy] ]] || { info "Отменено."; return; }

    local mode
    mode="$(_current_mode 2>/dev/null || echo service)"

    systemctl stop "$UNIT" "$FW_UNIT" "${SYNC_UNIT}.timer" "$SYNC_UNIT" "$NOTIFY_UNIT" 2>/dev/null
    systemctl disable "$UNIT" "$FW_UNIT" "${SYNC_UNIT}.timer" "$NOTIFY_UNIT" 2>/dev/null
    rm -f "$SYSTEMD_DIR/${UNIT}.service" "$SYSTEMD_DIR/${FW_UNIT}.service" \
          "$SYSTEMD_DIR/${SYNC_UNIT}.service" "$SYSTEMD_DIR/${SYNC_UNIT}.timer" \
          "$SYSTEMD_DIR/${NOTIFY_UNIT}.service"
    systemctl daemon-reload
    rm -f "$CLI_LINK"
    rm -rf "$INSTALL_DIR"
    read -rp "Удалить также логи в $LOG_DIR? [y/N] " a
    [[ "$a" =~ ^[Yy] ]] && rm -rf "$LOG_DIR"

    if [ "$mode" = "bot" ]; then
        ok "Skipa Watchdog полностью удалён. Правила iptables (SKIPA-BLOCK и переходы" \
           "в INPUT/DOCKER-USER/KUBE-*) не трогал - уберите вручную при необходимости:"
        echo "   iptables -D INPUT -j SKIPA-BLOCK ; iptables -F SKIPA-BLOCK ; iptables -X SKIPA-BLOCK"
    else
        ok "Skipa Watchdog полностью удалён. ipset skipa-scanners/skipa-manual и переходы" \
           "в INPUT/DOCKER-USER/KUBE-* не трогал - уберите вручную при необходимости:"
        echo "   iptables -D INPUT -m set --match-set skipa-scanners src -j DROP"
        echo "   iptables -D INPUT -m set --match-set skipa-manual src -j DROP"
        echo "   iptables -D INPUT -m set --match-set skipa-scanners src -j LOG --log-prefix \"CONN: \""
        echo "   iptables -D INPUT -m set --match-set skipa-manual src -j LOG --log-prefix \"CONN: \""
        echo "   ipset destroy skipa-scanners ; ipset destroy skipa-manual"
    fi
}

# ---------------------------------------------------------------------------
# Статус / здоровье / управление сервисом
# ---------------------------------------------------------------------------
health_check() {
    echo
    info "Проверка работоспособности:"

    if [ ! -f "$INSTALL_MODE_FILE" ]; then
        warn "Не установлен."
        pause
        return
    fi

    local mode
    mode="$(_current_mode)"
    echo "   Режим установки: $mode"

    if [ "$mode" = "bot" ]; then
        local active enabled
        active="$(systemctl is-active "$UNIT" 2>/dev/null || echo inactive)"
        enabled="$(systemctl is-enabled "$UNIT" 2>/dev/null || echo disabled)"
        echo "   Юнит: $UNIT, active=$active, enabled=$enabled"

        if [ -f "$INSTALL_DIR/data/ip_cache.json" ]; then
            local py last_ts age_days interval
            py="$(_python_bin)"
            last_ts="$("$py" -c "
import json
print(int(json.load(open('$INSTALL_DIR/data/ip_cache.json')).get('last_update_ts', 0)))
" 2>/dev/null)"
            interval="$(grep -oP '(?<=update_interval_days: ).*' "$INSTALL_DIR/config.yaml" 2>/dev/null | tr -d ' ')"
            interval="${interval:-7}"
            if [ -n "$last_ts" ] && [ "$last_ts" != "0" ]; then
                age_days=$(( ($(date +%s) - last_ts) / 86400 ))
                if [ "$age_days" -gt $(( interval * 2 )) ]; then
                    warn "База IP не обновлялась $age_days дн. (ожидалось раз в $interval дн.) -" \
                         "проверьте: journalctl -u $UNIT"
                else
                    ok "База IP обновлялась $age_days дн. назад (ожидается раз в $interval дн.)."
                fi
            fi
        fi

        if grep -q '^\s*bot_token: ""' "$INSTALL_DIR/config.yaml" 2>/dev/null; then
            info "Telegram не настроен - работает только локальный лог/блокировка (это нормально)."
        else
            ok "Telegram настроен."
        fi

        echo "   Последние строки лога:"
        journalctl -u "$UNIT" -n 8 --no-pager 2>/dev/null | sed 's/^/     /'

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
    else
        local timer_active notify_active action_mode entries
        timer_active="$(systemctl is-active "${SYNC_UNIT}.timer" 2>/dev/null || echo inactive)"
        echo "   Таймер обновления списков ($SYNC_UNIT.timer): $timer_active"

        # "active" у таймера значит только "запланирован", не "последний запуск
        # успешен" - реальную свежесть смотрим по метке времени, которую
        # sync-lists.sh пишет при каждом удачном обновлении.
        if [ -f /var/lib/skipa_watchdog/last-sync ]; then
            local last_sync now age_days interval
            last_sync="$(cat /var/lib/skipa_watchdog/last-sync 2>/dev/null || echo 0)"
            now="$(date +%s)"
            age_days=$(( (now - last_sync) / 86400 ))
            interval="$(_service_conf_get UPDATE_INTERVAL_DAYS)"
            interval="${interval:-7}"
            if [ "$age_days" -gt $(( interval * 2 )) ]; then
                warn "Список не обновлялся $age_days дн. (ожидался раз в $interval дн.) -" \
                     "проверьте сеть/таймер: journalctl -u $SYNC_UNIT"
            else
                ok "Список обновлялся $age_days дн. назад (ожидается раз в $interval дн.)."
            fi
        else
            warn "Список ещё ни разу не обновлялся успешно - запустите пункт 7."
        fi

        action_mode="$(_service_conf_get ACTION_MODE)"
        echo "   Режим действия: ${action_mode:-?}"

        if [ "$action_mode" != "block" ]; then
            notify_active="$(systemctl is-active "$NOTIFY_UNIT" 2>/dev/null || echo inactive)"
            echo "   Демон записи detections.log ($NOTIFY_UNIT): $notify_active"
        else
            echo "   Режим 'block' - демон уведомлений не нужен, блокировка целиком в ядре."
        fi

        if command -v ipset >/dev/null 2>&1 && ipset list skipa-scanners >/dev/null 2>&1; then
            entries="$(ipset list skipa-scanners 2>/dev/null | awk '/^Number of entries:/{print $NF}')"
            ok "ipset skipa-scanners существует, записей: ${entries:-?}"
        else
            warn "ipset skipa-scanners не найден - выполните пункт 5 (Docker/Kubernetes) ещё раз."
        fi

        if command -v iptables >/dev/null 2>&1; then
            if iptables -C INPUT -m set --match-set skipa-scanners src -j DROP >/dev/null 2>&1 \
                || iptables -C INPUT -m set --match-set skipa-scanners src -m limit --limit 30/second \
                    --limit-burst 40 -j LOG --log-prefix "CONN: " --log-level 4 >/dev/null 2>&1; then
                ok "INPUT подключён к ipset-правилам."
            else
                warn "INPUT НЕ подключён к ipset-правилам - запустите пункт 5 (Docker/Kubernetes)."
            fi
        fi
    fi

    if [ -f "$LOG_DIR/detections.log" ]; then
        local n
        n=$(grep -c '^=====' "$LOG_DIR/detections.log" 2>/dev/null || echo 0)
        echo "   Всего зафиксировано детектов в detections.log: $n"
    fi
    pause
}

manage_service() {
    echo
    if [ ! -f "$INSTALL_MODE_FILE" ]; then
        warn "Не установлен."
        pause
        return
    fi

    local mode
    mode="$(_current_mode)"
    if [ "$mode" = "bot" ]; then
        echo "Действие: 1) start  2) stop  3) restart  4) статус"
        read -rp "> " action
        case "$action" in
            1) systemctl start "$UNIT" && ok "Запущен" ;;
            2) systemctl stop "$UNIT" && ok "Остановлен" ;;
            3) systemctl restart "$UNIT" && ok "Перезапущен" ;;
            4) systemctl status "$UNIT" --no-pager -l | head -n 15 ;;
            *) warn "Неизвестное действие" ;;
        esac
    else
        echo "В режиме 'только сервис' блокировка идёт в ядре без отдельного процесса -"
        echo "управлять можно только вспомогательными юнитами:"
        echo "  1) Обновить список IP сейчас (запустить $SYNC_UNIT)"
        echo "  2) Перезапустить демон detections.log ($NOTIFY_UNIT)"
        echo "  3) Статус обоих юнитов"
        read -rp "> " action
        case "$action" in
            1) systemctl start "$SYNC_UNIT" && ok "Запущено" ;;
            2) systemctl restart "$NOTIFY_UNIT" 2>/dev/null && ok "Перезапущен" \
                || warn "Юнит $NOTIFY_UNIT не установлен (текущий режим действия - 'block'?)" ;;
            3)
                systemctl status "${SYNC_UNIT}.timer" --no-pager -l | head -n 10
                systemctl status "$NOTIFY_UNIT" --no-pager -l 2>/dev/null | head -n 10
                ;;
            *) warn "Неизвестное действие" ;;
        esac
    fi
    pause
}

# ---------------------------------------------------------------------------
# Настройки обнаружения: список IP / режим действия
# ---------------------------------------------------------------------------
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

# То же самое, но для service.conf (обычный bash KEY="value", без вложенных
# секций) - используется bash-режимом "только сервис".
_service_conf_set() {
    local key="$1" value="$2"
    if grep -q "^${key}=" "$SERVICE_CONF" 2>/dev/null; then
        sed -i "s#^${key}=.*#${key}=\"${value}\"#" "$SERVICE_CONF"
    else
        echo "${key}=\"${value}\"" >> "$SERVICE_CONF"
    fi
}

_service_conf_get() {
    local key="$1"
    [ -f "$SERVICE_CONF" ] || return 1
    ( # shellcheck disable=SC1090
      source "$SERVICE_CONF" 2>/dev/null
      eval "echo \"\${$key:-}\""
    )
}

detection_settings_menu() {
    local mode current_list current_action
    mode="$(_current_mode)"
    if [ "$mode" = "bot" ]; then
        current_list="$(grep -oP '(?<=active_list: ").*(?=")' "$INSTALL_DIR/config.yaml" 2>/dev/null || echo '?')"
        current_action="$(grep -oP '(?<=mode: ").*(?=")' "$INSTALL_DIR/config.yaml" 2>/dev/null || echo '?')"
    else
        current_list="$(_service_conf_get ACTIVE_LIST || echo '?')"
        current_action="$(_service_conf_get ACTION_MODE || echo '?')"
    fi
    echo
    echo "Настройки обнаружения:"
    echo "  1) Источник IP-листов (сейчас: ${current_list:-?})"
    echo "  2) Режим действия (сейчас: ${current_action:-?})"
    echo "  0) Назад"
    read -rp "> " c
    case "$c" in
        1) select_active_list ;;
        2) select_action_mode ;;
        *) return ;;
    esac
}

select_active_list() {
    if [ ! -f "$INSTALL_MODE_FILE" ]; then
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
    if [ "$(_current_mode)" = "bot" ]; then
        _set_yaml_scalar "$INSTALL_DIR/config.yaml" "active_list" "\"$value\""
        restart_if_running
    else
        _service_conf_set ACTIVE_LIST "$value"
        info "Пересобираю ipset под новый список..."
        bash "$INSTALL_DIR/service/sync-lists.sh" "$SERVICE_CONF"
    fi
    ok "active_list -> $value"
    pause
}

select_action_mode() {
    if [ ! -f "$INSTALL_MODE_FILE" ]; then
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
    local mode
    mode="$(_current_mode)"
    if [ "$mode" = "bot" ]; then
        _set_yaml_scalar "$INSTALL_DIR/config.yaml" "mode" "\"$value\""
        if [ "$value" != "notify" ] && ! firewall_rules_applied; then
            warn "Блокировка выбрана, но правила SKIPA-BLOCK ещё не настроены - зайдите в пункт" \
                 "про Docker/Kubernetes в меню."
        fi
        restart_if_running
    else
        _service_conf_set ACTION_MODE "$value"
        info "Применяю новый режим к iptables/ipset..."
        apply_firewall_rules
        _sync_notify_service_state "$value"
    fi
    ok "action.mode -> $value"
    pause
}

restart_if_running() {
    if [ "$(_current_mode 2>/dev/null)" = "bot" ] && systemctl is-active --quiet "$UNIT" 2>/dev/null; then
        echo "Перезапустить сервис, чтобы применить изменения? [y/N]"
        read -rp "> " a
        [[ "$a" =~ ^[Yy] ]] && systemctl restart "$UNIT" && ok "Перезапущено."
    fi
}

# ---------------------------------------------------------------------------
# Telegram
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Telegram (переключает с bash-режима на python-бота при первом подключении)
# ---------------------------------------------------------------------------
_migrate_service_to_bot() {
    info "Переключаю на режим 'сервис + бот': поднимаю venv и python-бота." \
         "Bash-демон уведомлений (notify-tail) остановлю - эту роль берёт на себя" \
         "бот, а таймер обновления списков и сам ipset НЕ трогаю: список" \
         "продолжает обновляться и блокироваться в ядре независимо от Python."

    if [ ! -f "$INSTALL_DIR/config.yaml" ]; then
        cp "$INSTALL_DIR/config.example.yaml" "$INSTALL_DIR/config.yaml" \
            || { err "Не удалось создать config.yaml."; return 1; }
        local al am
        al="$(_service_conf_get ACTIVE_LIST)"
        am="$(_service_conf_get ACTION_MODE)"
        [ -n "$al" ] && _set_yaml_scalar "$INSTALL_DIR/config.yaml" "active_list" "\"$al\""
        [ -n "$am" ] && _set_yaml_scalar "$INSTALL_DIR/config.yaml" "mode" "\"$am\""
    fi

    ensure_venv || return 1
    "$INSTALL_DIR/venv/bin/pip" install -q --upgrade pip
    "$INSTALL_DIR/venv/bin/pip" install -q -r "$INSTALL_DIR/requirements.txt" \
        || { err "Не удалось поставить базовые зависимости в venv."; return 1; }
    install_telegram_deps || return 1

    systemctl stop "$NOTIFY_UNIT" 2>/dev/null
    systemctl disable "$NOTIFY_UNIT" 2>/dev/null

    [ -f "$INSTALL_DIR/skipa-watchdog.service" ] || { err "skipa-watchdog.service не найден."; return 1; }
    cp "$INSTALL_DIR/skipa-watchdog.service" "$SYSTEMD_DIR/${UNIT}.service"
    sed -i "s#/opt/skipa_watchdog#$INSTALL_DIR#g" "$SYSTEMD_DIR/${UNIT}.service"
    _write_unit_exec_start
    systemctl daemon-reload || { err "systemctl daemon-reload не удался."; return 1; }
    systemctl enable "$UNIT" >/dev/null 2>&1

    echo "bot" > "$INSTALL_MODE_FILE"
    _apply_bot_firewall_rules
    ok "Режим переключён на 'сервис + бот'."
}

configure_telegram() {
    if [ ! -f "$INSTALL_MODE_FILE" ]; then
        warn "Сначала установите Skipa Watchdog."; pause; return
    fi
    if [ "$(_current_mode)" != "bot" ]; then
        _migrate_service_to_bot || { pause; return; }
    fi
    install_telegram_deps || { pause; return; }
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
    systemctl restart "$UNIT" 2>/dev/null
}

disable_telegram() {
    if [ "$(_current_mode 2>/dev/null)" != "bot" ]; then
        warn "Telegram и так не подключён (сейчас режим 'только сервис')."
        return
    fi
    _set_yaml_scalar "$INSTALL_DIR/config.yaml" "bot_token" '""'
    ok "Telegram отключён (bot_token очищен, venv и python-telegram-bot оставлены на месте)."
}

telegram_menu() {
    echo
    if [ "$(_current_mode 2>/dev/null)" != "bot" ]; then
        echo "Сейчас установлен режим 'только сервис' (без Python). Подключение"
        echo "Telegram создаст venv и поставит python-telegram-bot - единственное"
        echo "место во всём проекте, где используется Python."
        echo
    fi
    echo "Telegram:"
    echo "  1) Подключить/перенастроить"
    echo "  2) Отключить"
    echo "  0) Назад"
    read -rp "> " c
    case "$c" in
        1) configure_telegram; pause ;;
        2) disable_telegram; restart_if_running; pause ;;
        *) return ;;
    esac
}

# ---------------------------------------------------------------------------
# Блокировки
# ---------------------------------------------------------------------------
blocklist_menu() {
    if [ ! -f "$INSTALL_MODE_FILE" ]; then
        err "Сначала установите Skipa Watchdog."; pause; return
    fi
    local mode py
    mode="$(_current_mode)"
    echo
    echo "Заблокированные IP:"
    if [ "$mode" = "bot" ]; then
        py="$(_python_bin)"
        (cd "$INSTALL_DIR" && "$py" -c "
from bot import blocker
ips = blocker.list_blocked_ips()
print('  (никто не заблокирован)' if not ips else '\n'.join(f'  {ip}' for ip in ips))
")
    else
        bash "$INSTALL_DIR/service/blockctl.sh" list | sed 's/^/  /'
    fi
    echo
    echo "  1) Заблокировать IP вручную"
    echo "  2) Разблокировать IP"
    echo "  0) Назад"
    read -rp "> " c
    case "$c" in
        1)
            read -rp "IP для блокировки: " ip
            if [ "$mode" = "bot" ]; then
                (cd "$INSTALL_DIR" && "$py" -c "
from bot import blocker
print('OK' if blocker.block_ip('$ip') else 'FAIL')
")
            else
                bash "$INSTALL_DIR/service/blockctl.sh" block "$ip"
            fi
            ;;
        2)
            read -rp "IP для разблокировки: " ip
            if [ "$mode" = "bot" ]; then
                (cd "$INSTALL_DIR" && "$py" -c "
from bot import blocker
print('OK' if blocker.unblock_ip('$ip') else 'FAIL')
")
            else
                bash "$INSTALL_DIR/service/blockctl.sh" unblock "$ip"
            fi
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
    local mode
    mode="$(_current_mode 2>/dev/null || echo service)"
    echo "Какие логи посмотреть?"
    if [ "$mode" = "bot" ]; then
        echo "  1) journalctl бота (последние 50 строк)"
    else
        echo "  1) journalctl (sync-lists + notify, последние 50 строк)"
    fi
    echo "  2) $LOG_DIR/detections.log (последние 30 строк)"
    echo "  3) $LOG_DIR/skipa-watchdog.log (последние 30 строк)"
    echo "  0) Назад"
    read -rp "> " c
    case "$c" in
        1)
            if [ "$mode" = "bot" ]; then
                journalctl -u "$UNIT" -n 50 --no-pager
            else
                journalctl -u "$SYNC_UNIT" -u "$NOTIFY_UNIT" -n 50 --no-pager
            fi
            ;;
        2) tail -n 30 "$LOG_DIR/detections.log" 2>/dev/null || warn "Файл не найден" ;;
        3) tail -n 30 "$LOG_DIR/skipa-watchdog.log" 2>/dev/null || warn "Файл не найден" ;;
        *) return ;;
    esac
    pause
}

force_update_db() {
    if [ ! -f "$INSTALL_MODE_FILE" ]; then
        err "Skipa Watchdog не установлен - нечем обновлять базу."
        pause
        return
    fi
    local mode
    mode="$(_current_mode)"
    info "Принудительно обновляю базу IP-адресов..."
    if [ "$mode" = "bot" ]; then
        local py
        py="$(_python_bin)"
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
    else
        bash "$INSTALL_DIR/service/sync-lists.sh" "$SERVICE_CONF"
    fi
    pause
}

edit_config() {
    if [ ! -f "$INSTALL_MODE_FILE" ]; then
        err "Файл не найден."
        pause
        return
    fi
    local target
    if [ "$(_current_mode)" = "bot" ]; then
        target="$INSTALL_DIR/config.yaml"
    else
        target="$SERVICE_CONF"
    fi
    "${EDITOR:-nano}" "$target"
    if [ "$(_current_mode)" != "bot" ]; then
        info "Это service.conf (bash) - изменения в источниках/режиме действия" \
             "применятся после: пункт 7 (обновить базу) и/или пункт 5 (Docker/Kubernetes)."
    fi
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
            # Firewall-правила (INPUT -> SKIPA-BLOCK, + DOCKER-USER/KUBE-* если
            # есть) ставятся один раз, сразу после первой установки - без этого
            # блокировка физически не работает. Дальше можно повторить вручную
            # из меню (пункт "Docker/Kubernetes"), при обычных запусках это
            # больше не всплывает само.
            setup_firewall_after_install
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
