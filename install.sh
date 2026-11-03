#!/usr/bin/env bash
# Skipa Watchdog - установщик и менеджер.
#
# Мониторинг и блокировка целиком на bash + iptables/ipset: сканеры из списков режет ядро, постоянного
# процесса для блокировки нет. Python не нужен ни для установки, ни для работы. Необязательные
# уведомления (Telegram, Matrix) отправляет curl из bash (service/lib-notify.sh).
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

UNIT="skipa-watchdog"                       # юнит прежнего Python-бота: нужен только чтобы убрать его при переходе
FW_UNIT="skipa-watchdog-fw-rules"           # то же: юнит правил прежнего Python-бота
SYNC_UNIT="skipa-watchdog-sync-lists"       # таймер обновления ipset
NOTIFY_UNIT="skipa-watchdog-notify"         # демон записи detections.log
ALLOW_UNIT="skipa-watchdog-allow-ssh"       # таймер, добавляющий SSH-сессии в allowlist
SETS_UNIT="skipa-watchdog-ipset"            # при загрузке возвращает ipset-наборы (до netfilter-persistent)
RULES_UNIT="skipa-watchdog-rules"           # при загрузке ставит iptables-правила (после Docker/kubelet)
SERVICE_CONF="$INSTALL_DIR/config.yaml"      # единый конфиг (читается через service/lib-config.sh)

# Метка "установлено" (содержимое всегда "service"; у установок до 4.0 там мог быть "bot" - так
# распознаётся прежний Python-вариант, который переводится на bash при обновлении).
INSTALL_MODE_FILE="$INSTALL_DIR/.install_mode"

INSTALLER_VERSION="4.0.0"

DESCRIPTION="Skipa Watchdog сверяет сканеры из списков IP-адресов (CyberOK/Skipa, ГРЧЦ, НКЦКИ + доп.
списки) с входящими подключениями и блокирует их в ядре через iptables/ipset - сразу для
хоста, Docker и Kubernetes. Список обновляется по таймеру, блокировка полностью автоматическая.
Всё реализовано на bash, без Python. Необязательно: уведомления о сканерах в Telegram или
Matrix (через curl), без них работают локальные логи в /var/log/skipa_watchdog/."

# ---------------------------------------------------------------------------
# Вывод
# ---------------------------------------------------------------------------
C_RESET="\033[0m"; C_GREEN="\033[32m"; C_YELLOW="\033[33m"; C_RED="\033[31m"; C_BLUE="\033[34m"
info()  { echo -e "${C_BLUE}[i]${C_RESET} $*"; }
ok()    { echo -e "${C_GREEN}[+]${C_RESET} $*"; }
warn()  { echo -e "${C_YELLOW}[!]${C_RESET} $*"; }
err()   { echo -e "${C_RED}[x]${C_RESET} $*" >&2; }
pause() { read -rp "Нажмите Enter, чтобы продолжить..." _; }

# Подтверждение любого изменяющего действия: confirm "Что сделать?" -> 0 только на y/д
confirm() {
    local a
    read -rp "$1 [y/N] " a || return 1
    [[ "$a" =~ ^[YyДд] ]]
}

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
        # напоминание, если обновление было доступно, а его отложили
        [ "${UPD_STATE:-}" = "available" ] \
            && echo -e " ${C_YELLOW}Доступна версия ${UPD_REMOTE:-новее}: пункт 12 меню${C_RESET}"
    else
        echo " Версия установщика: $INSTALLER_VERSION (проект ещё не установлен)"
    fi
    echo "======================================"
}

is_installed() {
    [ -f "$INSTALL_MODE_FILE" ]
}

# ---------------------------------------------------------------------------
# Определение окружения: Docker / Kubernetes (упрощённая проверка
# нужна до того, как поставлен код проекта)
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

# Есть ли в цепочке правила проекта - независимо от точной формы правила
# (ipset-набор skipa-* или переход в SKIPA-BLOCK)
_chain_has_skipa_rules() {
    # вывод сначала в переменную: `iptables | grep -q` при pipefail падает по
    # SIGPIPE, когда grep закрывает канал после первого совпадения
    local rules
    rules="$(iptables -w 5 -S "$1" 2>/dev/null)" || return 1
    grep -qE 'SKIPA-BLOCK|skipa-(scanners|manual|allow|dyn|db)' <<<"$rules"
}

firewall_rules_applied() {
    command -v iptables >/dev/null 2>&1 || return 1
    ipset list skipa-scanners >/dev/null 2>&1
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

# Ставит правила: статический ipset skipa-scanners, без единого процесса в userspace
# для самой блокировки.
apply_firewall_rules() {
    _apply_service_firewall_rules
}

_apply_service_firewall_rules() {
    local script="$INSTALL_DIR/service/setup-ipset-rules.sh"
    if [ ! -f "$script" ]; then
        err "service/setup-ipset-rules.sh не найден - переустановите (пункт 12)."
        return 1
    fi
    chmod +x "$script"
    # Скрипт сам проверяет результат (наборы существуют, правила стоят в INPUT/DOCKER-USER/KUBE-*)
    # и завершается с ошибкой, если защита применена не полностью
    if bash "$script" "$SERVICE_CONF"; then
        ok "Готово. Правила применены и проверены (см. вывод выше)."
    else
        err "Правила применены не полностью - защита может не работать. Смотрите строки ✗ выше."
        return 1
    fi
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
    # читаем как данные, а не через source: в файле только две строки с hex-хэшами
    if [ -f "$LIST_HASH_STATE" ]; then
        HASH_PRIMARY="$(sed -n 's/^HASH_PRIMARY=\([0-9a-f]\{64\}\)$/\1/p' "$LIST_HASH_STATE" | head -n1)"
        HASH_BLACKLIST="$(sed -n 's/^HASH_BLACKLIST=\([0-9a-f]\{64\}\)$/\1/p' "$LIST_HASH_STATE" | head -n1)"
    fi

    # Адреса берём из config.yaml (как и бот с сервисом), а не зашиваем в скрипт: иначе
    # при своём списке проверялся бы чужой. Пустой blacklist_url - источник отключён.
    local primary_url="https://raw.githubusercontent.com/tread-lightly/CyberOK_Skipa_ips/main/lists/skipa_cidr.txt"
    local blacklist_url="https://gist.githubusercontent.com/sngvy/07cee7ac810c9d222fbebddff8c1d1b8/raw/37cde2b27a560c647d0e8eb9d274e3409082d3e7/blacklist.txt"
    if [ -f "$SERVICE_CONF" ] && [ -f "$INSTALL_DIR/service/lib-config.sh" ]; then
        _conf_lib
        local v
        v="$(yaml_get "$SERVICE_CONF" sources.primary_list_url)";  [ -n "$v" ] && primary_url="$v"
        # blacklist_url: пустое значение в конфиге значит «источник отключён»
        if grep -qE '^  blacklist_url:' "$SERVICE_CONF"; then blacklist_url="$(yaml_get "$SERVICE_CONF" sources.blacklist_url)"; fi
    fi

    info "Проверяю обновления списков IP..."
    local new_primary new_blacklist=""
    new_primary="$(url_hash "$primary_url")"
    [ -n "$blacklist_url" ] && new_blacklist="$(url_hash "$blacklist_url")"

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
# Обновляет клон. Если быстрое обновление невозможно (история в GitHub была
# переписана или в каталоге есть локальные коммиты), предлагает перейти на
# актуальную версию: config.yaml и data/ не отслеживаются git и остаются.
_update_repo() {
    local dir="$1"
    git -C "$dir" pull --ff-only && return 0
    warn "git pull --ff-only не удался: история в репозитории изменилась или есть локальные коммиты."
    if confirm "Перейти на актуальную версию origin (git reset --hard; правки отслеживаемых файлов пропадут, config.yaml и data/ останутся)?"; then
        git -C "$dir" fetch origin \
            && git -C "$dir" reset --hard '@{u}' \
            && ok "Репозиторий обновлён до актуальной версии." \
            || warn "Не удалось перейти на актуальную версию, продолжаю с текущей на диске."
    else
        warn "Продолжаю с текущей версией на диске."
    fi
}

ensure_repo() {
    if [ -d "$INSTALL_DIR/.git" ]; then
        info "Репозиторий уже есть в $INSTALL_DIR, обновляю (git pull)..."
        _update_repo "$INSTALL_DIR"
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

# Права на config.yaml: там токен Telegram / access token Matrix
_secure_config() {
    [ -f "$INSTALL_DIR/config.yaml" ] && chmod 600 "$INSTALL_DIR/config.yaml"
}

# ---------------------------------------------------------------------------
# Автоустановка системных пакетов (git, iptables, ipset, curl), если их нет.
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
    # Демон detections.log и уведомлений нужен, только если ACTION_MODE включает notify -
    # при чистом "block" вся защита в ядре, процесс не нужен вовсе. restart (а не enable --now):
    # после обновления проекта и смены каналов уведомлений процесс должен перечитать код и config.yaml.
    local action_mode="${1:-$(_service_conf_get ACTION_MODE)}"
    if [ "$action_mode" = "block" ]; then
        systemctl stop "$NOTIFY_UNIT" 2>/dev/null
        systemctl disable "$NOTIFY_UNIT" 2>/dev/null
    else
        systemctl enable "$NOTIFY_UNIT" >/dev/null 2>&1
        systemctl restart "$NOTIFY_UNIT" 2>/dev/null
    fi
}

do_install() {
    require_root
    ensure_command git git \
        || { err "Нужен git, не удалось поставить автоматически - поставьте вручную и повторите."; return 1; }

    # Установки с Python-ботом (до 4.0) переводятся на bash автоматически: блокировки на срок
    # не переносятся, бессрочные переносятся, Telegram-настройки (токен, chat_id) работают как раньше,
    # но уже как уведомления из bash. Список бессрочных блокировок снимаем ДО обновления кода.
    local legacy=0 carry=""
    if _has_legacy_bot; then
        legacy=1
        carry="$(mktemp)" || return 1
        _collect_bot_blocks | sort -u > "$carry"
        info "Найден прежний вариант с Python-ботом: перевожу на bash (защита в ядре не прерывается)."
        systemctl stop "$UNIT" 2>/dev/null     # иначе бот сам чинил бы правила, которые мы сейчас заменим
    else
        [ -f "$INSTALL_MODE_FILE" ] && info "Обновляю существующую установку..."
    fi

    ensure_repo
    mkdir -p "$LOG_DIR"
    if ! _do_install_service; then
        [ -n "$carry" ] && rm -f "$carry"
        [ "$legacy" -eq 1 ] && warn "Миграция не завершена. Правила в ядре продолжают работать; исправьте причину и повторите: sudo skipa-watchdog"
        return 1
    fi
    [ "$legacy" -eq 1 ] && _finish_legacy_migration "$carry"
    _cleanup_python_leftovers
    return 0
}

# Остался ли от прежних версий Python-бот (юнит или метка режима bot)
_has_legacy_bot() {
    [ "$(cat "$INSTALL_MODE_FILE" 2>/dev/null)" = "bot" ] || [ -f "$SYSTEMD_DIR/${UNIT}.service" ]
}

# Правила 'только сервис' уже стоят - теперь можно убрать всё от Python-варианта.
_finish_legacy_migration() {
    local carry="$1" n
    apply_firewall_rules || warn "Правила bash-варианта применились не полностью - проверьте пункт 1 меню."
    systemctl disable "$UNIT" "$FW_UNIT" 2>/dev/null
    systemctl stop "$FW_UNIT" 2>/dev/null
    rm -f "$SYSTEMD_DIR/${UNIT}.service" "$SYSTEMD_DIR/${FW_UNIT}.service"
    systemctl daemon-reload 2>/dev/null
    _remove_bot_firewall_rules
    if [ -s "$carry" ]; then
        n="$(bash "$INSTALL_DIR/service/blockctl.sh" import-blocks "$carry" 2>&1 | tail -n 1)"
        info "Бессрочные блокировки бота перенесены: ${n:-0}"
    fi
    rm -f "$carry"
    ok "Переход на bash завершён. Команд в чате и дашборда больше нет; уведомления Telegram/Matrix - пункт 4 меню."
}

# Python в проекте больше не используется: venv и каталог bot/ не нужны (в git их нет,
# остаются только если обновление шло поверх старой установки)
_cleanup_python_leftovers() {
    if [ -d "$INSTALL_DIR/venv" ]; then
        rm -rf "$INSTALL_DIR/venv" && info "Удалён venv ($INSTALL_DIR/venv): Python проекту больше не нужен."
    fi
    if [ -d "$INSTALL_DIR/bot" ] && [ -z "$(git -C "$INSTALL_DIR" ls-files bot 2>/dev/null)" ]; then
        rm -rf "$INSTALL_DIR/bot"
    fi
    return 0
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

    _migrate_legacy_service_conf
    if [ ! -f "$SERVICE_CONF" ]; then
        cp "$INSTALL_DIR/config.example.yaml" "$SERVICE_CONF" \
            || { err "Не удалось создать config.yaml."; return 1; }
        chmod 600 "$SERVICE_CONF"
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

    cp "$INSTALL_DIR/service/skipa-watchdog-allow-ssh.service" "$SYSTEMD_DIR/${ALLOW_UNIT}.service"
    sed -i "s#/opt/skipa_watchdog#$INSTALL_DIR#g" "$SYSTEMD_DIR/${ALLOW_UNIT}.service"
    cp "$INSTALL_DIR/service/skipa-watchdog-allow-ssh.timer" "$SYSTEMD_DIR/${ALLOW_UNIT}.timer"

    # Без этих двух юнитов защита пропадала после перезагрузки: ipset-наборы и iptables-правила
    # живут только в памяти ядра, а sync-lists.sh лишь наполняет наборы, но не ставит правила
    local u
    for u in "$SETS_UNIT" "$RULES_UNIT"; do
        cp "$INSTALL_DIR/service/${u}.service" "$SYSTEMD_DIR/${u}.service"
        sed -i "s#/opt/skipa_watchdog#$INSTALL_DIR#g" "$SYSTEMD_DIR/${u}.service"
    done

    systemctl daemon-reload || { err "systemctl daemon-reload не удался."; return 1; }
    systemctl enable "$SETS_UNIT" "$RULES_UNIT" >/dev/null 2>&1 \
        || warn "Не удалось включить юниты восстановления после перезагрузки ($SETS_UNIT, $RULES_UNIT)."
    systemctl enable --now "${SYNC_UNIT}.timer" >/dev/null 2>&1
    systemctl enable --now "${ALLOW_UNIT}.timer" >/dev/null 2>&1
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

    systemctl stop "$UNIT" "$FW_UNIT" "${SYNC_UNIT}.timer" "$SYNC_UNIT" "$NOTIFY_UNIT" \
        "${ALLOW_UNIT}.timer" "$ALLOW_UNIT" "$SETS_UNIT" "$RULES_UNIT" 2>/dev/null
    systemctl disable "$UNIT" "$FW_UNIT" "${SYNC_UNIT}.timer" "$NOTIFY_UNIT" "${ALLOW_UNIT}.timer" \
        "$SETS_UNIT" "$RULES_UNIT" 2>/dev/null
    rm -f "$SYSTEMD_DIR/${UNIT}.service" "$SYSTEMD_DIR/${FW_UNIT}.service" \
          "$SYSTEMD_DIR/${SYNC_UNIT}.service" "$SYSTEMD_DIR/${SYNC_UNIT}.timer" \
          "$SYSTEMD_DIR/${NOTIFY_UNIT}.service" \
          "$SYSTEMD_DIR/${ALLOW_UNIT}.service" "$SYSTEMD_DIR/${ALLOW_UNIT}.timer" \
          "$SYSTEMD_DIR/${SETS_UNIT}.service" "$SYSTEMD_DIR/${RULES_UNIT}.service"
    # сохранённые наборы больше не нужны: восстанавливать их некому
    rm -f /var/lib/skipa_watchdog/ipsets.save /var/lib/skipa_watchdog/ipset.lock
    systemctl daemon-reload
    rm -f "$CLI_LINK"
    rm -rf "$INSTALL_DIR"
    read -rp "Удалить также логи в $LOG_DIR? [y/N] " a
    [[ "$a" =~ ^[Yy] ]] && rm -rf "$LOG_DIR"

    if confirm "Убрать правила iptables и ipset проекта (SKIPA-BLOCK, skipa-*)?"; then
        _remove_firewall_rules
        ok "Skipa Watchdog полностью удалён, правила iptables и ipset убраны."
    else
        ok "Skipa Watchdog полностью удалён. Правила iptables/ipset оставлены - убрать позже:"
        echo "   (переустановите и выберите удаление правил, либо удалите правила с 'skipa' вручную: iptables -S | grep -i skipa)"
    fi
}

# Удаляет все правила проекта из INPUT/DOCKER-USER/KUBE-*, цепочку SKIPA-BLOCK и
# ipset-наборы skipa-*. Правила берутся из `iptables -S`, поэтому не важно,
# какой версией они были созданы.
_remove_firewall_rules() {
    command -v iptables >/dev/null 2>&1 || return 0
    local chain num
    for chain in INPUT DOCKER-USER KUBE-EXTERNAL-SERVICES KUBE-NODEPORTS; do
        iptables -w 5 -L "$chain" -n >/dev/null 2>&1 || continue
        # Удаляем по номерам строк, начиная с последней: так номера оставшихся правил не
        # сдвигаются, и не нужно собирать команду из текста `iptables -S` через eval.
        while IFS= read -r num; do
            iptables -w 5 -D "$chain" "$num" 2>/dev/null
        done < <(iptables -w 5 -L "$chain" -n --line-numbers 2>/dev/null \
                    | grep -E 'SKIPA-BLOCK|skipa-(scanners|manual|allow|dyn|db)' | awk '{print $1}' | sort -rn)
    done
    if iptables -w 5 -L SKIPA-BLOCK -n >/dev/null 2>&1; then
        iptables -w 5 -F SKIPA-BLOCK 2>/dev/null
        iptables -w 5 -X SKIPA-BLOCK 2>/dev/null
    fi
    if command -v ipset >/dev/null 2>&1; then
        local set
        for set in skipa-scanners skipa-manual skipa-allow skipa-dyn skipa-db skipa-scanners-tmp skipa-allow-tmp skipa-db-tmp; do
            ipset destroy "$set" 2>/dev/null
        done
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
        warn "Список ещё ни разу не обновлялся успешно - запустите пункт 9."
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

    # Восстановление после перезагрузки: оба юнита включены и есть что восстанавливать
    local u
    for u in "$SETS_UNIT" "$RULES_UNIT"; do
        if systemctl is-enabled --quiet "$u" 2>/dev/null; then
            echo "   Автозапуск после перезагрузки ($u): включён"
        else
            warn "Юнит $u не включён - после перезагрузки защита пропадёт. Исправить: пункт 12 (обновить проект)."
        fi
    done
    if [ -s /var/lib/skipa_watchdog/ipsets.save ]; then
        echo "   Сохранённые наборы для восстановления: есть"
    else
        warn "Файла сохранённых наборов ещё нет - появится после ближайшей синхронизации (пункт 9)."
    fi

    if command -v iptables >/dev/null 2>&1; then
        local chain
        for chain in INPUT DOCKER-USER KUBE-EXTERNAL-SERVICES KUBE-NODEPORTS; do
            iptables -w 5 -L "$chain" -n >/dev/null 2>&1 || continue
            if _chain_has_skipa_rules "$chain"; then
                ok "$chain подключён к правилам блокировки/логирования."
            else
                warn "$chain НЕ подключён к правилам - примените их: пункт 5 (Docker/Kubernetes)."
            fi
        done
    fi

    _notify_status

    if [ -f "$LOG_DIR/detections.log" ]; then
        local n
        n=$(grep -c '^=====' "$LOG_DIR/detections.log" 2>/dev/null || echo 0)
        echo "   Всего зафиксировано детектов в detections.log: $n"
    fi
    pause
}

manage_service() {
    if [ ! -f "$INSTALL_MODE_FILE" ]; then
        warn "Не установлен."
        pause
        return
    fi
    local action
    while true; do
        echo
        echo "Блокировка идёт в ядре без отдельного процесса - управлять можно только"
        echo "вспомогательными юнитами:"
        echo "  1) Обновить список IP сейчас (запустить $SYNC_UNIT)"
        echo "  2) Перезапустить демон detections.log и уведомлений ($NOTIFY_UNIT)"
        echo "  3) Статус обоих юнитов"
        echo "  0) Назад"
        read -rp "> " action || return
        case "$action" in
            1) confirm "Обновить список IP сейчас?" && systemctl start "$SYNC_UNIT" && ok "Запущено" ;;
            2) confirm "Перезапустить $NOTIFY_UNIT?" \
                && { systemctl restart "$NOTIFY_UNIT" 2>/dev/null && ok "Перезапущен" \
                    || warn "Юнит $NOTIFY_UNIT не установлен (текущий режим действия - 'block'?)"; } ;;
            3)
                systemctl status "${SYNC_UNIT}.timer" --no-pager -l | head -n 10
                systemctl status "$NOTIFY_UNIT" --no-pager -l 2>/dev/null | head -n 10
                ;;
            0) return ;;
            *) warn "Неизвестное действие" ;;
        esac
    done
}

# ---------------------------------------------------------------------------
# Настройки обнаружения: список IP / режим действия
# ---------------------------------------------------------------------------
# Единый конфиг: config.yaml читают и пишут оба варианта. Bash-часть работает
# через service/lib-config.sh (awk, без Python).
_conf_lib() {
    # shellcheck source=/dev/null
    source "$INSTALL_DIR/service/lib-config.sh"
}

# Старые имена ключей (service.conf) и короткие имена -> путь секция.ключ в config.yaml
_conf_path() {
    case "$1" in
        ACTION_MODE|mode) echo "action.mode" ;;
        ACTIVE_LIST|active_list) echo "sources.active_list" ;;
        UPDATE_INTERVAL_DAYS) echo "sources.update_interval_days" ;;
        PRIMARY_LIST_URL) echo "sources.primary_list_url" ;;
        BLACKLIST_URL) echo "sources.blacklist_url" ;;
        *) echo "$1" ;;
    esac
}

# Записывает значение, УЖЕ оформленное как YAML ("строка" в кавычках, число, [список])
_set_yaml_scalar() {
    local file="$1" key="$2" value="$3"
    _conf_lib
    yaml_set "$file" "$(_conf_path "$key")" "$value" raw
}

# Записывает обычную строку (кавычки добавляются сами)
_service_conf_set() {
    _conf_lib
    yaml_set "$SERVICE_CONF" "$(_conf_path "$1")" "$2"
}

_service_conf_get() {
    [ -f "$SERVICE_CONF" ] || return 1
    _conf_lib
    yaml_get "$SERVICE_CONF" "$(_conf_path "$1")"
}

# Раньше у варианта «только сервис» был отдельный service.conf (bash KEY="value").
# Теперь конфиг один - переносим значения в config.yaml и откладываем старый файл.
_migrate_legacy_service_conf() {
    local old="$INSTALL_DIR/service.conf"
    [ -f "$old" ] || return 0
    [ -f "$INSTALL_DIR/service/lib-config.sh" ] || return 0
    if [ -f "$SERVICE_CONF" ]; then
        warn "Найдены и service.conf, и config.yaml - оставляю config.yaml, старый файл" \
             "переименован в service.conf.migrated."
        mv "$old" "$old.migrated"
        return 0
    fi
    cp "$INSTALL_DIR/config.example.yaml" "$SERVICE_CONF" || return 1
    chmod 600 "$SERVICE_CONF"
    _conf_lib
    (
        # shellcheck source=/dev/null
        source "$old" 2>/dev/null
        [ -n "${ACTION_MODE:-}" ]            && yaml_set "$SERVICE_CONF" action.mode "$ACTION_MODE"
        [ -n "${ACTIVE_LIST:-}" ]            && yaml_set "$SERVICE_CONF" sources.active_list "$ACTIVE_LIST"
        [ -n "${PRIMARY_LIST_URL:-}" ]       && yaml_set "$SERVICE_CONF" sources.primary_list_url "$PRIMARY_LIST_URL"
        [ -n "${UPDATE_INTERVAL_DAYS:-}" ]   && yaml_set "$SERVICE_CONF" sources.update_interval_days "$UPDATE_INTERVAL_DAYS" raw
        [ -n "${LOG_DIR:-}" ]                && yaml_set "$SERVICE_CONF" logging.log_dir "$LOG_DIR"
        [ -n "${KERNEL_LOG_PREFIX:-}" ]      && yaml_set "$SERVICE_CONF" monitoring.kernel_log_prefix "$KERNEL_LOG_PREFIX"
        [ -n "${ALERT_COOLDOWN_MINUTES:-}" ] && yaml_set "$SERVICE_CONF" monitoring.alert_cooldown_minutes "$ALERT_COOLDOWN_MINUTES" raw
        # BLACKLIST_URL мог быть пустым намеренно (источник отключён) - переносим как есть
        yaml_set "$SERVICE_CONF" sources.blacklist_url "${BLACKLIST_URL-}"
        if [ -n "${IGNORE_IPS:-}" ]; then
            local list="" ip
            for ip in $IGNORE_IPS; do list="${list:+$list, }\"$ip\""; done
            yaml_set "$SERVICE_CONF" monitoring.ignore_ips "[$list]" raw
        fi
    )
    mv "$old" "$old.migrated"
    ok "service.conf перенесён в config.yaml (старый файл сохранён как service.conf.migrated)."
}

detection_settings_menu() {
    local c current_list current_action
    while true; do
        current_list="$(_service_conf_get ACTIVE_LIST || echo '?')"
        current_action="$(_service_conf_get ACTION_MODE || echo '?')"
        echo
        echo "Настройки обнаружения:"
        echo "  1) Источник IP-листов (сейчас: ${current_list:-?})"
        echo "  2) Режим действия (сейчас: ${current_action:-?})"
        echo "  0) Назад"
        read -rp "> " c || return
        case "$c" in
            1) select_active_list ;;
            2) select_action_mode ;;
            0) return ;;
            *) warn "Неизвестный пункт" ;;
        esac
    done
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
    confirm "Переключить источник на '$value' и применить?" || { info "Отменено."; pause; return; }
    _service_conf_set ACTIVE_LIST "$value"
    info "Пересобираю ipset под новый список..."
    bash "$INSTALL_DIR/service/sync-lists.sh" "$SERVICE_CONF"
    ok "sources.active_list -> $value"
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
    confirm "Установить режим '$value' и применить?" || { info "Отменено."; pause; return; }
    _service_conf_set ACTION_MODE "$value"
    info "Применяю новый режим к iptables/ipset..."
    apply_firewall_rules
    _sync_notify_service_state "$value"
    ok "action.mode -> $value"
    pause
}

# Постоянные блокировки варианта с ботом (skipa-dyn без таймаута и бессрочные записи из
# data/blocked_ips.json) - по одному адресу в строке. Нужны, чтобы при переключении на
# 'только сервис' не потерять то, что админ заблокировал бессрочно. Блокировки с таймаутом
# (в том числе автоблокировки) не переносятся: они и так истекли бы сами.
_collect_bot_blocks() {
    if command -v ipset >/dev/null 2>&1; then
        ipset save skipa-dyn 2>/dev/null | awk '$1=="add" && $2=="skipa-dyn" {
            t=0; for (i=4;i<=NF;i++) if ($i=="timeout") t=$(i+1)
            if (t+0==0) print $3 }'
    fi
    local f="$INSTALL_DIR/data/blocked_ips.json"
    [ -f "$f" ] && grep -E '^[[:space:]]*"[0-9a-fA-F.:/]+"[[:space:]]*:[[:space:]]*0(\.0+)?,?[[:space:]]*$' "$f" \
        | sed -E 's/^[[:space:]]*"([^"]+)".*/\1/'
}

# Убирает только то, что ставил python-вариант: переходы в SKIPA-BLOCK, саму цепочку и
# наборы skipa-dyn/skipa-db. Правила и наборы 'только сервис' (skipa-scanners/-manual/-allow)
# не трогает - именно поэтому нельзя использовать _remove_firewall_rules.
_remove_bot_firewall_rules() {
    command -v iptables >/dev/null 2>&1 || return 0
    local chain n
    for chain in INPUT DOCKER-USER KUBE-EXTERNAL-SERVICES KUBE-NODEPORTS; do
        iptables -w 5 -L "$chain" -n >/dev/null 2>&1 || continue
        n=0
        while iptables -w 5 -C "$chain" -j SKIPA-BLOCK 2>/dev/null && [ "$n" -lt 20 ]; do
            iptables -w 5 -D "$chain" -j SKIPA-BLOCK 2>/dev/null || break
            n=$((n + 1))
        done
    done
    if iptables -w 5 -L SKIPA-BLOCK -n >/dev/null 2>&1; then
        iptables -w 5 -F SKIPA-BLOCK 2>/dev/null
        iptables -w 5 -X SKIPA-BLOCK 2>/dev/null
    fi
    if command -v ipset >/dev/null 2>&1; then
        local set
        for set in skipa-dyn skipa-db skipa-db-tmp; do ipset destroy "$set" 2>/dev/null; done
    fi
}

# ---------------------------------------------------------------------------
# Блокировки
# ---------------------------------------------------------------------------
blocklist_menu() {
    # Блокировка полностью автоматическая: сканеры из списка режет ядро, ручной блокировки и
    # разблокировки нет. Единственный ручной рычаг - белый список (пункт 7).
    echo
    echo "Заблокированные IP (только просмотр):"
    bash "$INSTALL_DIR/service/blockctl.sh" list | sed 's/^/  /'
    echo
    echo "Список обновляется по таймеру, ядро режет всё, что в нём есть. Чтобы адрес не"
    echo "блокировался, добавьте его в белый список (пункт 7)."
    pause
}

# Белый список (monitoring.ignore_ips): адреса, которые не блокируются никогда. Те же операции
# есть в blockctl.sh (allow|unallow|allowlist); запись в config.yaml делает confctl.sh.
allowlist_menu() {
    if [ ! -f "$INSTALL_MODE_FILE" ]; then
        err "Сначала установите Skipa Watchdog."; pause; return
    fi
    local c ip
    while true; do
        echo
        echo "Белый список (monitoring.ignore_ips):"
        bash "$INSTALL_DIR/service/confctl.sh" "$SERVICE_CONF" ignore-list | sed 's/^/  /'
        echo "  (текущие SSH-сессии защищаются автоматически: monitoring.auto_allowlist)"
        echo
        echo "  1) Добавить IP или сеть"
        echo "  2) Убрать IP или сеть"
        echo "  0) Назад"
        read -rp "> " c || return
        case "$c" in
            1)
                read -rp "IP или сеть (0 - отмена): " ip
                { [ -z "$ip" ] || [ "$ip" = "0" ]; } && continue
                bash "$INSTALL_DIR/service/blockctl.sh" allow "$ip"            # конфиг + ipset сразу
                ;;
            2)
                read -rp "Что убрать (0 - отмена): " ip
                { [ -z "$ip" ] || [ "$ip" = "0" ]; } && continue
                bash "$INSTALL_DIR/service/blockctl.sh" unallow "$ip"
                ;;
            0) return ;;
            *) warn "Неизвестный пункт" ;;
        esac
    done
}

# Статистика детектов (detections.log есть в обоих вариантах, поэтому один и тот же вывод)
view_stats() {
    if [ ! -f "$INSTALL_MODE_FILE" ]; then
        err "Сначала установите Skipa Watchdog."; pause; return
    fi
    local days
    read -rp "За сколько дней (Enter - 7): " days
    days="${days:-7}"
    [[ "$days" =~ ^[0-9]+$ ]] || { warn "Нужно целое число дней."; pause; return; }
    echo
    bash "$INSTALL_DIR/service/stats.sh" "$SERVICE_CONF" "$days"
    pause
}

# ---------------------------------------------------------------------------
# Прочее: логи, конфиг, обновление базы, обновление проекта
# ---------------------------------------------------------------------------
view_logs() {
    local c
    while true; do
        echo
        echo "Какие логи посмотреть?"
        echo "  1) journalctl (sync-lists + уведомления, последние 50 строк)"
        echo "  2) $LOG_DIR/detections.log (последние 30 строк)"
        echo "  3) $LOG_DIR/skipa-watchdog.log (последние 30 строк)"
        echo "  0) Назад"
        read -rp "> " c || return
        case "$c" in
            1) journalctl -u "$SYNC_UNIT" -u "$NOTIFY_UNIT" -n 50 --no-pager ;;
            2) tail -n 30 "$LOG_DIR/detections.log" 2>/dev/null || warn "Файл не найден" ;;
            3) tail -n 30 "$LOG_DIR/skipa-watchdog.log" 2>/dev/null || warn "Файл не найден" ;;
            0) return ;;
            *) warn "Неизвестный пункт" ;;
        esac
    done
}

force_update_db() {
    if [ ! -f "$INSTALL_MODE_FILE" ]; then
        err "Skipa Watchdog не установлен - нечем обновлять базу."
        pause
        return
    fi
    confirm "Принудительно обновить базу IP-адресов сейчас?" || { info "Отменено."; pause; return; }
    info "Обновляю базу IP-адресов..."
    bash "$INSTALL_DIR/service/sync-lists.sh" "$SERVICE_CONF"
    pause
}

edit_config() {
    if [ ! -f "$INSTALL_MODE_FILE" ]; then
        err "Файл не найден."
        pause
        return
    fi
    confirm "Открыть $SERVICE_CONF в редакторе (${EDITOR:-nano})?" || { info "Отменено."; return; }
    "${EDITOR:-nano}" "$SERVICE_CONF"
    _secure_config
    if confirm "Применить изменения (пересобрать ipset и правила iptables, перезапустить уведомления)?"; then
        bash "$INSTALL_DIR/service/sync-lists.sh" "$SERVICE_CONF"
        apply_firewall_rules
        _sync_notify_service_state "$(_service_conf_get ACTION_MODE)"
    fi
    pause
}

update_project() {
    confirm "Обновить Skipa Watchdog (git pull) и перезапустить уведомления?" || { info "Отменено."; return; }
    info "Обновляю Skipa Watchdog (git pull)..."
    do_install
    pause
}

# При КАЖДОМ запуске меню: проверяем, не вышла ли новая версия проекта, и предлагаем
# установить. Отказ не навсегда: напоминание остаётся в шапке меню и повторится при
# следующем запуске. После успешного обновления панель перезапускается из новой версии.
# lib-update.sh лежит в самом репозитории; в очень старой установке его ещё нет -
# тогда проверка появится сразу после первого обновления.
_load_update_lib() {
    [ -f "$INSTALL_DIR/service/lib-update.sh" ] || return 1
    # shellcheck source=service/lib-update.sh
    source "$INSTALL_DIR/service/lib-update.sh"
}

offer_project_update() {
    _load_update_lib || return 0
    update_check "$INSTALL_DIR"
    [ "$UPD_STATE" = "available" ] || return 0
    echo
    warn "Доступна новая версия Skipa Watchdog: ${UPD_LOCAL:-?} -> ${UPD_REMOTE:-?} (новых коммитов: $UPD_BEHIND)"
    [ -n "$UPD_LOG" ] && printf '%s\n' "$UPD_LOG"
    if confirm "Установить обновление сейчас?"; then
        if do_install; then
            ok "Обновление установлено."
            if [ "${SKIPA_SOURCE_ONLY:-0}" != "1" ]; then
                SKIPA_NO_UPDATE_CHECK=1 exec bash "$INSTALL_DIR/install.sh"   # меню уже из новой версии
            fi
        else
            warn "Обновление не завершилось, продолжаю с текущей версией."
            UPD_STATE=available
        fi
    else
        info "Хорошо, напомню при следующем запуске (или пункт 12 меню)."
    fi
}

# ---------------------------------------------------------------------------
# Меню
# ---------------------------------------------------------------------------
firewall_menu() {
    local c chain
    while true; do
        echo
        echo "Docker/Kubernetes (логирование + блокировка):"
        echo "  1) Применить/обновить правила сейчас"
        echo "  2) Показать текущие правила проекта"
        echo "  0) Назад"
        read -rp "> " c || return
        case "$c" in
            1)
                if confirm "Применить правила iptables/ipset (INPUT, DOCKER-USER, KUBE-*)?"; then
                    apply_firewall_rules
                fi
                pause
                ;;
            2)
                for chain in INPUT DOCKER-USER KUBE-EXTERNAL-SERVICES KUBE-NODEPORTS SKIPA-BLOCK; do
                    iptables -w 5 -L "$chain" -n >/dev/null 2>&1 || continue
                    echo "--- $chain"
                    iptables -w 5 -S "$chain" | grep -E 'SKIPA-BLOCK|skipa-|CONN' | sed 's/^/  /'
                done
                pause
                ;;
            0) return ;;
            *) warn "Неизвестный пункт" ;;
        esac
    done
}

# ---------------------------------------------------------------------------
# Уведомления: Telegram и Matrix (только отправка, service/lib-notify.sh)
# ---------------------------------------------------------------------------
_notify_lib() {
    _conf_lib
    # shellcheck source=/dev/null
    source "$INSTALL_DIR/service/lib-notify.sh"
    # shellcheck disable=SC2034  # STATE_DIR читает load_notify_config (lib-notify.sh)
    STATE_DIR="${SKIPA_STATE_DIR:-/var/lib/skipa_watchdog}"
    load_service_config "$SERVICE_CONF"
    load_notify_config "$SERVICE_CONF"
}

_notify_status() {
    [ -f "$INSTALL_DIR/service/lib-notify.sh" ] && [ -f "$SERVICE_CONF" ] || return 0
    (
        _notify_lib
        local ch chans=""
        for ch in $(notify_channels); do chans="${chans:+$chans, }$ch"; done
        echo "   Уведомления: ${chans:-не настроены (это нормально: работают локальные логи)}"
        if [ -n "$chans" ] && [ "${ACTION_MODE:-}" = "block" ]; then
            warn "Режим действия 'block': демон уведомлений не запущен, сообщения не будут уходить (пункт 3)."
        fi
        [ "$(notify_spool_size)" -gt 0 ] 2>/dev/null \
            && warn "В очереди неотправленных сообщений: $(notify_spool_size) (нет связи или неверный токен - см. skipa-watchdog.log)"
    )
}

# После смены каналов: уведомления работают только при action.mode с notify, процесс читает конфиг при старте
_after_notify_change() {
    local mode
    mode="$(_service_conf_get ACTION_MODE)"
    if [ "$mode" = "block" ]; then
        if confirm "Сейчас режим действия 'block' - уведомления не отправляются. Включить 'block_notify' (блокировать и уведомлять)?"; then
            _service_conf_set ACTION_MODE block_notify
            mode="block_notify"
        fi
    fi
    _secure_config
    _sync_notify_service_state "$mode"
    if confirm "Отправить тестовое сообщение?"; then
        (_notify_lib; notify_test)
    fi
}

configure_telegram() {
    local token chat
    echo
    echo "Настройка Telegram (на любой вопрос можно ответить 0 - отмена)."
    echo "Нужен бот от @BotFather и chat_id (личный чат, группа или канал, куда бот добавлен)."
    read -rsp "Токен бота: " token; echo
    [ "$token" = "0" ] && { info "Отменено."; return; }
    read -rp "chat_id: " chat
    [ "$chat" = "0" ] && { info "Отменено."; return; }
    _notify_lib
    notify_validate_telegram "$token" "$chat" || { err "Ничего не сохранил."; return; }
    yaml_set "$SERVICE_CONF" telegram.bot_token "\"$token\"" raw
    yaml_set "$SERVICE_CONF" telegram.chat_id "$chat" raw
    ok "Telegram сохранён."
    _after_notify_change
}

configure_matrix() {
    local hs token room
    echo
    echo "Настройка Matrix (на любой вопрос можно ответить 0 - отмена)."
    echo "Нужны: адрес homeserver, access token пользователя (или бота) и ID комнаты (!abc:example.org),"
    echo "в которой этот пользователь состоит. Token можно взять в Element: Настройки -> Помощь и о программе."
    read -rp "homeserver (https://matrix.example.org): " hs
    [ "$hs" = "0" ] && { info "Отменено."; return; }
    read -rsp "access_token: " token; echo
    [ "$token" = "0" ] && { info "Отменено."; return; }
    read -rp "room_id (!abc:example.org): " room
    [ "$room" = "0" ] && { info "Отменено."; return; }
    _notify_lib
    hs="${hs%/}"
    notify_validate_matrix "$hs" "$token" "$room" || { err "Ничего не сохранил."; return; }
    yaml_set "$SERVICE_CONF" matrix.homeserver "\"$hs\"" raw
    yaml_set "$SERVICE_CONF" matrix.access_token "\"$token\"" raw
    yaml_set "$SERVICE_CONF" matrix.room_id "\"$room\"" raw
    ok "Matrix сохранён."
    _after_notify_change
}

disable_channel() {
    case "$1" in
        telegram)
            yaml_set "$SERVICE_CONF" telegram.bot_token '""' raw
            yaml_set "$SERVICE_CONF" telegram.chat_id 0 raw ;;
        matrix)
            yaml_set "$SERVICE_CONF" matrix.access_token '""' raw ;;
    esac
    _sync_notify_service_state
    ok "Канал $1 отключён."
}

notifications_menu() {
    if [ ! -f "$INSTALL_MODE_FILE" ]; then
        warn "Сначала установите Skipa Watchdog."; pause; return
    fi
    local c
    _conf_lib
    while true; do
        echo
        _notify_status
        echo
        echo "Уведомления (только отправка сообщений; управление - через это меню):"
        echo "  1) Настроить Telegram"
        echo "  2) Настроить Matrix"
        echo "  3) Отправить тестовое сообщение"
        echo "  4) Отключить Telegram"
        echo "  5) Отключить Matrix"
        echo "  0) Назад"
        read -rp "> " c || return
        case "$c" in
            1) configure_telegram; pause ;;
            2) configure_matrix; pause ;;
            3) (_notify_lib; notify_test); pause ;;
            4) confirm "Отключить Telegram (токен будет удалён из config.yaml)?" && disable_channel telegram; pause ;;
            5) confirm "Отключить Matrix (access_token будет удалён из config.yaml)?" && disable_channel matrix; pause ;;
            0) return ;;
            *) warn "Неизвестный пункт" ;;
        esac
    done
}

main_menu() {
    while true; do
        print_header
        echo " 1) Проверка работоспособности"
        echo " 2) Управление сервисом (обновление списка, уведомления, статус)"
        echo " 3) Настройки обнаружения (список IP / режим действия)"
        echo " 4) Уведомления (Telegram / Matrix)"
        echo " 5) Docker/Kubernetes (логирование + блокировка)"
        echo " 6) Заблокированные IP"
        echo " 7) Белый список (IP, которые не блокируются)"
        echo " 8) Статистика детектов"
        echo " 9) Принудительно обновить базу IP"
        echo "10) Просмотр логов"
        echo "11) Редактировать конфиг вручную"
        echo "12) Обновить Skipa Watchdog"
        echo "13) Удалить полностью"
        echo " 0) Выход"
        read -rp "> " choice || { echo; info "Ввод завершён, выхожу."; exit 0; }
        case "$choice" in
            1) health_check ;;
            2) manage_service ;;
            3) detection_settings_menu ;;
            4) notifications_menu ;;
            5) firewall_menu ;;
            6) blocklist_menu ;;
            7) allowlist_menu ;;
            8) view_stats ;;
            9) force_update_db ;;
            10) view_logs ;;
            11) edit_config ;;
            12) update_project ;;
            13) do_uninstall; pause ;;
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
            # Firewall-правила (INPUT, + DOCKER-USER/KUBE-* если
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
  sudo bash install.sh check-update проверить, вышла ли новая версия проекта (код 10 - да)
  sudo bash install.sh stats [дней] статистика детектов (как пункт 8 меню)
  sudo bash install.sh test-notify  отправить тестовое сообщение в Telegram/Matrix
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
            stats) bash "$INSTALL_DIR/service/stats.sh" "$SERVICE_CONF" "${2:-7}" ;;
            test-notify) (_notify_lib; notify_test) ;;
            check-update)
                # неинтерактивно: код возврата 0 - актуальная версия, 10 - есть обновление, 2 - не удалось проверить
                _load_update_lib || { echo "Проверка обновлений недоступна: нет $INSTALL_DIR/service/lib-update.sh"; exit 2; }
                update_check "$INSTALL_DIR"
                case "$UPD_STATE" in
                    available) echo "Доступно обновление: ${UPD_LOCAL:-?} -> ${UPD_REMOTE:-?} (коммитов: $UPD_BEHIND)"
                               [ -n "$UPD_LOG" ] && printf '%s\n' "$UPD_LOG"; exit 10 ;;
                    none) echo "Установлена актуальная версия ${UPD_LOCAL:-?}"; exit 0 ;;
                    *) echo "Не удалось проверить обновления (нет git-клона, сети или upstream)"; exit 2 ;;
                esac ;;
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
    _migrate_legacy_service_conf
    offer_project_update
    check_list_updates
    main_menu
}

# SKIPA_SOURCE_ONLY=1 - только подключить функции (для тестов), меню не запускать
[ "${SKIPA_SOURCE_ONLY:-0}" = "1" ] || main "$@"
