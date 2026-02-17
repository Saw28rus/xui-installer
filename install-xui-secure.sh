#!/usr/bin/env bash
#
# install-xui-secure.sh — Автоматическая установка 3x-ui + Fail2ban + Geo-правила
# Автор: VPN Admin Script
# Версия: 3.0.0
# Совместимость: Ubuntu 22.04 / 24.04, Debian 11 / 12
#
# Использование:
#   bash install-xui-secure.sh                             # Интерактивная установка
#   bash install-xui-secure.sh --server-type ru            # Российский сервер
#   bash install-xui-secure.sh --server-type foreign       # Зарубежный сервер
#   bash install-xui-secure.sh --whitelist-ip 1.2.3.4     # С указанием IP
#   bash install-xui-secure.sh --uninstall                 # Удаление
#

set -euo pipefail
IFS=$'\n\t'

# ─── Константы ──────────────────────────────────────────────────────────────────
readonly SCRIPT_VERSION="3.0.0"
readonly SCRIPT_NAME="$(basename "$0")"
readonly LOG_FILE="/var/log/xui-install.log"
readonly BACKUP_DIR="/root/.xui-install-backup"
readonly F2B_JAIL_DIR="/etc/fail2ban/jail.d"
readonly F2B_FILTER_DIR="/etc/fail2ban/filter.d"
readonly XUI_BIN="/usr/local/x-ui"
readonly XUI_CONFIG="$XUI_BIN/bin/config.json"
readonly MIN_RAM_MB=512
readonly SUPPORTED_OS=("ubuntu" "debian")

# Geo-файлы для России
readonly GEOIP_RU_URL="https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geoip.dat"
readonly GEOSITE_RU_URL="https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geosite.dat"

# ─── Цвета ──────────────────────────────────────────────────────────────────────
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly BOLD='\033[1m'
readonly DIM='\033[2m'
readonly NC='\033[0m'

# ─── Глобальные переменные ──────────────────────────────────────────────────────
SERVER_IP=""
CLIENT_IP=""
USER_IP=""
PANEL_PORT=""
PANEL_WEBBASEPATH=""
PANEL_USERNAME=""
PANEL_PASSWORD=""
CUSTOM_USERNAME=""
CUSTOM_PASSWORD=""
WHITELIST_IPS=""
SERVER_TYPE=""          # "ru" или "foreign"
SKIP_F2B=false
UNINSTALL=false

# Флаги уже установленных компонентов
XUI_INSTALLED=false
F2B_INSTALLED=false
F2B_XUI_CONFIGURED=false

# ─── Логирование ────────────────────────────────────────────────────────────────
log() {
    local level="$1"; shift
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    echo "[$timestamp] [$level] $*" >> "$LOG_FILE" 2>/dev/null || true
}

info()    { log "INFO"  "$*"; echo -e "${GREEN}  ✔ ${NC}$*"; }
warn()    { log "WARN"  "$*"; echo -e "${YELLOW}  ⚠ ${NC}$*"; }
error()   { log "ERROR" "$*"; echo -e "${RED}  ✖ ${NC}$*"; }
step()    { log "STEP"  "$*"; echo -e "\n${BLUE}  ▶ ${BOLD}$*${NC}"; }
detail()  { echo -e "${DIM}    $*${NC}"; }

die() {
    error "$*"
    error "Подробности в логе: $LOG_FILE"
    exit 1
}

# ─── Баннер ─────────────────────────────────────────────────────────────────────
show_banner() {
    echo -e "${CYAN}"
    cat << 'BANNER'
    ╔═══════════════════════════════════════════════════╗
    ║         3x-ui Panel + Server Protection           ║
    ║         Automated Installer v3.0.0                ║
    ╚═══════════════════════════════════════════════════╝
BANNER
    echo -e "${DIM}    Версия: ${SCRIPT_VERSION}${NC}"
    echo ""
}

# ─── Парсинг аргументов ─────────────────────────────────────────────────────────
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --server-type)
                SERVER_TYPE="$2"
                if [[ "$SERVER_TYPE" != "ru" && "$SERVER_TYPE" != "foreign" ]]; then
                    die "Неверный тип сервера: $SERVER_TYPE. Допустимые: ru, foreign"
                fi
                shift 2
                ;;
            --server-type=*)
                SERVER_TYPE="${1#*=}"
                if [[ "$SERVER_TYPE" != "ru" && "$SERVER_TYPE" != "foreign" ]]; then
                    die "Неверный тип сервера: $SERVER_TYPE. Допустимые: ru, foreign"
                fi
                shift
                ;;
            --whitelist-ip)
                USER_IP="$2"
                shift 2
                ;;
            --skip-fail2ban)
                SKIP_F2B=true
                shift
                ;;
            --uninstall)
                UNINSTALL=true
                shift
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            *)
                die "Неизвестный аргумент: $1. Используйте --help для справки"
                ;;
        esac
    done
}

show_help() {
    cat << EOF
Использование: $SCRIPT_NAME [ОПЦИИ]

Автоматическая установка панели 3x-ui с защитой Fail2ban,
умной маршрутизацией и поддержкой каскадного VPN.

Опции:
  --server-type TYPE   Тип сервера: ru (российский) или foreign (зарубежный)
  --whitelist-ip IP    Добавить IP в whitelist fail2ban (исключить из блокировки)
  --skip-fail2ban      Пропустить установку fail2ban
  --uninstall          Удалить 3x-ui и fail2ban
  --help, -h           Показать эту справку

Примеры:
  $SCRIPT_NAME                                  # Интерактивная установка
  $SCRIPT_NAME --server-type ru                 # Российский сервер
  $SCRIPT_NAME --server-type foreign            # Зарубежный сервер
  $SCRIPT_NAME --whitelist-ip 1.2.3.4           # С указанием IP
  $SCRIPT_NAME --uninstall                      # Удаление

Различия типов серверов:
  ru       — Устанавливает российские geo-файлы (geosite:ru, geoip:ru),
             настраивает маршрутизацию: РУ-сайты → напрямую, остальные → VPN
  foreign  — Стандартная установка без geo-правил (зарубежный выходной сервер)
EOF
}

# ─── Предварительные проверки ────────────────────────────────────────────────────
preflight_checks() {
    step "Предварительные проверки"

    # Проверка root
    if [[ "$EUID" -ne 0 ]]; then
        die "Скрипт должен быть запущен от root. Используйте: sudo $SCRIPT_NAME"
    fi
    info "Запущен от root"

    # Проверка ОС
    local os_id
    os_id=$(grep -oP '(?<=^ID=).+' /etc/os-release 2>/dev/null | tr -d '"' || echo "unknown")
    local os_ok=false
    for supported in "${SUPPORTED_OS[@]}"; do
        [[ "$os_id" == "$supported" ]] && os_ok=true && break
    done
    if ! $os_ok; then
        die "Неподдерживаемая ОС: $os_id. Поддерживаются: ${SUPPORTED_OS[*]}"
    fi
    local os_version
    os_version=$(grep -oP '(?<=^VERSION_ID=).+' /etc/os-release 2>/dev/null | tr -d '"' || echo "?")
    info "ОС: $os_id $os_version"

    # Проверка архитектуры
    local arch
    arch=$(uname -m)
    if [[ "$arch" != "x86_64" && "$arch" != "aarch64" ]]; then
        die "Неподдерживаемая архитектура: $arch"
    fi
    info "Архитектура: $arch"

    # Проверка оперативной памяти
    local total_ram_mb
    total_ram_mb=$(awk '/MemTotal/ {printf "%.0f", $2/1024}' /proc/meminfo)
    if [[ "$total_ram_mb" -lt "$MIN_RAM_MB" ]]; then
        warn "Мало ОЗУ: ${total_ram_mb}MB (рекомендуется ${MIN_RAM_MB}MB+)"
    else
        info "ОЗУ: ${total_ram_mb}MB"
    fi

    # Проверка свободного места
    local free_disk_mb
    free_disk_mb=$(df -m / | awk 'NR==2 {print $4}')
    if [[ "$free_disk_mb" -lt 1024 ]]; then
        warn "Мало свободного места: ${free_disk_mb}MB (рекомендуется 1GB+)"
    else
        info "Свободное место: ${free_disk_mb}MB"
    fi

    # Проверка интернета
    if ! curl -s --max-time 5 -o /dev/null https://github.com; then
        die "Нет доступа к интернету (github.com недоступен)"
    fi
    info "Интернет доступен"
}

# ─── Проверка уже установленных компонентов ──────────────────────────────────────
check_existing_installations() {
    step "Проверка установленных компонентов"

    # Проверка 3x-ui
    if systemctl is-active --quiet x-ui 2>/dev/null; then
        XUI_INSTALLED=true
        info "3x-ui: установлен и запущен"
    elif [[ -f "$XUI_BIN/x-ui" ]]; then
        XUI_INSTALLED=true
        warn "3x-ui: установлен, но не запущен"
    else
        info "3x-ui: не установлен"
    fi

    # Проверка Fail2ban
    if command -v fail2ban-client &>/dev/null; then
        F2B_INSTALLED=true
        if systemctl is-active --quiet fail2ban 2>/dev/null; then
            info "Fail2ban: установлен и запущен"
            local jails
            jails=$(fail2ban-client status 2>/dev/null | grep "Jail list" | sed 's/.*://;s/,/ /g' || true)
            detail "Активные jail: ${jails:-нет}"
        else
            warn "Fail2ban: установлен, но не запущен"
        fi
    else
        info "Fail2ban: не установлен"
    fi

    # Проверка конфигурации Fail2ban для x-ui
    if [[ -f "$F2B_JAIL_DIR/x-ui.conf" ]] && [[ -f "$F2B_FILTER_DIR/x-ui.conf" ]]; then
        F2B_XUI_CONFIGURED=true
        info "Fail2ban для x-ui: настроен"
        local current_whitelist
        current_whitelist=$(grep -oP 'ignoreip\s*=\s*\K.*' "$F2B_JAIL_DIR/x-ui.conf" 2>/dev/null || true)
        if [[ -n "$current_whitelist" ]]; then
            detail "Текущий whitelist: $current_whitelist"
        fi
    else
        info "Fail2ban для x-ui: не настроен"
    fi

    # Итог: что нужно установить
    echo ""
    if $XUI_INSTALLED && $F2B_INSTALLED && $F2B_XUI_CONFIGURED; then
        echo -e "  ${GREEN}${BOLD}Все компоненты уже установлены и настроены!${NC}"
        echo ""
        echo -e "  ${YELLOW}Выберите действие:${NC}"
        echo -e "    ${BOLD}1${NC} — Переустановить всё с нуля"
        echo -e "    ${BOLD}2${NC} — Обновить только настройки Fail2ban (whitelist)"
        echo -e "    ${BOLD}3${NC} — Обновить geo-правила маршрутизации (только для RU)"
        echo -e "    ${BOLD}4${NC} — Изменить логин/пароль панели"
        echo -e "    ${BOLD}5${NC} — Выйти, ничего не менять"
        echo ""
        local choice
        read -rp "    Ваш выбор [1/2/3/4/5]: " choice
        case "$choice" in
            1)
                info "Будет выполнена полная переустановка"
                XUI_INSTALLED=false
                F2B_INSTALLED=false
                F2B_XUI_CONFIGURED=false
                ;;
            2)
                info "Будут обновлены только настройки Fail2ban"
                ;;
            3)
                info "Будут обновлены geo-правила"
                SERVER_TYPE="ru"
                detect_server_ip
                install_geo_rules
                configure_routing_rules
                info "Geo-правила обновлены. Перезапуск панели..."
                systemctl restart x-ui
                exit 0
                ;;
            4)
                info "Смена учётных данных панели"
                ask_custom_credentials
                apply_custom_credentials
                echo ""
                echo -e "  ${GREEN}${BOLD}Учётные данные обновлены!${NC}"
                echo -e "  Username: ${GREEN}${PANEL_USERNAME}${NC}"
                echo -e "  Password: ${GREEN}${PANEL_PASSWORD}${NC}"
                exit 0
                ;;
            5)
                info "Выход без изменений"
                exit 0
                ;;
            *)
                die "Неверный выбор"
                ;;
        esac
    elif $XUI_INSTALLED && ! $F2B_XUI_CONFIGURED; then
        info "3x-ui уже установлен — будет настроена только защита Fail2ban"
    elif $XUI_INSTALLED && $F2B_XUI_CONFIGURED; then
        echo -e "  ${GREEN}Всё установлено. Обновить настройки Fail2ban? [y/N]${NC}"
        local update_f2b
        read -rp "    " update_f2b
        if [[ "${update_f2b,,}" != "y" ]]; then
            info "Выход без изменений"
            exit 0
        fi
    fi
}

# ─── Выбор типа сервера ──────────────────────────────────────────────────────────
ask_server_type() {
    # Если тип уже задан через аргумент — пропускаем
    if [[ -n "$SERVER_TYPE" ]]; then
        info "Тип сервера (из аргумента): $SERVER_TYPE"
        return 0
    fi

    step "Выбор типа сервера"

    echo ""
    echo -e "  ${CYAN}┌─────────────────────────────────────────────────────────┐${NC}"
    echo -e "  ${CYAN}│${NC}  ${BOLD}Какой это сервер?${NC}                                     ${CYAN}│${NC}"
    echo -e "  ${CYAN}│${NC}                                                         ${CYAN}│${NC}"
    echo -e "  ${CYAN}│${NC}  ${GREEN}1${NC} — ${BOLD}Российский сервер (RU)${NC}                            ${CYAN}│${NC}"
    echo -e "  ${CYAN}│${NC}      • Geo-правила: РУ-сайты → напрямую                 ${CYAN}│${NC}"
    echo -e "  ${CYAN}│${NC}      • Зарубежные → через VPN (каскад)                  ${CYAN}│${NC}"
    echo -e "  ${CYAN}│${NC}      • Блокировка рекламы                               ${CYAN}│${NC}"
    echo -e "  ${CYAN}│${NC}      • Российские geo-файлы (runetfreedom)              ${CYAN}│${NC}"
    echo -e "  ${CYAN}│${NC}                                                         ${CYAN}│${NC}"
    echo -e "  ${CYAN}│${NC}  ${BLUE}2${NC} — ${BOLD}Зарубежный сервер (Foreign)${NC}                       ${CYAN}│${NC}"
    echo -e "  ${CYAN}│${NC}      • Стандартная установка                             ${CYAN}│${NC}"
    echo -e "  ${CYAN}│${NC}      • Блокировка приватных IP                           ${CYAN}│${NC}"
    echo -e "  ${CYAN}│${NC}      • Выходной сервер каскада                           ${CYAN}│${NC}"
    echo -e "  ${CYAN}└─────────────────────────────────────────────────────────┘${NC}"
    echo ""

    local choice
    read -rp "    Ваш выбор [1/2]: " choice

    case "$choice" in
        1)
            SERVER_TYPE="ru"
            info "Тип сервера: Российский (с geo-правилами)"
            ;;
        2)
            SERVER_TYPE="foreign"
            info "Тип сервера: Зарубежный (стандартная установка)"
            ;;
        *)
            die "Неверный выбор. Укажите 1 или 2"
            ;;
    esac
}

# ─── Получение IP сервера ────────────────────────────────────────────────────────
detect_server_ip() {
    step "Определение IP сервера"

    local ip_services=(
        "https://ifconfig.me"
        "https://ipinfo.io/ip"
        "https://icanhazip.com"
        "https://api.ipify.org"
    )

    for service in "${ip_services[@]}"; do
        SERVER_IP=$(curl -s --max-time 5 "$service" 2>/dev/null | tr -d '[:space:]')
        if [[ "$SERVER_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            info "IP сервера: $SERVER_IP"
            return 0
        fi
    done

    warn "Не удалось определить IP автоматически"
    while true; do
        read -rp "    Введите IP сервера вручную: " SERVER_IP
        if [[ "$SERVER_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            info "IP сервера: $SERVER_IP"
            return 0
        fi
        error "Неверный формат IP. Пример: 192.168.1.1"
    done
}

# ─── Определение IP клиента ──────────────────────────────────────────────────────
detect_client_ip() {
    step "Определение IP клиента (вашего подключения)"

    CLIENT_IP=""

    # Метод 1: через переменную SSH_CLIENT
    if [[ -n "${SSH_CLIENT:-}" ]]; then
        CLIENT_IP=$(echo "$SSH_CLIENT" | awk '{print $1}')
    fi

    # Метод 2: через переменную SSH_CONNECTION
    if [[ -z "$CLIENT_IP" ]] && [[ -n "${SSH_CONNECTION:-}" ]]; then
        CLIENT_IP=$(echo "$SSH_CONNECTION" | awk '{print $1}')
    fi

    # Метод 3: через who
    if [[ -z "$CLIENT_IP" ]]; then
        CLIENT_IP=$(who am i 2>/dev/null | grep -oP '\(\K[0-9.]+' | head -1 || true)
    fi

    # Метод 4: через last
    if [[ -z "$CLIENT_IP" ]]; then
        CLIENT_IP=$(last -i -1 2>/dev/null | head -1 | awk '{print $3}' | grep -oP '^[0-9.]+$' || true)
    fi

    # Метод 5: через ss (активные SSH-соединения)
    if [[ -z "$CLIENT_IP" ]]; then
        CLIENT_IP=$(ss -tnp 2>/dev/null | grep sshd | grep ESTAB | awk '{print $5}' | grep -oP '^[0-9.]+' | head -1 || true)
    fi

    # Валидация найденного IP
    if [[ -n "$CLIENT_IP" ]] && [[ "$CLIENT_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        info "Обнаружен IP вашего подключения: $CLIENT_IP"
    else
        CLIENT_IP=""
        detail "Не удалось определить IP клиента автоматически"
    fi
}

# ─── Запрос IP пользователя ──────────────────────────────────────────────────────
ask_whitelist_ip() {
    # Если IP передан через аргумент, пропускаем вопрос
    if [[ -n "$USER_IP" ]]; then
        info "Whitelist IP (из аргумента): $USER_IP"
        return 0
    fi

    echo ""
    echo -e "  ${YELLOW}┌─────────────────────────────────────────────────────────┐${NC}"
    echo -e "  ${YELLOW}│${NC}  ${BOLD}Настройка whitelist Fail2ban${NC}                            ${YELLOW}│${NC}"
    echo -e "  ${YELLOW}│${NC}                                                         ${YELLOW}│${NC}"
    echo -e "  ${YELLOW}│${NC}  Укажите ваш IP-адрес, чтобы Fail2ban ${GREEN}никогда${NC}           ${YELLOW}│${NC}"
    echo -e "  ${YELLOW}│${NC}  не заблокировал вас при входе в панель управления.     ${YELLOW}│${NC}"
    echo -e "  ${YELLOW}│${NC}                                                         ${YELLOW}│${NC}"
    echo -e "  ${YELLOW}│${NC}  Даже если вы ошибетесь с паролем 100 раз —             ${YELLOW}│${NC}"
    echo -e "  ${YELLOW}│${NC}  ваш IP останется разрешенным.                          ${YELLOW}│${NC}"
    echo -e "  ${YELLOW}│${NC}                                                         ${YELLOW}│${NC}"
    echo -e "  ${YELLOW}│${NC}  ${DIM}Узнать свой IP: https://2ip.ru${NC}                         ${YELLOW}│${NC}"
    echo -e "  ${YELLOW}└─────────────────────────────────────────────────────────┘${NC}"
    echo ""

    # Если удалось определить IP клиента, предложить его
    if [[ -n "$CLIENT_IP" ]]; then
        echo -e "  ${BOLD}Выберите действие:${NC}"
        echo -e "    ${BOLD}1${NC} — Использовать обнаруженный IP: ${GREEN}${CLIENT_IP}${NC}"
        echo -e "    ${BOLD}2${NC} — Ввести другой IP вручную"
        echo -e "    ${BOLD}3${NC} — Пропустить (не добавлять IP в whitelist)"
        echo ""
        local choice
        read -rp "    Ваш выбор [1/2/3] (по умолчанию 1): " choice
        choice="${choice:-1}"

        case "$choice" in
            1)
                USER_IP="$CLIENT_IP"
                info "IP $USER_IP добавлен в whitelist — вы не будете заблокированы Fail2ban"
                ;;
            2)
                while true; do
                    read -rp "    Введите IP для whitelist: " USER_IP
                    if [[ "$USER_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                        info "IP $USER_IP добавлен в whitelist"
                        break
                    fi
                    error "Неверный формат IP. Пример: 192.168.1.1"
                done
                ;;
            3)
                USER_IP=""
                warn "Whitelist IP не указан — только localhost и IP сервера будут исключены"
                ;;
            *)
                USER_IP="$CLIENT_IP"
                info "IP $USER_IP добавлен в whitelist (выбор по умолчанию)"
                ;;
        esac
    else
        # IP клиента не определён — запрашиваем вручную
        read -rp "    Ваш IP для whitelist (Enter — пропустить): " USER_IP

        if [[ -n "$USER_IP" ]]; then
            if [[ "$USER_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                info "IP $USER_IP добавлен в whitelist"
            else
                warn "Некорректный IP: $USER_IP — пропускаем"
                USER_IP=""
            fi
        else
            warn "Whitelist IP не указан — только localhost и IP сервера будут исключены"
        fi
    fi
}

# ─── Запрос учётных данных ───────────────────────────────────────────────────────
ask_custom_credentials() {
    step "Настройка учётных данных панели"

    echo ""
    echo -e "  ${CYAN}┌─────────────────────────────────────────────────────────┐${NC}"
    echo -e "  ${CYAN}│${NC}  ${BOLD}Логин и пароль для входа в панель 3x-ui${NC}               ${CYAN}│${NC}"
    echo -e "  ${CYAN}│${NC}                                                         ${CYAN}│${NC}"
    echo -e "  ${CYAN}│${NC}  При установке панель создаст случайные данные.         ${CYAN}│${NC}"
    echo -e "  ${CYAN}│${NC}  Вы можете указать свои логин и пароль, и они           ${CYAN}│${NC}"
    echo -e "  ${CYAN}│${NC}  будут применены автоматически после установки.          ${CYAN}│${NC}"
    echo -e "  ${CYAN}│${NC}                                                         ${CYAN}│${NC}"
    echo -e "  ${CYAN}│${NC}  ${YELLOW}Рекомендации:${NC}                                         ${CYAN}│${NC}"
    echo -e "  ${CYAN}│${NC}  • Логин: минимум 5 символов, латиница/цифры            ${CYAN}│${NC}"
    echo -e "  ${CYAN}│${NC}  • Пароль: минимум 8 символов, буквы + цифры            ${CYAN}│${NC}"
    echo -e "  ${CYAN}│${NC}  • Не используйте: admin, password, 123456              ${CYAN}│${NC}"
    echo -e "  ${CYAN}└─────────────────────────────────────────────────────────┘${NC}"
    echo ""

    echo -e "  ${BOLD}Хотите задать свои логин и пароль?${NC}"
    echo -e "    ${GREEN}1${NC} — Да, указать свои"
    echo -e "    ${DIM}2${NC} — Нет, оставить случайные (будут показаны в отчёте)"
    echo ""
    local cred_choice
    read -rp "    Ваш выбор [1/2] (по умолчанию 1): " cred_choice
    cred_choice="${cred_choice:-1}"

    if [[ "$cred_choice" == "1" ]]; then
        # Запрос логина
        while true; do
            read -rp "    Введите логин (мин. 5 символов): " CUSTOM_USERNAME
            if [[ ${#CUSTOM_USERNAME} -ge 5 ]] && [[ "$CUSTOM_USERNAME" =~ ^[a-zA-Z0-9_.-]+$ ]]; then
                break
            else
                echo -e "    ${RED}✖ Логин: минимум 5 символов, допустимы: латиница, цифры, _ . -${NC}"
            fi
        done

        # Запрос пароля
        while true; do
            read -srp "    Введите пароль (мин. 8 символов): " CUSTOM_PASSWORD
            echo ""
            if [[ ${#CUSTOM_PASSWORD} -lt 8 ]]; then
                echo -e "    ${RED}✖ Пароль должен быть минимум 8 символов${NC}"
                continue
            fi
            local pass_confirm
            read -srp "    Повторите пароль: " pass_confirm
            echo ""
            if [[ "$CUSTOM_PASSWORD" == "$pass_confirm" ]]; then
                break
            else
                echo -e "    ${RED}✖ Пароли не совпадают, попробуйте снова${NC}"
            fi
        done

        info "Пользовательские учётные данные будут применены после установки"
        log "INFO" "Пользователь задал кастомные учётные данные (username: $CUSTOM_USERNAME)"
    else
        CUSTOM_USERNAME=""
        CUSTOM_PASSWORD=""
        info "Будут использованы случайные данные (показаны в финальном отчёте)"
        log "INFO" "Пользователь выбрал случайные учётные данные"
    fi
}

# ─── Применение кастомных учётных данных ─────────────────────────────────────────
apply_custom_credentials() {
    if [[ -n "$CUSTOM_USERNAME" ]] && [[ -n "$CUSTOM_PASSWORD" ]]; then
        step "Применение пользовательских учётных данных"

        # Используем встроенную команду 3x-ui
        if "$XUI_BIN/x-ui" setting -username "$CUSTOM_USERNAME" -password "$CUSTOM_PASSWORD" >> "$LOG_FILE" 2>&1; then
            PANEL_USERNAME="$CUSTOM_USERNAME"
            PANEL_PASSWORD="$CUSTOM_PASSWORD"
            log "INFO" "Логин и пароль успешно изменены"
            info "Логин и пароль успешно изменены"

            # Перезапускаем панель для применения
            systemctl restart x-ui >> "$LOG_FILE" 2>&1
            sleep 2

            if systemctl is-active --quiet x-ui 2>/dev/null; then
                info "Панель перезапущена с новыми данными"
            else
                warn "Панель не перезапустилась — попробуйте: systemctl restart x-ui"
            fi
        else
            warn "Не удалось изменить логин/пароль — используются случайные"
            log "WARN" "Ошибка при изменении учётных данных"
            PANEL_USERNAME=""
            PANEL_PASSWORD=""
        fi
    fi
}

# ─── Сбор данных панели для отчёта ───────────────────────────────────────────────
collect_panel_info() {
    step "Сбор данных панели"

    # Получаем настройки через x-ui setting -show
    local panel_output
    panel_output=$("$XUI_BIN/x-ui" setting -show 2>/dev/null || true)

    # Порт
    if [[ -z "$PANEL_PORT" ]]; then
        PANEL_PORT=$(echo "$panel_output" | grep -oP 'port:\s*\K\d+' || true)
    fi

    # WebBasePath
    PANEL_WEBBASEPATH=$(echo "$panel_output" | grep -oP 'webBasePath:\s*/?\K[^\s/]+' || true)

    # Если кастомные данные не были заданы — пытаемся получить из вывода установки
    if [[ -z "$PANEL_USERNAME" ]]; then
        # Данные были случайными — ищем в логе
        PANEL_USERNAME=$(grep -oP 'Username:\s*\K\S+' "$LOG_FILE" 2>/dev/null | tail -1 || echo "")
        PANEL_PASSWORD=$(grep -oP 'Password:\s*\K\S+' "$LOG_FILE" 2>/dev/null | tail -1 || echo "")

        if [[ -z "$PANEL_USERNAME" ]]; then
            PANEL_USERNAME="(см. вывод установки выше)"
            PANEL_PASSWORD="(см. вывод установки выше)"
        fi
    fi

    info "Данные панели собраны"
}

# ─── Формирование whitelist ──────────────────────────────────────────────────────
build_whitelist() {
    WHITELIST_IPS="127.0.0.1/8 ::1 $SERVER_IP"
    [[ -n "$USER_IP" ]] && WHITELIST_IPS="$WHITELIST_IPS $USER_IP"
    detail "Whitelist: $WHITELIST_IPS"
}

# ─── Создание бэкапа ────────────────────────────────────────────────────────────
create_backup() {
    if [[ -d "$XUI_BIN" ]] || [[ -f "$F2B_JAIL_DIR/x-ui.conf" ]]; then
        step "Создание резервной копии"
        mkdir -p "$BACKUP_DIR"
        local timestamp
        timestamp=$(date '+%Y%m%d_%H%M%S')
        local backup_file="$BACKUP_DIR/xui-backup-$timestamp.tar.gz"

        local files_to_backup=()
        [[ -f "$XUI_BIN/bin/config.json" ]] && files_to_backup+=("$XUI_BIN/bin/config.json")
        [[ -f "$F2B_JAIL_DIR/x-ui.conf" ]] && files_to_backup+=("$F2B_JAIL_DIR/x-ui.conf")
        [[ -f "$F2B_FILTER_DIR/x-ui.conf" ]] && files_to_backup+=("$F2B_FILTER_DIR/x-ui.conf")
        [[ -f "/etc/x-ui/x-ui.db" ]] && files_to_backup+=("/etc/x-ui/x-ui.db")
        [[ -f "$XUI_BIN/bin/geoip.dat" ]] && files_to_backup+=("$XUI_BIN/bin/geoip.dat")
        [[ -f "$XUI_BIN/bin/geosite.dat" ]] && files_to_backup+=("$XUI_BIN/bin/geosite.dat")

        if [[ ${#files_to_backup[@]} -gt 0 ]]; then
            tar -czf "$backup_file" "${files_to_backup[@]}" 2>/dev/null || true
            info "Бэкап сохранен: $backup_file"
        fi
    fi
}

# ─── Установка 3x-ui ────────────────────────────────────────────────────────────
install_xui() {
    step "Установка 3x-ui панели"

    if $XUI_INSTALLED; then
        info "3x-ui уже установлен — пропускаем установку"
        return 0
    fi

    # Перенаправляем вывод установки в лог и на экран одновременно
    bash <(curl -Ls https://raw.githubusercontent.com/MHSanaei/3x-ui/master/install.sh) 2>&1 | tee -a "$LOG_FILE"

    # Ожидание запуска сервиса
    local retries=10
    while [[ $retries -gt 0 ]]; do
        if systemctl is-active --quiet x-ui 2>/dev/null; then
            info "3x-ui запущен"
            return 0
        fi
        sleep 2
        ((retries--))
    done

    die "3x-ui не запустился после установки"
}

# ─── Определение порта панели ────────────────────────────────────────────────────
detect_panel_port() {
    step "Определение порта панели"

    # Метод 1: через x-ui setting -show
    PANEL_PORT=$("$XUI_BIN/x-ui" setting -show 2>/dev/null | grep -oP 'port:\s*\K\d+' | head -1 || true)

    # Метод 2: через netstat/ss
    if [[ -z "$PANEL_PORT" ]]; then
        PANEL_PORT=$(ss -tlnp | grep x-ui | grep -oP ':\K\d+' | head -1 || true)
    fi

    # Метод 3: из лога установки
    if [[ -z "$PANEL_PORT" ]]; then
        PANEL_PORT=$(grep -oP 'Port:\s*\K\d+' "$LOG_FILE" 2>/dev/null | tail -1 || true)
    fi

    # Метод 4: спросить пользователя
    if [[ -z "$PANEL_PORT" ]]; then
        warn "Не удалось определить порт автоматически"
        while true; do
            read -rp "    Введите порт панели 3x-ui: " PANEL_PORT
            if [[ "$PANEL_PORT" =~ ^[0-9]+$ ]] && (( PANEL_PORT >= 1 && PANEL_PORT <= 65535 )); then
                break
            fi
            error "Неверный порт. Допустимый диапазон: 1–65535"
        done
    fi

    info "Порт панели: $PANEL_PORT"
}

# ─── Установка Geo-файлов (только для RU) ────────────────────────────────────────
install_geo_rules() {
    if [[ "$SERVER_TYPE" != "ru" ]]; then
        return 0
    fi

    step "Установка российских geo-файлов (runetfreedom)"

    local geo_dir="$XUI_BIN/bin"

    # Бэкап оригинальных файлов
    if [[ -f "$geo_dir/geoip.dat" ]]; then
        cp "$geo_dir/geoip.dat" "$geo_dir/geoip.dat.bak" 2>/dev/null || true
        detail "Бэкап: geoip.dat.bak"
    fi
    if [[ -f "$geo_dir/geosite.dat" ]]; then
        cp "$geo_dir/geosite.dat" "$geo_dir/geosite.dat.bak" 2>/dev/null || true
        detail "Бэкап: geosite.dat.bak"
    fi

    # Скачиваем российские geo-файлы
    info "Скачиваем geoip.dat (runetfreedom)..."
    if curl -fsSL -o "$geo_dir/geoip.dat" "$GEOIP_RU_URL"; then
        info "geoip.dat обновлён"
    else
        warn "Не удалось скачать geoip.dat — используется стандартный"
        [[ -f "$geo_dir/geoip.dat.bak" ]] && mv "$geo_dir/geoip.dat.bak" "$geo_dir/geoip.dat"
    fi

    info "Скачиваем geosite.dat (runetfreedom)..."
    if curl -fsSL -o "$geo_dir/geosite.dat" "$GEOSITE_RU_URL"; then
        info "geosite.dat обновлён"
    else
        warn "Не удалось скачать geosite.dat — используется стандартный"
        [[ -f "$geo_dir/geosite.dat.bak" ]] && mv "$geo_dir/geosite.dat.bak" "$geo_dir/geosite.dat"
    fi

    info "Geo-файлы для России установлены"
}

# ─── Настройка правил маршрутизации ──────────────────────────────────────────────
configure_routing_rules() {
    step "Настройка правил маршрутизации"

    # Проверяем наличие config.json
    if [[ ! -f "$XUI_CONFIG" ]]; then
        warn "config.json не найден — правила будут добавлены через панель"
        detail "Откройте панель → Настройки Xray → Routing"
        return 0
    fi

    # Проверяем наличие jq
    if ! command -v jq &>/dev/null; then
        info "Устанавливаем jq для работы с JSON..."
        apt-get install -y -qq jq > /dev/null 2>&1 || {
            warn "Не удалось установить jq — настройте routing вручную в панели"
            show_routing_instructions
            return 0
        }
    fi

    if [[ "$SERVER_TYPE" == "ru" ]]; then
        # Российский сервер — умная маршрутизация
        info "Применяем правила маршрутизации для российского сервера"

        local routing_config
        routing_config=$(cat << 'ROUTING'
{
  "domainStrategy": "IPIfNonMatch",
  "rules": [
    {
      "type": "field",
      "inboundTag": ["api"],
      "outboundTag": "api"
    },
    {
      "type": "field",
      "outboundTag": "blocked",
      "domain": ["geosite:category-ads-all"]
    },
    {
      "type": "field",
      "outboundTag": "direct",
      "domain": ["geosite:ru"]
    },
    {
      "type": "field",
      "outboundTag": "direct",
      "ip": ["geoip:ru"]
    },
    {
      "type": "field",
      "outboundTag": "blocked",
      "ip": ["geoip:private"]
    },
    {
      "type": "field",
      "outboundTag": "blocked",
      "protocol": ["bittorrent"]
    }
  ]
}
ROUTING
)

        # Обновляем routing в config.json
        local tmp_config
        tmp_config=$(mktemp)
        if jq --argjson routing "$routing_config" '.routing = $routing' "$XUI_CONFIG" > "$tmp_config" 2>/dev/null; then
            # Проверяем, есть ли outbound "direct"
            local has_direct
            has_direct=$(jq '.outbounds[]? | select(.tag == "direct")' "$XUI_CONFIG" 2>/dev/null || true)
            if [[ -z "$has_direct" ]]; then
                # Добавляем direct outbound
                jq '.outbounds += [{"protocol": "freedom", "tag": "direct"}]' "$tmp_config" > "${tmp_config}.2" 2>/dev/null && mv "${tmp_config}.2" "$tmp_config"
                detail "Добавлен outbound: direct (freedom)"
            fi
            mv "$tmp_config" "$XUI_CONFIG"
            info "Правила маршрутизации применены:"
            detail "geosite:ru     → direct (напрямую)"
            detail "geoip:ru       → direct (напрямую)"
            detail "geoip:private  → blocked"
            detail "ads            → blocked"
            detail "bittorrent     → blocked"
        else
            rm -f "$tmp_config"
            warn "Не удалось обновить config.json автоматически"
            show_routing_instructions
        fi

    else
        # Зарубежный сервер — минимальные правила
        info "Применяем стандартные правила для зарубежного сервера"

        local routing_config
        routing_config=$(cat << 'ROUTING'
{
  "domainStrategy": "AsIs",
  "rules": [
    {
      "type": "field",
      "inboundTag": ["api"],
      "outboundTag": "api"
    },
    {
      "type": "field",
      "outboundTag": "blocked",
      "ip": ["geoip:private"]
    },
    {
      "type": "field",
      "outboundTag": "blocked",
      "protocol": ["bittorrent"]
    }
  ]
}
ROUTING
)

        local tmp_config
        tmp_config=$(mktemp)
        if jq --argjson routing "$routing_config" '.routing = $routing' "$XUI_CONFIG" > "$tmp_config" 2>/dev/null; then
            mv "$tmp_config" "$XUI_CONFIG"
            info "Стандартные правила маршрутизации применены:"
            detail "geoip:private → blocked"
            detail "bittorrent    → blocked"
        else
            rm -f "$tmp_config"
            warn "Не удалось обновить config.json"
        fi
    fi
}

# ─── Инструкции по ручной настройке routing ──────────────────────────────────────
show_routing_instructions() {
    echo ""
    echo -e "  ${YELLOW}Для ручной настройки маршрутизации:${NC}"
    echo -e "  1. Откройте панель 3x-ui"
    echo -e "  2. Перейдите: ${BOLD}Настройки Xray → Routing${NC}"
    echo -e "  3. Добавьте правила:"
    echo -e "     • geosite:ru → direct"
    echo -e "     • geoip:ru → direct"
    echo -e "     • geosite:category-ads-all → blocked"
    echo -e "     • geoip:private → blocked"
    echo ""
}

# ─── Установка Fail2ban ─────────────────────────────────────────────────────────
install_fail2ban() {
    if $SKIP_F2B; then
        warn "Установка fail2ban пропущена (--skip-fail2ban)"
        return 0
    fi

    step "Установка Fail2ban"

    if $F2B_INSTALLED; then
        info "Fail2ban уже установлен — пропускаем установку"
    else
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq > /dev/null 2>&1
        apt-get install -y -qq fail2ban > /dev/null 2>&1
        info "Fail2ban установлен"
    fi
}

# ─── Настройка Fail2ban ─────────────────────────────────────────────────────────
configure_fail2ban() {
    if $SKIP_F2B; then return 0; fi

    step "Настройка Fail2ban для защиты панели"

    if $F2B_XUI_CONFIGURED; then
        create_backup
        info "Обновляем существующую конфигурацию Fail2ban"
    fi

    mkdir -p "$F2B_JAIL_DIR" "$F2B_FILTER_DIR"

    # Jail конфигурация
    cat > "$F2B_JAIL_DIR/x-ui.conf" << EOF
# Защита панели 3x-ui от брутфорса
# Сгенерировано: $(date '+%Y-%m-%d %H:%M:%S')
# Скрипт: $SCRIPT_NAME v$SCRIPT_VERSION

[x-ui]
enabled  = true
port     = $PANEL_PORT
backend  = systemd
journalmatch = _SYSTEMD_UNIT=x-ui.service
maxretry = 10
bantime  = 3600
findtime = 600
ignoreip = $WHITELIST_IPS
action   = %(action_)s
EOF

    # Фильтр
    cat > "$F2B_FILTER_DIR/x-ui.conf" << 'EOF'
# Фильтр для обнаружения неудачных попыток входа в 3x-ui
[Definition]
failregex = ^.*[Ff]ailed\s+login.*from\s+<HOST>.*$
            ^.*[Aa]uthentication\s+failed.*<HOST>.*$
            ^.*[Ii]nvalid.*credentials.*<HOST>.*$
            ^.*[Uu]nauthorized.*<HOST>.*$
ignoreregex =
EOF

    info "Конфигурация Fail2ban создана"
    detail "Jail:   $F2B_JAIL_DIR/x-ui.conf"
    detail "Filter: $F2B_FILTER_DIR/x-ui.conf"

    # Перезапуск
    systemctl restart fail2ban
    systemctl enable fail2ban > /dev/null 2>&1

    # Проверка
    local retries=5
    while [[ $retries -gt 0 ]]; do
        if systemctl is-active --quiet fail2ban; then
            info "Fail2ban запущен и настроен"
            return 0
        fi
        sleep 1
        ((retries--))
    done

    die "Fail2ban не запустился"
}

# ─── Удаление ────────────────────────────────────────────────────────────────────
do_uninstall() {
    step "Удаление 3x-ui и Fail2ban"

    read -rp "    Вы уверены? Это удалит 3x-ui и настройки Fail2ban [y/N]: " confirm
    [[ "${confirm,,}" != "y" ]] && { info "Отменено"; exit 0; }

    create_backup

    # Удаляем fail2ban конфиги
    rm -f "$F2B_JAIL_DIR/x-ui.conf" "$F2B_FILTER_DIR/x-ui.conf"
    systemctl restart fail2ban 2>/dev/null || true
    info "Конфиги Fail2ban удалены"

    # Удаляем 3x-ui
    if command -v x-ui &>/dev/null; then
        x-ui uninstall
        info "3x-ui удален"
    else
        warn "3x-ui не найден"
    fi

    info "Удаление завершено"
    exit 0
}

# ─── Финальный отчет ─────────────────────────────────────────────────────────────
show_summary() {
    collect_panel_info

    local access_url="https://${SERVER_IP}:${PANEL_PORT}/${PANEL_WEBBASEPATH}"

    echo ""
    echo -e "  ${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "  ${CYAN}║${NC}         ${GREEN}${BOLD}Установка завершена успешно!${NC}                           ${CYAN}║${NC}"
    echo -e "  ${CYAN}╠════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "  ${CYAN}║${NC}                                                              ${CYAN}║${NC}"
    echo -e "  ${CYAN}║${NC}  ${BOLD}Панель 3x-ui:${NC}                                              ${CYAN}║${NC}"
    echo -e "  ${CYAN}║${NC}  IP сервера:     ${GREEN}${SERVER_IP}${NC}"
    echo -e "  ${CYAN}║${NC}  Порт панели:    ${GREEN}${PANEL_PORT}${NC}"
    echo -e "  ${CYAN}║${NC}  WebBasePath:    ${GREEN}${PANEL_WEBBASEPATH}${NC}"
    echo -e "  ${CYAN}║${NC}                                                              ${CYAN}║${NC}"
    echo -e "  ${CYAN}║${NC}  ${BOLD}${YELLOW}Учётные данные:${NC}                                            ${CYAN}║${NC}"
    echo -e "  ${CYAN}║${NC}  Username:       ${GREEN}${BOLD}${PANEL_USERNAME}${NC}"
    echo -e "  ${CYAN}║${NC}  Password:       ${GREEN}${BOLD}${PANEL_PASSWORD}${NC}"
    echo -e "  ${CYAN}║${NC}                                                              ${CYAN}║${NC}"
    echo -e "  ${CYAN}║${NC}  ${BOLD}Access URL:${NC}                                                ${CYAN}║${NC}"
    echo -e "  ${CYAN}║${NC}  ${GREEN}${access_url}${NC}"
    echo -e "  ${CYAN}║${NC}                                                              ${CYAN}║${NC}"

    # Тип сервера
    echo -e "  ${CYAN}║${NC}  ${BOLD}Тип сервера:${NC}                                               ${CYAN}║${NC}"
    if [[ "$SERVER_TYPE" == "ru" ]]; then
        echo -e "  ${CYAN}║${NC}  ${GREEN}Российский${NC} (с geo-правилами маршрутизации)                ${CYAN}║${NC}"
        echo -e "  ${CYAN}║${NC}  • Российские сайты → напрямую (без VPN)                  ${CYAN}║${NC}"
        echo -e "  ${CYAN}║${NC}  • Зарубежные сайты → через VPN                           ${CYAN}║${NC}"
        echo -e "  ${CYAN}║${NC}  • Реклама → заблокирована                                ${CYAN}║${NC}"
        echo -e "  ${CYAN}║${NC}  • Приватные IP → заблокированы                            ${CYAN}║${NC}"
        echo -e "  ${CYAN}║${NC}  • Geo-файлы: runetfreedom/russia-v2ray-rules-dat         ${CYAN}║${NC}"
    else
        echo -e "  ${CYAN}║${NC}  ${BLUE}Зарубежный${NC} (стандартная установка)                        ${CYAN}║${NC}"
        echo -e "  ${CYAN}║${NC}  • Приватные IP → заблокированы                            ${CYAN}║${NC}"
        echo -e "  ${CYAN}║${NC}  • Bittorrent → заблокирован                              ${CYAN}║${NC}"
    fi
    echo -e "  ${CYAN}║${NC}                                                              ${CYAN}║${NC}"

    if ! $SKIP_F2B; then
        local banned_ssh banned_xui
        banned_ssh=$(fail2ban-client status sshd 2>/dev/null | grep "Currently banned" | awk '{print $NF}' || echo "0")
        banned_xui=$(fail2ban-client status x-ui 2>/dev/null | grep "Currently banned" | awk '{print $NF}' || echo "0")

        echo -e "  ${CYAN}║${NC}  ${BOLD}Fail2ban:${NC}                                                  ${CYAN}║${NC}"
        echo -e "  ${CYAN}║${NC}  SSH заблокировано:   ${banned_ssh} IP"
        echo -e "  ${CYAN}║${NC}  x-ui заблокировано:  ${banned_xui} IP"

        if [[ -n "$USER_IP" ]]; then
            echo -e "  ${CYAN}║${NC}  Whitelist:           ${GREEN}${USER_IP}${NC}"
        fi
        echo -e "  ${CYAN}║${NC}                                                              ${CYAN}║${NC}"
    fi

    echo -e "  ${CYAN}╠════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "  ${CYAN}║${NC}  ${RED}${BOLD}⚠ СОХРАНИТЕ ЭТИ ДАННЫЕ В НАДЁЖНОМ МЕСТЕ!${NC}                   ${CYAN}║${NC}"
    echo -e "  ${CYAN}╠════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "  ${CYAN}║${NC}  ${BOLD}Полезные команды:${NC}                                          ${CYAN}║${NC}"
    echo -e "  ${CYAN}║${NC}  Статус панели:     ${DIM}systemctl status x-ui${NC}"
    echo -e "  ${CYAN}║${NC}  Настройки панели:  ${DIM}x-ui settings${NC}"
    echo -e "  ${CYAN}║${NC}  Статус защиты:     ${DIM}fail2ban-client status${NC}"
    echo -e "  ${CYAN}║${NC}  Разбан IP:         ${DIM}fail2ban-client set x-ui unbanip <IP>${NC}"
    echo -e "  ${CYAN}║${NC}  Логи fail2ban:     ${DIM}tail -f /var/log/fail2ban.log${NC}"
    echo -e "  ${CYAN}║${NC}  Лог установки:     ${DIM}${LOG_FILE}${NC}"

    if [[ "$SERVER_TYPE" == "ru" ]]; then
        echo -e "  ${CYAN}║${NC}  Обновить geo-файлы: ${DIM}bash $SCRIPT_NAME --server-type ru${NC}"
    fi

    echo -e "  ${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# ─── Главная функция ─────────────────────────────────────────────────────────────
main() {
    # Инициализация лога
    mkdir -p "$(dirname "$LOG_FILE")"
    echo "=== Установка начата: $(date) ===" >> "$LOG_FILE"

    parse_args "$@"
    show_banner

    # Удаление
    if $UNINSTALL; then
        preflight_checks
        do_uninstall
    fi

    # Установка
    preflight_checks
    check_existing_installations
    detect_server_ip
    detect_client_ip
    ask_whitelist_ip
    build_whitelist

    # Выбор типа сервера
    ask_server_type

    # Запрос кастомных учётных данных (перед установкой)
    if ! $XUI_INSTALLED; then
        ask_custom_credentials
    fi

    # Создание бэкапа (если есть что бэкапить)
    create_backup

    # Установка 3x-ui
    install_xui

    # Применение кастомных учётных данных (после установки)
    apply_custom_credentials

    # Определение порта панели
    detect_panel_port

    # Установка geo-файлов (только для RU)
    install_geo_rules

    # Настройка маршрутизации
    configure_routing_rules

    # Перезапуск панели после изменений конфига
    if [[ "$SERVER_TYPE" == "ru" ]]; then
        systemctl restart x-ui >> "$LOG_FILE" 2>&1
        sleep 2
        if systemctl is-active --quiet x-ui 2>/dev/null; then
            info "Панель перезапущена с новыми настройками маршрутизации"
        else
            warn "Панель не перезапустилась — проверьте: systemctl status x-ui"
        fi
    fi

    # Установка и настройка Fail2ban
    install_fail2ban
    configure_fail2ban

    # Финальный отчёт
    show_summary

    log "INFO" "Установка завершена успешно"
}

# ─── Запуск ──────────────────────────────────────────────────────────────────────
main "$@"

