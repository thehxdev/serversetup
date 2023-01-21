#!/usr/bin/env bash

# Colors
Color_Off='\033[0m'
#Black='\033[0;30m' 
Red='\033[0;31m'   
Green='\033[0;32m' 
Yellow='\033[0;33m'
Blue='\033[0;34m'  
#Purple='\033[0;35m'
Cyan='\033[0;36m'  
#White='\033[0;37m' 

# Variables
website_dir="/var/www/html" 
random_num=$((RANDOM % 12 + 4))
nginx_conf="/etc/nginx/sites-available/default"
caddy_conf="/etc/caddy/Caddyfile"
CLASH_VERSION="2022.11.25"

OK="${Green}[OK]"
ERROR="${Red}[ERROR]"
INFO="${Yellow}[INFO]"

SLEEP="sleep 0.2"

#print OK
function print_ok() {
    echo -e "${OK} $1 ${Color_Off}"
}

#print ERROR
function print_error() {
    echo -e "${ERROR} $1 ${Color_Off}"
}

#print INFO
function print_info() {
    echo -e "${INFO} $1 ${Color_Off}"
}

function installit() {
    apt install -y $*
}

function judge() {
    if [[ 0 -eq $? ]]; then
        print_ok "$1 Finished"
        $SLEEP
    else
        print_error "$1 Failed"
        exit 1
    fi
}

# Check the shell
function check_bash() {
    is_BASH=$(readlink /proc/$$/exe | grep -q "bash")
    if [[ -z ${is_BASH} ]]; then
        print_error "This installer needs to be run with bash, not sh."
        exit
    fi
}

# Check root
function check_root() {
    if [[ "$EUID" -ne 0 ]]; then
        print_error "This installer needs to be run with superuser privileges. Login as root user and run the script again!"
        exit
    else 
        print_ok "Root user checked!" && $SLEEP
    fi
}

# Check OS
#function check_os() {
#    if grep -qs "ubuntu" /etc/os-release; then
#        os="ubuntu"
#        os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
#        print_ok "Ubuntu detected!"
#    elif [[ -e /etc/debian_version ]]; then
#        os="debian"
#        os_version=$(cat /etc/debian_version | cut -d '.' -f 1)
#        print_ok "Debian detected!"
#    else
#        print_error "This installer seems to be running on an unsupported distribution.
#        Supported distros are ${Yellow}Debian${Color_Off} and ${Yellow}Ubuntu${Color_Off}."
#        exit
#    fi
#    if [[ "$os" == "ubuntu" && "$os_version" -lt 2004 ]]; then
#        print_error "${Yellow}Ubuntu 20.04${Color_Off} or higher is required to use this installer.
#        This version of Ubuntu is too old and unsupported."
#        exit
#    elif [[ "$os" == "debian" && "$os_version" -lt 10 ]]; then
#        print_error "${Yellow}Debian 11${Color_Off} or higher is required to use this installer.
#        This version of fedora is too old and unsupported."
#        exit
#    fi
#}

# save debian status
function debian_version_check() {
	source /etc/os-release
}

function disable_firewalls() {
    is_firewalld=$(systemctl list-units --type=service --state=active | grep -c firewalld)
    is_nftables=$(systemctl list-units --type=service --state=active | grep -c nftables)
    is_ufw=$(systemctl list-units --type=service --state=active | grep -c ufw)

    if [[ "$is_nftables" -ne 0 ]]; then
        systemctl stop nftables
        systemctl disable nftables
    fi 

    if [[ "$is_ufw" -ne 0 ]]; then
        systemctl stop ufw
        systemctl disable ufw
    fi

    if [[ "$is_firewalld" -ne 0 ]]; then
        systemctl stop firewalld
        systemctl disable firewalld
    fi
}

function debian_de() {
    debian_version_check
    #check_root
    sudo cp /etc/apt/sources.list /etc/apt/sources.list.bak
    judge "make backup from sources.list"
    if [[ -s "/etc/apt/sources.list.bak" ]]; then
        sudo tee /etc/apt/sources.list <<EOF
deb http://ftp.de.debian.org/debian/ ${VERSION_CODENAME} main non-free contrib
deb-src http://ftp.de.debian.org/debian/ ${VERSION_CODENAME} main non-free contrib

deb http://security.debian.org/debian-security ${VERSION_CODENAME}-security main contrib non-free
deb-src http://security.debian.org/debian-security ${VERSION_CODENAME}-security main contrib non-free

deb http://ftp.de.debian.org/debian/ ${VERSION_CODENAME}-updates main contrib non-free
deb-src http://ftp.de.debian.org/debian/ ${VERSION_CODENAME}-updates main contrib non-free
EOF
        judge "update mirrors to ftp.de.debian.org"
    else
        print_error "can't find backup file for sources.list"
    fi
    update_repos
}

function update_repos() {
    sudo apt update -y
    judge "update repos"
}

function install_deps() {
    update_repos
    installit lsof tar
    judge "Install lsof tar"

    installit cron htop
    judge "install crontab htop"

    installit ripgrep fd
    judge "install ripgrep fd-find"

    touch /var/spool/cron/crontabs/root && chmod 600 /var/spool/cron/crontabs/root
    systemctl start cron && systemctl enable cron
    judge "crontab autostart"

    installit unzip gzip
    judge "install unzip gzip"

    installit curl wget git proxychains4
    judge "install curl wget git"

    installit libpcre3 libpcre3-dev zlib1g-dev openssl libssl-dev
    judge "install libpcre3 libpcre3-dev zlib1g-dev openssl libssl-dev"

    installit qrencode neovim
    judge "install qrencode neovim"

    installit jq tmux
    judge "install jq tmux"

    mkdir /usr/local/bin >/dev/null 2>&1
}

function build_tools_install() {
    update_repos

    installit llvm build-essential
    judge "install llvm build-essential"
}

function basic_optimization() {
    sed -i '/^\*\ *soft\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
    sed -i '/^\*\ *hard\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
    echo '* soft nofile 65536' >>/etc/security/limits.conf
    echo '* hard nofile 65536' >>/etc/security/limits.conf
}

function ip_check() {
    local_ipv4=$(curl -s4m8 https://ip.gs)
    local_ipv6=$(curl -s6m8 https://ip.gs)
    if [[ -z ${local_ipv4} && -n ${local_ipv6} ]]; then
        print_ok "Pure IPv6 server"
        SERVER_IP=$(curl -s6m8 https://ip.gs)
    else
        print_ok "Server hase IPv4"
        SERVER_IP=$(curl -s4m8 https://ip.gs)
    fi
}

function cloudflare_dns() {
    ip_check
    if [[ -z ${local_ipv4} && -n ${local_ipv6} ]]; then
        echo "nameserver 2606:4700:4700::1111" > /etc/resolv.conf
        echo "nameserver 2606:4700:4700::1001" >> /etc/resolv.conf
        judge "add IPv6 DNS to resolv.conf"
    else
        echo "nameserver 1.1.1.1" > /etc/resolv.conf
        echo "nameserver 1.0.0.1" >> /etc/resolv.conf
        judge "add IPv4 DNS to resolv.conf"
    fi
}

function shecan_dns() {
    ip_check
    if [[ -z ${local_ipv4} && -n ${local_ipv6} ]]; then
        print_error "Shecan does not support IPv6"
        exit 1
    else
        echo "nameserver 178.22.122.100" > /etc/resolv.conf
        echo "nameserver 185.51.200.2" >> /etc/resolv.conf
        judge "add IPv4 DNS to resolv.conf"
    fi
}

function port_exist_check() {
    if [[ 0 -eq $(lsof -i:"$1" | grep -i -c "listen") ]]; then
        print_ok "$1 Port is not in use"
        sleep 1
    else
        print_error "It is detected that port $1 is occupied, the following is the occupancy information of port $1"
        lsof -i:"$1"
        print_error "After 5s, it will try to kill the occupied process automatically"
        sleep 5
        lsof -i:"$1" | awk '{print $2}' | grep -v "PID" | xargs kill -9
        print_ok "Kill Finished"
        sleep 1
    fi
}

function setup_fake_website() {
    wget https://github.com/arcdetri/sample-blog/archive/master.zip
    unzip master.zip
    cp -rf sample-blog-master/html/* /var/www/html/
}

function xray_install() {
    print_ok "Installing Xray"
    curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh | bash -s -- install
    judge "Xray Installation"

    # Import link for Xray generation
    #echo $domain >/usr/local/domain.txt
    #judge "Save Domain"
    groupadd nobody
    gpasswd -a nobody nobody
    judge "add nobody user to nobody group"
}


function clash_install() {
    print_info "Installing Clash-Core (Premium)"
    wget https://github.com/Dreamacro/clash/releases/download/premium/clash-linux-amd64-2022.11.25.gz -O clash.gz
    judge "Download Clash-core"

    gzip --decompress --keep clash.gz
    judge "Extract Clash-core"

    mv clash /usr/local/bin/clash
    judge "Move Clash-core to /usr/local/bin"

    tee -a /etc/systemd/system/clash.service <<EOF
[Unit]
Description=Clash daemon, A rule-based proxy in Go.
After=network.target

[Service]
Type=simple
Restart=always
ExecStart=/usr/local/bin/clash -f /etc/clash/clash.yml

[Install]
WantedBy=multi-user.target
EOF
    judge "Make Clash systemd service"

    mkdir -p /etc/clash/
    touch /etc/clash/clash.yml

    systemctl enable --now clash.service

    echo -e  "======================================================="
    print_ok "Put your Clash config file in /etc/clash/clash.yml"
    echo -e  "======================================================="
}


function add_socks_proxy_to_apt() {
    read -rp "Enter an Proxy IP: " proxy_ip
    read -rp "Enter an Proxy Port: " proxy_port
    echo -e "Acquire::http::proxy \"socks5h://${proxy_ip}:${proxy_port}\";" > /etc/apt/apt.conf
}


function add_http_proxy_to_docker() {
    read -rp "Enter an Proxy IP: " proxy_ip
    read -rp "Enter an Proxy Port: " proxy_port

    path="/etc/systemd/system/docker.service.d"
    mkdir -p ${path}
    tee ${path}/http-proxy.conf <<EOF
[Service]
Environment="HTTP_PROXY=http://${proxy_ip}:${proxy_port}/"
Environment="HTTPS_PROXY=http://${proxy_ip}:${proxy_port}/"
EOF

    systemctl daemon-reload
    systemctl restart docker
}


function configure_bash() {
    tee -a $HOME/.bashrc <<EOF
export PATH=/usr/local/bin:\$PATH

alias nv="nvim"
alias tm="tmux"
alias pt="proxychains4 -q -f /etc/proxychains4.conf"
alias spt="sudo proxychains4 -q -f /etc/proxychains4.conf"
EOF
    judge "configure bash"
}

function caddy_install() {
    installit debian-keyring debian-archive-keyring apt-transport-https
    judge "install caddy dependencies"

    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    judge "add caddy gpg keys"

    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list
    judge "add caddy repository"

    update_repos
    installit caddy
}

function caddy_matrix_configure() {
    port_exist_check 80
    port_exist_check 8008

    read -rp "Enter Your Domain (Matrix Server Name): " domain

    if [ -e "${caddy_conf}" ]; then
        cat << EOF > ${caddy_conf}
$domain {
  reverse_proxy /_matrix/* localhost:8008
  reverse_proxy /_synapse/client/* localhost:8008
  reverse_proxy localhost:8008
}

$domain:8448 {
  reverse_proxy localhost:8008
}
EOF
    fi

    systemctl restart caddy.service
    judge "restart caddy"

    print_ok "caddy configured"
}

function matrix_synapse_install() {
    installit lsb-release wget apt-transport-https python3 python3-pip
    judge "Install synapse dependencies"

    wget -O /usr/share/keyrings/matrix-org-archive-keyring.gpg https://packages.matrix.org/debian/matrix-org-archive-keyring.gpg
    judge "Get synapse gpg keys"

    echo "deb [signed-by=/usr/share/keyrings/matrix-org-archive-keyring.gpg] https://packages.matrix.org/debian/ $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/matrix-org.list
    judge "Add matrix synapse repos"

    update_repos
    installit matrix-synapse-py3
}

function postgres_install() {
    installit postgresql
}

function matrix_menu() {
    echo -e "==================== Matrix ===================="
    echo -e "${Green}1. Install Matrix Synapse (Official repos)${Color_Off}"
    echo -e "${Green}2. Install PostgreSQL 13${Color_Off}"
    echo -e "${Green}3. Install Caddy 2${Color_Off}"
    echo -e "${Green}4. Configure Caddy for synapse (Reverse Proxy)${Color_Off}"
    echo -e "${Yellow}5. Exit${Color_Off}"

    read -rp "Enter an Option: " matrix_menu_num
    case $matrix_menu_num in 
        1)
            matrix_synapse_install
            ;;
        2)
            postgres_install
            ;;
        3)
            caddy_install
            ;;
        4)
            caddy_matrix_configure
            ;;
        5)
            print_ok "Exit"
            exit 0
            ;;
        *)
            print_error "Invalid Option. Run script again!"
            exit 1
    esac
}

function main_menu() {
    clear

    echo -e "==================== Anti Filter ===================="
    echo -e "${Green}1. Install Xray${Color_Off}"
    echo -e "${Green}2. Install Clash-Core${Color_Off}"
    echo -e "${Green}3. Change DNS to Shecan${Color_Off}"
    echo -e "${Green}4. Change DNS to Cloudflare${Color_Off}"
    echo -e "${Green}5. Add Socks5 proxy to APT${Color_Off}"
    echo -e "${Green}6. Add HTTP proxy to Docker${Color_Off}"
    echo -e "======================= Tools ======================="
    echo -e "${Green}7. Install Usfull Packages${Color_Off}"
    echo -e "${Green}8. Basic Optimization${Color_Off}"
    echo -e "${Green}9. Disable Firewalls${Color_Off}"
    echo -e "${Green}10. Configure Bash${Color_Off}"
    echo -e "${Green}11. Change Mirrors to ftp.de.debian.org${Color_Off}"
    echo -e "${Green}12. Install Caddy 2${Color_Off}"
    echo -e "====================== Services ====================="
    echo -e "${Green}13. Matrix Menu${Color_Off}"
    echo -e "${Yellow}14. Exit${Color_Off}"

    read -rp "Enter an Option: " menu_num
    case $menu_num in 
        1)
            xray_install
            ;;
        2)
            clash_install
            ;;
        3)
            shecan_dns
            ;;
        4)
            cloudflare_dns
            ;;
        5)
            add_socks_proxy_to_apt
            ;;
        6)
            add_http_proxy_to_docker
            ;;
        7)
            install_deps
            ;;
        8)
            basic_optimization
            ;;
        9)
            disable_firewalls
            ;;
        10)
            configure_bash
            ;;
        11)
            debian_de
            ;;
        12)
            caddy_install
            ;;
        13)
            matrix_menu
            ;;
        14)
            print_ok "Exit"
            exit 0
            ;;
        *)
            print_error "Invalid Option! Run script again."
            exit 1
    esac
}

check_root
main_menu "$@"
