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
    if [[ $is_BASH -ne "bash" ]]; then
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
        print_ok "Root user checked!" ; $SLEEP
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

function debian_halifax_mirrors() {
	debian_version_check
	#check_root
	sudo cp /etc/apt/sources.list /etc/apt/sources.list.bak
	judge "make backup from sources.list"
	if [[ -s "/etc/apt/sources.list.bak" ]]; then
		sudo tee /etc/apt/sources.list <<EOF
deb http://ftp.halifax.rwth-aachen.de/debian/ ${VERSION_CODENAME} main non-free contrib
deb-src http://ftp.halifax.rwth-aachen.de/debian/ ${VERSION_CODENAME} main non-free contrib

deb http://security.debian.org/debian-security ${VERSION_CODENAME}-security main contrib non-free
deb-src http://security.debian.org/debian-security ${VERSION_CODENAME}-security main contrib non-free

deb http://ftp.halifax.rwth-aachen.de/debian/ ${VERSION_CODENAME}-updates main contrib non-free
deb-src http://ftp.halifax.rwth-aachen.de/debian/ ${VERSION_CODENAME}-updates main contrib non-free
EOF
		judge "update mirrors to halifax"
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
    installit lsof tar
    judge "Install lsof tar"

    installit cron
    judge "install crontab"

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
