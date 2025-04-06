#!/bin/bash
# 01_install_dependencies.sh - Inštalácia všetkých potrebných závislostí
# Autor: Cascade AI
# Dátum: 6.4.2025

set -e

# Farby pre výstup
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Funkcie pre výpis správ
info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

# Detekcia distribúcie
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VERSION=$VERSION_ID
else
    error "Nepodarilo sa detekovať distribúciu."
fi

info "Detekovaná distribúcia: $OS $VERSION"

# Inštalácia závislostí podľa distribúcie
case $OS in
    ubuntu|debian)
        info "Inštalujem závislosti pre Debian/Ubuntu..."
        apt update
        apt install -y build-essential git wget curl ccache libpcre3 libpcre3-dev zlib1g zlib1g-dev \
          libssl-dev libgeoip-dev libxslt1-dev libxml2-dev libgd-dev libperl-dev liblmdb-dev \
          libcurl4-openssl-dev automake libtool autoconf libyajl-dev pkgconf doxygen \
          cmake g++ python3 bison flex libpng-dev libjpeg-dev uuid-dev libicu-dev \
          gperftools libgoogle-perftools-dev libunwind-dev libpam0g-dev libtbb-dev \
          libluajit-5.1-dev lua5.1 liblua5.1-dev libmhash-dev libexpat1-dev libjemalloc-dev \
          libhiredis-dev libmaxminddb-dev libsodium-dev libcjson-dev \
          libpcre2-dev libcap-dev libelf-dev rustc cargo \
          zstd libzstd-dev libbrotli-dev autoconf automake libtool bc \
          openssl libssl3 libssl-dev golang-go
        
        # Kontrola verzie OpenSSL a prípadný upgrade na 3.x
        if openssl version | grep -q "OpenSSL 1"; then
            info "Detekovaná OpenSSL verzia 1.x, pokúšam sa aktualizovať na OpenSSL 3.x..."
            # Pre Ubuntu 20.04 a staršie verzie je potrebné pridať PPA
            if [ -f /etc/lsb-release ] && grep -q "Ubuntu" /etc/lsb-release; then
                UBUNTU_VERSION=$(lsb_release -rs)
                if (( $(echo "$UBUNTU_VERSION < 22.04" | bc -l) )); then
                    add-apt-repository -y ppa:ondrej/openssl
                    apt update
                    apt install -y libssl3 libssl-dev
                fi
            fi
        fi
        ;;
    centos|rhel|fedora|rocky|almalinux)
        info "Inštalujem závislosti pre RHEL/CentOS/Fedora/Rocky/AlmaLinux..."
        if [ "$OS" = "centos" ] && [ "$VERSION" -lt 8 ]; then
            yum install -y epel-release
            yum groupinstall -y 'Development Tools'
            yum install -y git wget curl ccache pcre pcre-devel zlib zlib-devel openssl-devel \
              libmaxminddb-devel libxslt-devel libxml2-devel gd-devel perl-devel lmdb \
              libcurl-devel automake libtool autoconf libyaml-devel pkgconfig doxygen \
              cmake gcc-c++ python3 bison flex libpng-devel libjpeg-devel libuuid-devel libicu-devel \
              gperftools gperftools-devel libunwind-devel pam-devel tbb-devel \
              luajit-devel lua lua-devel mhash-devel expat-devel jemalloc-devel \
              hiredis-devel libmaxminddb libsodium-devel cjson-devel \
              pcre2-devel libcap-devel libelf-devel rust cargo \
              zstd libzstd-devel brotli-devel autoconf automake libtool bc yajl-devel golang
        else
            dnf install -y epel-release
            
            # Povoliť CRB repozitár (CodeReady Builder pre Rocky/AlmaLinux)
            if [ "$OS" = "rocky" ] || [ "$OS" = "almalinux" ]; then
                info "Povoľujem CRB repozitár pre $OS..."
                dnf config-manager --set-enabled crb || :
                # Alternatívny spôsob povolenia PowerTools/CRB pre staršie verzie
                if echo "$VERSION < 9.0" | bc -l | grep -q 1; then
                    dnf config-manager --set-enabled powertools || :
                fi
            fi
            
            dnf groupinstall -y 'Development Tools'
            dnf install -y git wget curl ccache pcre pcre-devel zlib zlib-devel openssl-devel \
              libmaxminddb libxslt-devel libxml2-devel gd-devel perl-devel lmdb \
              libcurl-devel automake libtool autoconf libyaml-devel pkgconf doxygen \
              cmake gcc-c++ python3 bison flex libpng-devel libjpeg-devel libuuid-devel libicu-devel \
              gperftools gperftools-devel pam-devel \
              luajit lua lua-devel expat-devel jemalloc-devel \
              pcre2-devel libcap-devel elfutils-libelf-devel rust cargo \
              zstd libzstd-devel brotli-devel autoconf automake libtool bc yajl-devel golang
              
            # Pokus o inštaláciu dodatočných závislostí, ignorovanie chýb
            dnf install -y libunwind-devel tbb-devel hiredis-devel libsodium-devel cjson-devel || :
            
            # Kontrola verzie OpenSSL
            if [ "$OS" = "centos" ] || [ "$OS" = "rhel" ] || [ "$OS" = "rocky" ] || [ "$OS" = "almalinux" ]; then
                if openssl version | grep -q "OpenSSL 1"; then
                    info "Detekovaná OpenSSL verzia 1.x, pokúšam sa aktualizovať na OpenSSL 3.x..."
                    if [ "$OS" = "centos" ] && [ "$VERSION" -ge 8 ]; then
                        dnf -y --enablerepo=powertools install openssl11 openssl11-devel || :
                    else
                        # Pre RHEL/Rocky/AlmaLinux
                        dnf -y module enable openssl
                        dnf -y install openssl openssl-devel
                    fi
                fi
            fi
        fi
        ;;
    *)
        error "Nepodporovaná distribúcia: $OS"
        ;;
esac

# Nastavenie ccache
info "Nastavujem ccache..."
export PATH="/usr/lib/ccache:$PATH"
echo 'export PATH="/usr/lib/ccache:$PATH"' >> /etc/profile.d/ccache.sh
chmod +x /etc/profile.d/ccache.sh

# Nastavenie jemalloc
info "Nastavujem jemalloc..."
echo '/usr/local/lib' > /etc/ld.so.conf.d/jemalloc.conf
# Optimalizácie pre jemalloc
echo 'export MALLOC_CONF="background_thread:true,dirty_decay_ms:1000,muzzy_decay_ms:1000,tcache:true"' >> /etc/profile.d/jemalloc.sh
chmod +x /etc/profile.d/jemalloc.sh
ldconfig

info "Všetky závislosti boli úspešne nainštalované."
exit 0