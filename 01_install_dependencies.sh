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
          libluajit-5.1-dev lua5.1 liblua5.1-dev libmhash-dev libexpat1-dev libjemalloc-dev
        ;;
    centos|rhel|fedora|rocky|almalinux)
        info "Inštalujem závislosti pre RHEL/CentOS/Fedora/Rocky/AlmaLinux..."
        if [ "$OS" = "centos" ] && [ "$VERSION" -lt 8 ]; then
            yum install -y epel-release
            yum groupinstall -y 'Development Tools'
            yum install -y git wget curl ccache pcre pcre-devel zlib zlib-devel openssl-devel \
              GeoIP-devel libxslt-devel libxml2-devel gd-devel perl-devel lmdb-devel \
              libcurl-devel automake libtool autoconf yajl-devel pkgconfig doxygen \
              cmake gcc-c++ python3 bison flex libpng-devel libjpeg-devel libuuid-devel libicu-devel \
              gperftools gperftools-devel libunwind-devel pam-devel tbb-devel \
              luajit-devel lua lua-devel mhash-devel expat-devel jemalloc-devel
        else
            dnf install -y epel-release
            dnf groupinstall -y 'Development Tools'
            dnf install -y git wget curl ccache pcre pcre-devel zlib zlib-devel openssl-devel \
              GeoIP-devel libxslt-devel libxml2-devel gd-devel perl-devel lmdb-devel \
              libcurl-devel automake libtool autoconf yajl-devel pkgconf doxygen \
              cmake gcc-c++ python3 bison flex libpng-devel libjpeg-devel libuuid-devel libicu-devel \
              gperftools gperftools-devel libunwind-devel pam-devel tbb-devel \
              luajit-devel lua lua-devel mhash-devel expat-devel jemalloc-devel
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
ldconfig

info "Všetky závislosti boli úspešne nainštalované."
exit 0