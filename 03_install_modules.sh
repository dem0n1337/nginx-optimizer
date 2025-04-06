#!/bin/bash
# 03_install_modules.sh - Inštalácia a príprava modulov pred kompiláciou
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

# Kontrola BUILD_DIR
if [ -z "$BUILD_DIR" ]; then
    BUILD_DIR="/opt/nginx-build"
    warn "BUILD_DIR nie je nastavený, používam predvolenú hodnotu: $BUILD_DIR"
fi

# Načítanie konfigurácie
if [ -f "$BUILD_DIR/build_config.env" ]; then
    source $BUILD_DIR/build_config.env
else
    error "Konfiguračný súbor $BUILD_DIR/build_config.env neexistuje"
fi

# Prejsť do pracovného adresára
cd $BUILD_DIR || error "Nemôžem prejsť do $BUILD_DIR"

# Kompilácia Jemalloc
info "Kompilujem Jemalloc..."
cd jemalloc
./autogen.sh
./configure --enable-prof
make -j$(nproc)
make install
cd ..

# Kompilácia libmodsecurity
info "Kompilujem libmodsecurity..."
cd ModSecurity
git submodule init
git submodule update
./build.sh
./configure --with-pcre=/usr/bin/pcre-config --with-lmdb --with-yajl --with-curl --enable-json-logging
make -j$(nproc)
make install
cd ..

# Kompilácia AWS-LC
info "Kompilujem AWS-LC..."
cd aws-lc
mkdir -p build
cd build
cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=on -DBUILD_TESTING=OFF -DCMAKE_POSITION_INDEPENDENT_CODE=ON ..
make -j$(nproc)
make install
cd ../..

# Kompilácia BoringSSL (záloha)
info "Kompilujem BoringSSL..."
cd boringssl
mkdir -p build
cd build
cmake -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=0 ..
make -j$(nproc)
cd ../..
export BORINGSSL_PATH="$BUILD_DIR/boringssl"

# Príprava LuaJIT
info "Kompilujem LuaJIT..."
git clone --depth 1 [https://github.com/openresty/luajit2.git](https://github.com/openresty/luajit2.git)
cd luajit2
make -j$(nproc)
make install
export LUAJIT_LIB=/usr/local/lib
export LUAJIT_INC=/usr/local/include/luajit-2.1
cd ..

# Aplikácia patchov na NGINX zdrojový kód
info "Aplikujem patche na NGINX zdrojový kód..."
cd nginx-$NGINX_VERSION
patch -p1 < ../patches/pcre-jit.patch || warn "PCRE JIT patch sa nepodarilo aplikovať"
patch -p1 < ../patches/tls-dynamic.patch || warn "TLS Dynamic Records patch sa nepodarilo aplikovať"
cd ..

info "Inštalácia a príprava modulov bola úspešne dokončená."
exit 0