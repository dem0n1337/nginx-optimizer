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
./configure --enable-prof --enable-debug --enable-background-thread=yes
make -j$(nproc)
make install
cd ..

# Kompilácia PCRE2 zo zdrojov
info "Kompilujem PCRE2 zo zdrojov..."
cd pcre2-${PCRE2_VERSION}
./configure --prefix=/usr/local/pcre2 \
  --enable-jit --enable-pcre2-16 --enable-pcre2-32 --enable-unicode
make -j$(nproc)
make install
cd ..

# Kompilácia zlib-cloudflare
info "Kompilujem optimalizovaný zlib od Cloudflare..."
cd zlib-cloudflare
./configure --prefix=/usr/local/zlib-cf
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

# Kompilácia OpenSSL 3.x namiesto AWS-LC
info "Kompilujem OpenSSL 3.x..."
cd $OPENSSL_VERSION
./config --prefix=/usr/local/ssl --openssldir=/usr/local/ssl shared zlib enable-ktls enable-ec_nistp_64_gcc_128 -DTCP_FASTOPEN=23 -fstack-protector-strong -O3
make -j$(nproc)
make install
cd ..
export OPENSSL_DIR="$BUILD_DIR/$OPENSSL_VERSION"

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
git clone --depth 1 https://github.com/openresty/luajit2.git
cd luajit2
make -j$(nproc)
make install
export LUAJIT_LIB=/usr/local/lib
export LUAJIT_INC=/usr/local/include/luajit-2.1
cd ..

# Inštalácia LuaRocks
info "Inštalujem LuaRocks..."
cd luarocks
./configure --with-lua-include=/usr/local/include/luajit-2.1
make -j$(nproc)
make install
cd ..

# Inštalácia Lua Resty modulov
info "Inštalujem Lua Resty moduly..."
# lua-resty-core
cd lua-resty-core
make install
cd ..

# lua-resty-lrucache
cd lua-resty-lrucache
make install
cd ..

# Príprava oficiálneho QUIC modulu
if [ -d "nginx-quic" ]; then
    info "Pripravujem oficiálny QUIC modul..."
    # Skopírovanie QUIC implementácie do hlavného Nginx adresára
    cp -rf nginx-quic/* nginx-$NGINX_VERSION/
    cd nginx-$NGINX_VERSION
    # Aplikácia potrebných zmien pre QUIC
    patch -p1 < ../nginx-quic/patches/nginx-1.23.0-quic.patch || warn "QUIC patch sa nepodarilo aplikovať"
    cd ..
fi

# Inštalácia ngx_small_light pre optimalizáciu obrázkov
if [ -d "ngx_small_light" ]; then
    info "Inštalujem ngx_small_light závislosti..."
    cd ngx_small_light
    ./setup
    cd ..
fi

# Inštalácia OWASP ModSecurity Core Rule Set
if [ -d "owasp-modsecurity-crs" ]; then
    info "Inštalujem OWASP ModSecurity Core Rule Set..."
    mkdir -p $INSTALL_DIR/modsec/crs
    cp -R owasp-modsecurity-crs/rules $INSTALL_DIR/modsec/crs/
    cp owasp-modsecurity-crs/crs-setup.conf.example $INSTALL_DIR/modsec/crs/crs-setup.conf
fi

# Aplikácia patchov na NGINX zdrojový kód
info "Aplikujem patche na NGINX zdrojový kód..."
cd nginx-$NGINX_VERSION
patch -p1 < ../patches/pcre-jit.patch || warn "PCRE JIT patch sa nepodarilo aplikovať"
patch -p1 < ../patches/tls-dynamic.patch || warn "TLS Dynamic Records patch sa nepodarilo aplikovať"
# Aplikácia OpenSSL 3.x kompatibilného patchu
patch -p1 < ../patches/openssl3-compatibility.patch || warn "OpenSSL 3.x compatibility patch sa nepodarilo aplikovať"
cd ..

info "Inštalácia a príprava modulov bola úspešne dokončená."
exit 0