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
if [ -d "$BUILD_DIR/jemalloc" ]; then
    info "Kompilujem Jemalloc..."
    cd $BUILD_DIR/jemalloc
    # Pridať získanie tagov
    git fetch --tags || true
    # Opraviť background-thread voľbu
    autoconf
    ./configure --enable-autogen ""
    make -j$(nproc)
    make install
    ldconfig

    # Kompilácia optimalizovanej verzie s debugom
    ./configure --enable-prof --enable-debug
    make -j$(nproc)
    make install
    ldconfig
fi

# Kompilácia PCRE2 zo zdrojov
info "Kompilujem PCRE2 zo zdrojov..."
if [ -d "$BUILD_DIR/pcre2-${PCRE2_VERSION}" ]; then
    cd "$BUILD_DIR/pcre2-${PCRE2_VERSION}"
    ./configure --prefix=/usr/local/pcre2 \
    --enable-jit --enable-pcre2-16 --enable-pcre2-32 --enable-unicode
    make -j$(nproc)
    make install
    cd "$BUILD_DIR"
else
    warn "Adresár pcre2-${PCRE2_VERSION} nebol nájdený, preskakujem kompiláciu PCRE2."
fi

# Kompilácia zlib-cloudflare
info "Kompilujem optimalizovaný zlib od Cloudflare..."
if [ -d "$BUILD_DIR/zlib-cloudflare" ]; then
    cd "$BUILD_DIR/zlib-cloudflare"
    ./configure --prefix=/usr/local/zlib-cf
    make -j$(nproc)
    make install
    cd "$BUILD_DIR"
else
    warn "Adresár zlib-cloudflare nebol nájdený, preskakujem kompiláciu zlib."
fi

# Prípadná manuálna kompilácia YAJL, ak nie je dostupný systémový balík
info "Kontrolujem dostupnosť YAJL..."
if ! pkg-config --exists yajl || [ ! -f "/usr/include/yajl/yajl_version.h" ]; then
    info "YAJL nie je nainštalovaný alebo sa nedá nájsť, kompilujem zo zdrojov..."
    cd $BUILD_DIR
    rm -rf yajl
    git clone https://github.com/lloyd/yajl.git
    cd yajl
    mkdir -p build
    cd build
    cmake ..
    make -j$(nproc)
    make install
    ldconfig
    cd $BUILD_DIR
else
    info "YAJL už je nainštalovaný, pokračujem ďalej..."
fi

# Kompilácia libmodsecurity
if [ -d "$BUILD_DIR/ModSecurity" ]; then
    info "Kompilujem libmodsecurity..."
    cd $BUILD_DIR/ModSecurity
    git submodule init
    git submodule update
    
    # Vytvorím umelý tag pre potlačenie "No names found" chyby
    git tag -a v3.0.0 -m "Temporary tag for build" || true
    
    # Použiť bash na obídenie problémov s git
    bash -c "AUTOMAKE_ARGS='-Wno-unused-g++' ./build.sh" || true
    
    # Špeciálna konfigurácia s podporou pre YAJL
    ./configure --with-pcre=/usr/bin/pcre-config --with-lmdb --with-yajl --with-curl --enable-json-logging
    make -j$(nproc)
    make install
    cd $BUILD_DIR
fi

# Kompilácia AWS-LC pre podporu QUIC/HTTP3
info "Kompilujem AWS-LC pre podporu QUIC/HTTP3..."
if [ -d "aws-lc" ]; then
    cd aws-lc
    mkdir -p build
    cd build
    if command -v go >/dev/null 2>&1; then
        info "Go (golang) nájdený, pokračujem v kompilácii AWS-LC..."
        if cmake -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=0 .. && make -j$(nproc); then
            info "AWS-LC úspešne skompilovaný"
            export AWS_LC_PATH="$BUILD_DIR/aws-lc"
        else
            warn "Kompilácia AWS-LC zlyhala, QUIC/HTTP3 nemusí fungovať správne"
        fi
    else
        warn "Go (golang) nie je nainštalovaný, AWS-LC nemôže byť skompilovaný, QUIC/HTTP3 nebude dostupný"
    fi
    cd ../..
else
    warn "AWS-LC adresár neexistuje, QUIC/HTTP3 nemusí fungovať správne..."
fi

# Kompilácia OpenSSL 3.x ako zálohu
if [ ! -d "aws-lc" ] && [ -d "$OPENSSL_VERSION" ]; then
    info "Kompilujem OpenSSL 3.x..."
    cd $OPENSSL_VERSION
    ./config --prefix=/usr/local/ssl --openssldir=/usr/local/ssl shared zlib enable-ktls enable-ec_nistp_64_gcc_128 -DTCP_FASTOPEN=23 -fstack-protector-strong -O3
    make -j$(nproc)
    make install
    cd ..
    export OPENSSL_DIR="$BUILD_DIR/$OPENSSL_VERSION"
fi

# Kompilácia BoringSSL ako zálohu
if [ ! -d "aws-lc" ] && [ ! -d "$OPENSSL_VERSION" ] && [ -d "boringssl" ]; then
    info "Kompilujem BoringSSL..."
    cd boringssl
    mkdir -p build
    cd build
    cmake -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=0 ..
    make -j$(nproc)
    cd ../..
    export BORINGSSL_PATH="$BUILD_DIR/boringssl"
fi

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