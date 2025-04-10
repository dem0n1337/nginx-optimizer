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

# Funkcia pre registráciu dynamických modulov
register_dynamic_module() {
  local MODULE_NAME=$1
  local MODULE_PATH=$2
  
  if [ -f "$MODULE_PATH" ]; then
    info "Registrujem dynamický modul: $MODULE_NAME"
    echo "load_module $MODULE_PATH;" >> /usr/local/nginx/conf/dynamic-modules-includes.conf
    return 0
  else
    warn "Súbor modulu nebol nájdený: $MODULE_PATH"
    return 1
  fi
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

# Kompilácia OpenSSL 3.x ako zálohu
# Use AWS_LC_COMPILED flag to decide if OpenSSL is needed
AWS_LC_COMPILED=0 # Force OpenSSL build since AWS-LC is disabled
if [ "$AWS_LC_COMPILED" -ne 1 ] && [ -d "$OPENSSL_VERSION" ] && [ ! -d "boringssl" ]; then # Only build if BoringSSL isn't present
    info "Kompilujem OpenSSL 3.x..."
    cd $OPENSSL_VERSION
    ./config --prefix=/usr/local/ssl --openssldir=/usr/local/ssl shared zlib enable-ktls enable-ec_nistp_64_gcc_128 -DTCP_FASTOPEN=23 -fstack-protector-strong -O3
    make -j$(nproc)
    make install
    cd ..
    export OPENSSL_DIR="$BUILD_DIR/$OPENSSL_VERSION"
fi

# Kompilácia BoringSSL (enabled)
if [ -d "boringssl" ]; then
    info "Kompilujem BoringSSL..."
    cd boringssl
    mkdir -p build
    cd build
    # --- FIX: Temporarily remove ccache from PATH for BoringSSL build ---
    ORIGINAL_PATH="$PATH"
    PATH=$(echo "$PATH" | sed 's|/usr/lib/ccache:||g; s|:/usr/lib/ccache||g')
    info "Temporarily adjusted PATH for BoringSSL: $PATH"
    OLD_CFLAGS="$CFLAGS"; OLD_CXXFLAGS="$CXXFLAGS"
    unset CFLAGS CXXFLAGS
    info "Temporarily unset CFLAGS/CXXFLAGS for BoringSSL cmake & make..."

    if cmake -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=0 .. && \
       make -j$(nproc); then
       info "BoringSSL compiled successfully."
    else
        warn "BoringSSL compilation failed."
    fi

    # Restore original PATH, CFLAGS, CXXFLAGS
    export PATH="$ORIGINAL_PATH"
    export CFLAGS="$OLD_CFLAGS" CXXFLAGS="$OLD_CXXFLAGS"
    info "Restored PATH to: $PATH"
    info "Restored CFLAGS/CXXFLAGS to: $CFLAGS / $CXXFLAGS"
    # --- END FIX ---
    cd ../..
    export BORINGSSL_PATH="$BUILD_DIR/boringssl"
fi

# Inštalácia ngx_small_light pre optimalizáciu obrázkov
if [ -d "ngx_small_light" ]; then
    info "Inštalujem ngx_small_light závislosti..."
    cd ngx_small_light
    # ./setup # Commented out due to MagickWand dependency issues
    cd ..
fi

# Inštalácia OWASP ModSecurity Core Rule Set
if [ -d "owasp-modsecurity-crs" ]; then
    info "Inštalujem OWASP ModSecurity Core Rule Set..."
    mkdir -p $INSTALL_DIR/modsec/crs
    cp -R owasp-modsecurity-crs/rules $INSTALL_DIR/modsec/crs/
    cp owasp-modsecurity-crs/crs-setup.conf.example $INSTALL_DIR/modsec/crs/crs-setup.conf
fi

# Pripravíme adresár pre dynamické moduly
mkdir -p /usr/local/nginx/conf
touch /usr/local/nginx/conf/dynamic-modules-includes.conf

info "Inštalácia a príprava modulov bola úspešne dokončená."
exit 0