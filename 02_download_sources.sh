#!/bin/bash
# 02_download_sources.sh - Stiahnutie všetkých zdrojových kódov
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

# Prejsť do pracovného adresára
cd $BUILD_DIR || error "Nemôžem prejsť do $BUILD_DIR"

# Získať najnovšiu verziu NGINX
info "Získavam najnovšiu verziu NGINX..."
NGINX_VERSION=$(curl -s https://nginx.org/en/download.html | grep -oP 'nginx-\K[0-9]+\.[0-9]+\.[0-9]+(?=\.tar\.gz)' | head -1)
if [ -z "$NGINX_VERSION" ]; then
    error "Nepodarilo sa získať verziu NGINX"
fi
info "Najnovšia verzia NGINX: $NGINX_VERSION"

# Stiahnutie NGINX
info "Sťahujem NGINX $NGINX_VERSION..."
wget -q https://nginx.org/download/nginx-$NGINX_VERSION.tar.gz
tar xzf nginx-$NGINX_VERSION.tar.gz
rm nginx-$NGINX_VERSION.tar.gz

# Stiahnutie PCRE2 zo zdrojov
info "Sťahujem PCRE2 zo zdrojov..."
PCRE2_VERSION="10.42"
wget -q https://github.com/PCRE2Project/pcre2/releases/download/pcre2-${PCRE2_VERSION}/pcre2-${PCRE2_VERSION}.tar.gz
tar xzf pcre2-${PCRE2_VERSION}.tar.gz
rm pcre2-${PCRE2_VERSION}.tar.gz

# Stiahnutie optimalizovaného zlib od Cloudflare
info "Sťahujem optimalizovaný zlib od Cloudflare..."
git clone --depth 1 https://github.com/cloudflare/zlib.git zlib-cloudflare

# Stiahnutie jemalloc
info "Sťahujem jemalloc..."
git clone --depth 1 https://github.com/jemalloc/jemalloc.git

# Stiahnutie ModSecurity
info "Sťahujem ModSecurity..."
git clone --depth 1 -b v3/master --single-branch https://github.com/SpiderLabs/ModSecurity
git clone --depth 1 https://github.com/SpiderLabs/ModSecurity-nginx.git

# Stiahnutie OpenSSL 3.x namiesto AWS-LC
info "Sťahujem OpenSSL 3.x..."
OPENSSL_VERSION=$(curl -s https://www.openssl.org/source/ | grep -oP 'openssl-3\.[0-9]+\.[0-9]+\.tar\.gz' | head -1 | sed 's/\.tar\.gz//')
if [ -z "$OPENSSL_VERSION" ]; then
    warn "Nepodarilo sa získať verziu OpenSSL, používam poslednú známu verziu 3.2.0"
    OPENSSL_VERSION="openssl-3.2.0"
fi
wget -q https://www.openssl.org/source/$OPENSSL_VERSION.tar.gz
tar xzf $OPENSSL_VERSION.tar.gz
rm $OPENSSL_VERSION.tar.gz

# Stiahnutie BoringSSL (záloha ak OpenSSL 3.x nebude fungovať)
info "Sťahujem BoringSSL..."
git clone --depth 1 https://github.com/google/boringssl.git

# Overenie dostupnosti ngx_pagespeed
info "Kontrolujem dostupnosť ngx_pagespeed..."
if curl -s --head https://github.com/apache/incubator-pagespeed-ngx | grep "HTTP/1.1 200" > /dev/null; then
    info "Sťahujem ngx_pagespeed..."
    git clone --depth 1 https://github.com/apache/incubator-pagespeed-ngx.git ngx_pagespeed
    
    # Stiahnutie PSOL (PageSpeed Optimization Library)
    cd ngx_pagespeed
    NPS_VERSION=$(grep -o "PSOL_BINARY_URL=\".*\"" configure | cut -d '"' -f 2 | awk -F '/' '{print $(NF-1)}')
    if [ -z "$NPS_VERSION" ]; then
        warn "Nepodarilo sa získať verziu PSOL, skúšam alternatívny zdroj..."
        # Alternatívny zdroj pre PSOL
        wget -q https://dl.google.com/dl/page-speed/psol/latest/linux/x64/psol.tar.gz
    else
        wget -q https://dl.google.com/dl/page-speed/psol/$NPS_VERSION.tar.gz
    fi
    tar xzf *.tar.gz
    rm *.tar.gz
    cd ..
else
    warn "ngx_pagespeed repozitár nie je dostupný, preskakujem..."
fi

# Stiahnutie zstd-nginx-module pre zstd kompresiu
info "Sťahujem zstd-nginx-module..."
git clone --depth 1 https://github.com/tokers/zstd-nginx-module.git

# Stiahnutie ďalších modulov
info "Sťahujem doplnkové moduly..."

# Cache Purge Module
git clone --depth 1 https://github.com/FRiCKLE/ngx_cache_purge.git

# Headers More Module
git clone --depth 1 https://github.com/openresty/headers-more-nginx-module.git

# Brotli kompresný modul
git clone --depth 1 https://github.com/google/ngx_brotli.git
cd ngx_brotli
git submodule update --init
cd ..

# VTS Module (Virtual host traffic status)
git clone --depth 1 https://github.com/vozlt/nginx-module-vts.git

# Redis Module
git clone --depth 1 https://github.com/openresty/redis2-nginx-module.git

# RTMP Module
git clone --depth 1 https://github.com/arut/nginx-rtmp-module.git

# GeoIP2 Module
git clone --depth 1 https://github.com/leev/ngx_http_geoip2_module.git

# Lua Module a NDK
git clone --depth 1 https://github.com/openresty/lua-nginx-module.git
git clone --depth 1 https://github.com/vision5/ngx_devel_kit.git

# Doplnkové Lua moduly
git clone --depth 1 https://github.com/openresty/lua-resty-core.git
git clone --depth 1 https://github.com/openresty/lua-resty-lrucache.git

# Fancy index module
git clone --depth 1 https://github.com/aperezdc/ngx-fancyindex.git

# HTTP Substitution Filter Module
git clone --depth 1 https://github.com/yaoweibin/ngx_http_substitutions_filter_module.git

# Kontrola dostupnosti Upload Progress Module
if curl -s --head https://github.com/masterzen/nginx-upload-progress-module | grep "HTTP/1.1 200" > /dev/null; then
    git clone --depth 1 https://github.com/masterzen/nginx-upload-progress-module.git
else
    warn "nginx-upload-progress-module nie je dostupný, skúšam alternatívu..."
    # Alternatívna implementácia
    git clone --depth 1 https://github.com/fdintino/nginx-upload-module.git
fi

# Dynamic Upstream Module
git clone --depth 1 https://github.com/api7/ngx_dynamic_upstream.git

# HTTP Auth PAM Module
git clone --depth 1 https://github.com/sto/ngx_http_auth_pam_module.git

# HTTP Push Module
git clone --depth 1 https://github.com/slact/nginx_http_push_module.git

# NJS Module (JavaScript v Nginx)
git clone --depth 1 https://github.com/nginx/njs.git

# Stiahnutie oficiálnej implementácie QUIC/HTTP/3
info "Sťahujem oficiálnu implementáciu QUIC/HTTP/3..."
git clone --depth 1 https://github.com/nginx/nginx-quic.git

# Modul pre optimalizáciu obrázkov
info "Sťahujem ngx_small_light pre optimalizáciu obrázkov..."
git clone --depth 1 https://github.com/cubicdaiya/ngx_small_light.git

# Modul pre WAF (doplnok k ModSecurity)
info "Sťahujem ďalšie bezpečnostné moduly..."
git clone --depth 1 https://github.com/SpiderLabs/owasp-modsecurity-crs.git

# Stiahnutie LuaRocks pre správu Lua balíkov
info "Sťahujem LuaRocks..."
git clone --depth 1 https://github.com/luarocks/luarocks.git

# Stiahnutie patchov
info "Sťahujem patche..."
mkdir -p patches
cd patches

# PCRE JIT patch
wget -q -O pcre-jit.patch https://raw.githubusercontent.com/nginx-modules/ngx_http_tls_dyn_size/master/patches/nginx__dynamic_tls_records_1.17.7%2B.patch

# TLS Dynamic Records patch
wget -q -O tls-dynamic.patch https://raw.githubusercontent.com/kn007/patch/master/nginx_dynamic_tls_records.patch

# Pridanie OpenSSL 3.x patch (pre kompatibilitu)
wget -q -O openssl3-compatibility.patch https://raw.githubusercontent.com/nginx-modules/headers-more-nginx-module/master/patches/openssl3-compat.patch

cd ..

info "Sťahovanie zdrojových kódov bolo úspešne dokončené."
echo "NGINX_VERSION=$NGINX_VERSION" > $BUILD_DIR/build_config.env
echo "OPENSSL_VERSION=$OPENSSL_VERSION" >> $BUILD_DIR/build_config.env
echo "PCRE2_VERSION=$PCRE2_VERSION" >> $BUILD_DIR/build_config.env

exit 0