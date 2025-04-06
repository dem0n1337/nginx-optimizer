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
NGINX_VERSION=$(curl -s [https://nginx.org/en/download.html](https://nginx.org/en/download.html) | grep -oP 'nginx-\K[0-9]+\.[0-9]+\.[0-9]+(?=\.tar\.gz)' | head -1)
if [ -z "$NGINX_VERSION" ]; then
    error "Nepodarilo sa získať verziu NGINX"
fi
info "Najnovšia verzia NGINX: $NGINX_VERSION"

# Stiahnutie NGINX
info "Sťahujem NGINX $NGINX_VERSION..."
wget -q [https://nginx.org/download/nginx-$NGINX_VERSION.tar.gz](https://nginx.org/download/nginx-$NGINX_VERSION.tar.gz)
tar xzf nginx-$NGINX_VERSION.tar.gz
rm nginx-$NGINX_VERSION.tar.gz

# Stiahnutie Jemalloc
info "Sťahujem jemalloc..."
git clone --depth 1 [https://github.com/jemalloc/jemalloc.git](https://github.com/jemalloc/jemalloc.git)

# Stiahnutie ModSecurity
info "Sťahujem ModSecurity..."
git clone --depth 1 -b v3/master --single-branch [https://github.com/SpiderLabs/ModSecurity](https://github.com/SpiderLabs/ModSecurity)
git clone --depth 1 [https://github.com/SpiderLabs/ModSecurity-nginx.git](https://github.com/SpiderLabs/ModSecurity-nginx.git)

# Stiahnutie AWS-LC
info "Sťahujem AWS-LC..."
git clone --depth 1 [https://github.com/aws/aws-lc.git](https://github.com/aws/aws-lc.git)

# Stiahnutie BoringSSL (záloha ak AWS-LC nebude fungovať)
info "Sťahujem BoringSSL..."
git clone --depth 1 [https://github.com/google/boringssl.git](https://github.com/google/boringssl.git)

# Stiahnutie ngx_pagespeed
info "Sťahujem ngx_pagespeed..."
NPS_VERSION=$(curl -s [https://www.modpagespeed.com/doc/release_notes](https://www.modpagespeed.com/doc/release_notes) | grep -oP 'Release \K[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)
if [ -z "$NPS_VERSION" ]; then
    warn "Nepodarilo sa získať verziu ngx_pagespeed, používam poslednú známu verziu"
    NPS_VERSION="1.14.33.1"
fi
info "Verzia ngx_pagespeed: $NPS_VERSION"
wget -q [https://github.com/apache/incubator-pagespeed-ngx/archive/v${NPS_VERSION}.zip](https://github.com/apache/incubator-pagespeed-ngx/archive/v${NPS_VERSION}.zip)
unzip -q v${NPS_VERSION}.zip
mv incubator-pagespeed-ngx-${NPS_VERSION} ngx_pagespeed
rm v${NPS_VERSION}.zip

# Stiahnutie PSOL (PageSpeed Optimization Library)
cd ngx_pagespeed
wget -q [https://dl.google.com/dl/page-speed/psol/${NPS_VERSION}.tar.gz](https://dl.google.com/dl/page-speed/psol/${NPS_VERSION}.tar.gz)
tar xzf ${NPS_VERSION}.tar.gz
rm ${NPS_VERSION}.tar.gz
cd ..

# Stiahnutie ďalších modulov
info "Sťahujem doplnkové moduly..."

# Cache Purge Module
git clone --depth 1 [https://github.com/FRiCKLE/ngx_cache_purge.git](https://github.com/FRiCKLE/ngx_cache_purge.git)

# Headers More Module
git clone --depth 1 [https://github.com/openresty/headers-more-nginx-module.git](https://github.com/openresty/headers-more-nginx-module.git)

# Brotli kompresný modul
git clone --depth 1 [https://github.com/google/ngx_brotli.git](https://github.com/google/ngx_brotli.git)
cd ngx_brotli
git submodule update --init
cd ..

# VTS Module (Virtual host traffic status)
git clone --depth 1 [https://github.com/vozlt/nginx-module-vts.git](https://github.com/vozlt/nginx-module-vts.git)

# Redis Module
git clone --depth 1 [https://github.com/openresty/redis2-nginx-module.git](https://github.com/openresty/redis2-nginx-module.git)

# RTMP Module
git clone --depth 1 [https://github.com/arut/nginx-rtmp-module.git](https://github.com/arut/nginx-rtmp-module.git)

# GeoIP2 Module
git clone --depth 1 [https://github.com/leev/ngx_http_geoip2_module.git](https://github.com/leev/ngx_http_geoip2_module.git)

# Lua Module a NDK
git clone --depth 1 [https://github.com/openresty/lua-nginx-module.git](https://github.com/openresty/lua-nginx-module.git)
git clone --depth 1 [https://github.com/vision5/ngx_devel_kit.git](https://github.com/vision5/ngx_devel_kit.git)

# HTTP Substitution Filter Module
git clone --depth 1 [https://github.com/yaoweibin/ngx_http_substitutions_filter_module.git](https://github.com/yaoweibin/ngx_http_substitutions_filter_module.git)

# Upload Progress Module
git clone --depth 1 [https://github.com/masterzen/nginx-upload-progress-module.git](https://github.com/masterzen/nginx-upload-progress-module.git)

# Dynamic Upstream Module
git clone --depth 1 [https://github.com/api7/ngx_dynamic_upstream.git](https://github.com/api7/ngx_dynamic_upstream.git)

# HTTP Auth PAM Module
git clone --depth 1 [https://github.com/sto/ngx_http_auth_pam_module.git](https://github.com/sto/ngx_http_auth_pam_module.git)

# HTTP Push Module
git clone --depth 1 [https://github.com/slact/nginx_http_push_module.git](https://github.com/slact/nginx_http_push_module.git)

# NJS Module (JavaScript v Nginx)
git clone --depth 1 [https://github.com/nginx/njs.git](https://github.com/nginx/njs.git)

# Stiahnutie QUIC a HTTP/3
git clone --depth 1 [https://github.com/cloudflare/quiche.git](https://github.com/cloudflare/quiche.git)

# Stiahnutie patchov
info "Sťahujem patche..."
mkdir -p patches
cd patches

# PCRE JIT patch
wget -q -O pcre-jit.patch [https://raw.githubusercontent.com/nginx-modules/ngx_http_tls_dyn_size/master/patches/nginx__dynamic_tls_records_1.17.7%2B.patch](https://raw.githubusercontent.com/nginx-modules/ngx_http_tls_dyn_size/master/patches/nginx__dynamic_tls_records_1.17.7%2B.patch)

# TLS Dynamic Records patch
wget -q -O tls-dynamic.patch [https://raw.githubusercontent.com/kn007/patch/master/nginx_dynamic_tls_records.patch](https://raw.githubusercontent.com/kn007/patch/master/nginx_dynamic_tls_records.patch)

cd ..

info "Sťahovanie zdrojových kódov bolo úspešne dokončené."
echo "NGINX_VERSION=$NGINX_VERSION" > $BUILD_DIR/build_config.env
echo "NPS_VERSION=$NPS_VERSION" >> $BUILD_DIR/build_config.env

exit 0