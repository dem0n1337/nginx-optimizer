#!/bin/bash
# 02_download_sources.sh - Stiahnutie všetkých zdrojových kódov
# Autor: Cascade AI
# Dátum: 6.4.2025

# Namiesto set -e použijeme explicitné kontroly návratových kódov
# set -e

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
    return 1  # Namiesto exit 1 použijeme return, aby sa skript nezastavil
}

# Funkcia pre čistenie neúspešne stiahnutých repozitárov
cleanup_repo() {
    local dir="$1"
    if [ -d "$dir" ]; then
        # Kontrola, či je to platný git repozitár
        if [ ! -d "$dir/.git" ] || ! git -C "$dir" rev-parse --git-dir > /dev/null 2>&1; then
            warn "Našiel som neplatný repozitár $dir, odstraňujem..."
            rm -rf "$dir"
            return 0
        fi
    fi
    return 0
}

# Funkcia pre klonování repozitárov s kontrolou existencie
clone_repo() {
    local repo_url="$1"
    local target_dir="$2"
    local description="$3"
    
    # Najprv vyčistíme neplatný repozitár, ak existuje
    cleanup_repo "$target_dir"
    
    if [ -d "$target_dir" ]; then
        # Ak adresár stále existuje po čistení, je to platný repozitár
        warn "$target_dir už existuje a je platný, preskakujem klonování $description..."
        return 0
    fi
    
    info "Sťahujem $description..."
    git clone --depth 1 $repo_url $target_dir || {
        warn "Nepodarilo sa stiahnuť $description, skúšam pokračovať..."
        # Vyčistíme neúspešný pokus
        if [ -d "$target_dir" ]; then
            rm -rf "$target_dir"
        fi
        return 1
    }
}

# Kontrola BUILD_DIR
if [ -z "$BUILD_DIR" ]; then
    BUILD_DIR="/opt/nginx-build"
    warn "BUILD_DIR nie je nastavený, používam predvolenú hodnotu: $BUILD_DIR"
fi

# Prejsť do pracovného adresára
cd $BUILD_DIR || { error "Nemôžem prejsť do $BUILD_DIR"; exit 1; }

# Vyčistenie možných neúspešných predchádzajúcich pokusov
info "Kontrolujem existujúce repozitáre..."
for dir in zlib-cloudflare jemalloc ModSecurity ModSecurity-nginx boringssl ngx_pagespeed zstd-nginx-module \
    ngx_cache_purge headers-more-nginx-module ngx_brotli nginx-module-vts redis2-nginx-module nginx-rtmp-module \
    ngx_http_geoip2_module lua-nginx-module ngx_devel_kit lua-resty-core lua-resty-lrucache ngx-fancyindex \
    ngx_http_substitutions_filter_module nginx-upload-progress-module nginx-upload-module ngx_dynamic_upstream \
    ngx_http_auth_pam_module nginx_http_push_module njs nginx-quic ngx_small_light owasp-modsecurity-crs luarocks; do
    cleanup_repo "$dir"
done

# Získať najnovšiu verziu NGINX
info "Získavam najnovšiu verziu NGINX..."
NGINX_VERSION=$(curl -s https://nginx.org/en/download.html | grep -oP 'nginx-\K[0-9]+\.[0-9]+\.[0-9]+(?=\.tar\.gz)' | head -1)
if [ -z "$NGINX_VERSION" ]; then
    error "Nepodarilo sa získať verziu NGINX"
fi
info "Najnovšia verzia NGINX: $NGINX_VERSION"

# Stiahnutie NGINX
info "Sťahujem NGINX $NGINX_VERSION..."
if [ -d "nginx-$NGINX_VERSION" ]; then
    warn "nginx-$NGINX_VERSION už existuje, preskakujem sťahovanie..."
else
    wget -q https://nginx.org/download/nginx-$NGINX_VERSION.tar.gz
    tar xzf nginx-$NGINX_VERSION.tar.gz
    rm nginx-$NGINX_VERSION.tar.gz
fi

# Stiahnutie PCRE2 zo zdrojov
info "Sťahujem PCRE2 zo zdrojov..."
PCRE2_VERSION="10.42"
if [ -d "pcre2-${PCRE2_VERSION}" ]; then
    warn "pcre2-${PCRE2_VERSION} už existuje, preskakujem sťahovanie..."
else
    wget -q https://github.com/PCRE2Project/pcre2/releases/download/pcre2-${PCRE2_VERSION}/pcre2-${PCRE2_VERSION}.tar.gz
    tar xzf pcre2-${PCRE2_VERSION}.tar.gz
    rm pcre2-${PCRE2_VERSION}.tar.gz
fi

# Stiahnutie optimalizovaného zlib od Cloudflare
clone_repo "https://github.com/cloudflare/zlib.git" "zlib-cloudflare" "optimalizovaný zlib od Cloudflare"

# Stiahnutie jemalloc
info "Sťahujem jemalloc..."
clone_repo "https://github.com/jemalloc/jemalloc.git" "jemalloc" "jemalloc"

# Stiahnutie ModSecurity
info "Sťahujem ModSecurity..."
clone_repo "https://github.com/SpiderLabs/ModSecurity" "ModSecurity" "ModSecurity"
clone_repo "https://github.com/SpiderLabs/ModSecurity-nginx.git" "ModSecurity-nginx" "ModSecurity-nginx"

# Stiahnutie AWS-LC (Amazon's Lightweight Cryptography library)
info "Sťahujem AWS-LC..."
if [ -d "aws-lc" ]; then
    warn "aws-lc už existuje, preskakujem sťahovanie..."
else
    git clone --depth 1 https://github.com/aws/aws-lc.git || {
        warn "Nepodarilo sa stiahnuť AWS-LC, skúšam pokračovať s OpenSSL..."
    }
fi

# Stiahnutie BoringSSL pre podporu QUIC/HTTP3
info "Sťahujem BoringSSL (odporúčané pre QUIC/HTTP3)..."
if [ -d "boringssl" ]; then
    warn "boringssl už existuje, preskakujem sťahovanie..."
else
    git clone --depth 1 https://github.com/google/boringssl.git || {
        warn "Nepodarilo sa stiahnuť BoringSSL, QUIC/HTTP3 nemusí fungovať správne..."
    }
fi

# Stiahnutie OpenSSL 3.x ako zálohu
info "Sťahujem OpenSSL 3.x (záloha)..."
OPENSSL_VERSION=$(curl -s https://www.openssl.org/source/ | grep -oP 'openssl-3\.[0-9]+\.[0-9]+\.tar\.gz' | head -1 | sed 's/\.tar\.gz//')
if [ -z "$OPENSSL_VERSION" ]; then
    warn "Nepodarilo sa získať verziu OpenSSL, používam poslednú známu verziu 3.2.0"
    OPENSSL_VERSION="openssl-3.2.0"
fi
if [ -d "$OPENSSL_VERSION" ]; then
    warn "$OPENSSL_VERSION už existuje, preskakujem sťahovanie..."
else
    wget -q https://www.openssl.org/source/$OPENSSL_VERSION.tar.gz
    tar xzf $OPENSSL_VERSION.tar.gz
    rm $OPENSSL_VERSION.tar.gz
fi

# Overenie dostupnosti ngx_pagespeed
info "Kontrolujem dostupnosť ngx_pagespeed..."
if [ -d "ngx_pagespeed" ]; then
    warn "ngx_pagespeed už existuje, preskakujem sťahovanie..."
else
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
fi

# Stiahnutie zstd-nginx-module pre zstd kompresiu
info "Sťahujem zstd-nginx-module..."
clone_repo "https://github.com/tokers/zstd-nginx-module.git" "zstd-nginx-module" "zstd-nginx-module"

# Stiahnutie ďalších modulov
info "Sťahujem doplnkové moduly..."

# Cache Purge Module
info "Sťahujem Cache Purge Module..."
clone_repo "https://github.com/FRiCKLE/ngx_cache_purge.git" "ngx_cache_purge" "Cache Purge Module"

# Headers More Module
info "Sťahujem Headers More Module..."
clone_repo "https://github.com/openresty/headers-more-nginx-module.git" "headers-more-nginx-module" "Headers More Module"

# Brotli kompresný modul
if [ ! -d "ngx_brotli" ]; then
    info "Sťahujem Brotli kompresný modul..."
    git clone --depth 1 https://github.com/google/ngx_brotli.git
    cd ngx_brotli
    git submodule update --init
    cd ..
else
    warn "ngx_brotli už existuje, preskakujem sťahovanie..."
fi

# VTS Module (Virtual host traffic status)
info "Sťahujem VTS Module..."
clone_repo "https://github.com/vozlt/nginx-module-vts.git" "nginx-module-vts" "VTS Module"

# Redis Module
info "Sťahujem Redis Module..."
clone_repo "https://github.com/openresty/redis2-nginx-module.git" "redis2-nginx-module" "Redis Module"

# RTMP Module
info "Sťahujem RTMP Module..."
clone_repo "https://github.com/arut/nginx-rtmp-module.git" "nginx-rtmp-module" "RTMP Module"

# GeoIP2 Module
info "Sťahujem GeoIP2 Module..."
clone_repo "https://github.com/leev/ngx_http_geoip2_module.git" "ngx_http_geoip2_module" "GeoIP2 Module"

# Lua Module a NDK
info "Sťahujem Lua Module a NDK..."
clone_repo "https://github.com/openresty/lua-nginx-module.git" "lua-nginx-module" "Lua Module"
clone_repo "https://github.com/vision5/ngx_devel_kit.git" "ngx_devel_kit" "Ngx Devel Kit"

# Doplnkové Lua moduly
info "Sťahujem Lua Resty Core a Lua Resty LRU Cache..."
clone_repo "https://github.com/openresty/lua-resty-core.git" "lua-resty-core" "Lua Resty Core"
clone_repo "https://github.com/openresty/lua-resty-lrucache.git" "lua-resty-lrucache" "Lua Resty LRU Cache"

# Fancy index module
info "Sťahujem Fancy Index Module..."
clone_repo "https://github.com/aperezdc/ngx-fancyindex.git" "ngx-fancyindex" "Fancy Index Module"

# HTTP Substitution Filter Module
info "Sťahujem HTTP Substitutions Filter Module..."
clone_repo "https://github.com/yaoweibin/ngx_http_substitutions_filter_module.git" "ngx_http_substitutions_filter_module" "HTTP Substitutions Filter Module"

# Kontrola dostupnosti Upload Progress Module
if [ -d "nginx-upload-progress-module" ]; then
    warn "nginx-upload-progress-module už existuje, preskakujem sťahovanie..."
elif [ -d "nginx-upload-module" ]; then
    warn "nginx-upload-module už existuje, preskakujem sťahovanie..."
else
    if curl -s --head https://github.com/masterzen/nginx-upload-progress-module | grep "HTTP/1.1 200" > /dev/null; then
        info "Sťahujem Upload Progress Module..."
        clone_repo "https://github.com/masterzen/nginx-upload-progress-module.git" "nginx-upload-progress-module" "Upload Progress Module"
    else
        warn "nginx-upload-progress-module nie je dostupný, skúšam alternatívu..."
        # Alternatívna implementácia
        clone_repo "https://github.com/fdintino/nginx-upload-module.git" "nginx-upload-module" "Upload Module"
    fi
fi

# Dynamic Upstream Module
if [ -d "ngx_dynamic_upstream" ]; then
    warn "ngx_dynamic_upstream už existuje, preskakujem sťahovanie..."
else
    info "Sťahujem Dynamic Upstream Module..."
    # Použijeme správny repozitár bez autentifikácie
    git clone --depth 1 https://github.com/cubicdaiya/ngx_dynamic_upstream.git || {
        warn "Nepodarilo sa stiahnuť ngx_dynamic_upstream, skúšam alternatívny zdroj cez git protokol..."
        git clone --depth 1 git://github.com/cubicdaiya/ngx_dynamic_upstream.git || 
        warn "Nepodarilo sa stiahnuť ngx_dynamic_upstream, preskakujem..."
    }
fi

# HTTP Auth PAM Module
info "Sťahujem HTTP Auth PAM Module..."
clone_repo "https://github.com/sto/ngx_http_auth_pam_module.git" "ngx_http_auth_pam_module" "HTTP Auth PAM Module"

# HTTP Push Module
info "Sťahujem HTTP Push Module..."
clone_repo "https://github.com/slact/nginx_http_push_module.git" "nginx_http_push_module" "HTTP Push Module"

# NJS Module (JavaScript v Nginx)
info "Sťahujem NJS Module..."
clone_repo "https://github.com/nginx/njs.git" "njs" "NJS Module"

# Modul pre optimalizáciu obrázkov
info "Sťahujem ngx_small_light pre optimalizáciu obrázkov..."
clone_repo "https://github.com/cubicdaiya/ngx_small_light.git" "ngx_small_light" "ngx_small_light"

# Modul pre WAF (doplnok k ModSecurity)
info "Sťahujem OWASP ModSecurity CRS..."
clone_repo "https://github.com/SpiderLabs/owasp-modsecurity-crs.git" "owasp-modsecurity-crs" "OWASP ModSecurity CRS"

# Stiahnutie LuaRocks pre správu Lua balíkov
info "Sťahujem LuaRocks..."
clone_repo "https://github.com/luarocks/luarocks.git" "luarocks" "LuaRocks"

# Vytvorenie adresára pre patche, ak neexistuje
mkdir -p patches
cd patches

# PCRE JIT patch - This is downloaded but seems empty/corrupt, keeping download but it's not used
if [ ! -f "pcre-jit.patch" ]; then
    wget -q -O pcre-jit.patch https://raw.githubusercontent.com/nginx-modules/ngx_http_tls_dyn_size/master/patches/nginx__dynamic_tls_records_1.17.7%2B.patch || warn "Nepodarilo sa stiahnuť pcre-jit.patch"
fi

# TLS Dynamic Records patch
if [ ! -f "tls-dynamic.patch" ]; then
    wget -q -O tls-dynamic.patch https://raw.githubusercontent.com/kn007/patch/master/nginx_dynamic_tls_records.patch || warn "Nepodarilo sa stiahnuť tls-dynamic.patch"
fi

# Pridanie OpenSSL 3.x patch (pre kompatibilitu)
if [ ! -f "openssl3-compatibility.patch" ]; then
    wget -q -O openssl3-compatibility.patch https://raw.githubusercontent.com/nginx-modules/headers-more-nginx-module/master/patches/openssl3-compat.patch || warn "Nepodarilo sa stiahnuť openssl3-compatibility.patch"
fi

cd ..

info "Sťahovanie zdrojových kódov bolo úspešne dokončené."
echo "NGINX_VERSION=$NGINX_VERSION" > $BUILD_DIR/build_config.env
echo "OPENSSL_VERSION=$OPENSSL_VERSION" >> $BUILD_DIR/build_config.env
echo "PCRE2_VERSION=$PCRE2_VERSION" >> $BUILD_DIR/build_config.env

exit 0