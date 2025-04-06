#!/bin/bash
# 04_compile_nginx.sh - Kompilácia Nginx so všetkými modulmi a optimalizáciami
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

# Kontrola INSTALL_DIR
if [ -z "$INSTALL_DIR" ]; then
    INSTALL_DIR="/etc/nginx"
    warn "INSTALL_DIR nie je nastavený, používam predvolenú hodnotu: $INSTALL_DIR"
fi

# Načítanie konfigurácie
if [ -f "$BUILD_DIR/build_config.env" ]; then
    source $BUILD_DIR/build_config.env
else
    error "Konfiguračný súbor $BUILD_DIR/build_config.env neexistuje"
fi

# Prejsť do pracovného adresára
cd $BUILD_DIR || error "Nemôžem prejsť do $BUILD_DIR"

# Nastavenie premenných pre kompiláciu
export CC="ccache gcc"
export CXX="ccache g++"
export CFLAGS="-O3 -march=native -mtune=native -fstack-protector-strong -flto=auto -fuse-linker-plugin -pipe -fcode-hoisting"
export CXXFLAGS="-O3 -march=native -mtune=native -fstack-protector-strong -flto=auto -fuse-linker-plugin -pipe -fcode-hoisting"
export LDFLAGS="-Wl,-Bsymbolic-functions -Wl,-z,relro -Wl,-z,now -flto=auto -fuse-linker-plugin"
export LUAJIT_LIB=/usr/local/lib
export LUAJIT_INC=/usr/local/include/luajit-2.1
# Nastavenie optimalizácie pre jemalloc
export MALLOC_CONF="background_thread:true,dirty_decay_ms:1000,muzzy_decay_ms:1000,tcache:true"

# Kompilácia Nginx
info "Začínam kompiláciu Nginx $NGINX_VERSION..."
cd nginx-$NGINX_VERSION

# Konfigurácia s podporou HTTP/3 QUIC
USE_QUIC=0
if [ -f "auto/modules/ngx_http_v3_module.c" ]; then
    info "Detekovaná podpora pre HTTP/3 QUIC, zapínam..."
    USE_QUIC=1
fi

# Základné konfiguračné parametre
CONFIG_ARGS="--prefix=$INSTALL_DIR \
  --sbin-path=/usr/sbin/nginx \
  --modules-path=$INSTALL_DIR/modules \
  --conf-path=$INSTALL_DIR/nginx.conf \
  --error-log-path=/var/log/nginx/error.log \
  --http-log-path=/var/log/nginx/access.log \
  --pid-path=/var/run/nginx.pid \
  --lock-path=/var/run/nginx.lock \
  --http-client-body-temp-path=/var/cache/nginx/client_temp \
  --http-proxy-temp-path=/var/cache/nginx/proxy_temp \
  --http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp \
  --http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp \
  --http-scgi-temp-path=/var/cache/nginx/scgi_temp \
  --user=nginx \
  --group=nginx \
  --with-compat \
  --with-file-aio \
  --with-threads \
  --with-pcre-jit \
  --with-jemalloc=/usr/local \
  --with-debug \
  --with-http_addition_module \
  --with-http_auth_request_module \
  --with-http_dav_module \
  --with-http_flv_module \
  --with-http_gunzip_module \
  --with-http_gzip_static_module \
  --with-http_mp4_module \
  --with-http_random_index_module \
  --with-http_realip_module \
  --with-http_secure_link_module \
  --with-http_slice_module \
  --with-http_ssl_module \
  --with-http_stub_status_module \
  --with-http_sub_module \
  --with-http_v2_module \
  --with-http_ssl_stapling_module \
  --with-http_ssl_stapling_responder_module \
  --with-mail \
  --with-mail_ssl_module \
  --with-stream \
  --with-stream_realip_module \
  --with-stream_ssl_module \
  --with-stream_ssl_preread_module \
  --with-google_perftools_module"

# PCRE2 nastavenia
if [ -d "$BUILD_DIR/pcre2-${PCRE2_VERSION}" ]; then
    info "Používam PCRE2 zo zdrojov..."
    CONFIG_ARGS="$CONFIG_ARGS --with-pcre=$BUILD_DIR/pcre2-${PCRE2_VERSION} --with-pcre-jit"
fi

# zlib-cloudflare nastavenia
if [ -d "$BUILD_DIR/zlib-cloudflare" ]; then
    info "Používam optimalizovaný zlib od Cloudflare..."
    CONFIG_ARGS="$CONFIG_ARGS --with-zlib=$BUILD_DIR/zlib-cloudflare --with-zlib-opt=-O3"
fi

# Pridanie HTTP/3 ak je dostupný
if [ "$USE_QUIC" -eq 1 ]; then
    CONFIG_ARGS="$CONFIG_ARGS --with-http_v3_module"
    
    # Ak používame oficiálny QUIC modul, použijeme OpenSSL 3.x
    if [ -d "$OPENSSL_DIR" ]; then
        CONFIG_ARGS="$CONFIG_ARGS --with-openssl=$OPENSSL_DIR"
    else
        warn "Adresár s OpenSSL nebol nájdený, QUIC nemusí fungovať správne"
    fi
else
    # Štandardná konfigurácia s HTTP/3 QUIC od Cloudflare
    CONFIG_ARGS="$CONFIG_ARGS --with-http_v3_module"
    
    if [ -d "$BUILD_DIR/quiche" ]; then
        CONFIG_ARGS="$CONFIG_ARGS --with-quiche=$BUILD_DIR/quiche"
    else
        warn "Quiche modul nebol nájdený, HTTP/3 bude deaktivované"
        CONFIG_ARGS=$(echo "$CONFIG_ARGS" | sed 's/--with-http_v3_module//')
    fi
fi

# Pridanie optimalizácie kompilátora a linkera
CONFIG_ARGS="$CONFIG_ARGS \
  --with-cc-opt=\"-I/usr/local/pcre2/include -I/usr/local/zlib-cf/include -I/usr/local/include -I/usr/include -O3 -march=native -mtune=native -fstack-protector-strong -flto=auto -fPIC -fPIE -DTCP_FASTOPEN=23 -fcode-hoisting\" \
  --with-ld-opt=\"-L/usr/local/pcre2/lib -L/usr/local/zlib-cf/lib -L/usr/local/lib -Wl,-Bsymbolic-functions -Wl,-z,relro -Wl,-z,now -fPIC -ljemalloc -lpcre -lssl -lcrypto -ldl -lz -flto=auto -pie\" \
  --with-openssl-opt=\"enable-tls1_3 no-weak-ssl-ciphers enable-ec_nistp_64_gcc_128 -DOPENSSL_NO_HEARTBEATS\""

# Pridanie dynamických modulov
CONFIG_ARGS="$CONFIG_ARGS \
  --add-dynamic-module=$BUILD_DIR/ModSecurity-nginx"

# Pridanie zstd modulu
if [ -d "$BUILD_DIR/zstd-nginx-module" ]; then
    info "Pridávam zstd kompresný modul..."
    CONFIG_ARGS="$CONFIG_ARGS --add-module=$BUILD_DIR/zstd-nginx-module"
fi

# Kontrola existencie adresárov modulov
MODULES=(
    "ngx_pagespeed" 
    "ngx_cache_purge" 
    "headers-more-nginx-module" 
    "ngx_brotli" 
    "nginx-module-vts" 
    "redis2-nginx-module" 
    "nginx-rtmp-module" 
    "ngx_http_geoip2_module" 
    "lua-nginx-module" 
    "ngx_devel_kit" 
    "ngx_http_substitutions_filter_module" 
    "ngx_dynamic_upstream" 
    "ngx_http_auth_pam_module" 
    "nginx_http_push_module" 
    "njs/nginx"
    "ngx_small_light"
    "ngx-fancyindex"
)

# Pridanie dostupných modulov
for module in "${MODULES[@]}"; do
    if [ -d "$BUILD_DIR/$module" ]; then
        CONFIG_ARGS="$CONFIG_ARGS --add-dynamic-module=$BUILD_DIR/$module"
    else
        warn "Modul $module nebol nájdený, preskakujem"
    fi
done

# Kontrola upload modulu
if [ -d "$BUILD_DIR/nginx-upload-progress-module" ]; then
    CONFIG_ARGS="$CONFIG_ARGS --add-dynamic-module=$BUILD_DIR/nginx-upload-progress-module"
elif [ -d "$BUILD_DIR/nginx-upload-module" ]; then
    CONFIG_ARGS="$CONFIG_ARGS --add-dynamic-module=$BUILD_DIR/nginx-upload-module"
fi

# Spustenie konfigurácie
echo "./configure $CONFIG_ARGS" | bash

# Kompilácia s paralelizáciou
info "Kompilujem Nginx s ${YELLOW}$(nproc)${NC} vláknami..."
make -j$(nproc)

# Inštalácia
info "Inštalujem Nginx..."
make install

# Vytvorenie potrebných adresárov
mkdir -p /var/cache/nginx/client_temp \
         /var/cache/nginx/proxy_temp \
         /var/cache/nginx/fastcgi_temp \
         /var/cache/nginx/uwsgi_temp \
         /var/cache/nginx/scgi_temp

# Vytvorenie cache adresárov
mkdir -p /var/cache/nginx/proxy_cache
mkdir -p /var/cache/nginx/fastcgi_cache

# Ak je ngx_pagespeed dostupný, vytvoríme cache adresár
if [ -d "$BUILD_DIR/ngx_pagespeed" ]; then
    mkdir -p /var/cache/ngx_pagespeed
    chown -R nginx:nginx /var/cache/ngx_pagespeed
fi

# Nastavenie správnych práv
chown -R nginx:nginx /var/cache/nginx
chown -R nginx:nginx /var/log/nginx

info "Kompilácia a inštalácia Nginx bola úspešne dokončená."
exit 0