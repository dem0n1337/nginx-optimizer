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
export CFLAGS="-O3 -march=native -mtune=native -fstack-protector-strong -flto -fuse-linker-plugin -pipe"
export CXXFLAGS="-O3 -march=native -mtune=native -fstack-protector-strong -flto -fuse-linker-plugin -pipe"
export LDFLAGS="-Wl,-Bsymbolic-functions -Wl,-z,relro -Wl,-z,now -flto -fuse-linker-plugin"
export LUAJIT_LIB=/usr/local/lib
export LUAJIT_INC=/usr/local/include/luajit-2.1

# Kompilácia Nginx
info "Začínam kompiláciu Nginx $NGINX_VERSION..."
cd nginx-$NGINX_VERSION

# Konfigurácia Nginx s podporou všetkých modulov a optimalizácií
./configure \
  --prefix=$INSTALL_DIR \
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
  --with-http_v3_module \
  --with-mail \
  --with-mail_ssl_module \
  --with-stream \
  --with-stream_realip_module \
  --with-stream_ssl_module \
  --with-stream_ssl_preread_module \
  --with-google_perftools_module \
  --with-cc-opt="-O3 -march=native -mtune=native -fstack-protector-strong -flto -fPIC -fPIE -DTCP_FASTOPEN=23 -I/usr/local/include -I/usr/include" \
  --with-ld-opt="-Wl,-Bsymbolic-functions -Wl,-z,relro -Wl,-z,now -fPIC -ljemalloc -lpcre -lssl -lcrypto -ldl -lz -flto -pie -L/usr/local/lib" \
  --with-openssl-opt="enable-tls1_3 no-weak-ssl-ciphers enable-ec_nistp_64_gcc_128 -DOPENSSL_NO_HEARTBEATS" \
  --with-quiche=$BUILD_DIR/quiche \
  --add-dynamic-module=$BUILD_DIR/ngx_pagespeed \
  --add-dynamic-module=$BUILD_DIR/ModSecurity-nginx \
  --add-dynamic-module=$BUILD_DIR/ngx_cache_purge \
  --add-dynamic-module=$BUILD_DIR/headers-more-nginx-module \
  --add-dynamic-module=$BUILD_DIR/ngx_brotli \
  --add-dynamic-module=$BUILD_DIR/nginx-module-vts \
  --add-dynamic-module=$BUILD_DIR/redis2-nginx-module \
  --add-dynamic-module=$BUILD_DIR/nginx-rtmp-module \
  --add-dynamic-module=$BUILD_DIR/ngx_http_geoip2_module \
  --add-dynamic-module=$BUILD_DIR/lua-nginx-module \
  --add-dynamic-module=$BUILD_DIR/ngx_devel_kit \
  --add-dynamic-module=$BUILD_DIR/ngx_http_substitutions_filter_module \
  --add-dynamic-module=$BUILD_DIR/nginx-upload-progress-module \
  --add-dynamic-module=$BUILD_DIR/ngx_dynamic_upstream \
  --add-dynamic-module=$BUILD_DIR/ngx_http_auth_pam_module \
  --add-dynamic-module=$BUILD_DIR/nginx_http_push_module \
  --add-dynamic-module=$BUILD_DIR/njs/nginx

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
         /var/cache/nginx/scgi_temp \
         /var/cache/ngx_pagespeed

# Nastavenie správnych práv
chown -R nginx:nginx /var/cache/nginx
chown -R nginx:nginx /var/cache/ngx_pagespeed
chown -R nginx:nginx /var/log/nginx

info "Kompilácia a inštalácia Nginx bola úspešne dokončená."
exit 0