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
    echo -e "${GREEN}[INFO]${NC} $1" >&2 # Redirect to stderr
}

warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1" >&2 # Redirect to stderr
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2 # Redirect to stderr
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

# Default values (Mimicking CentminMod defaults, adjust in build_config.env as needed)
NGINX_USER=${NGINX_USER:-nginx}
NGINX_GROUP=${NGINX_GROUP:-nginx}
NGINX_HTTP2=${NGINX_HTTP2:-y}
NGINX_SSL=${NGINX_SSL:-y}
NGINX_STREAM=${NGINX_STREAM:-y}
NGINX_STREAM_SSL=${NGINX_STREAM_SSL:-y}
NGINX_STREAM_SSL_PREREAD=${NGINX_STREAM_SSL_PREREAD:-y}
NGINX_MAIL=${NGINX_MAIL:-y}
NGINX_MAIL_SSL=${NGINX_MAIL_SSL:-y}
NGINX_THREADS=${NGINX_THREADS:-y}
NGINX_FILE_AIO=${NGINX_FILE_AIO:-y}
NGINX_IPV6=${NGINX_IPV6:-y}
NGINX_DEBUG=${NGINX_DEBUG:-n} # Keep your debug setting (--with-debug)
NGINX_COMPAT=${NGINX_COMPAT:-y}
NGINX_HTTP_ADDITION=${NGINX_HTTP_ADDITION:-y}
NGINX_HTTP_AUTH_REQ=${NGINX_HTTP_AUTH_REQ:-y}
NGINX_HTTP_DAV=${NGINX_HTTP_DAV:-y}
NGINX_HTTP_FLV=${NGINX_HTTP_FLV:-y}
NGINX_HTTP_GUNZIP=${NGINX_HTTP_GUNZIP:-y}
NGINX_HTTP_GZIP_STATIC=${NGINX_HTTP_GZIP_STATIC:-y}
NGINX_HTTP_MP4=${NGINX_HTTP_MP4:-y}
NGINX_HTTP_RANDOM_INDEX=${NGINX_HTTP_RANDOM_INDEX:-y}
NGINX_HTTP_REALIP=${NGINX_HTTP_REALIP:-y}
NGINX_HTTP_SECURE_LINK=${NGINX_HTTP_SECURE_LINK:-y}
NGINX_HTTP_SLICE=${NGINX_HTTP_SLICE:-y}
NGINX_HTTP_STUB_STATUS=${NGINX_HTTP_STUB_STATUS:-y}
NGINX_HTTP_SUB=${NGINX_HTTP_SUB:-y}
NGINX_STREAM_REALIP=${NGINX_STREAM_REALIP:-y}
NGINX_GOOGLE_PERFTOOLS=${NGINX_GOOGLE_PERFTOOLS:-y}
NGINX_ZLIB_OPTIMIZE=${NGINX_ZLIB_OPTIMIZE:-y} # Assume Cloudflare zlib usage implies optimization desire
NGINX_LIBATOMIC=${NGINX_LIBATOMIC:-y} # Often needed with newer GCC/atomics
NGINX_JEMALLOC=${NGINX_JEMALLOC:-y}   # Your script uses jemalloc
NGINX_PCRE_JIT=${NGINX_PCRE_JIT:-y}

# Patch Control Variables (Set to 'y' in build_config.env to enable)
NGINX_GZIP_MULTI_STATUS=${NGINX_GZIP_MULTI_STATUS:-n}
NGINX_STAPLE_CACHE_OVERRIDE=${NGINX_STAPLE_CACHE_OVERRIDE:-n}
NGINX_STAPLE_CACHE_TTL=${NGINX_STAPLE_CACHE_TTL:-3600} # Default TTL if overridden
NGINX_IOURING_PATCH_BETA=${NGINX_IOURING_PATCH_BETA:-n}
NGINX_HPACK=${NGINX_HPACK:-n}
NGINX_HEADERSMORE_PATCH=${NGINX_HEADERSMORE_PATCH:-n} # Assumes headers-more v0.33
NGINX_SRCACHE_PATCH=${NGINX_SRCACHE_PATCH:-n} # Assumes srcache-nginx v0.32
NGINX_LUA_STREAM_PATCH=${NGINX_LUA_STREAM_PATCH:-n}
NGINX_LUA_PATCH=${NGINX_LUA_PATCH:-n} # Enables the set of OpenResty core patches for 1.27.0
FREENGINX_BACKPORT_PATCHES=${FREENGINX_BACKPORT_PATCHES:-n}

# Base flags (adjust as needed, these are examples)
# BASE_CFLAGS="-O3" # REMOVED - Let Nginx handle optimization
# BASE_LDFLAGS="-Wl,-Bsymbolic-functions -Wl,-z,relro -Wl,-z,now -pie" # REMOVED - Let Nginx handle linker flags

# TLS Library selection (prioritize user's choice: AWS-LC > OpenSSL 3 > BoringSSL > System)
USE_AWS_LC=n
USE_OPENSSL3=n
USE_BORINGSSL=n
USE_SYSTEM_SSL=n

# Check OpenSSL next
if [ -d "$BUILD_DIR/$OPENSSL_VERSION" ]; then
    info "Using OpenSSL 3.x from $BUILD_DIR/$OPENSSL_VERSION"
    USE_OPENSSL3=y
elif [ -d "$BUILD_DIR/boringssl" ]; then
    info "Using BoringSSL from $BUILD_DIR/boringssl"
    USE_BORINGSSL=y
else
    info "Using system's OpenSSL library."
    USE_SYSTEM_SSL=y
fi

# Function to generate Nginx configure arguments dynamically
generate_nginx_config_args() {
    local args=""
    local cc_opts="$cc_opts -I/usr/local/include -I/usr/include"

    # --- Basic Paths and User ---
    args="$args --prefix=$INSTALL_DIR"
    args="$args --sbin-path=/usr/sbin/nginx"
    args="$args --modules-path=$INSTALL_DIR/modules"
    args="$args --conf-path=$INSTALL_DIR/nginx.conf"
    args="$args --error-log-path=/var/log/nginx/error.log"
    args="$args --http-log-path=/var/log/nginx/access.log"
    args="$args --pid-path=/var/run/nginx.pid"
    args="$args --lock-path=/var/run/nginx.lock"
    args="$args --http-client-body-temp-path=/var/cache/nginx/client_temp"
    args="$args --http-proxy-temp-path=/var/cache/nginx/proxy_temp"
    args="$args --http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp"
    args="$args --http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp"
    args="$args --http-scgi-temp-path=/var/cache/nginx/scgi_temp"
    args="$args --user=$NGINX_USER"
    args="$args --group=$NGINX_GROUP"

    # --- Core Features (Based on CentminMod variables) ---
    [[ "$NGINX_COMPAT" = [yY] ]] && args="$args --with-compat"
    [[ "$NGINX_THREADS" = [yY] ]] && args="$args --with-threads"
    [[ "$NGINX_FILE_AIO" = [yY] ]] && args="$args --with-file-aio"
    [[ "$NGINX_IPV6" = [yY] ]] && args="$args --with-ipv6" # Note: This is default usually, added for clarity
    [[ "$NGINX_DEBUG" = [yY] ]] && args="$args --with-debug"

    # --- HTTP Modules ---
    [[ "$NGINX_HTTP_ADDITION" = [yY] ]] && args="$args --with-http_addition_module"
    [[ "$NGINX_HTTP_AUTH_REQ" = [yY] ]] && args="$args --with-http_auth_request_module"
    [[ "$NGINX_HTTP_DAV" = [yY] ]] && args="$args --with-http_dav_module"
    [[ "$NGINX_HTTP_FLV" = [yY] ]] && args="$args --with-http_flv_module"
    [[ "$NGINX_HTTP_GUNZIP" = [yY] ]] && args="$args --with-http_gunzip_module"
    [[ "$NGINX_HTTP_GZIP_STATIC" = [yY] ]] && args="$args --with-http_gzip_static_module"
    [[ "$NGINX_HTTP_MP4" = [yY] ]] && args="$args --with-http_mp4_module"
    [[ "$NGINX_HTTP_RANDOM_INDEX" = [yY] ]] && args="$args --with-http_random_index_module"
    [[ "$NGINX_HTTP_REALIP" = [yY] ]] && args="$args --with-http_realip_module"
    [[ "$NGINX_HTTP_SECURE_LINK" = [yY] ]] && args="$args --with-http_secure_link_module"
    [[ "$NGINX_HTTP_SLICE" = [yY] ]] && args="$args --with-http_slice_module"
    [[ "$NGINX_HTTP_STUB_STATUS" = [yY] ]] && args="$args --with-http_stub_status_module"
    [[ "$NGINX_HTTP_SUB" = [yY] ]] && args="$args --with-http_sub_module"
    [[ "$NGINX_HTTP2" = [yY] ]] && args="$args --with-http_v2_module"

    # --- Stream Modules ---
    if [[ "$NGINX_STREAM" = [yY] ]]; then
        args="$args --with-stream"
        [[ "$NGINX_STREAM_REALIP" = [yY] ]] && args="$args --with-stream_realip_module"
        if [[ "$NGINX_STREAM_SSL" = [yY] ]]; then
             args="$args --with-stream_ssl_module"
             [[ "$NGINX_STREAM_SSL_PREREAD" = [yY] ]] && args="$args --with-stream_ssl_preread_module"
        fi
    fi

    # --- Mail Modules ---
    if [[ "$NGINX_MAIL" = [yY] ]]; then
        args="$args --with-mail"
        [[ "$NGINX_MAIL_SSL" = [yY] ]] && args="$args --with-mail_ssl_module"
    fi

    # --- Optional Performance/Utility Modules ---
     [[ "$NGINX_GOOGLE_PERFTOOLS" = [yY] ]] && args="$args --with-google_perftools_module"

    # --- Libraries (PCRE, Zlib, SSL, Jemalloc, Libatomic) ---

    # PCRE2 (Prefer local build)
    if [ -d "$BUILD_DIR/pcre2-${PCRE2_VERSION}" ]; then
        args="$args --with-pcre=$BUILD_DIR/pcre2-${PCRE2_VERSION}"
        [[ "$NGINX_PCRE_JIT" = [yY] ]] && args="$args --with-pcre-jit"
        cc_opts="$cc_opts -I/usr/local/pcre2/include"
    else
        # Fallback to system PCRE (may lack JIT)
        warn "Using system PCRE. JIT support may be unavailable."
        args="$args --with-pcre"
        [[ "$NGINX_PCRE_JIT" = [yY] ]] && args="$args --with-pcre-jit"
    fi

    # Zlib (Prefer Cloudflare build)
    if [ -d "$BUILD_DIR/zlib-cloudflare" ]; then
        args="$args --with-zlib=$BUILD_DIR/zlib-cloudflare"
        [[ "$NGINX_ZLIB_OPTIMIZE" = [yY] ]] && args="$args --with-zlib-opt=-O3"
        cc_opts="$cc_opts -I/usr/local/zlib-cf/include"
    else
        warn "Using system zlib."
        args="$args --with-zlib=auto" # Nginx doesn't have a direct --with-zlib flag, relies on system find
    fi

    # TLS Library
    local openssl_opt="-DOPENSSL_NO_HEARTBEATS"
    if [[ "$USE_AWS_LC" = [yY] ]]; then
        info "Configuring with AWS-LC..."
        warn "AWS-LC usage was requested but is disabled, falling back..."
    fi
    
    # Use BoringSSL if available (PRIORITY)
    if [[ "$USE_BORINGSSL" = [yY] ]]; then
        info "Configuring with BoringSSL..."
        args="$args --with-openssl=$BUILD_DIR/boringssl"
        args="$args --with-http_v3_module" # Keep v3 for BoringSSL
        cc_opts="$cc_opts -I$BUILD_DIR/boringssl/include"
    # Use OpenSSL 3 if available and BoringSSL is not
    elif [[ "$USE_OPENSSL3" = [yY] ]]; then
        info "Configuring with OpenSSL 3.x..."
        args="$args --with-openssl=$BUILD_DIR/$OPENSSL_VERSION"
        args="$args --with-openssl-opt='$openssl_opt'"
        cc_opts="$cc_opts -I/usr/local/ssl/include"
    # Fallback to system OpenSSL
    elif [[ "$USE_SYSTEM_SSL" = [yY] ]]; then
        info "Configuring with system OpenSSL..."
        args="$args --with-openssl=auto"
    fi
    # Always include SSL module if selected
    [[ "$NGINX_SSL" = [yY] ]] && args="$args --with-http_ssl_module"

    # --- Third-Party Modules ---
    MODULES_STATIC=( # Modules typically built statically in CentminMod if enabled
        "$BUILD_DIR/zstd-nginx-module" # Add as static (--add-module)
    )
    MODULES_DYNAMIC=( # Modules typically built dynamically
        "$BUILD_DIR/ngx_pagespeed"
        "$BUILD_DIR/ngx_cache_purge"
        "$BUILD_DIR/headers-more-nginx-module"
        "$BUILD_DIR/ngx_brotli"
        "$BUILD_DIR/nginx-module-vts"
        "$BUILD_DIR/redis2-nginx-module"
        "$BUILD_DIR/nginx-rtmp-module"
        "$BUILD_DIR/ngx_http_substitutions_filter_module"
        "$BUILD_DIR/ngx_dynamic_upstream"
        "$BUILD_DIR/ngx_http_auth_pam_module"
        "$BUILD_DIR/nginx_http_push_module"
        "$BUILD_DIR/njs/nginx" # Path for NJS module
        "$BUILD_DIR/ngx-fancyindex"
        "$BUILD_DIR/nginx-upload-module"
        # "$BUILD_DIR/ModSecurity-nginx" # Added dynamic based on user script - REMOVED
    )
    # Add upload module variations
    if [ -d "$BUILD_DIR/nginx-upload-progress-module" ]; then
        MODULES_DYNAMIC+=("$BUILD_DIR/nginx-upload-progress-module")
    elif [ -d "$BUILD_DIR/nginx-upload-module" ]; then
        MODULES_DYNAMIC+=("$BUILD_DIR/nginx-upload-module")
    fi

    for module_path in "${MODULES_STATIC[@]}"; do
        if [ -d "$module_path" ]; then
             info "Adding static module: $(basename $module_path)"
             args="$args --add-module=$module_path"
        else
             warn "Static module path not found: $module_path"
        fi
    done

    for module_path in "${MODULES_DYNAMIC[@]}"; do
        if [ -d "$module_path" ]; then
             info "Adding dynamic module: $(basename $module_path)"
             args="$args --add-dynamic-module=$module_path"
        else
             # Don't warn for all, some are optional alternatives
             # warn "Dynamic module path not found: $module_path"
             : # No-op
        fi
    done

    # --- Compiler and Linker Flags Finalization ---
    # No longer explicitly adding cc_opts or ld_opts; relying on --with flags

    echo "$args"
}

# Funkcia na detekciu AWS-LC
AWS_LC_DETECTION() {
  if [ -f "$BUILD_DIR/aws-lc/include/openssl/ssl.h" ]; then
    grep -q "AWSLC" "$BUILD_DIR/aws-lc/include/openssl/ssl.h" && return 0 || return 1
  fi
  return 1
}

# Kompilácia Nginx
info "Začínam kompiláciu Nginx $NGINX_VERSION..."
cd nginx-$NGINX_VERSION || error "Nemôžem prejsť do nginx-$NGINX_VERSION"

# --- BEGIN ADDED/MODIFIED PATCHING LOGIC ---

# Define NGINX_DYNAMICTLS - Set this in build_config.env or globally if needed
# Example: export NGINX_DYNAMICTLS=y
NGINX_DYNAMICTLS=${NGINX_DYNAMICTLS:-y} # Default to enabling the dynamic TLS patch

# Function to apply patches conditionally
apply_nginx_patches() {
    info "Aplikujem patche na NGINX zdrojový kód (verzia $NGINX_VERSION)..."
    local NGINX_VER_NUM=$(echo "$NGINX_VERSION" | sed 's/\.//g') # e.g., 1027004
    local PATCH_DIR="../patches" # Assuming patches are one level up

    # --- Generic Patches from user script ---
    # Apply openssl3-compatibility patch
    if [ -f "$PATCH_DIR/openssl3-compatibility.patch" ]; then
        patch -p1 < $PATCH_DIR/openssl3-compatibility.patch || warn "OpenSSL 3.x compatibility patch sa nepodarilo aplikovať"
    else
        warn "Patch file not found: $PATCH_DIR/openssl3-compatibility.patch"
    fi

    # --- Dynamic TLS Patch (Cloudflare) ---
    if [[ "$NGINX_DYNAMICTLS" = [yY] ]]; then
        # For Nginx 1.27.x, this patch is likely not needed as dynamic TLS is built-in or handled differently.
        # The logic from inc/nginx_patch.inc stops applying this around 1.21.x
        # Keeping the check here for completeness but warning if attempted.
        # If a specific patch for 1.27.4 exists, update the filename.
        if [ -f "$PATCH_DIR/tls-dynamic.patch" ]; then
            warn "Dynamic TLS patch ($PATCH_DIR/tls-dynamic.patch) might not be applicable or needed for Nginx $NGINX_VERSION."
            # patch -p1 < $PATCH_DIR/tls-dynamic.patch || warn "TLS Dynamic Records patch sa nepodarilo aplikovať"
        else
            warn "Dynamic TLS patch file not found: $PATCH_DIR/tls-dynamic.patch (Likely not needed anyway)"
        fi
    fi

    # --- AWS-LC Patches (Conditional) ---
    if [[ "$USE_AWS_LC" = [yY] ]]; then
        info "Applying AWS-LC patches..."
        if [[ "$NGINX_VER_NUM" -ge 1274 ]]; then
            info "Aplikujem AWS-LC patche pre Nginx 1.27.4+"
            if [ -f "$PATCH_DIR/aws-lc-nginx-1.27.4.patch" ]; then
                patch -p1 < $PATCH_DIR/aws-lc-nginx-1.27.4.patch || warn "AWS-LC patch pre Nginx 1.27.4+ sa nepodarilo aplikovať"
            else
                warn "Patch file not found: $PATCH_DIR/aws-lc-nginx-1.27.4.patch"
            fi
            if [ -f "$PATCH_DIR/aws-lc-nginx2.patch" ]; then # ssl_curve support
                 patch -p1 < $PATCH_DIR/aws-lc-nginx2.patch || warn "AWS-LC ssl_curve patch sa nepodarilo aplikovať"
            else
                 warn "Patch file not found: $PATCH_DIR/aws-lc-nginx2.patch"
            fi
        elif [[ "$NGINX_VER_NUM" -ge 1273 ]]; then
             # Logic for 1.27.3 (kept for completeness, but current version is 1.27.4)
             info "Aplikujem AWS-LC patche pre Nginx 1.27.3"
             if [ -f "$PATCH_DIR/aws-lc-nginx-1.27.3.patch" ]; then
                 patch -p1 < $PATCH_DIR/aws-lc-nginx-1.27.3.patch || warn "AWS-LC patch pre Nginx 1.27.3+ sa nepodarilo aplikovať"
             else
                 warn "Patch file not found: $PATCH_DIR/aws-lc-nginx-1.27.3.patch"
             fi
             if [ -f "$PATCH_DIR/aws-lc-nginx2.patch" ]; then
                 patch -p1 < $PATCH_DIR/aws-lc-nginx2.patch || warn "AWS-LC ssl_curve patch sa nepodarilo aplikovať"
             else
                 warn "Patch file not found: $PATCH_DIR/aws-lc-nginx2.patch"
             fi
        else
            # Generic patch logic (unlikely to be hit with 1.27.4)
            info "Aplikujem generické AWS-LC patche"
            if [ -f "$PATCH_DIR/aws-lc-nginx.patch" ]; then
                 patch -p1 < $PATCH_DIR/aws-lc-nginx.patch || warn "AWS-LC generický patch sa nepodarilo aplikovať"
            else
                 warn "Patch file not found: $PATCH_DIR/aws-lc-nginx.patch"
            fi
        fi
    fi

    # --- Gzip Multi-Status Patch ---
    if [[ "$NGINX_GZIP_MULTI_STATUS" = [yY] ]]; then
        # This patch targetted 1.25.0+ in inc file.
        info "Applying Gzip Multi-Status patch..."
        if [ -f "$PATCH_DIR/nginx-gzip-207-status.patch" ]; then
             patch -p1 < $PATCH_DIR/nginx-gzip-207-status.patch || warn "Gzip Multi-Status patch sa nepodarilo aplikovať"
        else
            warn "Patch file not found: $PATCH_DIR/nginx-gzip-207-status.patch"
        fi
    fi

    # --- OCSP TTL Override Patch ---
    if [[ "$NGINX_STAPLE_CACHE_OVERRIDE" = [yY] ]]; then
        info "Applying OCSP Stapling TTL override (TTL: $NGINX_STAPLE_CACHE_TTL seconds)..."
        local ocsp_file="src/event/ngx_event_openssl_stapling.c"
        if [ -f "$ocsp_file" ]; then
            # Check if patch already applied (simple grep check)
            if ! grep -q "now + $NGINX_STAPLE_CACHE_TTL" "$ocsp_file"; then
                 # Use sed to replace the default 3600 with the desired TTL
                 sed -i.bak "s|now + 3600|now + $NGINX_STAPLE_CACHE_TTL|" "$ocsp_file" || warn "Failed to apply OCSP TTL override via sed"
                 if grep -q "now + $NGINX_STAPLE_CACHE_TTL" "$ocsp_file"; then
                     info "OCSP TTL override applied via sed."
                 else
                     warn "Failed to verify OCSP TTL override after sed attempt."
                 fi
            else
                info "OCSP TTL override seems to be already applied or matches default."
            fi
        else
            warn "Could not find $ocsp_file to apply OCSP TTL override."
        fi
    fi

    # --- IO Uring Patch ---
    if [[ "$NGINX_IOURING_PATCH_BETA" = [yY] ]]; then
        local KERNEL_NUMERICVER=$(uname -r | awk -F. '{ printf("%d%03d%03d%03d\n", $1,$2,$3,$4); }')
        if [[ "$NGINX_VER_NUM" -gt 1017000 && "$KERNEL_NUMERICVER" -ge 5001000000 ]]; then
             info "Applying IO Uring patch (Kernel >= 5.1 detected)..."
             # Requires liburing to be built and installed (handled in 03_install_modules.sh ideally)
             if [ -f "$PATCH_DIR/nginx_io_uring.patch" ]; then
                  patch -p1 < $PATCH_DIR/nginx_io_uring.patch || warn "IO Uring patch sa nepodarilo aplikovať"
             else
                 warn "Patch file not found: $PATCH_DIR/nginx_io_uring.patch"
             fi
        else
             warn "IO Uring patch requires Nginx > 1.17.0 and Kernel >= 5.1. Skipping."
        fi
    fi

    # --- HPACK Full Encoding Patch ---
    if [[ "$NGINX_HPACK" = [yY] ]]; then
         # inc/nginx_patch.inc applies nginx-1.25.0_http2-hpack.patch for 1.25.0+
         info "Applying HPACK Full Encoding patch..."
         if [ -f "$PATCH_DIR/nginx-1.25.0_http2-hpack.patch" ]; then
             patch -p1 < $PATCH_DIR/nginx-1.25.0_http2-hpack.patch || warn "HPACK Full Encoding patch sa nepodarilo aplikovať"
         else
             warn "Patch file not found: $PATCH_DIR/nginx-1.25.0_http2-hpack.patch"
         fi
    fi

    # --- Headers More Patch (for v0.33) ---
    if [[ "$NGINX_HEADERSMORE_PATCH" = [yY] ]]; then
        # inc/nginx_patch.inc applies headers-more-nginx-1.23.0.patch for Nginx 1.23.0+
        # Assuming this patch is still valid for 1.27.4 when using Headers More 0.33
        info "Applying Headers More patch (for v0.33 compatibility with Nginx 1.23.0+)..."
        if [ -d "$BUILD_DIR/headers-more-nginx-module" ]; then
            pushd "$BUILD_DIR/headers-more-nginx-module" > /dev/null
            patch -p1 < $PATCH_DIR/headers-more-nginx-1.23.0.patch || warn "Headers More patch sa nepodarilo aplikovať na zdroj modulu"
            popd > /dev/null
        else
            warn "Headers More module source directory not found for patching."
        fi
    fi

    # --- Srcache Patch (for v0.32) ---
    if [[ "$NGINX_SRCACHE_PATCH" = [yY] ]]; then
        # inc/nginx_patch.inc applies srcache-nginx-1.23.0.patch for Nginx 1.23.0+
        # Assuming this patch is still valid for 1.27.4 when using Srcache 0.32
        info "Applying Srcache patch (for v0.32 compatibility with Nginx 1.23.0+)..."
        if [ -d "$BUILD_DIR/srcache-nginx-module" ]; then # Adjust dir name if needed
            pushd "$BUILD_DIR/srcache-nginx-module" > /dev/null
            patch -p1 < $PATCH_DIR/srcache-nginx-1.23.0.patch || warn "Srcache patch sa nepodarilo aplikovať na zdroj modulu"
            popd > /dev/null
        else
            warn "Srcache module source directory not found for patching."
        fi
    fi

    # --- Lua Stream Patch (for Nginx 1.27.0+) ---
    if [[ "$NGINX_LUA_STREAM_PATCH" = [yY] ]]; then
        info "Applying Lua Stream patch (for Nginx 1.27.0+ compatibility)..."
        if [ -d "$BUILD_DIR/stream-lua-nginx-module" ]; then # Adjust dir name if needed
            pushd "$BUILD_DIR/stream-lua-nginx-module" > /dev/null
            patch -p1 < $PATCH_DIR/luanginx-1.27.0.patch || warn "Lua Stream patch sa nepodarilo aplikovať na zdroj modulu"
            popd > /dev/null
        else
            warn "Lua Stream module source directory not found for patching."
        fi
    fi

    # --- OpenResty Core Patches (for Nginx 1.27.0) ---
    if [[ "$NGINX_LUA_PATCH" = [yY] ]]; then
        info "Applying OpenResty core patches for Nginx 1.27.0 compatibility..."
        local OR_PATCH_SUBDIR="$PATCH_DIR/luanginx/nginx-1.27.0"
        if [ -d "$OR_PATCH_SUBDIR" ]; then
            for or_patch in "$OR_PATCH_SUBDIR"/*.patch; do
                if [ -f "$or_patch" ]; then
                     info "Applying OpenResty patch: $(basename $or_patch)"
                     # Use --dry-run first (optional but safer)
                     # patch -p1 --dry-run < "$or_patch" > /dev/null 2>&1
                     # if [ $? -eq 0 ]; then
                         patch -p1 < "$or_patch" || warn "OpenResty patch $(basename $or_patch) sa nepodarilo aplikovať"
                     # else
                     #    warn "OpenResty patch $(basename $or_patch) sa nedá aplikovať (už aplikovaný?)"
                     # fi
                fi
            done
        else
            warn "OpenResty patch subdirectory not found: $OR_PATCH_SUBDIR"
        fi
    fi

    # --- HTTP/2 Shutdown Fix Backport ---
    if [[ "$FREENGINX_BACKPORT_PATCHES" = [yY] ]]; then
        info "Applying HTTP/2 Shutdown Fix backport patch..."
        if [ -f "$PATCH_DIR/http2-shutdown-fix.patch" ]; then
             patch -p1 < $PATCH_DIR/http2-shutdown-fix.patch || warn "HTTP/2 Shutdown Fix patch sa nepodarilo aplikovať"
        else
            warn "Patch file not found: $PATCH_DIR/http2-shutdown-fix.patch"
        fi
    fi

    info "Patching complete."
}

# Apply patches before configuration
apply_nginx_patches

# --- END ADDED/MODIFIED PATCHING LOGIC ---

# Generate config args dynamically
CONFIG_ARGS=$(generate_nginx_config_args)

# Spustenie konfigurácie
info "Spúšťam ./configure ..."
# Log the command for debugging
info "Running: ./configure $CONFIG_ARGS"
./configure $CONFIG_ARGS || error "Konfigurácia Nginx zlyhala!"

# Kompilácia s paralelizáciou
info "Kompilujem Nginx s ${YELLOW}$(nproc)${NC} vláknami..."
make -j$(nproc)

# Inštalácia
info "Inštalujem Nginx..."
make install

# --- BEGIN REFACTORED POST-MAKE LOGIC ---

# Optional: Strip the binary if not debugging
STRIPNGINX=${STRIPNGINX:-y} # Default to stripping
if [[ "$STRIPNGINX" = [yY] && "$NGINX_DEBUG" != [yY] ]]; then
    local nginx_binary="/usr/sbin/nginx" # Path set during configure
    if [ -f "$nginx_binary" ]; then
        info "Stripping Nginx binary at $nginx_binary..."
        ls -lah "$nginx_binary"
        strip -s "$nginx_binary" || warn "Failed to strip $nginx_binary"
        ls -lah "$nginx_binary"
    else
        warn "Nginx binary not found at $nginx_binary for stripping."
    fi
fi

# Clean up build directory (optional)
# cd $BUILD_DIR
# rm -rf nginx-$NGINX_VERSION

# --- END REFACTORED POST-MAKE LOGIC ---

# Funkcia na validáciu bezpečnostných funkcií
validate_security() {
  local BINARY=$1
  info "Validujem bezpečnostné funkcie pre: $BINARY"
  
  # Kontrola PIE/RELRO/NX
  if command -v readelf >/dev/null 2>&1; then
    # Kontrola PIE
    if readelf -h "$BINARY" | grep -q "Type:[[:space:]]*EXEC"; then
      warn "$BINARY nie je skompilovaný ako PIE (Position Independent Executable)"
    else
      info "$BINARY je správne skompilovaný ako PIE"
    fi
    
    # Kontrola RELRO
    if readelf -l "$BINARY" | grep -q "GNU_RELRO"; then
      info "$BINARY má RELRO ochranu"
    else
      warn "$BINARY nemá RELRO ochranu"
    fi
    
    # Kontrola stack canary
    if readelf -s "$BINARY" | grep -q "__stack_chk_fail"; then
      info "$BINARY má stack canary ochranu"
    else
      warn "$BINARY nemá stack canary ochranu"
    fi
  else
    warn "readelf nie je k dispozícii, preskakujem validáciu bezpečnosti binárky"
  fi
}

# Funkcia na validáciu bezpečnosti modulov
verify_module_security() {
  info "Verifikujem bezpečnosť dynamických modulov..."
  for module in "$INSTALL_DIR/modules/"*.so; do
    if [ -f "$module" ]; then
      validate_security "$module"
    fi
  done
}

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

# Validácia bezpečnosti skompilovaného Nginx
validate_security "/usr/sbin/nginx"
verify_module_security

info "Kompilácia a inštalácia Nginx bola úspešne dokončená."
exit 0