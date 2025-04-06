#!/bin/bash
# 05_configure_system.sh - Konfigurácia systému pre optimálnu prevádzku Nginx
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

# Vytvorenie nginx užívateľa ak neexistuje
if ! id -u nginx > /dev/null 2>&1; then
    info "Vytváram systémového užívateľa nginx..."
    useradd -r -s /bin/false nginx
fi

# Konfigurácia ModSecurity
info "Konfigurujem ModSecurity..."
mkdir -p $INSTALL_DIR/modsec

# Stiahnutie odporúčaného konfiguračného súboru
wget -q -P $INSTALL_DIR/modsec/ [https://raw.githubusercontent.com/SpiderLabs/ModSecurity/v3/master/modsecurity.conf-recommended](https://raw.githubusercontent.com/SpiderLabs/ModSecurity/v3/master/modsecurity.conf-recommended)
mv $INSTALL_DIR/modsec/modsecurity.conf-recommended $INSTALL_DIR/modsec/modsecurity.conf

# Skopírovanie unicode mapovania
cp $BUILD_DIR/ModSecurity/unicode.mapping $INSTALL_DIR/modsec/

# Zapneme aktívny režim ModSecurity
sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' $INSTALL_DIR/modsec/modsecurity.conf

# Vytvorenie hlavného konfiguračného súboru
cat > $INSTALL_DIR/modsec/main.conf << EOL
# Základná konfigurácia ModSecurity
Include $INSTALL_DIR/modsec/modsecurity.conf

# Pravidlá OWASP Core Rule Set (CRS)
# Odkomentujte nasledujúci riadok po inštalácii OWASP CRS
# Include $INSTALL_DIR/modsec/crs/crs-setup.conf
# Include $INSTALL_DIR/modsec/crs/rules/*.conf
EOL

# Vytvorenie systemd service pre Nginx
info "Vytváram systemd service pre Nginx..."
cat > /etc/systemd/system/nginx.service << EOL
[Unit]
Description=High-performance NGINX HTTP server with optimizations
After=network.target

[Service]
Type=forking
PIDFile=/var/run/nginx.pid
ExecStartPre=/usr/sbin/nginx -t -q -g 'daemon on; master_process on;'
ExecStart=/usr/sbin/nginx -g 'daemon on; master_process on;'
ExecReload=/usr/sbin/nginx -g 'daemon on; master_process on;' -s reload
ExecStop=/bin/kill -s QUIT \$MAINPID
TimeoutStopSec=5
KillMode=process
PrivateTmp=true
# TCP optimalizácie
LimitNOFILE=65535
# Ochrana adresného priestoru ASLR
AmbientCapabilities=CAP_NET_BIND_SERVICE
# Jemalloc optimalizácie
Environment="LD_PRELOAD=/usr/local/lib/libjemalloc.so"
Environment="MALLOC_CONF=background_thread:true,dirty_decay_ms:2000,muzzy_decay_ms:2000,tcache:true"

[Install]
WantedBy=multi-user.target
EOL

# Optimalizácia parametrov jadra
info "Optimalizujem parametre jadra pre webový server..."
cat > /etc/sysctl.d/99-nginx-performance.conf << EOL
# Maximálne TCP výkonnostné optimalizácie
net.core.somaxconn = 65536
net.core.netdev_max_backlog = 16384
net.ipv4.tcp_max_syn_backlog = 16384
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_max_tw_buckets = 1440000
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_congestion_control = bbr
EOL

# Aplikácia parametrov jadra
sysctl -p /etc/sysctl.d/99-nginx-performance.conf || warn "Nemôžem aplikovať parametre jadra"

# Nastavenie limitov systémových zdrojov pre nginx
info "Nastavujem limity systémových zdrojov pre nginx..."
cat > /etc/security/limits.d/nginx.conf << EOL
# Vyššie limity pre Nginx a PHP-FPM
nginx soft nofile 65536
nginx hard nofile 65536
www-data soft nofile 65536
www-data hard nofile 65536
EOL

# Vytvorenie základnej konfigurácie Nginx
info "Vytváram základnú konfiguráciu Nginx..."
cat > $INSTALL_DIR/nginx.conf << EOL
# Načítanie dynamických modulov
load_module modules/ngx_http_modsecurity_module.so;
load_module modules/ngx_http_brotli_filter_module.so;
load_module modules/ngx_http_brotli_static_module.so;
load_module modules/ngx_http_cache_purge_module.so;
load_module modules/ngx_http_headers_more_filter_module.so;
load_module modules/ngx_http_vhost_traffic_status_module.so;

user nginx;
worker_processes auto;
worker_cpu_affinity auto;
worker_rlimit_nofile 65535;
pid /var/run/nginx.pid;

events {
    worker_connections 65535;
    multi_accept on;
    use epoll;
}

http {
    include       mime.types;
    default_type  application/octet-stream;

    # Základné nastavenia
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    server_tokens off;
    
    # Logovací formát
    log_format main '\$remote_addr - \$remote_user [\$time_local] "\$request" '
                    '\$status \$body_bytes_sent "\$http_referer" '
                    '"\$http_user_agent" "\$http_x_forwarded_for" '
                    '\$request_time \$upstream_response_time';
    
    access_log /var/log/nginx/access.log main;
    error_log /var/log/nginx/error.log warn;
    
    # Kompresné nastavenia - Gzip
    gzip on;
    gzip_vary on;
    gzip_comp_level 6;
    gzip_min_length 256;
    gzip_proxied any;
    gzip_types
        application/atom+xml
        application/javascript
        application/json
        application/ld+json
        application/manifest+json
        application/rss+xml
        application/vnd.geo+json
        application/vnd.ms-fontobject
        application/wasm
        application/x-font-ttf
        application/x-web-app-manifest+json
        application/xhtml+xml
        application/xml
        font/opentype
        font/ttf
        font/eot
        font/otf
        image/bmp
        image/svg+xml
        image/x-icon
        text/cache-manifest
        text/calendar
        text/css
        text/javascript
        text/markdown
        text/plain
        text/vcard
        text/vnd.rim.location.xloc
        text/vtt
        text/x-component
        text/x-cross-domain-policy;
    
    # Brotli kompresia
    brotli on;
    brotli_comp_level 6;
    brotli_static on;
    brotli_types
        application/atom+xml
        application/javascript
        application/json
        application/ld+json
        application/manifest+json
        application/rss+xml
        application/vnd.geo+json
        application/vnd.ms-fontobject
        application/wasm
        application/x-font-ttf
        application/x-web-app-manifest+json
        application/xhtml+xml
        application/xml
        font/opentype
        font/ttf
        font/eot
        font/otf
        image/bmp
        image/svg+xml
        image/x-icon
        text/cache-manifest
        text/calendar
        text/css
        text/javascript
        text/markdown
        text/plain
        text/vcard
        text/vnd.rim.location.xloc
        text/vtt
        text/x-component
        text/x-cross-domain-policy;
    
    # ModSecurity
    modsecurity on;
    modsecurity_rules_file $INSTALL_DIR/modsec/main.conf;
    
    # Cache pre FastCGI (pre WordPress)
    fastcgi_cache_path /var/cache/nginx levels=1:2
                     keys_zone=WORDPRESS:100m
                     inactive=60m;
    fastcgi_cache_key "\$scheme\$request_method\$host\$request_uri";
    
    # Ukážkový server blok
    server {
        listen 80 default_server;
        listen [::]:80 default_server;
        
        server_name localhost;
        
        root /var/www/html;
        index index.php index.html;
        
        location / {
            try_files \$uri \$uri/ /index.php?\$args;
        }
        
        # PHP spracovanie
        location ~ \.php$ {
            fastcgi_pass unix:/var/run/php/php-fpm.sock;
            fastcgi_index index.php;
            fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
            include fastcgi_params;
        }
    }

    # Zahrň ďalšie konfiguračné súbory
    include $INSTALL_DIR/conf.d/*.conf;
}
EOL

# Vytvorenie adresárov pre dodatočné konfigurácie
mkdir -p $INSTALL_DIR/conf.d
mkdir -p $INSTALL_DIR/sites-available
mkdir -p $INSTALL_DIR/sites-enabled

# Konfigurácia pre virtuálne hosty
cat > $INSTALL_DIR/conf.d/virtual-hosts.conf << EOL
# Zahrnutie všetkých povolených stránok
include $INSTALL_DIR/sites-enabled/*.conf;
EOL

# Vytvorenie predpripravenej konfigurácie pre WordPress
cat > $INSTALL_DIR/sites-available/wordpress-example.conf << EOL
# Vzorová konfigurácia pre WordPress
server {
    listen 80;
    listen [::]:80;
    
    server_name example.com [www.example.com](www.example.com);
    
    root /var/www/example.com;
    index index.php index.html;
    
    # WordPress permalinks
    location / {
        try_files \$uri \$uri/ /index.php?\$args;
    }
    
    # Statický obsah
    location ~* \.(jpg|jpeg|gif|png|css|js|ico|webp|svg|woff|woff2|ttf|eot)$ {
        expires max;
        log_not_found off;
    }
    
    # Spracovanie PHP
    set \$skip_cache 0;
    
    # POST požiadavky a URL s query parametrami
    if (\$request_method = POST) {
        set \$skip_cache 1;
    }
    if (\$query_string != "") {
        set \$skip_cache 1;
    }
    
    # Vynechanie admin URL z cache
    if (\$request_uri ~* "/wp-admin/|/xmlrpc.php|wp-.*.php|/feed/|index.php|sitemap(_index)?.xml") {
        set \$skip_cache 1;
    }
    
    # Vynechanie prihlásených používateľov a komentujúcich
    if (\$http_cookie ~* "comment_author|wordpress_[a-f0-9]+|wp-postpass|wordpress_no_cache|wordpress_logged_in") {
        set \$skip_cache 1;
    }
    
    # PHP spracovanie
    location ~ \.php$ {
        try_files \$uri =404;
        fastcgi_pass unix:/var/run/php/php-fpm.sock;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
        fastcgi_cache_bypass \$skip_cache;
        fastcgi_no_cache \$skip_cache;
        fastcgi_cache WORDPRESS;
        fastcgi_cache_valid 60m;
    }
    
    # Vyčistenie cache
    location ~ /purge(/.*) {
        fastcgi_cache_purge WORDPRESS "\$scheme\$request_method\$host\$1";
    }
}
EOL

# Aktivácia služby Nginx
info "Aktivujem Nginx službu..."
systemctl daemon-reload
systemctl enable nginx

info "Konfigurácia systému bola úspešne dokončená."
info "Pre spustenie Nginx vykonajte: systemctl start nginx"
exit 0