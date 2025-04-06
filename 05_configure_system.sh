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
wget -q -P $INSTALL_DIR/modsec/ https://raw.githubusercontent.com/SpiderLabs/ModSecurity/v3/master/modsecurity.conf-recommended
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
load_module modules/ngx_http_fancyindex_module.so;

user nginx;
worker_processes auto;
worker_cpu_affinity auto;
worker_rlimit_nofile 65535;
pid /var/run/nginx.pid;

# Optimalizácia pre jemalloc
env MALLOC_CONF=background_thread:true,dirty_decay_ms:1000,muzzy_decay_ms:1000,tcache:true;

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
    reset_timedout_connection on;
    
    # Logovací formát
    log_format main '\$remote_addr - \$remote_user [\$time_local] "\$request" '
                    '\$status \$body_bytes_sent "\$http_referer" '
                    '"\$http_user_agent" "\$http_x_forwarded_for" '
                    '\$request_time \$upstream_response_time';
    
    access_log /var/log/nginx/access.log main;
    error_log /var/log/nginx/error.log warn;
    
    # Nastavenie cache pre statický obsah
    open_file_cache max=200000 inactive=20s;
    open_file_cache_valid 30s;
    open_file_cache_min_uses 2;
    open_file_cache_errors on;
    
    # Nastavenia limitov a timeoutov
    client_body_timeout 15;
    client_header_timeout 15;
    send_timeout 15;
    
    # Proxy cache nastavenia
    proxy_cache_path /var/cache/nginx/proxy_cache levels=1:2 
                     keys_zone=PROXYCACHE:10m
                     max_size=1g
                     inactive=60m
                     use_temp_path=off;
    proxy_cache_key "\$scheme\$request_method\$host\$request_uri";
    proxy_cache_methods GET HEAD;
    proxy_cache_valid 200 302 10m;
    proxy_cache_valid 404 1m;
    
    # FastCGI cache nastavenia
    fastcgi_cache_path /var/cache/nginx/fastcgi_cache levels=1:2
                     keys_zone=WORDPRESS:100m
                     inactive=60m
                     max_size=1g
                     use_temp_path=off;
    fastcgi_cache_key "\$scheme\$request_method\$host\$request_uri";
    
    # SSL/TLS nastavenia - moderné a bezpečné
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384';
    ssl_ecdh_curve secp384r1:X25519:prime256v1;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;
    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 1.1.1.1 8.8.8.8 valid=300s;
    resolver_timeout 5s;
    
    # OCSP Stapling
    ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;
    
    # Security headers
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    
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
    
    # zstd kompresia
    zstd on;
    zstd_comp_level 5;
    zstd_min_length 256;
    zstd_types
        application/javascript
        application/json
        application/xml
        application/xhtml+xml
        application/atom+xml
        application/rss+xml
        application/wasm
        application/x-font-ttf
        application/x-web-app-manifest+json
        font/opentype
        font/ttf
        font/eot
        font/otf
        image/svg+xml
        text/css
        text/javascript
        text/plain
        text/xml;
    
    # ModSecurity
    modsecurity on;
    modsecurity_rules_file $INSTALL_DIR/modsec/main.conf;
    
    # HTTP/3 nastavenia
    http3 on;
    http3_max_concurrent_streams 256;
    quic_retry on;
    quic_gso on;
    
    # Ukážkový server blok
    server {
        listen 80 default_server;
        listen [::]:80 default_server;
        
        # HTTP/3 podporované porte
        listen 443 quic reuseport;
        listen [::]:443 quic reuseport;
        listen 443 ssl http2;
        listen [::]:443 ssl http2;
        
        server_name localhost;
        
        # Auto-redirect na HTTPS
        if (\$scheme = http) {
            return 301 https://\$host\$request_uri;
        }
        
        # Základný self-signed certifikát
        ssl_certificate $INSTALL_DIR/ssl/self-signed.crt;
        ssl_certificate_key $INSTALL_DIR/ssl/self-signed.key;
        
        # HTTP/3 oznámenie
        add_header Alt-Svc 'h3=":443"; ma=86400, h3-29=":443"; ma=86400';
        
        # Root adresár
        root /var/www/html;
        index index.php index.html;
        
        # Nastavenie pre FancyIndex
        location /downloads {
            fancyindex on;
            fancyindex_exact_size off;
            fancyindex_localtime on;
            fancyindex_name_length 255;
        }
        
        location / {
            try_files \$uri \$uri/ /index.php?\$args;
        }
        
        # PHP spracovanie
        location ~ \.php$ {
            try_files \$uri =404;
            fastcgi_pass unix:/var/run/php/php-fpm.sock;
            fastcgi_index index.php;
            fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
            include fastcgi_params;
            
            # FastCGI cache
            fastcgi_cache_bypass \$cookie_nocache \$arg_nocache\$arg_comment;
            fastcgi_cache_valid 200 302 60m;
            fastcgi_cache_min_uses 1;
            fastcgi_cache WORDPRESS;
            add_header X-Cache \$upstream_cache_status;
        }
        
        # Statické súbory
        location ~* \.(jpg|jpeg|gif|png|css|js|ico|webp|svg|woff|woff2|ttf|eot)$ {
            expires max;
            access_log off;
            log_not_found off;
            add_header Cache-Control "public, max-age=31536000";
        }
        
        # Obmedzenie prístupu k súborom .htaccess a .git
        location ~ /\.(?!well-known) {
            deny all;
            access_log off;
            log_not_found off;
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
mkdir -p $INSTALL_DIR/ssl
mkdir -p $INSTALL_DIR/letsencrypt

# Vytvorenie self-signed certifikátu
info "Vytváram self-signed certifikát pre lokálne testovanie..."
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout $INSTALL_DIR/ssl/self-signed.key \
  -out $INSTALL_DIR/ssl/self-signed.crt \
  -subj "/C=SK/ST=Slovakia/L=Bratislava/O=Nginx Optimizer/OU=DevOps/CN=localhost"

# Konfigurácia pre virtuálne hosty
cat > $INSTALL_DIR/conf.d/virtual-hosts.conf << EOL
# Zahrnutie všetkých povolených stránok
include $INSTALL_DIR/sites-enabled/*.conf;
EOL

# Vytvorenie predpripravenej konfigurácie pre WordPress
cat > $INSTALL_DIR/sites-available/wordpress-example.conf << EOL
# Vzorová konfigurácia pre WordPress s HTTP/3 a SSL/TLS
server {
    listen 80;
    listen [::]:80;
    
    # HTTP/3 a SSL porte
    listen 443 quic reuseport;
    listen [::]:443 quic reuseport;
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    
    server_name example.com www.example.com;
    
    # Auto-redirect na HTTPS
    if (\$scheme = http) {
        return 301 https://\$host\$request_uri;
    }
    
    # SSL certifikáty (Let's Encrypt)
    ssl_certificate $INSTALL_DIR/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key $INSTALL_DIR/letsencrypt/live/example.com/privkey.pem;
    
    # HTTP/3 oznámenie
    add_header Alt-Svc 'h3=":443"; ma=86400, h3-29=":443"; ma=86400';
    
    # Security headers
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    
    # CSP (Content Security Policy) - Odkomentujte a upravte podľa potreby
    # add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://www.google-analytics.com; img-src 'self' data: https://www.google-analytics.com; style-src 'self' 'unsafe-inline'; font-src 'self'; frame-src 'self'; object-src 'none'" always;
    
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
        
        # Optimalizácia obrázkov pomocou ngx_small_light (odkomentujte po inštalácii modulu)
        # set \$small_light_enable "on";
        # set \$small_light_url_pattern "_small_light";
        # small_light on;
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
    
    # Let's Encrypt certifikáty
    location ^~ /.well-known/acme-challenge/ {
        default_type "text/plain";
        root /var/www/letsencrypt;
    }
}
EOL

# Vytvorenie adresárov pre skripty
mkdir -p $INSTALL_DIR/scripts

# Certbot/Let's Encrypt konfigurácia
mkdir -p /var/www/letsencrypt

# Skript pre automatické vydanie/obnovu Let's Encrypt certifikátu
cat > $INSTALL_DIR/scripts/setup-letsencrypt.sh << 'EOL'
#!/bin/bash
# Let's Encrypt konfiguračný skript pre Nginx
# Použitie: ./setup-letsencrypt.sh example.com www.example.com

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

# Kontrola argumentov
if [ $# -lt 1 ]; then
    error "Použitie: $0 example.com [www.example.com ...]"
fi

DOMAINS=("$@")
PRIMARY_DOMAIN="${DOMAINS[0]}"
DOMAIN_ARGS=""

for domain in "${DOMAINS[@]}"; do
    DOMAIN_ARGS="$DOMAIN_ARGS -d $domain"
done

# Kontrola či je Certbot nainštalovaný
if ! command -v certbot >/dev/null 2>&1; then
    info "Certbot nie je nainštalovaný. Inštalujem..."
    
    # Detekcia distribúcie
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
    else
        error "Nepodporovaná distribúcia"
    fi
    
    case $OS in
        ubuntu|debian)
            apt-get update
            apt-get install -y certbot
            ;;
        centos|rhel|fedora|rocky|almalinux)
            if [ "$OS" = "centos" ] && [ "$VERSION" -lt 8 ]; then
                yum install -y epel-release
                yum install -y certbot
            else
                dnf install -y epel-release
                dnf install -y certbot
            fi
            ;;
        *)
            error "Nepodporovaná distribúcia: $OS"
            ;;
    esac
fi

# Vytvorenie adresára pre webroot autentifikáciu
mkdir -p /var/www/letsencrypt

# Vydanie certifikátu
info "Získavam Let's Encrypt certifikát pre doménu(y): ${DOMAINS[*]}"
certbot certonly --webroot -w /var/www/letsencrypt $DOMAIN_ARGS \
    --email admin@$PRIMARY_DOMAIN --agree-tos --non-interactive

# Vytvorenie symlinku do nginx SSL adresára
mkdir -p /etc/nginx/letsencrypt/live/$PRIMARY_DOMAIN
ln -sf /etc/letsencrypt/live/$PRIMARY_DOMAIN/fullchain.pem /etc/nginx/letsencrypt/live/$PRIMARY_DOMAIN/fullchain.pem
ln -sf /etc/letsencrypt/live/$PRIMARY_DOMAIN/privkey.pem /etc/nginx/letsencrypt/live/$PRIMARY_DOMAIN/privkey.pem

# Nastavenie automatickej obnovy
cat > /etc/cron.weekly/certbot-renew << 'CRON'
#!/bin/bash
certbot renew --quiet --post-hook "systemctl reload nginx"
CRON

chmod +x /etc/cron.weekly/certbot-renew

info "Let's Encrypt certifikát bol úspešne vydaný a nakonfigurovaný!"
info "Pre aktiváciu WordPress config súboru vykonajte:"
echo "  ln -s /etc/nginx/sites-available/wordpress-example.conf /etc/nginx/sites-enabled/"
echo "  systemctl reload nginx"

exit 0
EOL

chmod +x $INSTALL_DIR/scripts/setup-letsencrypt.sh

# Vytvorenie adresárov pre skripty
mkdir -p $INSTALL_DIR/scripts

# Automatické zálohovanie konfigurácie
cat > $INSTALL_DIR/scripts/backup-config.sh << 'EOL'
#!/bin/bash
# Automatické zálohovanie Nginx konfigurácie
# Autor: Cascade AI

# Nastavenie adresárov
NGINX_CONFIG="/etc/nginx"
BACKUP_DIR="/var/backups/nginx"
DATE=$(date +%Y-%m-%d_%H-%M-%S)
BACKUP_FILE="$BACKUP_DIR/nginx_config_$DATE.tar.gz"

# Vytvorenie zálohovacieho adresára
mkdir -p $BACKUP_DIR

# Vytvorenie zálohy
tar -czf $BACKUP_FILE $NGINX_CONFIG

# Vyčistenie starých záloh (staršie ako 30 dní)
find $BACKUP_DIR -type f -name "nginx_config_*.tar.gz" -mtime +30 -delete

echo "Nginx konfigurácia bola zálohovaná do $BACKUP_FILE"
exit 0
EOL

chmod +x $INSTALL_DIR/scripts/backup-config.sh

# Pridanie zálohovacieho skriptu do crontab
cat > /etc/cron.daily/nginx-backup << 'CRON'
#!/bin/bash
/etc/nginx/scripts/backup-config.sh
CRON

chmod +x /etc/cron.daily/nginx-backup

# Vytvorenie konfigurácie pre monitoring stavu Nginx
cat > $INSTALL_DIR/conf.d/status.conf << EOL
# Nginx Status a VTS monitoring
server {
    listen 127.0.0.1:8080;
    server_name localhost;
    
    # Basic status
    location /nginx_status {
        stub_status on;
        access_log off;
        allow 127.0.0.1;
        deny all;
    }
    
    # VTS status
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format html;
        access_log off;
        allow 127.0.0.1;
        deny all;
    }
}
EOL

# Aktivácia služby Nginx
info "Aktivujem Nginx službu..."
if [ -f "/etc/systemd/system/nginx.service" ]; then
    systemctl daemon-reload || warn "Nemôžem vykonať daemon-reload"
    systemctl enable nginx || warn "Nemôžem povoliť nginx službu"
    info "Nginx služba bola úspešne nakonfigurovaná"
else
    error "Súbor nginx.service nebol vytvorený, niečo sa pokazilo"
fi

info "Konfigurácia systému bola úspešne dokončená."
info "Pre spustenie Nginx vykonajte: systemctl start nginx"
exit 0