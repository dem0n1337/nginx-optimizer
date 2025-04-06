#!/bin/bash
# 05_configure_system.sh - Konfigurácia a optimalizácia systému po kompilácii
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

# Vytvorenie systemd služby
info "Vytváram systemd službu pre Nginx..."
cat > /etc/systemd/system/nginx.service << 'EOF'
[Unit]
Description=The NGINX HTTP and reverse proxy server with optimized compilation
After=network.target nss-lookup.target

[Service]
Type=forking
PIDFile=/var/run/nginx.pid
ExecStartPre=/usr/sbin/nginx -t
ExecStart=/usr/sbin/nginx
ExecReload=/usr/sbin/nginx -s reload
ExecStop=/bin/kill -s QUIT $MAINPID
PrivateTmp=true
ProtectSystem=full
NoNewPrivileges=true
PrivateDevices=true
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
MemoryDenyWriteExecute=true
RestrictRealtime=true
LimitNOFILE=65535
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
EOF

# Vytvorenie užívateľa nginx, ak neexistuje
if ! id -u nginx > /dev/null 2>&1; then
    info "Vytváram užívateľa nginx..."
    useradd -r -s /sbin/nologin -M nginx
fi

# Vytvorenie základných adresárov
mkdir -p /var/www/html
mkdir -p /var/cache/nginx
mkdir -p /var/log/nginx

# Vytvorenie záložnej kópie konfigurácie
if [ -f "$INSTALL_DIR/nginx.conf" ]; then
    info "Vytváram záložnú kópiu pôvodnej konfigurácie..."
    cp $INSTALL_DIR/nginx.conf $INSTALL_DIR/nginx.conf.bak
fi

# Nastavenie správnych oprávnení
chown -R nginx:nginx /var/www/html
chown -R nginx:nginx /var/cache/nginx
chown -R nginx:nginx /var/log/nginx
chmod 750 /var/www/html
chmod 700 /var/cache/nginx
chmod 755 /var/log/nginx

# Vytvorenie základnej stránky
cat > /var/www/html/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Vitajte v optimalizovanom Nginx!</title>
    <style>
        body {
            width: 35em;
            margin: 0 auto;
            font-family: Tahoma, Verdana, Arial, sans-serif;
        }
    </style>
</head>
<body>
    <h1>Vitajte v optimalizovanom Nginx!</h1>
    <p>Ak vidíte túto stránku, tak optimalizovaný Nginx server bol úspešne nainštalovaný a funguje.</p>

    <p>Pre viac informácií o Nginx, prosím navštívte:
    <a href="https://nginx.org/">nginx.org</a>.<br/>

    <p>Pre viac informácií o tejto optimalizovanej verzii, navštívte GitHub repozitár.</p>

    <p><em>Ďakujeme, že používate optimalizovaný Nginx.</em></p>
</body>
</html>
EOF

# Konfigurácia TLS a protokolov
info "Konfigurujem TLS protokoly a šifry..."
configure_tls_protocols

# Konfigurácia SSL certifikátového cache ak je podporované
info "Konfigurujem SSL certifikátový cache..."
configure_ssl_cert_cache

# Vytvorenie konfiguračných šablón
info "Vytváram konfiguračné šablóny..."
create_config_templates

# Konfigurácia logrotate
info "Konfigurujem rotáciu logov..."
configure_logrotate

# Reštart systemd
info "Reštartujem systemd daemon..."
systemctl daemon-reload

# Povolenie služby
info "Povolujem Nginx službu..."
systemctl enable nginx

# Kontrola konfigurácie
info "Kontrolujem konfiguráciu Nginx..."
if ! nginx -t; then
    warn "Konfigurácia Nginx obsahuje chyby. Prosím, skontrolujte ju ručne."
else
    info "Konfigurácia Nginx je v poriadku."
    # Spustenie služby
    info "Spúšťam Nginx službu..."
    systemctl start nginx
fi

# Finálna správa
info "Konfigurácia systému bola úspešne dokončená."
info "Nginx je nakonfigurovaný a beží na porte 80 a 443 (ak ste nakonfigurovali SSL)."
info "Základná stránka je dostupná na: http://localhost/"
info "Konfiguračné súbory sú umiestnené v: $INSTALL_DIR"
info "Šablóny konfigurácie sú umiestnené v: $INSTALL_DIR/conf/templates"
info "Pre spustenie Nginx vykonajte: systemctl start nginx"
exit 0

# Funkcie pre TLS a protokolové konfigurácie
configure_tls_protocols() {
  # Detekcia podpory TLS 1.3
  TLS13_SUPPORTED=0
  if [ -f "$INSTALL_DIR/modules/ngx_http_ssl_module.so" ]; then
    objdump -T "$INSTALL_DIR/modules/ngx_http_ssl_module.so" | grep -q "TLSv1_3" && TLS13_SUPPORTED=1
  fi
  
  # Vytvorenie TLS konfigurácie
  mkdir -p $INSTALL_DIR/conf
  if [ "$TLS13_SUPPORTED" -eq 1 ]; then
    info "Konfigurujem s podporou TLS 1.3"
    cat > "$INSTALL_DIR/conf/ssl_protocols.conf" <<EOF
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers on;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
EOF
  else
    info "Konfigurujem len s podporou TLS 1.2"
    cat > "$INSTALL_DIR/conf/ssl_protocols.conf" <<EOF
ssl_protocols TLSv1.2;
ssl_prefer_server_ciphers on;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
EOF
  fi
  
  # Pridanie HTTP/2 alebo HTTP/3 konfigurácie na základe QUIC podpory
  if [ -f "$BUILD_DIR/aws-lc/build/ssl/libssl.a" ] && grep -q "http_v3_module" "$INSTALL_DIR/sbin/nginx" ; then
    cat >> "$INSTALL_DIR/conf/ssl_protocols.conf" <<EOF
# HTTP/3 a QUIC povolené s AWS-LC
http3 on;
quic_retry on;
quic_gso on;
EOF
  else
    cat >> "$INSTALL_DIR/conf/ssl_protocols.conf" <<EOF
# HTTP/2 povolené (HTTP/3 nie je k dispozícii)
http2 on;
EOF
  fi
  
  # Pridanie include smerníc do nginx.conf
  if [ -f "$INSTALL_DIR/nginx.conf" ]; then
    if ! grep -q "ssl_protocols.conf" "$INSTALL_DIR/nginx.conf"; then
      sed -i 's|http {|http {\n    include '$INSTALL_DIR'/conf/ssl_protocols.conf;|' "$INSTALL_DIR/nginx.conf"
    fi
  fi
}

# Funkcia na konfiguráciu SSL certifikačného cache
configure_ssl_cert_cache() {
  if [ "$NGINX_VERSION" ]; then
    NGINX_VER_NUM=$(echo $NGINX_VERSION | sed 's/\.//g')
    if [ "$NGINX_VER_NUM" -ge 1274 ]; then
      info "Konfigurujem SSL certificate cache pre Nginx 1.27.4+"
      mkdir -p $INSTALL_DIR/conf
      cat > "$INSTALL_DIR/conf/ssl_cert_cache.conf" <<EOF
ssl_certificate_cache max=1000 inactive=20s valid=1m;
EOF
      # Pridanie include smernice do nginx.conf
      if [ -f "$INSTALL_DIR/nginx.conf" ]; then
        grep -q "ssl_cert_cache.conf" "$INSTALL_DIR/nginx.conf" || \
        sed -i 's|http {|http {\n    include '$INSTALL_DIR'/conf/ssl_cert_cache.conf;|' "$INSTALL_DIR/nginx.conf"
      fi
    fi
  fi
}

# Funkcia na vytvorenie konfiguračných šablón
create_config_templates() {
  mkdir -p $INSTALL_DIR/conf/templates
  
  # Vytvorenie základných šablón
  cat > "$INSTALL_DIR/conf/templates/security.conf" <<EOF
# Bezpečnostné hlavičky
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()";

# Skrytie verzie Nginx
server_tokens off;
EOF

  cat > "$INSTALL_DIR/conf/templates/performance.conf" <<EOF
# Výkonnostné optimalizácie
sendfile on;
tcp_nopush on;
tcp_nodelay on;
keepalive_timeout 65;
types_hash_max_size 2048;
server_names_hash_bucket_size 64;

# Cache súborov
open_file_cache max=10000 inactive=60s;
open_file_cache_valid 80s;
open_file_cache_min_uses 2;
open_file_cache_errors on;

# Kompresia
gzip on;
gzip_vary on;
gzip_proxied any;
gzip_comp_level 6;
gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;
EOF

  # Vytvorenie logformat podobného ako v referenčnej implementácii
  cat > "$INSTALL_DIR/conf/templates/logging.conf" <<EOF
log_format main '\$remote_addr - \$remote_user [\$time_local] "\$request" '
                '\$status \$body_bytes_sent "\$http_referer" '
                '"\$http_user_agent" "\$http_x_forwarded_for"'
                'rt=\$request_time uct="\$upstream_connect_time" uht="\$upstream_header_time" urt="\$upstream_response_time"';

access_log /var/log/nginx/access.log main buffer=16k flush=10s;
error_log /var/log/nginx/error.log warn;
EOF

  # Vytvorenie vzorovej vhost šablóny
  cat > "$INSTALL_DIR/conf/templates/vhost.conf.sample" <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name example.com www.example.com;
    
    # Presmerovanie na HTTPS
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name example.com www.example.com;
    
    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;
    
    # Zahrnutie štandardných konfigurácií
    include $INSTALL_DIR/conf/templates/security.conf;
    include $INSTALL_DIR/conf/templates/performance.conf;
    
    root /var/www/html;
    index index.html index.htm index.php;
    
    location / {
        try_files \$uri \$uri/ =404;
    }
    
    # PHP spracovanie (ak je potrebné)
    location ~ \.php$ {
        fastcgi_pass unix:/var/run/php-fpm/www.sock;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
    }
}
EOF

  info "Vytvoril som konfiguračné šablóny v $INSTALL_DIR/conf/templates"
}

# Funkcia na konfiguráciu logrotate
configure_logrotate() {
  cat > /etc/logrotate.d/nginx <<EOF
/var/log/nginx/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 nginx nginx
    sharedscripts
    postrotate
        if [ -f /var/run/nginx.pid ]; then
            kill -USR1 \`cat /var/run/nginx.pid\`
        fi
    endscript
}
EOF
  info "Nakonfigurovaná rotácia logov pre Nginx"
}