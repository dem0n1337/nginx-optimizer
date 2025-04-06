#!/bin/bash
# 05_configure_system.sh - Konfigurácia a optimalizácia systému po kompilácii
# Autor: Cascade AI
# Dátum: 6.4.2025

# This script is heavily modified based on inc/nginx_install.inc logic

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

# --- Configuration Variables (Should match those used in 04_compile_nginx.sh) ---
# Kontrola BUILD_DIR
if [ -z "$BUILD_DIR" ]; then
    BUILD_DIR="/opt/nginx-build"
    warn "BUILD_DIR nie je nastavený, používam predvolenú hodnotu: $BUILD_DIR"
fi

# Kontrola INSTALL_DIR
if [ -z "$INSTALL_DIR" ]; then
    INSTALL_DIR="/etc/nginx" # This was the Nginx --prefix
    warn "INSTALL_DIR nie je nastavený, používam predvolenú hodnotu: $INSTALL_DIR"
fi

# Source build config if it exists (might contain NGINX_USER/GROUP etc.)
if [ -f "$BUILD_DIR/build_config.env" ]; then
    source "$BUILD_DIR/build_config.env"
fi

# Default Nginx user/group (should match configure args)
NGINX_USER=${NGINX_USER:-nginx}
NGINX_GROUP=${NGINX_GROUP:-nginx}

# Default UID/GID (Mimicking inc/nginx_install.inc)
DESIRED_UID=${DESIRED_UID:-1068} # Example UID from inc file
DESIRED_GID=${DESIRED_GID:-1068} # Example GID from inc file

# Other potentially needed variables (defaults)
NGINX_MAINHOSTNAME_BLANK_INDEX=${NGINX_MAINHOSTNAME_BLANK_INDEX:-n}
HN=$(hostname -f) # Get the fully qualified domain name

# --- Helper Functions (Derived from inc/nginx_install.inc) ---

# Function to check if a UID or GID is available
id_available() {
  ! getent passwd "$1" &>/dev/null && ! getent group "$1" &>/dev/null
}

# Function to find the next available UID/GID
find_next_available_id() {
  local start_id=$1
  local current_id=$start_id
  while ! id_available "$current_id"; do
    ((current_id++))
  done
  echo "$current_id"
}

# Function to fix mime types (derived from inc/nginx_mimetype.inc)
mimefix() {
  local mime_file="$INSTALL_DIR/mime.types"
  if [ -f "$mime_file" ]; then
    info "Applying mime.types fixes..."
    local bak_file="${mime_file}.bak-$(date +%Y%m%d-%H%M%S)"
    cp -af "$mime_file" "$bak_file"
    warn "Backed up existing mime types to $bak_file"

    # Add common types if missing (simplified from inc file)
    grep -q 'font/woff2' "$mime_file" || \
        sed -i '/^}/i \tfont/woff2                                       woff2;' "$mime_file"
    grep -q 'application/x-font-ttf' "$mime_file" || \
        sed -i '/^}/i \tapplication/x-font-ttf                          ttf;' "$mime_file"
    grep -q 'font/opentype' "$mime_file" || \
        sed -i '/^}/i \tfont/opentype                           otf;' "$mime_file"
    grep -q 'image/avif' "$mime_file" || \
        sed -i '/^}/i \timage/avif                                       avif;' "$mime_file"

    # Remove duplicate text/xml if application/xml exists
    if grep -q 'application/xml' "$mime_file" && grep -q 'text/xml' "$mime_file"; then
        sed -i '/text\/xml/d' "$mime_file"
    fi
  else
    warn "Mime types file not found: $mime_file"
  fi
}

# Function to setup logrotate
configure_logrotate() {
  info "Configuring logrotate for Nginx..."
  cat > /etc/logrotate.d/nginx <<EOF
/var/log/nginx/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 $NGINX_USER $NGINX_GROUP
    sharedscripts
    postrotate
        if [ -f /var/run/nginx.pid ]; then
            kill -USR1 `cat /var/run/nginx.pid`
        fi
    endscript
}
EOF
}

# --- Main Setup Logic (Derived from inc/nginx_install.inc) ---

info "Starting Nginx post-installation configuration..."

# Apply mime.types fixes
mimefix

# Determine the UID and GID to use
if id_available "$DESIRED_UID"; then
  NGINX_UID=$DESIRED_UID
  NGINX_GID=$DESIRED_GID
else
  warn "Desired UID/GID $DESIRED_UID/$DESIRED_GID is already in use. Finding next available..."
  NGINX_UID=$(find_next_available_id $((DESIRED_UID + 1)))
  NGINX_GID=$NGINX_UID # Use the same for GID in this case
  warn "Found next available UID/GID: $NGINX_UID/$NGINX_GID"
fi

info "Using UID=$NGINX_UID and GID=$NGINX_GID for Nginx user/group."

# Create or modify Nginx user/group
if ! getent group "$NGINX_GROUP" > /dev/null; then
    info "Creating group '$NGINX_GROUP' with GID $NGINX_GID..."
    groupadd -g "$NGINX_GID" "$NGINX_GROUP" || error "Failed to create group $NGINX_GROUP"
else
    CURRENT_GID=$(getent group "$NGINX_GROUP" | cut -d: -f3)
    if [ "$CURRENT_GID" -ne "$NGINX_GID" ]; then
        info "Modifying group '$NGINX_GROUP' GID from $CURRENT_GID to $NGINX_GID..."
        groupmod -g "$NGINX_GID" "$NGINX_GROUP" || error "Failed to modify group GID for $NGINX_GROUP"
    fi
fi

if ! getent passwd "$NGINX_USER" > /dev/null; then
    info "Creating user '$NGINX_USER' with UID $NGINX_UID and GID $NGINX_GID..."
    useradd -u "$NGINX_UID" -g "$NGINX_GID" -M -s /sbin/nologin -d /var/cache/nginx "$NGINX_USER" || error "Failed to create user $NGINX_USER"
else
    CURRENT_UID=$(getent passwd "$NGINX_USER" | cut -d: -f3)
    CURRENT_GID=$(getent passwd "$NGINX_USER" | cut -d: -f4)
    MOD_ARGS=""
    if [ "$CURRENT_UID" -ne "$NGINX_UID" ]; then
        info "Modifying user '$NGINX_USER' UID from $CURRENT_UID to $NGINX_UID..."
        MOD_ARGS="$MOD_ARGS -u $NGINX_UID"
    fi
    if [ "$CURRENT_GID" -ne "$NGINX_GID" ]; then
        info "Modifying user '$NGINX_USER' GID from $CURRENT_GID to $NGINX_GID..."
        MOD_ARGS="$MOD_ARGS -g $NGINX_GID"
    fi
    if [ -n "$MOD_ARGS" ]; then
        usermod $MOD_ARGS "$NGINX_USER" || error "Failed to modify user UID/GID for $NGINX_USER"
    fi
fi

info "Verifying nginx user details:"
id $NGINX_USER

# Set user file limits
info "Setting open file descriptor limits for Nginx user..."
LIMITS_CONF="/etc/security/limits.d/nginx.conf" # Use a dedicated file
LIMITS_VALUE=524288
if ! grep -q "^$NGINX_USER soft nofile $LIMITS_VALUE" "$LIMITS_CONF" 2>/dev/null; then
    echo "$NGINX_USER soft nofile $LIMITS_VALUE" | sudo tee "$LIMITS_CONF" > /dev/null
    echo "$NGINX_USER hard nofile $LIMITS_VALUE" | sudo tee -a "$LIMITS_CONF" > /dev/null
    info "Added limits to $LIMITS_CONF"
    # Note: These limits apply on next login. Nginx service limits are set in systemd unit.
else
    info "Nginx limits already seem to be set in $LIMITS_CONF"
fi

# Create necessary directories
info "Creating Nginx directories..."
umask 022 # Ensure default permissions
mkdir -p $INSTALL_DIR/conf.d
mkdir -p $INSTALL_DIR/snippets # Common practice for reusable snippets
mkdir -p $INSTALL_DIR/sites-available # Common practice
mkdir -p $INSTALL_DIR/sites-enabled   # Common practice
mkdir -p $INSTALL_DIR/ssl # For certificates
mkdir -p /var/log/nginx
mkdir -p /var/www/html # Default web root (can be changed)

# Create cache directories defined in configure
mkdir -p /var/cache/nginx/client_temp \
         /var/cache/nginx/proxy_temp \
         /var/cache/nginx/fastcgi_temp \
         /var/cache/nginx/uwsgi_temp \
         /var/cache/nginx/scgi_temp

# Create example proxy/fastcgi cache dirs (optional, depends on config)
mkdir -p /var/cache/nginx/proxy_cache
mkdir -p /var/cache/nginx/fastcgi_cache

# Create PageSpeed cache dir if module was added
if grep -q 'ngx_pagespeed' "/usr/sbin/nginx" &>/dev/null; then
    info "Creating PageSpeed cache directory..."
    mkdir -p /var/cache/ngx_pagespeed
    chown $NGINX_USER:$NGINX_GROUP /var/cache/ngx_pagespeed
fi

# Set ownership and permissions
info "Setting ownership and permissions..."
chown -R root:root $INSTALL_DIR
chmod 755 $INSTALL_DIR
chmod 750 $INSTALL_DIR/conf.d
chmod 750 $INSTALL_DIR/snippets
chmod 750 $INSTALL_DIR/sites-available
chmod 750 $INSTALL_DIR/sites-enabled
chmod 700 $INSTALL_DIR/ssl # Keep SSL private

chown -R $NGINX_USER:$NGINX_GROUP /var/cache/nginx
chmod -R 700 /var/cache/nginx # Nginx worker needs access

chown -R $NGINX_USER:$NGINX_GROUP /var/log/nginx
chmod 755 /var/log/nginx

chown $NGINX_USER:$NGINX_GROUP /var/www/html
chmod 755 /var/www/html

# Copy default config files if they don't exist (or replace)
info "Copying base configuration files..."
# Base nginx.conf (minimal example, needs customization)
cat > $INSTALL_DIR/nginx.conf << EOF
user $NGINX_USER $NGINX_GROUP;
worker_processes auto;
pid /var/run/nginx.pid;

# Load dynamic modules
include $INSTALL_DIR/modules/*.conf;

events {
    worker_connections 1024;
    # multi_accept on; # Consider enabling
}

http {
    include       $INSTALL_DIR/mime.types;
    default_type  application/octet-stream;

    log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for"';

    access_log  /var/log/nginx/access.log  main;
    error_log   /var/log/nginx/error.log   warn;

    sendfile        on;
    tcp_nopush     on;
    tcp_nodelay on;

    keepalive_timeout  65;

    #gzip  on;

    # Load virtual host configs
    include $INSTALL_DIR/conf.d/*.conf;
    include $INSTALL_DIR/sites-enabled/*;
}
EOF

# Copy mime.types if not present (Nginx install usually does this)
if [ ! -f "$INSTALL_DIR/mime.types" ]; then
    warn "$INSTALL_DIR/mime.types not found, attempting to copy from common locations..."
    if [ -f "/etc/mime.types" ]; then
        cp /etc/mime.types $INSTALL_DIR/mime.types
    # Add other potential source locations if needed
    fi
fi

# Copy fastcgi_params / scgi_params / uwsgi_params if not present
for param_file in fastcgi_params scgi_params uwsgi_params; do
    if [ ! -f "$INSTALL_DIR/$param_file" ]; then
        # Create basic versions or copy from known locations if available
        info "Creating basic $INSTALL_DIR/$param_file..."
        touch "$INSTALL_DIR/$param_file"
    fi
done

# Create htpasswd file if it doesn't exist
if [ ! -f "$INSTALL_DIR/conf/htpasswd" ]; then
    info "Creating empty htpasswd file: $INSTALL_DIR/conf/htpasswd"
    touch "$INSTALL_DIR/conf/htpasswd"
    chown root:$NGINX_GROUP "$INSTALL_DIR/conf/htpasswd" # Allow nginx group to read? Or keep root only?
    chmod 640 "$INSTALL_DIR/conf/htpasswd"
fi

# Optional: Create default index page if configured
if [[ "$NGINX_MAINHOSTNAME_BLANK_INDEX" = [yY] ]]; then
    info "Creating blank index.html..."
    local default_html_dir="/var/www/html" # Adjust if default root changed
    if [ -f "$default_html_dir/index.html" ]; then
        mv "$default_html_dir/index.html" "$default_html_dir/index.html-orig"
    fi
    touch "$default_html_dir/index.html"
    chown $NGINX_USER:$NGINX_GROUP "$default_html_dir/index.html"
fi

# Setup systemd service file
info "Configuring systemd service file..."
# Determine if running on CentOS 8/9 or equivalent for systemd specifics
OS_MAJOR_VERSION=$(grep '^VERSION_ID' /etc/os-release | cut -d'"' -f2 | cut -d'.' -f1)
SYSTEMD_DIR="/etc/systemd/system"
NGINX_SERVICE_FILE="$SYSTEMD_DIR/nginx.service"

cat > "$NGINX_SERVICE_FILE" <<EOF
[Unit]
Description=The NGINX HTTP and reverse proxy server (Custom Build)
After=syslog.target network-online.target remote-fs.target nss-lookup.target
Wants=network-online.target

[Service]
Type=forking
PIDFile=/var/run/nginx.pid
ExecStartPre=/usr/sbin/nginx -t -q -g 'daemon on; master_process on;'
ExecStart=/usr/sbin/nginx -g 'daemon on; master_process on;'
ExecReload=/usr/sbin/nginx -g 'daemon on; master_process on;' -s reload
ExecStop=/usr/sbin/nginx -s quit
TimeoutStopSec=5
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
NoNewPrivileges=true
# Consider adding more hardening options from systemd.exec

[Install]
WantedBy=multi-user.target
EOF

# Create systemd override for limits
info "Setting systemd service limits..."
SYSTEMD_OVERRIDE_DIR="$SYSTEMD_DIR/nginx.service.d"
mkdir -p "$SYSTEMD_OVERRIDE_DIR"
cat > "$SYSTEMD_OVERRIDE_DIR/limits.conf" <<TDG
[Service]
LimitNOFILE=524288
LimitNPROC=10240 # Example value, adjust as needed
TDG

# Create systemd override for restart behaviour (example from inc file)
if [[ "$OS_MAJOR_VERSION" -ge 8 ]]; then # CentOS 8+ style
    cat > "$SYSTEMD_OVERRIDE_DIR/restart.conf" <<TDG
[Unit]
StartLimitIntervalSec=30
StartLimitBurst=5

[Service]
Restart=on-failure
RestartSec=5s
TDG
elif [[ "$OS_MAJOR_VERSION" -eq 7 ]]; then # CentOS 7 style
     cat > "$SYSTEMD_OVERRIDE_DIR/restart.conf" <<TDG
[Service]
StartLimitInterval=30
StartLimitBurst=5
Restart=on-failure
RestartSec=5s
TDG
fi

# Configure logrotate
configure_logrotate

# Reload systemd
info "Reloading systemd daemon..."
systemctl daemon-reload

# Enable Nginx service
info "Enabling Nginx service..."
systemctl enable nginx

# Final check and start
info "Performing final configuration check (nginx -t)..."
if ! /usr/sbin/nginx -t; then
    error "Nginx configuration test failed! Please check $INSTALL_DIR/nginx.conf and included files."
else
    info "Nginx configuration test successful."
    info "Attempting to start Nginx service..."
    if systemctl start nginx; then
        info "Nginx service started successfully."
    else
        error "Failed to start Nginx service. Check logs: journalctl -u nginx and /var/log/nginx/error.log"
    fi
fi

info "Nginx installation and basic configuration complete."
info "Web root: /var/www/html"
info "Config dir: $INSTALL_DIR"
info "Log dir: /var/log/nginx"
exit 0