#!/bin/bash
# build_nginx_master.sh - Hlavný skript pre kompiláciu Nginx s pokročilými optimalizáciami
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

# Kontrola či skript beží pod root právami
if [[ $EUID -ne 0 ]]; then
   error "Tento skript musí byť spustený ako root. Použite sudo."
fi

# Nastavenie pracovného adresára
export BUILD_DIR="/opt/nginx-build"
export INSTALL_DIR="/etc/nginx"
export SCRIPTS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

info "Vytváram pracovný adresár: $BUILD_DIR"
mkdir -p $BUILD_DIR
cd $BUILD_DIR

# Spustenie jednotlivých skriptov v správnom poradí
info "Spúšťam skript na inštaláciu závislostí..."
bash $SCRIPTS_DIR/01_install_dependencies.sh || error "Inštalácia závislostí zlyhala"

info "Spúšťam skript na stiahnutie zdrojových kódov..."
bash $SCRIPTS_DIR/02_download_sources.sh || error "Sťahovanie zdrojových kódov zlyhalo"

info "Spúšťam skript na inštaláciu modulov..."
bash $SCRIPTS_DIR/03_install_modules.sh || error "Inštalácia modulov zlyhala"

info "Spúšťam skript na kompiláciu Nginx..."
bash $SCRIPTS_DIR/04_compile_nginx.sh || error "Kompilácia Nginx zlyhala"

info "Spúšťam skript na konfiguráciu systému..."
bash $SCRIPTS_DIR/05_configure_system.sh || error "Konfigurácia systému zlyhala"

info "Kompilácia Nginx bola úspešne dokončená!"
info "Nginx je nainštalovaný v: $INSTALL_DIR"
info "Konfiguračné súbory sú v: $INSTALL_DIR/conf"
info "Pre spustenie Nginx použite: systemctl start nginx"

exit 0