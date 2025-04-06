#!/bin/bash
# install_optimized_nginx.sh - Inštalačný skript pre optimalizovaný Nginx z GitHub
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

# Nastavenie GitHub repozitára
GITHUB_USER="dem0n1337"
GITHUB_REPO="nginx-optimizer"
GITHUB_BRANCH="master"  # Používame vetvu master

# URL pre raw súbory na GitHub
GITHUB_RAW_URL="[https://raw.githubusercontent.com/$GITHUB_USER/$GITHUB_REPO/$GITHUB_BRANCH"](https://raw.githubusercontent.com/$GITHUB_USER/$GITHUB_REPO/$GITHUB_BRANCH")

# Vytvorenie dočasného adresára
TMP_DIR=$(mktemp -d)
info "Vytvorený dočasný adresár: $TMP_DIR"
cd $TMP_DIR

# Stiahnutie skriptov z GitHub
info "Sťahujem inštalačné skripty z GitHub..."
wget -q $GITHUB_RAW_URL/build_nginx_master.sh -O build_nginx_master.sh || error "Nemôžem stiahnuť build_nginx_master.sh"
wget -q $GITHUB_RAW_URL/01_install_dependencies.sh -O 01_install_dependencies.sh || error "Nemôžem stiahnuť 01_install_dependencies.sh"
wget -q $GITHUB_RAW_URL/02_download_sources.sh -O 02_download_sources.sh || error "Nemôžem stiahnuť 02_download_sources.sh"
wget -q $GITHUB_RAW_URL/03_install_modules.sh -O 03_install_modules.sh || error "Nemôžem stiahnuť 03_install_modules.sh"
wget -q $GITHUB_RAW_URL/04_compile_nginx.sh -O 04_compile_nginx.sh || error "Nemôžem stiahnuť 04_compile_nginx.sh"
wget -q $GITHUB_RAW_URL/05_configure_system.sh -O 05_configure_system.sh || error "Nemôžem stiahnuť 05_configure_system.sh"

# Nastavenie práv na spustenie
chmod +x build_nginx_master.sh
chmod +x 01_install_dependencies.sh
chmod +x 02_download_sources.sh
chmod +x 03_install_modules.sh
chmod +x 04_compile_nginx.sh
chmod +x 05_configure_system.sh

# Spustenie hlavného skriptu
info "Spúšťam inštaláciu..."
./build_nginx_master.sh

# Vyčistenie
cd /
rm -rf $TMP_DIR

info "Inštalácia optimalizovaného Nginx servera bola úspešne dokončená!"
info "Pre spustenie Nginx vykonajte: systemctl start nginx"
exit 0