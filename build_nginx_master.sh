#!/bin/bash
# build_nginx_master.sh - Hlavný skript pre kompiláciu Nginx s pokročilými optimalizáciami
# Autor: Cascade AI
# Dátum: 6.4.2025

# Odstránim set -e aby sme mohli pokračovať po chybách, ale sledovali ich
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

# Premenná pre sledovanie celkového úspechu
INSTALL_SUCCESS=true

# Spustenie jednotlivých skriptov v správnom poradí
info "Spúšťam skript na inštaláciu závislostí..."
if ! bash $SCRIPTS_DIR/01_install_dependencies.sh; then
    warn "Inštalácia závislostí zlyhala, pokúšam sa pokračovať..."
    INSTALL_SUCCESS=false
fi

info "Spúšťam skript na stiahnutie zdrojových kódov..."
if ! bash $SCRIPTS_DIR/02_download_sources.sh; then
    warn "Sťahovanie zdrojových kódov zlyhalo, pokúšam sa pokračovať..."
    INSTALL_SUCCESS=false
fi

info "Spúšťam skript na inštaláciu modulov..."
if ! bash $SCRIPTS_DIR/03_install_modules.sh; then
    warn "Inštalácia modulov zlyhala, pokúšam sa pokračovať..."
    INSTALL_SUCCESS=false
fi

info "Spúšťam skript na kompiláciu Nginx..."
if ! bash $SCRIPTS_DIR/04_compile_nginx.sh; then
    warn "Kompilácia Nginx zlyhala, pokúšam sa pokračovať..."
    INSTALL_SUCCESS=false
fi

info "Spúšťam skript na konfiguráciu systému..."
if ! bash $SCRIPTS_DIR/05_configure_system.sh; then
    warn "Konfigurácia systému zlyhala, pokúšam sa pokračovať..."
    INSTALL_SUCCESS=false
fi

# Kontrola či je Nginx nainštalovaný a funguje
if [ -f "/usr/sbin/nginx" ]; then
    info "Kontrolujem inštaláciu Nginx..."
    if ! /usr/sbin/nginx -t &>/dev/null; then
        warn "Nginx konfigurácia obsahuje chyby!"
        INSTALL_SUCCESS=false
    fi
else
    warn "Nginx binárka nebola nájdená v /usr/sbin/nginx!"
    INSTALL_SUCCESS=false
fi

# Kontrola či existuje systemd service
if [ ! -f "/etc/systemd/system/nginx.service" ]; then
    warn "Nginx systemd service nebol vytvorený!"
    INSTALL_SUCCESS=false
fi

if [ "$INSTALL_SUCCESS" = true ]; then
    info "Kompilácia Nginx bola úspešne dokončená!"
    info "Nginx je nainštalovaný v: $INSTALL_DIR"
    info "Konfiguračné súbory sú v: $INSTALL_DIR/conf"
    info "Pre spustenie Nginx použite: systemctl start nginx"
    exit 0
else
    error "Inštalácia Nginx zlyhala! Skontrolujte predchádzajúce chybové správy."
fi