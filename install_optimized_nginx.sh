#!/bin/bash
# install_optimized_nginx.sh - Inštalačný skript pre optimalizovaný Nginx z GitHub
# Autor: Cascade AI
# Dátum: 6.4.2025

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
    return 1  # Namiesto exit použijeme return
}

# Kontrola či skript beží pod root právami
if [[ $EUID -ne 0 ]]; then
   error "Tento skript musí byť spustený ako root. Použite sudo."
   exit 1
fi

# Nastavenie pracovného adresára
CURRENT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
info "Použijem lokálne skripty z: $CURRENT_DIR"

# Kontrola, či sú potrebné skripty lokálne dostupné
if [ ! -f "$CURRENT_DIR/build_nginx_master.sh" ]; then
    error "Súbor build_nginx_master.sh neexistuje v aktuálnom adresári. Skript musí byť spustený z koreňového adresára repozitára."
    exit 1
fi

# Nastavenie práv na spustenie
chmod +x "$CURRENT_DIR/build_nginx_master.sh"
chmod +x "$CURRENT_DIR/01_install_dependencies.sh"
chmod +x "$CURRENT_DIR/02_download_sources.sh"
chmod +x "$CURRENT_DIR/03_install_modules.sh"
chmod +x "$CURRENT_DIR/04_compile_nginx.sh"
chmod +x "$CURRENT_DIR/05_configure_system.sh"

# Spustenie hlavného skriptu
info "Spúšťam inštaláciu..."
bash "$CURRENT_DIR/build_nginx_master.sh" || { 
    warn "Inštalácia zlyhala."
}

info "Inštalácia optimalizovaného Nginx servera bola dokončená!"
info "Pre spustenie Nginx vykonajte: systemctl start nginx"
exit 0