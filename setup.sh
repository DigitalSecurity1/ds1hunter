#!/usr/bin/env bash
# DS1 Hunter - Quick Setup Script (venv + PostgreSQL)
# DigitalSecurity1 - "Hunt. Chain. Prove."
#
# Usage:  chmod +x setup.sh && ./setup.sh

set -e

BOLD="\033[1m"
CYAN="\033[0;36m"
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
RED="\033[0;31m"
RESET="\033[0m"

banner() {
  echo ""
  echo -e "${CYAN}${BOLD}"
  echo "╔═══════════════════════════════════╗"
  echo "║                                   ║"
  echo "║         🎯 DS1 HUNTER             ║"
  echo '║      "Hunt. Chain. Prove."        ║'
  echo "║                                   ║"
  echo "║       by DigitalSecurity1         ║"
  echo "║                                   ║"
  echo "╚═══════════════════════════════════╝"
  echo -e "${RESET}"
}

banner

echo -e "${CYAN}[+] Setting up DS1 Hunter...${RESET}"

# ─── Python venv ────────────────────────────────────────────────────────────
echo -e "${CYAN}[+] Creating Python virtual environment...${RESET}"
python3 -m venv .venv
source .venv/bin/activate

echo -e "${CYAN}[+] Installing Python dependencies...${RESET}"
pip install --upgrade pip -q
pip install -r requirements.txt -q
echo -e "${GREEN}[✓] Python deps installed${RESET}"

# ─── Playwright Chromium ─────────────────────────────────────────────────────
echo -e "${CYAN}[+] Installing Playwright Chromium browser...${RESET}"
if .venv/bin/playwright install chromium --with-deps 2>&1; then
  echo -e "${GREEN}[✓] Playwright Chromium installed${RESET}"
else
  # Fallback: install browser only without system deps (user may need to install deps manually)
  if .venv/bin/playwright install chromium 2>&1; then
    echo -e "${GREEN}[✓] Playwright Chromium installed (without system deps)${RESET}"
    echo -e "${YELLOW}[!] If crawling fails, run: sudo .venv/bin/playwright install chromium --with-deps${RESET}"
  else
    echo -e "${YELLOW}[!] Playwright Chromium install failed — crawl-based scanning will be limited${RESET}"
    echo -e "${YELLOW}    To fix: source .venv/bin/activate && playwright install chromium --with-deps${RESET}"
  fi
fi

# ─── .env ───────────────────────────────────────────────────────────────────
if [ ! -f web/.env ]; then
  cp .env.example web/.env
  echo -e "${YELLOW}[!] Created web/.env from .env.example — edit it with your DB credentials${RESET}"
else
  echo -e "${GREEN}[✓] web/.env already exists${RESET}"
fi

# ─── PostgreSQL check ───────────────────────────────────────────────────────
echo -e "${CYAN}[+] Checking PostgreSQL connection...${RESET}"
if command -v psql &>/dev/null; then
  # Try to create DB and user (may fail if they exist already — that's fine)
  psql -U postgres -c "CREATE USER ds1hunter WITH PASSWORD 'ds1hunter_pass';" 2>/dev/null || true
  psql -U postgres -c "CREATE DATABASE ds1hunter OWNER ds1hunter;" 2>/dev/null || true
  echo -e "${GREEN}[✓] PostgreSQL ready${RESET}"
else
  echo -e "${YELLOW}[!] psql not found — make sure PostgreSQL is running and the DB/user exist${RESET}"
  echo -e "${YELLOW}    DB: ds1hunter  USER: ds1hunter  PASS: ds1hunter_pass${RESET}"
fi

# ─── Django migrations ──────────────────────────────────────────────────────
echo -e "${CYAN}[+] Running Django migrations...${RESET}"
cd web
python manage.py migrate
echo -e "${GREEN}[✓] Migrations complete${RESET}"

# ─── Superuser ──────────────────────────────────────────────────────────────
echo -e "${YELLOW}[?] Create a superuser account? (y/n)${RESET}"
read -r CREATE_SUPER
if [[ "$CREATE_SUPER" == "y" || "$CREATE_SUPER" == "Y" ]]; then
  python manage.py createsuperuser
fi

cd ..

# ─── Frontend ───────────────────────────────────────────────────────────────
echo -e "${CYAN}[+] Installing React dependencies...${RESET}"
cd frontend
npm install -q
echo -e "${GREEN}[✓] Frontend deps installed${RESET}"
cd ..

# ─── Done ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}╔═══════════════════════════════════╗"
echo "║   ✅ DS1 Hunter Setup Complete!   ║"
echo "╚═══════════════════════════════════╝${RESET}"
echo ""
echo -e "  ${CYAN}To start Django:${RESET}"
echo "    source .venv/bin/activate"
echo "    cd web && python manage.py runserver"
echo ""
echo -e "  ${CYAN}To start CLI:${RESET}"
echo "    source .venv/bin/activate"
echo "    python cli/main.py https://your-target.com --full-hunt"
echo ""
echo -e "  ${CYAN}To start React frontend:${RESET}"
echo "    cd frontend && npm start   # listens on port 13000"
echo ""
echo -e "  ${YELLOW}API:      http://localhost:18000${RESET}"
echo -e "  ${YELLOW}UI:       http://localhost:13000${RESET}"
echo ""
