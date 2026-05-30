#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║          DS1 Hunter v1.0.2 - Linux Production Installer      ║
# ║                   by DigitalSecurity1                        ║
# ║               "Hunt. Chain. Prove."                          ║
# ╚══════════════════════════════════════════════════════════════╝
#
# Usage:  sudo bash install-linux.sh
# Tested: Debian 12, Ubuntu 22.04/24.04, Kali Linux 2024+

set -euo pipefail

# ── Constants ──────────────────────────────────────────────────────────────
INSTALL_DIR="/opt/ds1hunter"
SERVICE_USER="ds1hunter"
API_PORT=18000
UI_PORT=13000
VERSION="1.0.2"
CERT_DIR="$INSTALL_DIR/deploy/certs"
CERT="$CERT_DIR/ds1hunter.crt"
KEY="$CERT_DIR/ds1hunter.key"

# ── Colors ─────────────────────────────────────────────────────────────────
BOLD="\033[1m"
CYAN="\033[0;36m"
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
RED="\033[0;31m"
DIM="\033[2m"
RESET="\033[0m"

# ── Helpers ────────────────────────────────────────────────────────────────
ok()   { echo -e "${GREEN}[✓]${RESET} $*"; }
info() { echo -e "${CYAN}[+]${RESET} $*"; }
warn() { echo -e "${YELLOW}[!]${RESET} $*"; }
die()  { echo -e "\n${RED}${BOLD}[✗] $*${RESET}\n" >&2; exit 1; }
step() {
  echo ""
  echo -e "${CYAN}${BOLD}━━ $* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
}

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Banner ─────────────────────────────────────────────────────────────────
echo -e "${CYAN}${BOLD}"
echo "  +=========================================================+"
echo "  |                                                         |"
echo "  |      DS1 HUNTER  Community Edition v${VERSION}               |"
echo "  |         \"Hunt. Chain. Prove.\"                           |"
echo "  |              by DigitalSecurity1                        |"
echo "  |                                                         |"
echo "  +=========================================================+"
echo -e "${RESET}"
echo -e "${DIM}  Production installer for Linux${RESET}"
echo ""

# ── Root check ─────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && die "This installer must be run as root.\n  Run: sudo bash install-linux.sh"


# ══════════════════════════════════════════════════════════════════════════
step "Step 1 / 12  Checking system dependencies"
# ══════════════════════════════════════════════════════════════════════════

MISSING=()
for cmd in python3 node npm openssl curl git; do
  command -v "$cmd" &>/dev/null || MISSING+=("$cmd")
done

if [[ ${#MISSING[@]} -gt 0 ]]; then
  warn "Missing system packages: ${MISSING[*]}"
  info "Attempting to install via apt..."
  apt-get update -q
  for pkg in "${MISSING[@]}"; do
    case "$pkg" in
      python3) apt-get install -y -q python3 python3-venv python3-pip ;;
      node|npm) apt-get install -y -q nodejs npm ;;
      *) apt-get install -y -q "$pkg" ;;
    esac
  done
  ok "System packages installed"
fi

# Python version (3.10+)
PY_MIN_MINOR=10
PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MINOR=$(python3 -c "import sys; print(sys.version_info.minor)")
PY_MAJOR=$(python3 -c "import sys; print(sys.version_info.major)")
if [[ $PY_MAJOR -lt 3 || ($PY_MAJOR -eq 3 && $PY_MINOR -lt $PY_MIN_MINOR) ]]; then
  die "Python 3.10+ is required. Found: Python $PY_VER"
fi
ok "Python $PY_VER"

# Node version (16+)
NODE_VER=$(node --version | sed 's/v//' | cut -d. -f1)
if [[ $NODE_VER -lt 16 ]]; then
  die "Node.js 16+ is required. Found: $(node --version)\n  Install from: https://nodejs.org"
fi
ok "Node.js $(node --version)"

# python3-venv
python3 -m venv --help &>/dev/null || {
  apt-get install -y -q python3-venv
  ok "python3-venv installed"
}


# ══════════════════════════════════════════════════════════════════════════
step "Step 2 / 12  Preparing installation directory"
# ══════════════════════════════════════════════════════════════════════════

if [[ -d "$INSTALL_DIR" ]]; then
  warn "Existing installation found at $INSTALL_DIR"
  echo -e "  ${YELLOW}This will erase the current database and all stored hunts.${RESET}"
  echo -n "  Overwrite? [y/N] "
  read -r CONFIRM
  [[ "$CONFIRM" =~ ^[yY]$ ]] || die "Installation cancelled."
  systemctl stop ds1hunter-api ds1hunter-ui 2>/dev/null || true
  rm -rf "$INSTALL_DIR"
  ok "Old installation removed"
fi

mkdir -p "$INSTALL_DIR"
info "Copying files to $INSTALL_DIR..."
rsync -a --exclude='.venv' --exclude='node_modules' --exclude='__pycache__' \
  --exclude='.env' --exclude='db.sqlite3' \
  "$SRC_DIR/" "$INSTALL_DIR/"
ok "Files installed to $INSTALL_DIR"


# ══════════════════════════════════════════════════════════════════════════
step "Step 3 / 12  Creating system user"
# ══════════════════════════════════════════════════════════════════════════

if id "$SERVICE_USER" &>/dev/null; then
  ok "System user '$SERVICE_USER' already exists"
else
  useradd \
    --system \
    --create-home \
    --home-dir /var/lib/ds1hunter \
    --shell /usr/sbin/nologin \
    --comment "DS1 Hunter service account" \
    "$SERVICE_USER"
  ok "System user '$SERVICE_USER' created"
fi

# Ensure the home dir exists (upgrade-safe)
mkdir -p /var/lib/ds1hunter
chown "$SERVICE_USER:$SERVICE_USER" /var/lib/ds1hunter


# ══════════════════════════════════════════════════════════════════════════
step "Step 4 / 12  Setting up Python virtual environment"
# ══════════════════════════════════════════════════════════════════════════

VENV="$INSTALL_DIR/.venv"
PYTHON="$VENV/bin/python"
PIP="$VENV/bin/pip"

info "Creating venv..."
python3 -m venv "$VENV"
"$PIP" install --upgrade pip setuptools wheel -q
ok "Venv created"

info "Installing Python dependencies (this may take a few minutes)..."
"$PIP" install -r "$INSTALL_DIR/requirements.txt" -q
ok "Python dependencies installed"

info "Installing daphne (ASGI server)..."
"$PIP" install daphne -q
ok "Daphne ready"

info "Registering ds1hunter CLI..."
"$PIP" install -e "$INSTALL_DIR" -q
ok "CLI registered"


# ══════════════════════════════════════════════════════════════════════════
step "Step 4.5 / 12  Compiling Python bytecode for local Python version"
# ══════════════════════════════════════════════════════════════════════════
# Python .pyc magic numbers are version-specific. Compile on the target
# machine using the venv Python so bytecode always matches the interpreter.

VENV_PY_VER=$("$PYTHON" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
info "Compiling Python source to optimized bytecode (Python $VENV_PY_VER)..."

"$PYTHON" -OO -m compileall -b -q \
  "$INSTALL_DIR/core/" \
  "$INSTALL_DIR/cli/" \
  "$INSTALL_DIR/web/" \
  2>/dev/null || true

PYC_MADE=$(find "$INSTALL_DIR" -name "*.pyc" | wc -l)
ok "Compiled $PYC_MADE modules (Python $VENV_PY_VER bytecode)"

info "Stripping Python source (keeping only bytecode)..."
# Scope strip to OUR source directories only — never touch .venv or
# site-packages, or the editable install finder and Django itself get deleted.
for _src_dir in "$INSTALL_DIR/core" "$INSTALL_DIR/cli" "$INSTALL_DIR/web"; do
  [ -d "$_src_dir" ] && find "$_src_dir" -name "*.py" \
    ! -name "__init__.py" \
    ! -name "manage.py" \
    ! -path "*/migrations/*.py" \
    -delete
done

ok "Python source protected"


# ══════════════════════════════════════════════════════════════════════════
step "Step 5 / 12  Installing Playwright browser"
# ══════════════════════════════════════════════════════════════════════════

info "Installing Playwright Chromium (needed for Active Scanner and Spider)..."
if "$VENV/bin/playwright" install chromium --with-deps 2>&1; then
  ok "Playwright Chromium installed"
else
  warn "System deps install hit an issue - fixing dpkg and retrying..."
  dpkg --configure -a 2>/dev/null || true
  if "$VENV/bin/playwright" install chromium 2>&1; then
    ok "Playwright Chromium installed (system libs were already present)"
  else
    warn "Playwright could not be installed automatically."
    warn "Spider and Active Scanner modules need it - run after install:"
    warn "  sudo /opt/ds1hunter/.venv/bin/playwright install chromium --with-deps"
  fi
fi


# ══════════════════════════════════════════════════════════════════════════
step "Step 6 / 12  Building React frontend"
# ══════════════════════════════════════════════════════════════════════════

info "React frontend pre-built - installing serve for static HTTPS serving..."
npm install -g serve -q
SERVE_BIN=$(which serve 2>/dev/null || echo "/usr/local/bin/serve")
ok "serve ready at $SERVE_BIN"

cd "$SRC_DIR"


# ══════════════════════════════════════════════════════════════════════════
step "Step 7 / 12  Generating TLS certificate"
# ══════════════════════════════════════════════════════════════════════════

mkdir -p "$CERT_DIR"

if [[ -f "$CERT" && -f "$KEY" ]]; then
  ok "Certificate already exists, skipping generation"
else
  info "Generating self-signed RSA 4096 certificate (valid 825 days)..."
  openssl req -x509 -nodes \
    -newkey rsa:4096 \
    -keyout "$KEY" \
    -out    "$CERT" \
    -days   825 \
    -subj   "/CN=ds1hunter.local/O=DigitalSecurity1/C=US" \
    -addext "subjectAltName=DNS:localhost,DNS:ds1hunter.local,IP:127.0.0.1" \
    2>/dev/null
  ok "TLS certificate generated"
fi

chmod 640 "$KEY"
chmod 644 "$CERT"


# ══════════════════════════════════════════════════════════════════════════
step "Step 8 / 12  Generating secure credentials"
# ══════════════════════════════════════════════════════════════════════════

SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(50))")
ADMIN_PASS=$(python3 -c "
import secrets, string
chars = string.ascii_letters + string.digits + '!@#%^&*'
print(''.join(secrets.choice(chars) for _ in range(22)))
")
ADMIN_URL_TOKEN=$(python3 -c "import secrets; print(secrets.token_hex(6))")
ADMIN_URL="ds1-ops-${ADMIN_URL_TOKEN}/"
ok "SECRET_KEY generated (50 chars)"
ok "Admin password generated (22 chars)"
ok "Admin URL randomized"


# ══════════════════════════════════════════════════════════════════════════
step "Step 9 / 12  Writing production configuration"
# ══════════════════════════════════════════════════════════════════════════

cat > "$INSTALL_DIR/web/.env" << ENV_EOF
# DS1 Hunter — Production Environment
# Generated: $(date '+%Y-%m-%d %H:%M:%S')
# Installer: install-linux.sh v${VERSION}
# !! Do not share or commit this file !!

# ─── Django Core ──────────────────────────────────────────────────────────
SECRET_KEY=${SECRET_KEY}
DEBUG=False
ALLOWED_HOSTS=localhost,127.0.0.1
LOG_LEVEL=WARNING

# ─── CORS (must match UI origin exactly) ──────────────────────────────────
CORS_ALLOWED_ORIGINS=https://127.0.0.1:${UI_PORT},https://localhost:${UI_PORT}

# ─── Admin ────────────────────────────────────────────────────────────────
ADMIN_URL=${ADMIN_URL}
ADMIN_ALLOWED_IPS=127.0.0.1,::1

# ─── Redis (disabled — enable if you install Redis) ───────────────────────
REDIS_AVAILABLE=False
REDIS_URL=redis://localhost:6379/0
ENV_EOF

chmod 600 "$INSTALL_DIR/web/.env"
ok ".env written (mode 600)"

# Frontend env — point to HTTPS API
cat > "$INSTALL_DIR/frontend/.env.production" << FE_EOF
PORT=${UI_PORT}
REACT_APP_API_BASE=https://127.0.0.1:${API_PORT}
HTTPS=false
GENERATE_SOURCEMAP=false
FE_EOF
ok "Frontend production env written"


# ══════════════════════════════════════════════════════════════════════════
step "Step 10 / 12  Setting up database"
# ══════════════════════════════════════════════════════════════════════════

cd "$INSTALL_DIR/web"
MANAGE="$PYTHON $INSTALL_DIR/web/manage.py"

# Export .env so python-decouple can find SECRET_KEY at runtime
set -a
# shellcheck source=/dev/null
source "$INSTALL_DIR/web/.env"
set +a

info "Running migrations..."
$MANAGE migrate --run-syncdb -v 0
ok "Database schema created"

info "Collecting static files..."
$MANAGE collectstatic --no-input -v 0
ok "Static files collected"

info "Creating admin user..."
$MANAGE shell -c "
from django.contrib.auth import get_user_model
User = get_user_model()
if User.objects.filter(username='admin').exists():
    u = User.objects.get(username='admin')
    u.set_password('${ADMIN_PASS}')
    u.save()
    print('Admin password reset.')
else:
    User.objects.create_superuser('admin', 'admin@ds1hunter.local', '${ADMIN_PASS}')
    print('Admin user created.')
"
ok "Admin user ready"

cd "$SRC_DIR"


# ══════════════════════════════════════════════════════════════════════════
step "Step 11 / 12  Setting permissions"
# ══════════════════════════════════════════════════════════════════════════

chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
# Key must stay restricted
chmod 640 "$KEY"
# Let the service user read the key
chgrp "$SERVICE_USER" "$KEY"

# CLI available to all users
ln -sf "$INSTALL_DIR/.venv/bin/ds1hunter" /usr/local/bin/ds1hunter
ok "ds1hunter command available system-wide"
ok "Permissions set"


# ══════════════════════════════════════════════════════════════════════════
step "Step 12 / 12  Creating systemd services"
# ══════════════════════════════════════════════════════════════════════════

DAPHNE="$INSTALL_DIR/.venv/bin/daphne"

# ── API service ───────────────────────────────────────────────────────────
cat > /etc/systemd/system/ds1hunter-api.service << SVC_EOF
[Unit]
Description=DS1 Hunter API Server (ASGI/HTTPS)
Documentation=https://digitalsecurity1.com/DS1-Hunter/docs/
After=network.target
Wants=network.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_USER}
WorkingDirectory=${INSTALL_DIR}/web
EnvironmentFile=${INSTALL_DIR}/web/.env
ExecStart=${DAPHNE} \\
    -e "ssl:${API_PORT}:interface=127.0.0.1:privateKey=${KEY}:certKey=${CERT}" \\
    ds1hunter_project.asgi:application
Restart=on-failure
RestartSec=5
TimeoutStopSec=15
StandardOutput=journal
StandardError=journal
SyslogIdentifier=ds1hunter-api

# Hardening
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=full
ReadWritePaths=${INSTALL_DIR}

[Install]
WantedBy=multi-user.target
SVC_EOF

# ── UI service ────────────────────────────────────────────────────────────
cat > /etc/systemd/system/ds1hunter-ui.service << SVC_EOF
[Unit]
Description=DS1 Hunter Web UI (React / HTTPS)
After=ds1hunter-api.service
Wants=ds1hunter-api.service

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_USER}
WorkingDirectory=${INSTALL_DIR}/frontend
ExecStart=${SERVE_BIN} -s build \\
    --ssl-cert ${CERT} \\
    --ssl-key ${KEY} \\
    -l ${UI_PORT} \\
    --no-port-switching
Restart=on-failure
RestartSec=5
TimeoutStopSec=15
StandardOutput=journal
StandardError=journal
SyslogIdentifier=ds1hunter-ui

NoNewPrivileges=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
SVC_EOF

systemctl daemon-reload
systemctl enable ds1hunter-api ds1hunter-ui -q

# Kill any process still holding the API or UI ports (dev servers, old instances)
for PORT in $API_PORT $UI_PORT; do
  PIDS=$(lsof -ti tcp:$PORT 2>/dev/null || true)
  if [[ -n "$PIDS" ]]; then
    warn "Port $PORT in use — stopping process(es): $PIDS"
    kill -9 $PIDS 2>/dev/null || true
    sleep 1
  fi
done

systemctl start  ds1hunter-api ds1hunter-ui

# Give services 3 seconds to come up then check
sleep 3
API_OK=false
UI_OK=false
systemctl is-active --quiet ds1hunter-api && API_OK=true
systemctl is-active --quiet ds1hunter-ui  && UI_OK=true

$API_OK && ok "ds1hunter-api  service started" || warn "ds1hunter-api  did not start — check: journalctl -u ds1hunter-api"
$UI_OK  && ok "ds1hunter-ui   service started" || warn "ds1hunter-ui   did not start — check: journalctl -u ds1hunter-ui"


# ══════════════════════════════════════════════════════════════════════════
#  FINAL SUMMARY
# ══════════════════════════════════════════════════════════════════════════

# Box helpers — inner width = 63, lead indent = 2, so content area = 61
_brow() {
  # $1 = plain text (for width measurement), $2 = colored text (for display)
  local pad=$(( 61 - ${#1} ))
  printf "  \033[1;32m\033[1m║\033[0m  %b%${pad}s\033[1;32m\033[1m║\033[0m\n" "$2" ""
}
_bempty() { printf "  \033[1;32m\033[1m║\033[0m%63s\033[1;32m\033[1m║\033[0m\n" ""; }
_bsep()   { printf "\033[1;32m\033[1m  ╠═══════════════════════════════════════════════════════════════╣\033[0m\n"; }

_TITLE="DS1 Hunter - Community Edition v${VERSION} installed successfully!"
_WEB="Web UI  :  https://127.0.0.1:${UI_PORT}"
_API="API     :  https://127.0.0.1:${API_PORT}"
_PW="Password :  ${ADMIN_PASS}"

echo ""
printf "\033[1;32m\033[1m  ╔═══════════════════════════════════════════════════════════════╗\033[0m\n"
_bempty
_brow "${_TITLE}" "\033[1;32m\033[1m${_TITLE}\033[0m"
_bempty
_bsep
_bempty
_brow "${_WEB}" "\033[2mWeb UI\033[0m  :  \033[1mhttps://127.0.0.1:${UI_PORT}\033[0m"
_brow "${_API}" "\033[2mAPI\033[0m     :  \033[1mhttps://127.0.0.1:${API_PORT}\033[0m"
_brow "CLI     :  ds1hunter --help" "\033[2mCLI\033[0m     :  \033[1mds1hunter --help\033[0m"
_bempty
_bsep
_brow "CREDENTIALS  (shown once - save them now)" "\033[1;31mCREDENTIALS\033[0m  \033[2m(shown once - save them now)\033[0m"
_bempty
_brow "Username :  admin" "\033[2mUsername\033[0m :  \033[1madmin\033[0m"
_brow "${_PW}"            "\033[2mPassword\033[0m :  \033[1;31m${ADMIN_PASS}\033[0m"
_bempty
_bsep
_brow "BROWSER SETUP  (one time)" "\033[1mBROWSER SETUP\033[0m  \033[2m(one time)\033[0m"
_bempty
_brow "Import this certificate to trust HTTPS:" "\033[2mImport this certificate to trust HTTPS:\033[0m"
_brow "${CERT}" "\033[2m${CERT}\033[0m"
_bempty
_brow "Firefox  : Preferences > Privacy & Security >"  "Firefox  : Preferences > Privacy & Security >"
_brow "             Certificates > Authorities > Import"  "             Certificates > Authorities > Import"
_brow "Chromium : Settings > Privacy > Certificates > Import" "Chromium : Settings > Privacy > Certificates > Import"
_bempty
_bsep
_brow "SERVICE MANAGEMENT" "\033[1mSERVICE MANAGEMENT\033[0m"
_bempty
_brow "Start   : systemctl start  ds1hunter-api ds1hunter-ui"  "\033[2mStart\033[0m   : systemctl start  ds1hunter-api ds1hunter-ui"
_brow "Stop    : systemctl stop   ds1hunter-api ds1hunter-ui"  "\033[2mStop\033[0m    : systemctl stop   ds1hunter-api ds1hunter-ui"
_brow "Restart : systemctl restart ds1hunter-api ds1hunter-ui" "\033[2mRestart\033[0m : systemctl restart ds1hunter-api ds1hunter-ui"
_brow "Logs    : journalctl -u ds1hunter-api -f"               "\033[2mLogs\033[0m    : journalctl -u ds1hunter-api -f"
_brow "          journalctl -u ds1hunter-ui -f"               "          journalctl -u ds1hunter-ui -f"
_bempty
printf "\033[1;32m\033[1m  ╚═══════════════════════════════════════════════════════════════╝\033[0m\n"
echo ""
