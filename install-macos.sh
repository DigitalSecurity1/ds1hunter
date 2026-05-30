#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║        DS1 Hunter v1.0.2 - macOS Production Installer        ║
# ║                   by DigitalSecurity1                        ║
# ║               "Hunt. Chain. Prove."                          ║
# ╚══════════════════════════════════════════════════════════════╝
#
# Usage:  sudo bash install-macos.sh
# Tested: macOS Ventura 13, Sonoma 14, Sequoia 15 (Intel + Apple Silicon)

set -euo pipefail

# ── Constants ──────────────────────────────────────────────────────────────
INSTALL_DIR="/opt/ds1hunter"
SERVICE_USER="_ds1hunter"
API_PORT=18000
UI_PORT=13000
VERSION="1.0.2"
CERT_DIR="$INSTALL_DIR/deploy/certs"
CERT="$CERT_DIR/ds1hunter.crt"
KEY="$CERT_DIR/ds1hunter.key"
LOG_DIR="/var/log/ds1hunter"
PLIST_API="com.ds1hunter.api"
PLIST_UI="com.ds1hunter.ui"
LAUNCHD_DIR="/Library/LaunchDaemons"

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
echo "  ╔═══════════════════════════════════════════════════════╗"
echo "  ║                                                       ║"
echo "  ║     DS1 HUNTER  Community Edition v${VERSION}         ║"
echo "  ║             \"Hunt. Chain. Prove.\"                     ║"
echo "  ║                 by DigitalSecurity1                   ║"
echo "  ║                                                       ║"
echo "  ╚═══════════════════════════════════════════════════════╝"
echo -e "${RESET}"
echo -e "${DIM}  Production installer for macOS${RESET}"
echo ""

# ── Root check ─────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && die "This installer must be run as root.\n  Run: sudo bash install-macos.sh"

# Detect macOS
[[ "$(uname -s)" != "Darwin" ]] && die "This installer is for macOS only."

MACOS_VER=$(sw_vers -productVersion)
info "macOS $MACOS_VER detected"

# Detect Homebrew prefix (Apple Silicon vs Intel)
if [[ -d "/opt/homebrew" ]]; then
  BREW_PREFIX="/opt/homebrew"
elif [[ -d "/usr/local/Homebrew" ]]; then
  BREW_PREFIX="/usr/local"
else
  BREW_PREFIX=""
fi


# ══════════════════════════════════════════════════════════════════════════
step "Step 1 / 12  Checking system dependencies"
# ══════════════════════════════════════════════════════════════════════════

# Homebrew
if ! command -v brew &>/dev/null; then
  warn "Homebrew not found. Installing..."
  NONINTERACTIVE=1 /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" || \
    die "Homebrew installation failed. Install manually from https://brew.sh"
  # Reload brew path
  [[ -d "/opt/homebrew/bin" ]] && export PATH="/opt/homebrew/bin:$PATH"
  [[ -d "/usr/local/bin" ]]    && export PATH="/usr/local/bin:$PATH"
  BREW_PREFIX="$(brew --prefix)"
  ok "Homebrew installed"
else
  BREW_PREFIX="$(brew --prefix)"
  ok "Homebrew at $BREW_PREFIX"
fi

export PATH="$BREW_PREFIX/bin:$BREW_PREFIX/sbin:$PATH"

# Required packages
MISSING=()
for cmd in python3 node npm openssl curl git rsync; do
  command -v "$cmd" &>/dev/null || MISSING+=("$cmd")
done

if [[ ${#MISSING[@]} -gt 0 ]]; then
  warn "Missing tools: ${MISSING[*]}"
  info "Installing via Homebrew..."
  brew update -q
  for pkg in "${MISSING[@]}"; do
    case "$pkg" in
      python3) brew install python@3.13 -q ;;
      node|npm) brew install node -q ;;
      openssl) brew install openssl@3 -q ;;
      *) brew install "$pkg" -q ;;
    esac
  done
  export PATH="$BREW_PREFIX/bin:$PATH"
  ok "Dependencies installed"
fi

# Python 3.10+
PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MINOR=$(python3 -c "import sys; print(sys.version_info.minor)")
PY_MAJOR=$(python3 -c "import sys; print(sys.version_info.major)")
if [[ $PY_MAJOR -lt 3 || ($PY_MAJOR -eq 3 && $PY_MINOR -lt 10) ]]; then
  die "Python 3.10+ is required. Found: Python $PY_VER\n  Install: brew install python@3.13"
fi
ok "Python $PY_VER"

# Node 16+
NODE_VER=$(node --version | sed 's/v//' | cut -d. -f1)
if [[ $NODE_VER -lt 16 ]]; then
  die "Node.js 16+ is required. Found: $(node --version)\n  Install: brew install node"
fi
ok "Node.js $(node --version)"


# ══════════════════════════════════════════════════════════════════════════
step "Step 2 / 12  Preparing installation directory"
# ══════════════════════════════════════════════════════════════════════════

if [[ -d "$INSTALL_DIR" ]]; then
  warn "Existing installation found at $INSTALL_DIR"
  echo -e "  ${YELLOW}This will erase the current database and all stored hunts.${RESET}"
  echo -n "  Overwrite? [y/N] "
  read -r CONFIRM
  [[ "$CONFIRM" =~ ^[yY]$ ]] || die "Installation cancelled."
  # Unload running services before removing
  launchctl unload "$LAUNCHD_DIR/$PLIST_API.plist" 2>/dev/null || true
  launchctl unload "$LAUNCHD_DIR/$PLIST_UI.plist"  2>/dev/null || true
  rm -rf "$INSTALL_DIR"
  ok "Old installation removed"
fi

mkdir -p "$INSTALL_DIR"
info "Copying files to $INSTALL_DIR..."
rsync -a \
  --exclude='.venv' \
  --exclude='node_modules' \
  --exclude='__pycache__' \
  --exclude='.env' \
  --exclude='db.sqlite3' \
  "$SRC_DIR/" "$INSTALL_DIR/"
ok "Files installed to $INSTALL_DIR"


# ══════════════════════════════════════════════════════════════════════════
step "Step 3 / 12  Creating system service account"
# ══════════════════════════════════════════════════════════════════════════

if id "$SERVICE_USER" &>/dev/null 2>&1; then
  ok "Service user '$SERVICE_USER' already exists"
else
  info "Creating hidden system user '$SERVICE_USER'..."

  # Find a free UID in the hidden user range (300-499)
  USED_UIDS=$(dscl . -list /Users UniqueID 2>/dev/null | awk '{print $2}')
  NEW_UID=""
  for uid in $(seq 301 499); do
    echo "$USED_UIDS" | grep -q "^${uid}$" || { NEW_UID=$uid; break; }
  done
  [[ -z "$NEW_UID" ]] && die "Could not find a free UID in range 301-499"

  dscl . -create "/Users/$SERVICE_USER"
  dscl . -create "/Users/$SERVICE_USER" UserShell /usr/bin/false
  dscl . -create "/Users/$SERVICE_USER" RealName "DS1 Hunter Service"
  dscl . -create "/Users/$SERVICE_USER" UniqueID "$NEW_UID"
  dscl . -create "/Users/$SERVICE_USER" PrimaryGroupID 67   # _daemon group
  dscl . -create "/Users/$SERVICE_USER" NFSHomeDirectory /var/empty
  dscl . -delete "/Users/$SERVICE_USER" AuthenticationAuthority 2>/dev/null || true
  dscl . -delete "/Users/$SERVICE_USER" Password 2>/dev/null || true
  dscl . -create "/Users/$SERVICE_USER" Password "*"

  ok "Service user '$SERVICE_USER' created (UID $NEW_UID)"
fi


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
# Python .pyc bytecode is version-specific (magic number must match the
# running interpreter). The release package ships .py source so the correct
# .pyc is always generated for whatever Python version is installed here.

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
if "$VENV/bin/playwright" install chromium --with-deps 2>/dev/null; then
  ok "Playwright Chromium installed"
else
  warn "Playwright install had issues. Run manually if needed:"
  warn "  $VENV/bin/playwright install chromium"
fi


# ══════════════════════════════════════════════════════════════════════════
step "Step 6 / 12  Building React frontend"
# ══════════════════════════════════════════════════════════════════════════

info "React frontend pre-built — installing serve for static HTTPS serving..."
npm install -g serve -q
SERVE_BIN=$(command -v serve 2>/dev/null || echo "$BREW_PREFIX/bin/serve")
ok "serve ready at $SERVE_BIN"

cd "$SRC_DIR"


# ══════════════════════════════════════════════════════════════════════════
step "Step 7 / 12  Generating TLS certificate"
# ══════════════════════════════════════════════════════════════════════════

mkdir -p "$CERT_DIR"

if [[ -f "$CERT" && -f "$KEY" ]]; then
  ok "Certificate already exists, skipping generation"
else
  info "Generating self-signed RSA 4096 certificate (825 days)..."

  # Use config file for SAN - works with both LibreSSL (macOS system) and OpenSSL (brew)
  CERT_CNF="$(mktemp /tmp/ds1hunter-cert-XXXXXX.cnf)"
  cat > "$CERT_CNF" << 'CNFEOF'
[req]
distinguished_name = req_distinguished_name
x509_extensions    = v3_req
prompt             = no
[req_distinguished_name]
CN = ds1hunter.local
O  = DigitalSecurity1
C  = US
[v3_req]
keyUsage         = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName   = @alt_names
[alt_names]
DNS.1 = localhost
DNS.2 = ds1hunter.local
IP.1  = 127.0.0.1
CNFEOF

  openssl req -x509 -nodes \
    -newkey rsa:4096 \
    -keyout "$KEY" \
    -out    "$CERT" \
    -days   825 \
    -config "$CERT_CNF" \
    2>/dev/null

  rm -f "$CERT_CNF"
  ok "TLS certificate generated"
fi

chmod 640 "$KEY"
chmod 644 "$CERT"

# Trust the certificate in the macOS System Keychain
info "Adding certificate to macOS System Keychain..."
if security add-trusted-cert -d -r trustRoot \
     -k /Library/Keychains/System.keychain \
     "$CERT" 2>/dev/null; then
  ok "Certificate trusted system-wide (no browser warning)"
else
  warn "Could not auto-trust certificate. Import manually:"
  warn "  Open Keychain Access > System > Import $CERT > Trust > Always Trust"
fi


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
# DS1 Hunter - Production Environment (macOS)
# Generated: $(date '+%Y-%m-%d %H:%M:%S')
# Installer: install-macos.sh v${VERSION}
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

# ─── Redis (disabled - enable if you install Redis) ───────────────────────
REDIS_AVAILABLE=False
REDIS_URL=redis://localhost:6379/0
ENV_EOF

chmod 600 "$INSTALL_DIR/web/.env"
ok ".env written (mode 600)"

cat > "$INSTALL_DIR/frontend/.env.production" << FE_EOF
PORT=${UI_PORT}
REACT_APP_API_BASE=https://127.0.0.1:${API_PORT}
HTTPS=false
GENERATE_SOURCEMAP=false
FE_EOF
ok "Frontend production env written"

# Create service wrapper scripts (launchd cannot source .env files directly)
mkdir -p "$INSTALL_DIR/bin"

cat > "$INSTALL_DIR/bin/start-api.sh" << APISH_EOF
#!/bin/bash
set -a
source "$INSTALL_DIR/web/.env"
set +a
exec "$INSTALL_DIR/.venv/bin/daphne" \\
    -e "ssl:${API_PORT}:interface=127.0.0.1:privateKey=${KEY}:certKey=${CERT}" \\
    ds1hunter_project.asgi:application
APISH_EOF

cat > "$INSTALL_DIR/bin/start-ui.sh" << UISH_EOF
#!/bin/bash
exec "$SERVE_BIN" -s "$INSTALL_DIR/frontend/build" \\
    --ssl-cert "${CERT}" \\
    --ssl-key  "${KEY}" \\
    -l ${UI_PORT} \\
    --no-port-switching
UISH_EOF

chmod +x "$INSTALL_DIR/bin/start-api.sh" "$INSTALL_DIR/bin/start-ui.sh"
ok "Service wrapper scripts created"


# ══════════════════════════════════════════════════════════════════════════
step "Step 10 / 12  Setting up database"
# ══════════════════════════════════════════════════════════════════════════

cd "$INSTALL_DIR/web"
MANAGE="$PYTHON $INSTALL_DIR/web/manage.py"
set -a
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

# Log directory
mkdir -p "$LOG_DIR"
chown "$SERVICE_USER" "$LOG_DIR"

# Installation directory
chown -R "$SERVICE_USER" "$INSTALL_DIR"
chmod 640 "$KEY"
chgrp 67 "$KEY"   # _daemon group can read the key

# CLI symlink (available to all users)
ln -sf "$INSTALL_DIR/.venv/bin/ds1hunter" /usr/local/bin/ds1hunter
ok "ds1hunter command available system-wide"
ok "Permissions set"


# ══════════════════════════════════════════════════════════════════════════
step "Step 12 / 12  Installing launchd services"
# ══════════════════════════════════════════════════════════════════════════

# ── API service plist ─────────────────────────────────────────────────────
cat > "$LAUNCHD_DIR/$PLIST_API.plist" << PLIST_EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${PLIST_API}</string>

    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>${INSTALL_DIR}/bin/start-api.sh</string>
    </array>

    <key>UserName</key>
    <string>${SERVICE_USER}</string>

    <key>WorkingDirectory</key>
    <string>${INSTALL_DIR}/web</string>

    <key>RunAtLoad</key>
    <true/>

    <key>KeepAlive</key>
    <true/>

    <key>ThrottleInterval</key>
    <integer>5</integer>

    <key>StandardOutPath</key>
    <string>${LOG_DIR}/api.log</string>

    <key>StandardErrorPath</key>
    <string>${LOG_DIR}/api-error.log</string>
</dict>
</plist>
PLIST_EOF

# ── UI service plist ──────────────────────────────────────────────────────
cat > "$LAUNCHD_DIR/$PLIST_UI.plist" << PLIST_EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${PLIST_UI}</string>

    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>${INSTALL_DIR}/bin/start-ui.sh</string>
    </array>

    <key>UserName</key>
    <string>${SERVICE_USER}</string>

    <key>WorkingDirectory</key>
    <string>${INSTALL_DIR}/frontend</string>

    <key>RunAtLoad</key>
    <true/>

    <key>KeepAlive</key>
    <true/>

    <key>ThrottleInterval</key>
    <integer>5</integer>

    <key>StandardOutPath</key>
    <string>${LOG_DIR}/ui.log</string>

    <key>StandardErrorPath</key>
    <string>${LOG_DIR}/ui-error.log</string>
</dict>
</plist>
PLIST_EOF

# Set correct ownership and permissions for plists
chown root:wheel "$LAUNCHD_DIR/$PLIST_API.plist" "$LAUNCHD_DIR/$PLIST_UI.plist"
chmod 644 "$LAUNCHD_DIR/$PLIST_API.plist" "$LAUNCHD_DIR/$PLIST_UI.plist"

# Kill any process holding the ports before starting services
for PORT in $API_PORT $UI_PORT; do
  PIDS=$(lsof -ti tcp:$PORT 2>/dev/null || true)
  if [[ -n "$PIDS" ]]; then
    warn "Port $PORT in use — stopping process(es): $PIDS"
    kill -9 $PIDS 2>/dev/null || true
    sleep 1
  fi
done

# Load and start services
launchctl load "$LAUNCHD_DIR/$PLIST_API.plist" 2>/dev/null || true
launchctl load "$LAUNCHD_DIR/$PLIST_UI.plist"  2>/dev/null || true

sleep 3

API_OK=false
UI_OK=false
launchctl list | grep -q "$PLIST_API" && API_OK=true
launchctl list | grep -q "$PLIST_UI"  && UI_OK=true

$API_OK && ok "ds1hunter-api service started" || warn "ds1hunter-api did not start -- check: tail -f $LOG_DIR/api-error.log"
$UI_OK  && ok "ds1hunter-ui  service started" || warn "ds1hunter-ui  did not start -- check: tail -f $LOG_DIR/ui-error.log"


# ══════════════════════════════════════════════════════════════════════════
#  FINAL SUMMARY
# ══════════════════════════════════════════════════════════════════════════

# Box helpers — inner width = 63, lead indent = 2, content area = 61
_brow() {
  local pad=$(( 61 - ${#1} ))
  printf "  \033[1;32m\033[1m║\033[0m  %b%${pad}s\033[1;32m\033[1m║\033[0m\n" "$2" ""
}
_bempty() { printf "  \033[1;32m\033[1m║\033[0m%63s\033[1;32m\033[1m║\033[0m\n" ""; }
_bsep()   { printf "\033[1;32m\033[1m  ╠═══════════════════════════════════════════════════════════════╣\033[0m\n"; }

_TITLE="DS1 Hunter - Community Edition v${VERSION} installed successfully!"
_WEB="Web UI  :  https://127.0.0.1:${UI_PORT}"
_API="API     :  https://127.0.0.1:${API_PORT}"
_PW="Password :  ${ADMIN_PASS}"
_LOAD_API="launchctl load ${LAUNCHD_DIR}/${PLIST_API}.plist"
_LOAD_UI="launchctl load ${LAUNCHD_DIR}/${PLIST_UI}.plist"
_UNLOAD="launchctl unload ${LAUNCHD_DIR}/com.ds1hunter.*.plist"
_LOG_API="Logs    : tail -f ${LOG_DIR}/api.log"
_LOG_UI="             tail -f ${LOG_DIR}/ui.log"

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
_brow "Certificate auto-added to System Keychain." "\033[2mCertificate auto-added to System Keychain.\033[0m"
_brow "If browser still shows a warning:" "\033[2mIf browser still shows a warning:\033[0m"
_brow "  Keychain Access > System > ds1hunter.local" "\033[2m  Keychain Access > System > ds1hunter.local\033[0m"
_brow "  Double-click > Trust > Always Trust" "\033[2m  Double-click > Trust > Always Trust\033[0m"
_bempty
_bsep
_brow "SERVICE MANAGEMENT" "\033[1mSERVICE MANAGEMENT\033[0m"
_bempty
_brow "${_LOAD_API}" "\033[2m${_LOAD_API}\033[0m"
_brow "${_LOAD_UI}"  "\033[2m${_LOAD_UI}\033[0m"
_brow "${_UNLOAD}"   "\033[2m${_UNLOAD}\033[0m"
_brow "${_LOG_API}"  "\033[2m${_LOG_API}\033[0m"
_brow "${_LOG_UI}"   "\033[2m${_LOG_UI}\033[0m"
_bempty
_bsep
_brow "GATEKEEPER NOTE (if blocked on first run)" "\033[1mGATEKEEPER NOTE\033[0m \033[2m(if blocked on first run)\033[0m"
_brow "  System Settings > Privacy & Security > Allow Anyway" "\033[2m  System Settings > Privacy & Security > Allow Anyway\033[0m"
_bempty
printf "\033[1;32m\033[1m  ╚═══════════════════════════════════════════════════════════════╝\033[0m\n"
echo ""
