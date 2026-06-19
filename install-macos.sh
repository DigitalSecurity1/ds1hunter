#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║        DS1 Hunter v1.0.4 - macOS Production Installer        ║
# ║                   by DigitalSecurity1                        ║
# ║               "Hunt. Chain. Prove."                          ║
# ╚══════════════════════════════════════════════════════════════╝
#
# Usage:  sudo bash install-macos.sh
# Tested: macOS Ventura 13, Sonoma 14, Sequoia 15 (Intel + Apple Silicon)
#
# ── Changelog ──────────────────────────────────────────────────────────────
# v1.0.4  2026-06-18  Accuracy & OOB infrastructure release:
#                     · 8 false-positive fixes: LDAP injection confirmation
#                       now requires error keywords (not just HTTP 500);
#                       CORS flagged only when credentials=true + sensitive
#                       data; integer overflow requires content diff too;
#                       S3 403 no longer reported (expected behavior);
#                       CSS injection requires behavioral evidence;
#                       public third-party subdomain filtering added;
#                       Verifier chain requires 2 independent signals;
#                       accuracy scorer thresholds recalibrated
#                     · OOB VPS deployed: HTTP callbacks on port 8089,
#                       DNS on port 53, poll API at /poll/<token>;
#                       DS1 Hunter polls VPS before checking local cache
#                     · macOS fix: Homebrew commands now run as the
#                       invoking non-root user (sudo -u $SUDO_USER) to
#                       avoid "Running Homebrew as root" fatal error
#
# v1.0.3  2026-06-16  Bug fixes & scanner improvements (patch release):
#                     · macOS fix: launchd services now set PATH explicitly so
#                       Node.js (Homebrew) is found when running as daemon user;
#                       fixes ERR_CONNECTION_REFUSED on Chrome/Safari at :13000
#                     · macOS fix: SSL key permissions changed from chgrp _daemon
#                       to chown _ds1hunter so the service user can read the key
#                     · macOS fix: cert now also trusted in user Login keychain
#                       (fixes Safari requiring manual cert trust)
#                     · Active Scanner: 7 scanner improvements —
#                       SQLi error regex expanded to 6 additional DB stacks
#                       (DB2, Firebird, MSSQL OLE, Hibernate, JDBC, PDO);
#                       sensitive file list 20 → 100+ entries;
#                       XSS: 8 payloads per param (WAF bypass variants);
#                       CMD injection: 12 payloads (was 3);
#                       NoSQL injection added as per-param check;
#                       CRLF injection added (new vuln class);
#                       Web Cache Deception added (new vuln class)
#                     · Verifier: HHI false-positive fix — Cloudflare DNS error
#                       pages no longer counted as Host Header Injection hits
#                     · Proxy UI: "Start Proxy" button added — proxy can now be
#                       restarted from the UI without restarting the server
#
# v1.0.3  2026-06-08  Knowledge base overhaul (core/knowledge.py):
#                     · 80 vuln types (was 53) — 27 new types added:
#                       csrf, bfla, mfa_bypass, saml_injection, ldap_injection,
#                       padding_oracle, xpath_injection, crlf_injection,
#                       websocket_injection, second_order_sqli, session_fixation,
#                       weak_session_token, ssl_tls_weak, file_upload_unrestricted,
#                       subdomain_takeover, prompt_injection, llm_data_exfiltration,
#                       bola, api_key_exposure, sensitive_data_exposure,
#                       html_injection, default_credentials, debug_mode_enabled,
#                       directory_listing, sensitive_file_exposure,
#                       weak_password_policy, and more
#                     · exploit_poc, fix_code added to every KB entry
#                     · generate_poc() and enrich_findings_knowledge() improved

set -euo pipefail

# ── Constants ──────────────────────────────────────────────────────────────
INSTALL_DIR="/opt/ds1hunter"
SERVICE_USER="_ds1hunter"
API_PORT=18000
UI_PORT=13000
VERSION="1.0.4"
CERT_DIR="$INSTALL_DIR/deploy/certs"
CERT="$CERT_DIR/ds1hunter.crt"
KEY="$CERT_DIR/ds1hunter.key"
LOG_DIR="/var/log/ds1hunter"
PLIST_API="com.ds1hunter.api"
PLIST_UI="com.ds1hunter.ui"
LAUNCHD_DIR="/Library/LaunchDaemons"
MACOS_MAJOR=$(sw_vers -productVersion | cut -d. -f1)

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

# launchctl wrappers: use bootstrap/bootout on Sequoia 15+, load/unload below
lctl_load() {
  if (( MACOS_MAJOR >= 15 )); then
    launchctl bootstrap system "$1" 2>/dev/null || true
  else
    launchctl load "$1" 2>/dev/null || true
  fi
}
lctl_unload() {
  if (( MACOS_MAJOR >= 15 )); then
    launchctl bootout system "$1" 2>/dev/null || true
  else
    launchctl unload "$1" 2>/dev/null || true
  fi
}

# ── Banner ─────────────────────────────────────────────────────────────────
echo -e "${CYAN}${BOLD}"
echo "  ╔═══════════════════════════════════════════════════════╗"
echo "  ║                                                       ║"
echo "  ║     DS1 HUNTER  Community Edition v${VERSION}              ║"
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

# Homebrew must never run as root — detect the invoking user via $SUDO_USER
REAL_USER="${SUDO_USER:-}"
if [[ -z "$REAL_USER" || "$REAL_USER" == "root" ]]; then
  # Truly running as root (not via sudo) — Homebrew cannot help us
  REAL_USER=""
fi

# brew_cmd: always invoke brew as the non-root user when available.
# This avoids the "Running Homebrew as root is not supported" fatal error.
brew_cmd() {
  if [[ -n "$REAL_USER" ]]; then
    sudo -u "$REAL_USER" brew "$@"
  else
    brew "$@"
  fi
}

if ! command -v brew &>/dev/null; then
  if [[ -z "$REAL_USER" ]]; then
    die "Homebrew is not installed and cannot be auto-installed when running directly as root.\n\n  1. Exit this installer\n  2. Install Homebrew as your normal user:\n       /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\"\n  3. Re-run: sudo bash install-macos.sh"
  fi
  warn "Homebrew not found — installing as '$REAL_USER'..."
  NONINTERACTIVE=1 sudo -u "$REAL_USER" \
    HOME="$(eval echo "~$REAL_USER")" \
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" || \
    die "Homebrew installation failed.\n  Install manually: https://brew.sh — then re-run this installer."
  [[ -d "/opt/homebrew/bin" ]] && export PATH="/opt/homebrew/bin:$PATH"
  [[ -d "/usr/local/bin" ]]    && export PATH="/usr/local/bin:$PATH"
  BREW_PREFIX="$(brew_cmd --prefix 2>/dev/null || echo /opt/homebrew)"
  ok "Homebrew installed"
else
  BREW_PREFIX="$(brew_cmd --prefix)"
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
  info "Installing via Homebrew (running as '$REAL_USER')..."
  brew_cmd update -q
  for pkg in "${MISSING[@]}"; do
    case "$pkg" in
      python3) brew_cmd install python@3.13 -q ;;
      node|npm) brew_cmd install node -q ;;
      openssl) brew_cmd install openssl@3 -q ;;
      *) brew_cmd install "$pkg" -q ;;
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
  lctl_unload "$LAUNCHD_DIR/$PLIST_API.plist"
  lctl_unload "$LAUNCHD_DIR/$PLIST_UI.plist"
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

# pip --retries only covers connection setup, not mid-stream resets.
# This wrapper retries at the shell level with exponential backoff.
pip_retry() {
    local max=5 n=1 delay=5
    until "$PIP" "$@"; do
        [[ $n -ge $max ]] && die "pip install failed after $max attempts. Check your internet connection and try again."
        warn "pip download interrupted (attempt $n/$max) — retrying in ${delay}s..."
        sleep "$delay"
        delay=$((delay * 2))
        n=$((n + 1))
    done
}

info "Creating venv..."
python3 -m venv "$VENV"
pip_retry install --upgrade pip setuptools wheel -q
ok "Venv created"

# Export Homebrew openssl/libffi paths so cryptography and lxml can find them
# if they need to compile from source (e.g. Apple Silicon, new Python minor).
# Binary wheels are available for most configurations, but this is a safe fallback.
if [[ -d "$BREW_PREFIX/opt/openssl@3" ]]; then
  export LDFLAGS="-L$BREW_PREFIX/opt/openssl@3/lib ${LDFLAGS:-}"
  export CPPFLAGS="-I$BREW_PREFIX/opt/openssl@3/include ${CPPFLAGS:-}"
  export PKG_CONFIG_PATH="$BREW_PREFIX/opt/openssl@3/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
fi
if [[ -d "$BREW_PREFIX/opt/libffi" ]]; then
  export LDFLAGS="-L$BREW_PREFIX/opt/libffi/lib ${LDFLAGS:-}"
  export CPPFLAGS="-I$BREW_PREFIX/opt/libffi/include ${CPPFLAGS:-}"
  export PKG_CONFIG_PATH="$BREW_PREFIX/opt/libffi/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
fi

info "Installing Python dependencies (this may take a few minutes)..."
pip_retry install -r "$INSTALL_DIR/requirements.txt" -q
ok "Python dependencies installed (includes daphne, cryptography, PyYAML)"

info "Registering ds1hunter CLI..."
pip_retry install -e "$INSTALL_DIR" -q
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
npm install -g serve@14 -q
# npm global bin dir can differ from Homebrew prefix when running as root
NPM_GLOBAL_BIN="$(npm config get prefix)/bin"
SERVE_BIN="$(command -v serve 2>/dev/null || echo "$NPM_GLOBAL_BIN/serve")"
[[ ! -x "$SERVE_BIN" ]] && SERVE_BIN="$BREW_PREFIX/bin/serve"
[[ ! -x "$SERVE_BIN" ]] && die "serve binary not found after npm install. Run: npm install -g serve@14"
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
IP.2  = ::1
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

# Make key readable by the service user
chown root:"$SERVICE_USER" "$KEY" 2>/dev/null || chmod 644 "$KEY"

# Trust the certificate in the macOS System Keychain
info "Adding certificate to macOS System Keychain..."
if security add-trusted-cert -d -r trustRoot \
     -k /Library/Keychains/System.keychain \
     "$CERT" 2>/dev/null; then
  ok "Certificate trusted in System Keychain"
else
  warn "Could not auto-trust certificate in System Keychain."
fi

# Also trust in the actual user's Login keychain (needed for Safari)
if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
  USER_HOME=$(eval echo "~$SUDO_USER")
  LOGIN_KC="$USER_HOME/Library/Keychains/login.keychain-db"
  if [[ -f "$LOGIN_KC" ]]; then
    if sudo -u "$SUDO_USER" security add-trusted-cert -r trustRoot \
         -k "$LOGIN_KC" "$CERT" 2>/dev/null; then
      ok "Certificate trusted in $SUDO_USER Login Keychain (Safari will trust it)"
    else
      warn "Could not auto-trust in Login Keychain. Safari fix:"
      warn "  Open Keychain Access > Login > Import $CERT > Trust > Always Trust"
    fi
  fi
fi


# ══════════════════════════════════════════════════════════════════════════
step "Step 8 / 12  Generating secure credentials"
# ══════════════════════════════════════════════════════════════════════════

SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(50))")
# Alphanumeric only: no special chars that break shell interpolation or are
# hard to read in a terminal (no !, @, #, %, ', \, $, etc.)
ADMIN_PASS=$(python3 -c "
import secrets, string
chars = string.ascii_letters + string.digits
print(''.join(secrets.choice(chars) for _ in range(24)))
")
ADMIN_URL_TOKEN=$(python3 -c "import secrets; print(secrets.token_hex(6))")
ADMIN_URL="ds1-ops-${ADMIN_URL_TOKEN}/"
ok "SECRET_KEY generated (50 chars)"
ok "Admin password generated (24 chars, alphanumeric)"
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
# DS1 Hunter API service wrapper
# Explicitly set PATH so launchd daemon context can find binaries
export PATH="${BREW_PREFIX}/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
set -a
source "$INSTALL_DIR/web/.env"
set +a
exec "$INSTALL_DIR/.venv/bin/daphne" \\
    -e "ssl:${API_PORT}:interface=127.0.0.1:privateKey=${KEY}:certKey=${CERT}" \\
    ds1hunter_project.asgi:application
APISH_EOF

cat > "$INSTALL_DIR/bin/start-ui.sh" << UISH_EOF
#!/bin/bash
# DS1 Hunter UI service wrapper
# Explicitly set PATH so launchd daemon context can find Node.js for serve
export PATH="${BREW_PREFIX}/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
exec "$SERVE_BIN" -s "$INSTALL_DIR/frontend/build" \\
    --ssl-cert "${CERT}" \\
    --ssl-key  "${KEY}" \\
    -l ${UI_PORT} \\
    --no-clipboard
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
# Pass password via environment variable to avoid shell-quoting issues
export DS1_ADMIN_PASS="$ADMIN_PASS"
$MANAGE shell -c "
import os
from django.contrib.auth import get_user_model
User = get_user_model()
pwd = os.environ['DS1_ADMIN_PASS']
if User.objects.filter(username='admin').exists():
    u = User.objects.get(username='admin')
    u.set_password(pwd)
    u.save()
    print('Admin password reset.')
else:
    User.objects.create_superuser('admin', 'admin@ds1hunter.local', pwd)
    print('Admin user created.')
"
unset DS1_ADMIN_PASS
ok "Admin user ready"

cd "$SRC_DIR"


# ══════════════════════════════════════════════════════════════════════════
step "Step 11 / 12  Setting permissions"
# ══════════════════════════════════════════════════════════════════════════

# Log directory
mkdir -p "$LOG_DIR"
chown "$SERVICE_USER" "$LOG_DIR"

# Proxy CA directory (service user must be able to write CA cert)
mkdir -p /var/lib/ds1hunter/proxy_ca
chown -R "$SERVICE_USER" /var/lib/ds1hunter
chmod 700 /var/lib/ds1hunter/proxy_ca

# Installation directory
chown -R "$SERVICE_USER" "$INSTALL_DIR"
# Key must be readable by the service user that runs serve and daphne
chmod 640 "$KEY"
chown root:"$SERVICE_USER" "$KEY"   # service user's group can read the key

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

    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>${BREW_PREFIX}/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
        <key>HOME</key>
        <string>/var/empty</string>
    </dict>

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

    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>${BREW_PREFIX}/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
        <key>HOME</key>
        <string>/var/empty</string>
    </dict>

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
lctl_load "$LAUNCHD_DIR/$PLIST_API.plist"
lctl_load "$LAUNCHD_DIR/$PLIST_UI.plist"

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
if (( MACOS_MAJOR >= 15 )); then
  _LOAD_API="launchctl bootstrap system ${LAUNCHD_DIR}/${PLIST_API}.plist"
  _LOAD_UI="launchctl bootstrap system ${LAUNCHD_DIR}/${PLIST_UI}.plist"
  _UNLOAD="launchctl bootout system ${LAUNCHD_DIR}/com.ds1hunter.*.plist"
else
  _LOAD_API="launchctl load ${LAUNCHD_DIR}/${PLIST_API}.plist"
  _LOAD_UI="launchctl load ${LAUNCHD_DIR}/${PLIST_UI}.plist"
  _UNLOAD="launchctl unload ${LAUNCHD_DIR}/com.ds1hunter.*.plist"
fi
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
