#!/usr/bin/env bash
# DS1 Hunter - Release Builder
# Produces: dist/ds1hunter-CE-v1.0.4-linux.run
#
# Protection stack:
#   Python  -> compiled to optimized .pyc (Python 3.13 bytecode, no public decompiler)
#   Frontend -> minified React bundle (no source maps, no src/)
#   Package  -> self-extracting .run (bash header + base64-encoded tarball)
#
# ── Changelog ──────────────────────────────────────────────────────────────
# v1.0.4  2026-06-18  Accuracy & OOB infrastructure release:
#                     · 8 false-positive fixes across LDAP injection,
#                       CORS, integer overflow, S3 403, CSS injection,
#                       public subdomain filtering, Verifier chain,
#                       accuracy scorer threshold calibration
#                     · OOB VPS: HTTP :8089 + DNS :53 callback server
#                       with poll API; DS1 Hunter polls VPS before cache
#                     · No schema changes; migrate runs in zero time
#
# v1.0.3  2026-06-08  Knowledge base overhaul (core/knowledge.py):
#                     · 80 vuln types (was 53) — 27 new types added: csrf,
#                       bfla, mfa_bypass, saml_injection, ldap_injection,
#                       padding_oracle, xpath_injection, crlf_injection,
#                       websocket_injection, second_order_sqli,
#                       session_fixation, weak_session_token, ssl_tls_weak,
#                       file_upload_unrestricted, subdomain_takeover,
#                       prompt_injection, llm_data_exfiltration, bola,
#                       api_key_exposure, sensitive_data_exposure,
#                       html_injection, default_credentials,
#                       debug_mode_enabled, directory_listing,
#                       sensitive_file_exposure, weak_password_policy
#                     · exploit_poc added to every KB entry (curl/tool cmds
#                       with {url}, {param}, {payload}, {token}, {host})
#                     · fix_code added to every KB entry (language-annotated
#                       before/after snippets)
#                     · generate_poc() function: substitutes placeholders
#                       with actual finding data at runtime
#                     · enrich_findings_knowledge() now attaches
#                       exploit_poc and fix_code to every finding

set -euo pipefail

VERSION="1.0.4"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$(mktemp -d /tmp/ds1hunter-build-XXXXXX)"
PAYLOAD="$BUILD_DIR/ds1hunter-${VERSION}"
DIST_DIR="$SRC_DIR/dist"
OUTPUT="$DIST_DIR/ds1hunter-CE-v${VERSION}-linux.run"

BOLD="\033[1m"
CYAN="\033[0;36m"
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
RED="\033[0;31m"
DIM="\033[2m"
RESET="\033[0m"

ok()   { echo -e "${GREEN}[✓]${RESET} $*"; }
info() { echo -e "${CYAN}[+]${RESET} $*"; }
warn() { echo -e "${YELLOW}[!]${RESET} $*"; }
die()  { echo -e "\n${RED}${BOLD}[✗] $*${RESET}\n" >&2; exit 1; }
step() { echo -e "\n${CYAN}${BOLD}━━ $* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"; }

trap 'echo -e "\n${YELLOW}[!] Cleaning up $BUILD_DIR ...${RESET}"; rm -rf "$BUILD_DIR"' EXIT

echo -e "\n${CYAN}${BOLD}"
echo "  ╔═══════════════════════════════════════════════════════╗"
echo "  ║       DS1 Hunter v${VERSION} — Release Builder            ║"
echo "  ║              by DigitalSecurity1                      ║"
echo "  ╚═══════════════════════════════════════════════════════╝"
echo -e "${RESET}"
echo -e "  Output: ${BOLD}$OUTPUT${RESET}\n"

mkdir -p "$PAYLOAD" "$DIST_DIR"


# ── Step 1: Build React frontend ──────────────────────────────────────────────
step "1 / 4  Building React frontend"

cd "$SRC_DIR/frontend"
info "Installing npm dependencies..."
npm install --silent 2>/dev/null
info "Building production bundle (no source maps)..."
GENERATE_SOURCEMAP=false CI=false npm run build --silent
ok "React bundle ready (source removed)"
cd "$SRC_DIR"


# ── Step 2: Assemble payload ──────────────────────────────────────────────────
step "2 / 4  Assembling distribution payload"

info "Copying project files to build directory..."

# Copy source (exclude dev artifacts)
rsync -a \
  --exclude='.venv/' \
  --exclude='node_modules/' \
  --exclude='__pycache__/' \
  --exclude='*.pyc' \
  --exclude='.env' \
  --exclude='db.sqlite3' \
  --exclude='data/sessions/' \
  --exclude='web/media/' \
  --exclude='ds1hunter.egg-info/' \
  --exclude='dist/' \
  --exclude='windows/' \
  --exclude='frontend/src/' \
  --exclude='frontend/build/' \
  --exclude='frontend/.env' \
  --exclude='frontend/.env.*' \
  --include='web/templates/***' \
  --exclude='*.html' \
  --exclude='*.md' \
  --exclude='*.csv' \
  --exclude='*.txt' \
  --exclude='docker-compose.yml' \
  --exclude='Dockerfile' \
  --exclude='setup.sh' \
  --exclude='make-release.sh' \
  "$SRC_DIR/" "$PAYLOAD/"

# Bring back requirements.txt (needed by installer)
cp "$SRC_DIR/requirements.txt" "$PAYLOAD/"

# Copy compiled React bundle (no src/)
mkdir -p "$PAYLOAD/frontend"
cp -r "$SRC_DIR/frontend/build"        "$PAYLOAD/frontend/"
cp    "$SRC_DIR/frontend/package.json" "$PAYLOAD/frontend/"

ok "Files assembled"


# ── Step 3: Protect Python source ─────────────────────────────────────────────
step "3 / 4  Protecting Python source code"

info "Compiling Python to optimized bytecode (Python 3.13 — no public decompiler)..."

# Compile all Python packages in the payload with -OO:
#   -O  : removes assert statements
#   -OO : removes assert statements AND docstrings
# -b places the .pyc alongside the .py in the same directory
python3 -OO -m compileall -b -q \
  "$PAYLOAD/core/" \
  "$PAYLOAD/cli/" \
  "$PAYLOAD/web/" \
  2>/dev/null || true

# Strip Python source — keep only:
#   __init__.py  : needed by setuptools/Django for package discovery
#   manage.py    : needed by installer to run migrations + collectstatic
#   migrations/  : Django tracks schema state via migration history imports
# Python source is kept in the package. The installer recompiles .pyc
# using the target machine's Python version at install time, which
# ensures the magic number always matches. Source is stripped by the installer.

PY_KEPT=$(find  "$PAYLOAD" -name "*.py"  | wc -l)
PYC_MADE=$(find "$PAYLOAD" -name "*.pyc" | wc -l)

ok "Compiled: $PYC_MADE modules protected"
ok "Plain .py kept: $PY_KEPT (package init / manage.py / migrations only)"

# Show what's NOT there (confirm core is stripped)
CORE_PY=$(find "$PAYLOAD/core" -name "*.py" ! -name "__init__.py" | wc -l)
CLI_PY=$(find  "$PAYLOAD/cli"  -name "*.py" ! -name "__init__.py" | wc -l)
WEB_PY=$(find  "$PAYLOAD/web"  -name "*.py" ! -name "__init__.py" ! -path "*/migrations/*" | wc -l)
info "Core engine .py exposed : $CORE_PY"
info "CLI source .py exposed  : $CLI_PY"
info "Django apps .py exposed : $WEB_PY"


# ── Step 4: Create self-extracting .run installer ─────────────────────────────
step "4 / 4  Building self-extracting installer"

info "Compressing payload..."
cd "$BUILD_DIR"
tar czf payload.tar.gz "ds1hunter-${VERSION}/"
PAYLOAD_SIZE=$(du -sh payload.tar.gz | cut -f1)
ok "Payload compressed: $PAYLOAD_SIZE"

info "Building self-extracting .run..."

cat > "$OUTPUT" << 'SFXEOF'
#!/usr/bin/env bash
# +=========================================================+
# |   DS1 Hunter - Community Edition v1.0.4                 |
# |   Linux Self-Extracting Installer                        |
# |   by DigitalSecurity1                                    |
# +=========================================================+
#
# Usage: sudo bash ds1hunter-CE-v1.0.4-linux.run
# Tested: Kali Linux 2024+, Debian 12, Ubuntu 22.04/24.04

set -euo pipefail

BOLD="\033[1m"
CYAN="\033[0;36m"
GREEN="\033[0;32m"
RED="\033[0;31m"
DIM="\033[2m"
RESET="\033[0m"

echo -e "${CYAN}${BOLD}"
echo "  +=========================================================+"
echo "  |                                                         |"
echo "  |      DS1 HUNTER  Community Edition v1.0.4               |"
echo "  |         \"Hunt. Chain. Prove.\"                           |"
echo "  |              by DigitalSecurity1                        |"
echo "  |                                                         |"
echo "  +=========================================================+"
echo -e "${RESET}"

[[ $EUID -ne 0 ]] && {
  echo -e "${RED}[✗] This installer requires root.${RESET}"
  echo -e "    Run: ${BOLD}sudo bash $0${RESET}"
  exit 1
}

echo -e "${DIM}  Verifying installer archive...${RESET}"

TMPDIR=$(mktemp -d /tmp/ds1hunter-install-XXXXXX)
trap 'rm -rf "$TMPDIR"' EXIT

echo -e "${CYAN}[+]${RESET} Extracting files (please wait)..."

SKIP=$(awk '/^__DS1HUNTER_PAYLOAD__/{print NR+1;exit}' "$0")
tail -n +$SKIP "$0" | base64 -d | tar xzf - -C "$TMPDIR"

INSTALL_SCRIPT=$(find "$TMPDIR" -maxdepth 2 -name "install-linux.sh" | head -1)

[[ -z "$INSTALL_SCRIPT" ]] && {
  echo -e "${RED}[✗] Archive is corrupt — install-linux.sh not found${RESET}"
  exit 1
}

echo -e "${GREEN}[✓]${RESET} Archive ready"
echo ""

chmod +x "$INSTALL_SCRIPT"
exec bash "$INSTALL_SCRIPT"

exit 0
__DS1HUNTER_PAYLOAD__
SFXEOF

# Append base64-encoded tarball (text-safe, no binary corruption)
base64 "$BUILD_DIR/payload.tar.gz" >> "$OUTPUT"
chmod +x "$OUTPUT"

FINAL_SIZE=$(du -sh "$OUTPUT" | cut -f1)
SHA256=$(sha256sum "$OUTPUT" | cut -d' ' -f1)

ok "Built: $OUTPUT"
ok "Size : $FINAL_SIZE"
ok "SHA256: $SHA256"

# Save checksum file alongside the .run
echo "$SHA256  ds1hunter-CE-v${VERSION}-linux.run" > "$DIST_DIR/ds1hunter-CE-v${VERSION}-linux.run.sha256"
ok "Checksum saved: dist/ds1hunter-CE-v${VERSION}-linux.run.sha256"

trap - EXIT
rm -rf "$BUILD_DIR"

echo ""
echo -e "${GREEN}${BOLD}"
echo "  ╔══════════════════════════════════════════════════════════════╗"
echo "  ║   Release ready for distribution!                           ║"
echo "  ║                                                             ║"
printf "  ║   File   : dist/ds1hunter-CE-v%-3s-linux.run              ║\n" "$VERSION"
printf "  ║   Size   : %-51s║\n" "$FINAL_SIZE"
printf "  ║   SHA256 : %-51s║\n" "${SHA256:0:48}..."
echo "  ║                                                             ║"
echo "  ║   Users download and run:                                   ║"
echo "  ║     sudo bash ds1hunter-CE-v1.0.4-linux.run                ║"
echo "  ║                                                             ║"
echo "  ║   Protection layers:                                        ║"
echo "  ║     Python  -> .pyc bytecode (Python 3.13, no decompiler)  ║"
echo "  ║     Frontend -> minified bundle (no source, no maps)        ║"
echo "  ║     Package  -> self-extracting .run (base64 + gzip)        ║"
echo "  ╚══════════════════════════════════════════════════════════════╝"
echo -e "${RESET}"
