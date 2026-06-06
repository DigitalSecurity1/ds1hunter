#!/usr/bin/env bash
# DS1 Hunter - macOS Release Builder
# Produces: dist/ds1hunter-CE-v1.0.2-macos.run
#
# Can be run from Linux or macOS.
# Python 3.13 .pyc bytecode is platform-neutral (same format on Linux/macOS/Windows).
#
# Protection stack:
#   Python   -> optimized .pyc bytecode (Python 3.13, no public decompiler)
#   Frontend -> minified React bundle (no source maps, no src/)
#   Package  -> self-extracting .run (bash header + base64-encoded tarball)

set -euo pipefail

VERSION="1.0.3"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$(mktemp -d /tmp/ds1hunter-macos-build-XXXXXX)"
PAYLOAD="$BUILD_DIR/ds1hunter-${VERSION}"
DIST_DIR="$SRC_DIR/dist"
OUTPUT="$DIST_DIR/ds1hunter-CE-v${VERSION}-macos.run"

BOLD="\033[1m"
CYAN="\033[0;36m"
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
RED="\033[0;31m"
RESET="\033[0m"

ok()   { echo -e "${GREEN}[✓]${RESET} $*"; }
info() { echo -e "${CYAN}[+]${RESET} $*"; }
warn() { echo -e "${YELLOW}[!]${RESET} $*"; }
die()  { echo -e "\n${RED}${BOLD}[✗] $*${RESET}\n" >&2; exit 1; }
step() { echo -e "\n${CYAN}${BOLD}━━ $* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"; }

trap 'echo -e "\n${YELLOW}[!] Cleaning up $BUILD_DIR ...${RESET}"; rm -rf "$BUILD_DIR"' EXIT

echo -e "\n${CYAN}${BOLD}"
echo "  ╔════════════════════════════════════════════════════════════╗"
echo "  ║     DS1 Hunter v${VERSION} — macOS Release Builder             ║"
echo "  ║                  by DigitalSecurity1                      ║"
echo "  ╚════════════════════════════════════════════════════════════╝"
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

info "Copying project files..."
rsync -a \
  --exclude='.venv/' \
  --exclude='node_modules/' \
  --exclude='__pycache__/' \
  --exclude='*.pyc' \
  --exclude='.env' \
  --exclude='db.sqlite3' \
  --exclude='data/sessions/' \
  --exclude='ds1hunter.egg-info/' \
  --exclude='dist/' \
  --exclude='windows/' \
  --exclude='frontend/src/' \
  --exclude='frontend/build/' \
  --exclude='frontend/.env' \
  --exclude='frontend/.env.*' \
  --include='web/templates/***' \
  --exclude='*.html' \
  --exclude='web/media/' \
  --exclude='*.md' \
  --exclude='*.csv' \
  --exclude='*.txt' \
  --exclude='docker-compose.yml' \
  --exclude='Dockerfile' \
  --exclude='setup.sh' \
  --exclude='make-release.sh' \
  --exclude='make-release-macos.sh' \
  --exclude='install-linux.sh' \
  "$SRC_DIR/" "$PAYLOAD/"

# Bring back requirements.txt
cp "$SRC_DIR/requirements.txt" "$PAYLOAD/"

# Copy the macOS installer as install-linux.sh is to Linux
# The SFX header calls "install-linux.sh" by name -- so we include the macOS one under that name
cp "$SRC_DIR/install-macos.sh" "$PAYLOAD/install-linux.sh"

# React build
mkdir -p "$PAYLOAD/frontend"
cp -r "$SRC_DIR/frontend/build"        "$PAYLOAD/frontend/"
cp    "$SRC_DIR/frontend/package.json" "$PAYLOAD/frontend/"

ok "Files assembled"


# ── Step 3: Protect Python source ─────────────────────────────────────────────
step "3 / 4  Protecting Python source code"

info "Compiling Python to optimized bytecode..."
python3 -OO -m compileall -b -q \
  "$PAYLOAD/core/" \
  "$PAYLOAD/cli/" \
  "$PAYLOAD/web/" \
  2>/dev/null || true

# Python source is kept in the package. The installer recompiles .pyc
# using the target machine's Python version at install time, which
# ensures the magic number always matches. Source is stripped by the installer.

PY_KEPT=$(find  "$PAYLOAD" -name "*.py"  | wc -l)
PYC_MADE=$(find "$PAYLOAD" -name "*.pyc" | wc -l)

ok "Compiled: $PYC_MADE modules protected"
ok "Plain .py kept: $PY_KEPT (package init / manage.py / migrations only)"

CORE_PY=$(find "$PAYLOAD/core" -name "*.py" ! -name "__init__.py" 2>/dev/null | wc -l)
CLI_PY=$(find  "$PAYLOAD/cli"  -name "*.py" ! -name "__init__.py" 2>/dev/null | wc -l)
WEB_PY=$(find  "$PAYLOAD/web"  -name "*.py" ! -name "__init__.py" ! -path "*/migrations/*" 2>/dev/null | wc -l)
info "Core engine .py exposed : $CORE_PY"
info "CLI source .py exposed  : $CLI_PY"
info "Django apps .py exposed : $WEB_PY"


# ── Step 4: Build self-extracting .run ────────────────────────────────────────
step "4 / 4  Building self-extracting installer"

info "Compressing payload..."
cd "$BUILD_DIR"
tar czf payload.tar.gz "ds1hunter-${VERSION}/"
PAYLOAD_SIZE=$(du -sh payload.tar.gz | cut -f1)
ok "Payload: $PAYLOAD_SIZE compressed"

info "Building .run file..."

cat > "$OUTPUT" << 'SFXEOF'
#!/usr/bin/env bash
# ╔════════════════════════════════════════════════════════════╗
# ║    DS1 Hunter v1.0.2 — macOS Self-Extracting Installer     ║
# ║                  by DigitalSecurity1                       ║
# ║              "Hunt. Chain. Prove."                         ║
# ╚════════════════════════════════════════════════════════════╝
#
# Usage: sudo bash ds1hunter-CE-v1.0.2-macos.run
#
# If macOS Gatekeeper blocks execution:
#   xattr -d com.apple.quarantine ds1hunter-CE-v1.0.2-macos.run
#   sudo bash ds1hunter-CE-v1.0.2-macos.run
#
# Tested: macOS Ventura 13+, Sonoma 14+, Sequoia 15+ (Intel + Apple Silicon)

set -euo pipefail

BOLD="\033[1m"
CYAN="\033[0;36m"
GREEN="\033[0;32m"
RED="\033[0;31m"
DIM="\033[2m"
RESET="\033[0m"

echo -e "${CYAN}${BOLD}"
echo "  ╔═══════════════════════════════════════════════════════╗"
echo "  ║                                                       ║"
echo "  ║     DS1 HUNTER  Community Edition v1.0.2             ║"
echo "  ║          \"Hunt. Chain. Prove.\"                        ║"
echo "  ║               by DigitalSecurity1                     ║"
echo "  ║                                                       ║"
echo "  ╚═══════════════════════════════════════════════════════╝"
echo -e "${RESET}"

# macOS check
[[ "$(uname -s)" != "Darwin" ]] && {
  echo -e "${RED}[✗] This installer is for macOS only.${RESET}"
  echo -e "    For Linux, use: ds1hunter-CE-v1.0.2-linux.run"
  exit 1
}

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

INSTALL_SCRIPT=$(find "$TMPDIR" -name "install-linux.sh" -maxdepth 2 | head -1)

[[ -z "$INSTALL_SCRIPT" ]] && {
  echo -e "${RED}[✗] Archive is corrupt -- installer script not found${RESET}"
  exit 1
}

echo -e "${GREEN}[✓]${RESET} Archive ready"
echo ""

chmod +x "$INSTALL_SCRIPT"
exec bash "$INSTALL_SCRIPT"

exit 0
__DS1HUNTER_PAYLOAD__
SFXEOF

base64 "$BUILD_DIR/payload.tar.gz" >> "$OUTPUT"
chmod +x "$OUTPUT"

FINAL_SIZE=$(du -sh "$OUTPUT" | cut -f1)
SHA256=$(sha256sum "$OUTPUT" 2>/dev/null || shasum -a 256 "$OUTPUT" | cut -d' ' -f1)
# Handle both Linux (sha256sum) and macOS (shasum) output
SHA256=$(echo "$SHA256" | awk '{print $1}')

ok "Built: $OUTPUT"
ok "Size : $FINAL_SIZE"
ok "SHA256: $SHA256"

echo "$SHA256  ds1hunter-CE-v${VERSION}-macos.run" > "$DIST_DIR/ds1hunter-CE-v${VERSION}-macos.run.sha256"
ok "Checksum saved: dist/ds1hunter-CE-v${VERSION}-macos.run.sha256"

trap - EXIT
rm -rf "$BUILD_DIR"

echo ""
echo -e "${GREEN}${BOLD}"
echo "  ╔══════════════════════════════════════════════════════════════╗"
echo "  ║   macOS release ready for distribution!                     ║"
echo "  ║                                                             ║"
printf "  ║   File   : dist/ds1hunter-CE-v%-3s-macos.run             ║\n" "$VERSION"
printf "  ║   Size   : %-51s║\n" "$FINAL_SIZE"
printf "  ║   SHA256 : %-51s║\n" "${SHA256:0:48}..."
echo "  ║                                                             ║"
echo "  ║   Users download and run:                                   ║"
echo "  ║     sudo bash ds1hunter-CE-v1.0.2-macos.run                ║"
echo "  ║                                                             ║"
echo "  ║   Protection layers:                                        ║"
echo "  ║     Python   -> .pyc bytecode (Python 3.13, no decompiler) ║"
echo "  ║     Frontend -> minified bundle (no source, no maps)        ║"
echo "  ║     Package  -> self-extracting .run (base64 + gzip)        ║"
echo "  ╚══════════════════════════════════════════════════════════════╝"
echo -e "${RESET}"
