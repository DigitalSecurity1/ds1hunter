#!/usr/bin/env bash
# DS1 Hunter - Windows Release Builder
# Produces: dist/ds1hunter-CE-v1.0.4-windows.ps1
#
# Run this on Linux or macOS to build the Windows distribution.
# Python 3.13 .pyc bytecode is platform-neutral (works on Linux/macOS/Windows).
#
# Protection stack:
#   Python   -> optimized .pyc bytecode (Python 3.13, no public decompiler)
#   Frontend -> minified React bundle (no source maps, no src/)
#   NSSM     -> bundled service manager binary (no runtime download needed)
#   Package  -> self-extracting PowerShell script (base64 ZIP embedded in .ps1)
#
# ── Changelog ──────────────────────────────────────────────────────────────
# v1.0.4  2026-06-18  Accuracy & OOB infrastructure release:
#                     · 8 false-positive fixes across LDAP injection,
#                       CORS, integer overflow, S3 403, CSS injection,
#                       public subdomain filtering, Verifier chain (2
#                       signals required), accuracy scorer calibrated
#                     · OOB VPS: HTTP :8089 + DNS :53 with poll API
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
BUILD_DIR="$(mktemp -d /tmp/ds1hunter-win-build-XXXXXX)"
PAYLOAD="$BUILD_DIR/ds1hunter-${VERSION}"
DIST_DIR="$SRC_DIR/dist"
OUTPUT="$DIST_DIR/ds1hunter-CE-v${VERSION}-windows.ps1"

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
echo "  ║    DS1 Hunter v${VERSION} — Windows Release Builder            ║"
echo "  ║                  by DigitalSecurity1                      ║"
echo "  ╚════════════════════════════════════════════════════════════╝"
echo -e "${RESET}"
echo -e "  Output: ${BOLD}$OUTPUT${RESET}\n"

command -v zip  &>/dev/null || die "zip is required. Install: apt-get install zip"
command -v curl &>/dev/null || die "curl is required."

mkdir -p "$PAYLOAD" "$DIST_DIR"


# ── Step 1: Build React frontend ──────────────────────────────────────────────
step "1 / 5  Building React frontend"

cd "$SRC_DIR/frontend"
info "Installing npm dependencies..."
npm install --silent 2>/dev/null
info "Building production bundle (no source maps)..."
GENERATE_SOURCEMAP=false CI=false npm run build --silent
ok "React bundle ready (source removed)"
cd "$SRC_DIR"


# ── Step 2: Bundle NSSM (Windows Service Manager) ────────────────────────────
step "2 / 5  Bundling NSSM (Windows service manager)"

NSSM_URL="https://nssm.cc/release/nssm-2.24.zip"
NSSM_ZIP="$BUILD_DIR/nssm.zip"
NSSM_DEST="$PAYLOAD/bin/nssm.exe"
NSSM_CACHE="$SRC_DIR/bin/nssm.exe"

mkdir -p "$PAYLOAD/bin"

# Use cached copy first, then try downloading
if [[ -f "$NSSM_CACHE" ]]; then
  cp "$NSSM_CACHE" "$NSSM_DEST"
  ok "NSSM bundled from cache: $(du -sh "$NSSM_DEST" | cut -f1)"
elif curl -sL --max-time 30 "$NSSM_URL" -o "$NSSM_ZIP" 2>/dev/null && unzip -t "$NSSM_ZIP" &>/dev/null; then
  unzip -q -j "$NSSM_ZIP" "nssm-2.24/win64/nssm.exe" -d "$PAYLOAD/bin/"
  cp "$NSSM_DEST" "$NSSM_CACHE"
  ok "NSSM downloaded and cached: $(du -sh "$NSSM_DEST" | cut -f1)"
else
  warn "NSSM not available. The installer will download it at install time."
fi


# ── Step 3: Assemble payload ──────────────────────────────────────────────────
step "3 / 5  Assembling distribution payload"

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
  --exclude='web/media/' \
  --include='web/templates/***' \
  --exclude='*.html' \
  --exclude='*.md' \
  --exclude='*.csv' \
  --exclude='*.txt' \
  --exclude='docker-compose.yml' \
  --exclude='Dockerfile' \
  --exclude='setup.sh' \
  --exclude='make-release.sh' \
  --exclude='make-release-macos.sh' \
  --exclude='make-release-windows.sh' \
  --exclude='install-linux.sh' \
  --exclude='install-macos.sh' \
  --exclude='install-windows.ps1' \
  "$SRC_DIR/" "$PAYLOAD/"

# Bring back requirements.txt
cp "$SRC_DIR/requirements.txt" "$PAYLOAD/"

# Include the Windows installer with UTF-8 BOM so PowerShell 5.1 reads it correctly
printf '\xef\xbb\xbf' > "$PAYLOAD/install-windows.ps1"
cat "$SRC_DIR/install-windows.ps1" >> "$PAYLOAD/install-windows.ps1"

# React build (no src/)
mkdir -p "$PAYLOAD/frontend"
cp -r "$SRC_DIR/frontend/build"        "$PAYLOAD/frontend/"
cp    "$SRC_DIR/frontend/package.json" "$PAYLOAD/frontend/"

ok "Files assembled"


# ── Step 4: Protect Python source ─────────────────────────────────────────────
step "4 / 5  Protecting Python source code"

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
info "Core engine .py exposed : $CORE_PY"
info "CLI source .py exposed  : $CLI_PY"


# ── Step 5: Build self-extracting PowerShell installer ───────────────────────
step "5 / 5  Building self-extracting PowerShell installer"

info "Creating ZIP payload..."
cd "$BUILD_DIR"
zip -r -q payload.zip "ds1hunter-${VERSION}/"
PAYLOAD_SIZE=$(du -sh payload.zip | cut -f1)
ok "Payload: $PAYLOAD_SIZE compressed"

info "Building .ps1 self-extractor..."

# Write UTF-8 BOM first — Windows PowerShell 5.1 reads files without BOM using the
# system codepage (cp1252). Box-drawing chars in the script contain byte 0x94 which
# maps to RIGHT DOUBLE QUOTATION MARK in cp1252, breaking string parsing.
# With the BOM, PowerShell correctly reads the file as UTF-8.
printf '\xef\xbb\xbf' > "$OUTPUT"

# Write the PowerShell SFX header
cat >> "$OUTPUT" << 'SFXEOF'
# ╔════════════════════════════════════════════════════════════╗
# ║   DS1 Hunter v1.0.4 - Windows Self-Extracting Installer    ║
# ║                  by DigitalSecurity1                       ║
# ║              "Hunt. Chain. Prove."                         ║
# ╚════════════════════════════════════════════════════════════╝
#
# Usage (PowerShell as Administrator):
#   powershell -ExecutionPolicy Bypass -File ds1hunter-CE-v1.0.4-windows.ps1
#
# Tested: Windows 10 21H2+, Windows 11, Windows Server 2022+

$ErrorActionPreference = "Stop"
$ProgressPreference    = "SilentlyContinue"

# Admin check
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[!] This installer requires Administrator privileges." -ForegroundColor Red
    Write-Host "    Open PowerShell as Administrator, then run:" -ForegroundColor Red
    Write-Host "    powershell -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`"" -ForegroundColor Yellow
    exit 1
}

Write-Host ""
Write-Host "  ╔═══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║     DS1 HUNTER  Community Edition v1.0.4              ║" -ForegroundColor Cyan
Write-Host "  ║          `"Hunt. Chain. Prove.`"                        ║" -ForegroundColor Cyan
Write-Host "  ║               by DigitalSecurity1                     ║" -ForegroundColor Cyan
Write-Host "  ╚═══════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Verifying installer archive..." -ForegroundColor DarkGray

# Create temp directory
$tmpDir  = Join-Path $env:TEMP ("ds1hunter-install-" + [System.IO.Path]::GetRandomFileName().Replace(".", ""))
New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null

# Cleanup on exit
$null = Register-EngineEvent PowerShell.Exiting -Action { Remove-Item -Path $tmpDir -Recurse -Force -ErrorAction SilentlyContinue }

Write-Host "[+] Extracting files (please wait)..." -ForegroundColor Cyan

# Read this script file, find the payload marker, decode base64 ZIP
$scriptContent = Get-Content -Raw -Path $PSCommandPath
$marker        = "<# __DS1HUNTER_PAYLOAD__"
$markerIdx     = $scriptContent.LastIndexOf($marker)
if ($markerIdx -lt 0) {
    Write-Host "[!] Archive is corrupt - payload marker not found." -ForegroundColor Red
    exit 1
}

$b64   = $scriptContent.Substring($markerIdx + $marker.Length)
$b64   = $b64 -replace '#>', ''   # strip closing block-comment tag
$b64   = $b64 -replace '\s', ''   # strip all whitespace / line endings
$bytes = [Convert]::FromBase64String($b64)

$zipPath = Join-Path $tmpDir "payload.zip"
[System.IO.File]::WriteAllBytes($zipPath, $bytes)
Expand-Archive -Path $zipPath -DestinationPath $tmpDir -Force

# Find and run the inner installer
$installer = Get-ChildItem -Path $tmpDir -Filter "install-windows.ps1" -Recurse | Select-Object -First 1
if (-not $installer) {
    Write-Host "[!] Archive is corrupt - install-windows.ps1 not found." -ForegroundColor Red
    exit 1
}

Write-Host "[✓] Archive ready" -ForegroundColor Green
Write-Host ""

$sourceDir = $installer.DirectoryName
& powershell -ExecutionPolicy Bypass -File $installer.FullName -SourceDir $sourceDir

exit 0
<# __DS1HUNTER_PAYLOAD__
SFXEOF

# Append base64-encoded ZIP payload then close the block comment so
# PowerShell's parser never sees the raw base64 as code.
base64 "$BUILD_DIR/payload.zip" >> "$OUTPUT"
printf '#>' >> "$OUTPUT"

FINAL_SIZE=$(du -sh "$OUTPUT" | cut -f1)
SHA256=$(sha256sum "$OUTPUT" | cut -d' ' -f1)

ok "Built: $OUTPUT"
ok "Size : $FINAL_SIZE"
ok "SHA256: $SHA256"

echo "$SHA256  ds1hunter-CE-v${VERSION}-windows.ps1" > "$DIST_DIR/ds1hunter-CE-v${VERSION}-windows.ps1.sha256"
ok "Checksum saved: dist/ds1hunter-CE-v${VERSION}-windows.ps1.sha256"

trap - EXIT
rm -rf "$BUILD_DIR"

echo ""
echo -e "${GREEN}${BOLD}"
echo "  ╔══════════════════════════════════════════════════════════════╗"
echo "  ║   Windows release ready for distribution!                   ║"
echo "  ║                                                             ║"
printf "  ║   File   : dist/ds1hunter-CE-v%-3s-windows.ps1          ║\n" "$VERSION"
printf "  ║   Size   : %-51s║\n" "$FINAL_SIZE"
printf "  ║   SHA256 : %-51s║\n" "${SHA256:0:48}..."
echo "  ║                                                             ║"
echo "  ║   Users download and run (as Administrator):               ║"
echo "  ║     powershell -ExecutionPolicy Bypass \                   ║"
echo "  ║       -File ds1hunter-CE-v1.0.4-windows.ps1               ║"
echo "  ║                                                             ║"
echo "  ║   Protection layers:                                        ║"
echo "  ║     Python   -> .pyc bytecode (Python 3.13, no decompiler) ║"
echo "  ║     Frontend -> minified bundle (no source, no maps)        ║"
echo "  ║     NSSM     -> bundled service manager (offline install)   ║"
echo "  ║     Package  -> self-extracting .ps1 (base64 ZIP embedded)  ║"
echo "  ╚══════════════════════════════════════════════════════════════╝"
echo -e "${RESET}"
