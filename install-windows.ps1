# ╔══════════════════════════════════════════════════════════════╗
# ║       DS1 Hunter v1.0.2 - Windows Production Installer       ║
# ║                   by DigitalSecurity1                        ║
# ║               "Hunt. Chain. Prove."                          ║
# ╚══════════════════════════════════════════════════════════════╝
#
# Usage:  (extracted automatically by the .ps1 self-extractor)
# Tested: Windows 10 21H2+, Windows 11, Windows Server 2022+

param(
    [string]$SourceDir = $PSScriptRoot
)

Set-StrictMode -Off
$ErrorActionPreference = "Stop"
$ProgressPreference    = "SilentlyContinue"   # suppress progress bars for Invoke-WebRequest

# Force TLS 1.2+ for ALL web requests.
# Windows 10 Home PowerShell defaults to TLS 1.0 which python.org / nodejs.org reject.
try {
    [Net.ServicePointManager]::SecurityProtocol = `
        [Net.SecurityProtocolType]::Tls13 -bor [Net.SecurityProtocolType]::Tls12
} catch {
    # TLS 1.3 not available on this Windows build — TLS 1.2 is sufficient
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}

# ── Constants ──────────────────────────────────────────────────────────────────
$INSTALL_DIR = "C:\ds1hunter"
$API_PORT    = 18000
$UI_PORT     = 13000
$VERSION     = "1.0.2"
$CERT_DIR    = "$INSTALL_DIR\certs"
$CERT        = "$CERT_DIR\ds1hunter.crt"
$KEY         = "$CERT_DIR\ds1hunter.key"
$LOG_DIR     = "$INSTALL_DIR\logs"
$BIN_DIR     = "$INSTALL_DIR\bin"
$NSSM        = "$BIN_DIR\nssm.exe"
$NODE_GLOBAL = "$INSTALL_DIR\node-global"

# ── Helpers ────────────────────────────────────────────────────────────────────
function Write-Ok   { param($msg) Write-Host "[✓] $msg" -ForegroundColor Green }
function Write-Info { param($msg) Write-Host "[+] $msg" -ForegroundColor Cyan }
function Write-Warn { param($msg) Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Step { param($msg) Write-Host "`n━━ $msg ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan }
function Write-Die  {
    param($msg)
    Write-Host "`n[✗] $msg" -ForegroundColor Red
    exit 1
}

function Refresh-Path {
    $machine = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
    $user    = [System.Environment]::GetEnvironmentVariable("Path", "User")
    $env:Path = "$machine;$user"
}

function Find-Python {
    Refresh-Path
    $py = Get-Command python -ErrorAction SilentlyContinue
    if ($py -and $py.Source -notlike "*WindowsApps*") { return $py.Source }
    $candidates = @(
        "$env:LOCALAPPDATA\Programs\Python\Python313\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe",
        "C:\Python313\python.exe",
        "C:\Python312\python.exe",
        "C:\Program Files\Python313\python.exe",
        "C:\Program Files\Python312\python.exe"
    )
    foreach ($c in $candidates) { if (Test-Path $c) { return $c } }
    return $null
}

function Find-Node {
    Refresh-Path
    $node = Get-Command node -ErrorAction SilentlyContinue
    if ($node) { return $node.Source }
    $candidates = @(
        "C:\Program Files\nodejs\node.exe",
        "C:\Program Files (x86)\nodejs\node.exe"
    )
    foreach ($c in $candidates) { if (Test-Path $c) { return $c } }
    return $null
}

function Find-Npm {
    Refresh-Path
    $npm = Get-Command npm -ErrorAction SilentlyContinue
    if ($npm) { return $npm.Source }
    $dir = Split-Path (Find-Node) -Parent
    $candidate = "$dir\npm.cmd"
    if (Test-Path $candidate) { return $candidate }
    return $null
}

function Invoke-Npm {
    param([string[]]$NpmArgs)
    $npmCmd = Find-Npm
    if (-not $npmCmd) { Write-Die "npm not found" }
    & $npmCmd @NpmArgs
}

function Invoke-Manage {
    param([string[]]$ManageArgs)
    & $VENV_PYTHON "$INSTALL_DIR\web\manage.py" @ManageArgs
    if ($LASTEXITCODE -ne 0) { throw "manage.py $($ManageArgs[0]) failed" }
}

# Track whether installation has started so the trap only cleans up if needed
$script:_setupActive = $false

trap {
    Write-Host ""
    Write-Host "  [!] Installation failed: $($_.Exception.Message)" -ForegroundColor Red
    if ($script:_setupActive) {
        Write-Host "  Cleaning up partial installation..." -ForegroundColor Yellow
        foreach ($svc in @("DS1HunterAPI", "DS1HunterUI")) {
            Stop-Service $svc -Force -ErrorAction SilentlyContinue
            if ((Test-Path "$BIN_DIR\nssm.exe") -and (Get-Service $svc -ErrorAction SilentlyContinue)) {
                & "$BIN_DIR\nssm.exe" remove $svc confirm 2>&1 | Out-Null
            }
        }
        Start-Sleep -Seconds 1
        if (Test-Path $INSTALL_DIR) {
            icacls $INSTALL_DIR /reset /t 2>&1 | Out-Null
            Remove-Item -Path $INSTALL_DIR -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "  [!] Partial installation removed. Re-run the installer to try again." -ForegroundColor Yellow
        }
    }
    exit 1
}

# ── Banner ─────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ╔═══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║                                                       ║" -ForegroundColor Cyan
Write-Host "  ║     DS1 HUNTER  Community Edition v$VERSION              ║" -ForegroundColor Cyan
Write-Host "  ║             `"Hunt. Chain. Prove.`"                     ║" -ForegroundColor Cyan
Write-Host "  ║                 by DigitalSecurity1                   ║" -ForegroundColor Cyan
Write-Host "  ║                                                       ║" -ForegroundColor Cyan
Write-Host "  ╚═══════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Production installer for Windows" -ForegroundColor DarkGray
Write-Host ""

# ── Admin check ────────────────────────────────────────────────────────────────
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Die "Run as Administrator:`n  Right-click PowerShell > Run as Administrator`n  Then: powershell -ExecutionPolicy Bypass -File ds1hunter-CE-v1.0.2-windows.ps1" }

# Windows version check (10+)
$winVer = [System.Environment]::OSVersion.Version
if ($winVer.Major -lt 10) { Write-Die "Windows 10 or newer is required." }

# ══════════════════════════════════════════════════════════════════════════════
Write-Step "Step 1 / 12  Checking system dependencies"
# ══════════════════════════════════════════════════════════════════════════════

# ── Dependency installer helpers ───────────────────────────────────────────────

function Install-ViaWinget {
    param([string]$Id, [string]$Name)
    # Try community source first, then msstore, then no source.
    # Omitting --source works on all Windows editions including Home.
    $attempts = @(
        @("--id", $Id, "-e", "--silent", "--accept-package-agreements", "--accept-source-agreements"),
        @("--id", $Id, "-e", "--silent", "--accept-package-agreements", "--accept-source-agreements", "--source", "msstore")
    )
    foreach ($args in $attempts) {
        try {
            $result = & winget install @args 2>&1
            if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq -1978335189) {
                # 0 = success, -1978335189 = already installed
                return $true
            }
        } catch { }
    }
    return $false
}

function Install-PythonDirect {
    Write-Info "Downloading Python 3.13 installer from python.org..."
    $pyUrl  = "https://www.python.org/ftp/python/3.13.3/python-3.13.3-amd64.exe"
    $pyTmp  = "$env:TEMP\python-313-setup.exe"
    try {
        Invoke-WebRequest -Uri $pyUrl -OutFile $pyTmp -UseBasicParsing
        Write-Info "Running Python installer (silent)..."
        Start-Process -FilePath $pyTmp -ArgumentList @(
            "/quiet", "InstallAllUsers=1", "PrependPath=1",
            "Include_test=0", "Include_doc=0"
        ) -Wait
        Remove-Item $pyTmp -ErrorAction SilentlyContinue
        Refresh-Path
        return $true
    } catch {
        Write-Warn "Direct Python download failed: $_"
        return $false
    }
}

function Install-NodeDirect {
    Write-Info "Downloading Node.js LTS installer from nodejs.org..."
    $nodeUrl = "https://nodejs.org/dist/v22.11.0/node-v22.11.0-x64.msi"
    $nodeTmp = "$env:TEMP\nodejs-setup.msi"
    try {
        Invoke-WebRequest -Uri $nodeUrl -OutFile $nodeTmp -UseBasicParsing
        Write-Info "Running Node.js installer (silent)..."
        Start-Process -FilePath "msiexec.exe" -ArgumentList @(
            "/i", $nodeTmp, "/quiet", "/norestart", "ADDLOCAL=ALL"
        ) -Wait
        Remove-Item $nodeTmp -ErrorAction SilentlyContinue
        Refresh-Path
        return $true
    } catch {
        Write-Warn "Direct Node.js download failed: $_"
        return $false
    }
}

# ── Check / install dependencies ───────────────────────────────────────────────

$hasWinget = $null -ne (Get-Command winget -ErrorAction SilentlyContinue)
if ($hasWinget) {
    Write-Ok "winget available"
} else {
    Write-Warn "winget not found - will use direct downloads from python.org and nodejs.org"
}

# Python
$PYTHON = Find-Python
if (-not $PYTHON) {
    $installed = $false
    if ($hasWinget) {
        Write-Info "Installing Python 3.13 via winget..."
        $installed = Install-ViaWinget "Python.Python.3.13" "Python 3.13"
        Refresh-Path; $PYTHON = Find-Python
    }
    if (-not $PYTHON) {
        Write-Info "Trying direct download from python.org..."
        $installed = Install-PythonDirect
        $PYTHON = Find-Python
    }
    if (-not $PYTHON) {
        Write-Die "Python 3.13+ not found and automatic install failed.`nInstall manually from https://www.python.org/downloads/windows/ then re-run."
    }
}
$pyVer = & $PYTHON --version 2>&1
Write-Ok "$pyVer at $PYTHON"

# Node.js
$NODE = Find-Node
if (-not $NODE) {
    $installed = $false
    if ($hasWinget) {
        Write-Info "Installing Node.js LTS via winget..."
        $installed = Install-ViaWinget "OpenJS.NodeJS.LTS" "Node.js LTS"
        Refresh-Path; $NODE = Find-Node
    }
    if (-not $NODE) {
        Write-Info "Trying direct download from nodejs.org..."
        $installed = Install-NodeDirect
        $NODE = Find-Node
    }
    if (-not $NODE) {
        Write-Die "Node.js not found and automatic install failed.`nInstall manually from https://nodejs.org/ then re-run."
    }
}
$nodeVer = & $NODE --version 2>&1
Write-Ok "Node.js $nodeVer at $NODE"


# ══════════════════════════════════════════════════════════════════════════════
Write-Step "Step 2 / 12  Preparing installation directory"
# ══════════════════════════════════════════════════════════════════════════════

$script:_setupActive = $true

if (Test-Path $INSTALL_DIR) {
    Write-Warn "Existing installation found at $INSTALL_DIR"
    Write-Host "  This will erase the current database and all stored hunts." -ForegroundColor Yellow
    $confirm = Read-Host "  Overwrite? [y/N]"
    if ($confirm -notmatch "^[yY]$") { Write-Die "Installation cancelled." }
    # Stop running services
    foreach ($svc in @("DS1HunterAPI", "DS1HunterUI")) {
        $s = Get-Service $svc -ErrorAction SilentlyContinue
        if ($s) { Stop-Service $svc -Force -ErrorAction SilentlyContinue }
    }
    if (Test-Path "$BIN_DIR\nssm.exe") {
        foreach ($svc in @("DS1HunterAPI", "DS1HunterUI")) {
            if (Get-Service $svc -ErrorAction SilentlyContinue) {
                & "$BIN_DIR\nssm.exe" remove $svc confirm 2>&1 | Out-Null
            }
        }
    }
    Start-Sleep -Seconds 2
    Remove-Item -Path $INSTALL_DIR -Recurse -Force -ErrorAction SilentlyContinue
    Write-Ok "Old installation removed"
}

New-Item -Path $INSTALL_DIR -ItemType Directory -Force | Out-Null

Write-Info "Copying files to $INSTALL_DIR..."
$excludes = @('.venv', 'node_modules', '__pycache__', '.env', 'db.sqlite3', 'dist')
$srcItems = Get-ChildItem -Path $SourceDir -Force | Where-Object { $_.Name -notin $excludes }
foreach ($item in $srcItems) {
    Copy-Item -Path $item.FullName -Destination $INSTALL_DIR -Recurse -Force
}
Write-Ok "Files installed to $INSTALL_DIR"
New-Item -Path $LOG_DIR -ItemType Directory -Force | Out-Null
New-Item -Path $BIN_DIR -ItemType Directory -Force | Out-Null


# ══════════════════════════════════════════════════════════════════════════════
Write-Step "Step 3 / 12  Setting up Python virtual environment"
# ══════════════════════════════════════════════════════════════════════════════

$VENV        = "$INSTALL_DIR\.venv"
$VENV_PYTHON = "$VENV\Scripts\python.exe"
$VENV_PIP    = "$VENV\Scripts\pip.exe"
$VENV_DAPHNE = "$VENV\Scripts\daphne.exe"

Write-Info "Creating venv..."
& $PYTHON -m venv $VENV
& $VENV_PYTHON -m pip install --upgrade pip setuptools wheel -q --timeout 120 2>&1 | Out-Null
Write-Ok "Venv created"

Write-Info "Installing Python dependencies..."
& $VENV_PYTHON -m pip install -r "$INSTALL_DIR\requirements.txt" -q --timeout 120 --retries 5
Write-Ok "Dependencies installed"

Write-Info "Installing daphne (ASGI server)..."
& $VENV_PYTHON -m pip install daphne -q --timeout 120 --retries 5
Write-Ok "Daphne ready"

Write-Info "Registering ds1hunter CLI..."
& $VENV_PIP install -e "$INSTALL_DIR" -q
Write-Ok "CLI registered"


# ══════════════════════════════════════════════════════════════════════════════
Write-Step "Step 3.5 / 12  Compiling Python bytecode for local Python version"
# ══════════════════════════════════════════════════════════════════════════════
# Python .pyc magic numbers are version-specific. Compiling on the target
# machine ensures bytecode always matches the installed Python interpreter.

$venvPyVer = (& $VENV_PYTHON -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')").Trim()
Write-Info "Compiling Python source to optimized bytecode (Python $venvPyVer)..."

$pyDirs = @("$INSTALL_DIR\core", "$INSTALL_DIR\cli", "$INSTALL_DIR\web")
foreach ($d in $pyDirs) {
    if (Test-Path $d) {
        & $VENV_PYTHON -OO -m compileall -b -q $d 2>$null
    }
}

$pycCount = (Get-ChildItem -Path $INSTALL_DIR -Filter "*.pyc" -Recurse -ErrorAction SilentlyContinue).Count
Write-Ok "Compiled $pycCount modules (Python $venvPyVer bytecode)"

Write-Info "Stripping Python source files (keeping only bytecode)..."
# Scope strip to OUR source directories only. Never touch .venv or
# site-packages - that would delete Django and the editable install finder.
foreach ($srcDir in @("$INSTALL_DIR\core", "$INSTALL_DIR\cli", "$INSTALL_DIR\web")) {
    if (Test-Path $srcDir) {
        Get-ChildItem -Path $srcDir -Filter "*.py" -Recurse -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Name -ne "__init__.py" -and
                $_.Name -ne "manage.py" -and
                $_.FullName -notlike "*\migrations\*"
            } |
            Remove-Item -Force -ErrorAction SilentlyContinue
    }
}

Write-Ok "Python source protected"


# ══════════════════════════════════════════════════════════════════════════════
Write-Step "Step 4 / 12  Installing Playwright browser"
# ══════════════════════════════════════════════════════════════════════════════

Write-Info "Installing Playwright Chromium (needed for Active Scanner and Spider)..."
try {
    & $VENV_PYTHON -m playwright install chromium --with-deps 2>$null
    Write-Ok "Playwright Chromium installed"
} catch {
    Write-Warn "Playwright install had issues. Run manually if needed:"
    Write-Warn "  $VENV_PYTHON -m playwright install chromium"
}


# ══════════════════════════════════════════════════════════════════════════════
Write-Step "Step 5 / 12  Building React frontend"
# ══════════════════════════════════════════════════════════════════════════════

Write-Info "React frontend pre-built — installing serve for static HTTPS serving..."
Push-Location "$INSTALL_DIR\frontend"
Write-Info "Installing 'serve' for static HTTPS serving..."
Invoke-Npm @("install", "--prefix", $NODE_GLOBAL, "serve")
$SERVE_MAIN = "$NODE_GLOBAL\node_modules\serve\build\main.js"
if (-not (Test-Path $SERVE_MAIN)) {
    # Fallback: try installed in node_modules under serve package
    $SERVE_MAIN = (Get-ChildItem "$NODE_GLOBAL" -Recurse -Filter "main.js" | Where-Object { $_.FullName -like "*\serve\build\main.js" } | Select-Object -First 1).FullName
}
Write-Ok "serve ready"
Pop-Location


# ══════════════════════════════════════════════════════════════════════════════
Write-Step "Step 6 / 12  Generating TLS certificate"
# ══════════════════════════════════════════════════════════════════════════════

New-Item -Path $CERT_DIR -ItemType Directory -Force | Out-Null
# Reset any restrictive ACLs left by a previous failed install so we can write cert/key files
icacls $CERT_DIR /reset /t 2>&1 | Out-Null
icacls $CERT_DIR /grant "Administrators:(OI)(CI)F" 2>&1 | Out-Null

if ((Test-Path $CERT) -and (Test-Path $KEY)) {
    Write-Ok "Certificate already exists, skipping generation"
} else {
    Write-Info "Generating self-signed RSA 4096 certificate (825 days)..."

    # TextExtension adds proper IP SANs for 127.0.0.1 and ::1.
    # Without IP SANs, Chrome/Edge rejects the cert when accessed via IP address.
    $certParams = @{
        DnsName           = @("localhost", "ds1hunter.local")
        TextExtension     = @("2.5.29.17={text}DNS=localhost&DNS=ds1hunter.local&IPAddress=127.0.0.1&IPAddress=::1")
        KeyAlgorithm      = "RSA"
        KeyLength         = 4096
        CertStoreLocation = "Cert:\LocalMachine\My"
        FriendlyName      = "DS1 Hunter TLS"
        NotAfter          = (Get-Date).AddDays(825)
        KeyExportPolicy   = "Exportable"
        HashAlgorithm     = "SHA256"
    }
    $certObj = New-SelfSignedCertificate @certParams

    # Export as PFX then use Python to convert to PEM cert+key
    # (avoids .NET Framework 4.x RSA key export limitations)
    $pfxPass  = [System.Guid]::NewGuid().ToString("N")
    $pfxPath  = "$CERT_DIR\temp.pfx"
    $pfxBytes = $certObj.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $pfxPass)
    [System.IO.File]::WriteAllBytes($pfxPath, $pfxBytes)

    $pyConvert = @"
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
import os
os.makedirs(os.path.dirname(r'$KEY'), exist_ok=True)
with open(r'$pfxPath', 'rb') as f:
    data = f.read()
priv_key, certificate, _ = pkcs12.load_key_and_certificates(data, b'$pfxPass')
with open(r'$CERT', 'wb') as f:
    f.write(certificate.public_bytes(serialization.Encoding.PEM))
with open(r'$KEY', 'wb') as f:
    f.write(priv_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    ))
os.remove(r'$pfxPath')
print('OK')
"@
    $pyScriptPath = "$CERT_DIR\__cert_convert.py"
    Set-Content -Path $pyScriptPath -Value $pyConvert -Encoding UTF8
    $pyResult = & $VENV_PYTHON $pyScriptPath
    Remove-Item -Path $pyScriptPath -ErrorAction SilentlyContinue
    if ($LASTEXITCODE -ne 0 -or $pyResult -ne 'OK') { throw "Failed to export certificate/key from PFX" }
    Write-Ok "Certificate exported: $CERT"
    Write-Ok "Private key exported: $KEY"

    # Trust in Local Machine Root CA (removes browser warning)
    Write-Info "Trusting certificate in Windows Root CA store..."
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
    $store.Open("ReadWrite")
    $store.Add($certObj)
    $store.Close()
    Write-Ok "Certificate trusted (no browser security warning)"
}

# Restrict key permissions
icacls $KEY /inheritance:r /grant:r "SYSTEM:R" /grant:r "Administrators:R" | Out-Null


# ══════════════════════════════════════════════════════════════════════════════
Write-Step "Step 7 / 12  Generating secure credentials"
# ══════════════════════════════════════════════════════════════════════════════

$SECRET_KEY = & $VENV_PYTHON -c "import secrets; print(secrets.token_urlsafe(50))"
$ADMIN_PASS = & $VENV_PYTHON -c @"
import secrets, string
# Letters + digits only: no special chars that are hard to read or type
chars = string.ascii_letters + string.digits
print(''.join(secrets.choice(chars) for _ in range(24)))
"@
$ADMIN_URL_TOKEN = & $VENV_PYTHON -c "import secrets; print(secrets.token_hex(6))"
$ADMIN_URL       = "ds1-ops-$ADMIN_URL_TOKEN/"

Write-Ok "SECRET_KEY generated (50 chars)"
Write-Ok "Admin password generated (22 chars)"
Write-Ok "Admin URL randomized"


# ══════════════════════════════════════════════════════════════════════════════
Write-Step "Step 8 / 12  Writing production configuration"
# ══════════════════════════════════════════════════════════════════════════════

$envContent = @"
# DS1 Hunter - Production Environment (Windows)
# Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
# Installer: install-windows.ps1 v$VERSION
# !! Do not share or commit this file !!

# --- Django Core ---------------------------------------------------------------
SECRET_KEY=$SECRET_KEY
DEBUG=False
ALLOWED_HOSTS=localhost,127.0.0.1
LOG_LEVEL=WARNING

# --- CORS (must match UI origin exactly) --------------------------------------
CORS_ALLOWED_ORIGINS=https://127.0.0.1:${UI_PORT},https://localhost:${UI_PORT}

# --- Admin --------------------------------------------------------------------
ADMIN_URL=$ADMIN_URL
ADMIN_ALLOWED_IPS=127.0.0.1,::1

# --- Redis (disabled - enable if you install Redis) ---------------------------
REDIS_AVAILABLE=False
REDIS_URL=redis://localhost:6379/0
"@
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText("$INSTALL_DIR\web\.env", $envContent, $utf8NoBom)

# Restrict .env to Administrators only
icacls "$INSTALL_DIR\web\.env" /inheritance:r /grant:r "Administrators:F" /grant:r "SYSTEM:F" | Out-Null
Write-Ok ".env written (Administrators-only permissions)"

# Service wrapper scripts (load .env, then start the process)
# Twisted endpoint strings split on ':' so Windows drive letters (C:) must be
# escaped as C\: and backslashes converted to forward slashes.
$KEY_TW  = ($KEY  -replace '\\', '/') -replace '^([A-Za-z]):', '$1\:'
$CERT_TW = ($CERT -replace '\\', '/') -replace '^([A-Za-z]):', '$1\:'

$apiScript = @"
`$envFile = "$INSTALL_DIR\web\.env"
Get-Content `$envFile | ForEach-Object {
    if (`$_ -match '^([^#][^=]*)=(.*)$') {
        [System.Environment]::SetEnvironmentVariable(`$Matches[1].Trim(), `$Matches[2].Trim(), 'Process')
    }
}
Set-Location "$INSTALL_DIR\web"
& "$VENV_DAPHNE" ``
    -e "ssl:${API_PORT}:interface=127.0.0.1:privateKey=$KEY_TW`:certKey=$CERT_TW" ``
    ds1hunter_project.asgi:application
"@
[System.IO.File]::WriteAllText("$BIN_DIR\start-api.ps1", $apiScript, $utf8NoBom)

$uiScript = @"
Set-Location "$INSTALL_DIR\frontend"
& "$NODE" "$SERVE_MAIN" ``
    -s build ``
    --ssl-cert "$CERT" ``
    --ssl-key  "$KEY" ``
    -l $UI_PORT ``
    --no-port-switching
"@
[System.IO.File]::WriteAllText("$BIN_DIR\start-ui.ps1", $uiScript, $utf8NoBom)
Write-Ok "Service wrapper scripts created"


# ══════════════════════════════════════════════════════════════════════════════
Write-Step "Step 9 / 12  Setting up database"
# ══════════════════════════════════════════════════════════════════════════════

$env:SECRET_KEY              = $SECRET_KEY
$env:DEBUG                   = "False"
$env:ALLOWED_HOSTS           = "localhost,127.0.0.1"
$env:CORS_ALLOWED_ORIGINS    = "https://127.0.0.1:$UI_PORT,https://localhost:$UI_PORT"
$env:ADMIN_URL               = $ADMIN_URL
$env:ADMIN_ALLOWED_IPS       = "127.0.0.1,::1"
$env:REDIS_AVAILABLE         = "False"

Push-Location "$INSTALL_DIR\web"

Write-Info "Running migrations..."
Invoke-Manage @("migrate", "--run-syncdb", "-v", "0")
Write-Ok "Database schema created"

Write-Info "Collecting static files..."
Invoke-Manage @("collectstatic", "--no-input", "-v", "0")
Write-Ok "Static files collected"

Write-Info "Creating admin user..."
$env:DS1_ADMIN_PASS = $ADMIN_PASS
$adminPy = [System.IO.Path]::Combine($env:TEMP, "ds1_create_admin.py")
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($adminPy, @"
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
"@, $utf8NoBom)
Push-Location "$INSTALL_DIR\web"
& $VENV_PYTHON "$INSTALL_DIR\web\manage.py" shell -c "exec(open(r'$adminPy').read())"
if ($LASTEXITCODE -ne 0) { throw "Failed to create admin user" }
Pop-Location
Remove-Item $adminPy -ErrorAction SilentlyContinue
Remove-Item Env:DS1_ADMIN_PASS -ErrorAction SilentlyContinue
Write-Ok "Admin user ready"

Pop-Location


# ══════════════════════════════════════════════════════════════════════════════
Write-Step "Step 10 / 12  Windows Defender exclusion"
# ══════════════════════════════════════════════════════════════════════════════

# Security tools commonly trigger AV - exclude the install directory
try {
    Add-MpPreference -ExclusionPath $INSTALL_DIR -ErrorAction SilentlyContinue
    Write-Ok "Windows Defender exclusion added for $INSTALL_DIR"
} catch {
    Write-Warn "Could not add Defender exclusion (may already exist or policy blocks it)"
    Write-Warn "If scans are flagged, add manually: Windows Security > Virus protection > Exclusions"
}


# ══════════════════════════════════════════════════════════════════════════════
Write-Step "Step 11 / 12  Installing CLI symlink"
# ══════════════════════════════════════════════════════════════════════════════

$cliExe = "$VENV\Scripts\ds1hunter.exe"
$cliBin = "C:\Windows\System32\ds1hunter.exe"
if (Test-Path $cliExe) {
    Copy-Item $cliExe $cliBin -Force
    Write-Ok "ds1hunter command available system-wide"
} else {
    Write-Warn "CLI executable not found at $cliExe - run 'ds1hunter --help' from $cliExe"
}


# ══════════════════════════════════════════════════════════════════════════════
Write-Step "Step 12 / 12  Installing Windows services (NSSM)"
# ══════════════════════════════════════════════════════════════════════════════

# NSSM is bundled in bin\nssm.exe (included in payload at build time)
if (-not (Test-Path $NSSM)) {
    Write-Warn "NSSM not found in payload - downloading..."
    try {
        $nssmZip = "$env:TEMP\nssm.zip"
        Invoke-WebRequest "https://nssm.cc/release/nssm-2.24.zip" -OutFile $nssmZip -UseBasicParsing
        Expand-Archive $nssmZip -DestinationPath "$env:TEMP\nssm-extract" -Force
        Copy-Item "$env:TEMP\nssm-extract\nssm-2.24\win64\nssm.exe" $NSSM -Force
        Write-Ok "NSSM downloaded"
    } catch {
        Write-Die "Could not obtain NSSM. Download nssm.exe from https://nssm.cc and place at $NSSM"
    }
}

$psExe = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"

# Remove old services if they exist
foreach ($svc in @("DS1HunterAPI", "DS1HunterUI")) {
    if (Get-Service $svc -ErrorAction SilentlyContinue) {
        Stop-Service $svc -Force -ErrorAction SilentlyContinue
        & $NSSM remove $svc confirm 2>&1 | Out-Null
    }
}

# API service
Write-Info "Installing DS1HunterAPI service..."
& $NSSM install   DS1HunterAPI $psExe
& $NSSM set DS1HunterAPI AppParameters "-ExecutionPolicy Bypass -NonInteractive -File `"$BIN_DIR\start-api.ps1`""
& $NSSM set DS1HunterAPI AppDirectory  "$INSTALL_DIR\web"
& $NSSM set DS1HunterAPI DisplayName   "DS1 Hunter API Server"
& $NSSM set DS1HunterAPI Description   "DS1 Hunter ASGI/HTTPS backend (daphne)"
& $NSSM set DS1HunterAPI Start         SERVICE_AUTO_START
& $NSSM set DS1HunterAPI AppStdout     "$LOG_DIR\api.log"
& $NSSM set DS1HunterAPI AppStderr     "$LOG_DIR\api-error.log"
& $NSSM set DS1HunterAPI AppRotateFiles 1
& $NSSM set DS1HunterAPI ObjectName    LocalSystem ""
Write-Ok "DS1HunterAPI service installed"

# UI service
Write-Info "Installing DS1HunterUI service..."
& $NSSM install   DS1HunterUI $psExe
& $NSSM set DS1HunterUI AppParameters "-ExecutionPolicy Bypass -NonInteractive -File `"$BIN_DIR\start-ui.ps1`""
& $NSSM set DS1HunterUI AppDirectory  "$INSTALL_DIR\frontend"
& $NSSM set DS1HunterUI DisplayName   "DS1 Hunter Web UI"
& $NSSM set DS1HunterUI Description   "DS1 Hunter React frontend (serve/HTTPS)"
& $NSSM set DS1HunterUI Start         SERVICE_AUTO_START
& $NSSM set DS1HunterUI DependOnService DS1HunterAPI
& $NSSM set DS1HunterUI AppStdout     "$LOG_DIR\ui.log"
& $NSSM set DS1HunterUI AppStderr     "$LOG_DIR\ui-error.log"
& $NSSM set DS1HunterUI AppRotateFiles 1
& $NSSM set DS1HunterUI ObjectName    LocalSystem ""
Write-Ok "DS1HunterUI service installed"

# Kill any process holding the ports before starting services
foreach ($port in @($API_PORT, $UI_PORT)) {
    $conns = Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue
    if ($conns) {
        $pids = $conns | Select-Object -ExpandProperty OwningProcess -Unique
        foreach ($pid in $pids) {
            Write-Warn "Port $port in use - stopping process $pid"
            Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
        }
        Start-Sleep -Seconds 1
    }
}

# Start services
Write-Info "Starting services..."
Start-Service DS1HunterAPI -ErrorAction SilentlyContinue
Start-Sleep -Seconds 3
Start-Service DS1HunterUI  -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

$apiSvc = Get-Service DS1HunterAPI -ErrorAction SilentlyContinue
$apiOk  = ($apiSvc -ne $null) -and ($apiSvc.Status -eq "Running")
$uiSvc  = Get-Service DS1HunterUI  -ErrorAction SilentlyContinue
$uiOk   = ($uiSvc  -ne $null) -and ($uiSvc.Status  -eq "Running")

if ($apiOk) { Write-Ok  "DS1HunterAPI service running" } else { Write-Warn "DS1HunterAPI did not start - check: Get-Content $LOG_DIR\api-error.log" }
if ($uiOk)  { Write-Ok  "DS1HunterUI  service running" } else { Write-Warn "DS1HunterUI  did not start  - check: Get-Content $LOG_DIR\ui-error.log" }


# ══════════════════════════════════════════════════════════════════════════════
#  FINAL SUMMARY
# ══════════════════════════════════════════════════════════════════════════════

Write-Host ""
Write-Host "  ╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "  ║ DS1 Hunter - Community Edition v$VERSION installed successfully! ║" -ForegroundColor Green
Write-Host "  ╠═══════════════════════════════════════════════════════════════╣" -ForegroundColor Green
Write-Host "  ║                                                               ║" -ForegroundColor Green
Write-Host ("  ║  {0,-61}║" -f "  Web UI   :  https://127.0.0.1:$UI_PORT") -ForegroundColor Green
Write-Host ("  ║  {0,-61}║" -f "  API      :  https://127.0.0.1:$API_PORT") -ForegroundColor Green
Write-Host ("  ║  {0,-61}║" -f "  CLI      :  ds1hunter --help") -ForegroundColor Green
Write-Host "  ║                                                               ║" -ForegroundColor Green
Write-Host "  ╠═══════════════════════════════════════════════════════════════╣" -ForegroundColor Green
Write-Host "  ║  CREDENTIALS  (shown once - save them now)                    ║" -ForegroundColor Red
Write-Host "  ║                                                               ║" -ForegroundColor Red
Write-Host ("  ║  {0,-61}║" -f "  Username :  admin") -ForegroundColor Red
Write-Host ("  ║  {0,-61}║" -f "  Password :  $ADMIN_PASS") -ForegroundColor Red
Write-Host "  ║                                                               ║" -ForegroundColor Red
Write-Host "  ╠═══════════════════════════════════════════════════════════════╣" -ForegroundColor Green
Write-Host "  ║  BROWSER SETUP  (one time)                                    ║" -ForegroundColor Green
Write-Host "  ║                                                               ║" -ForegroundColor Green
Write-Host "  ║  Certificate auto-trusted in Windows Root CA store.           ║" -ForegroundColor Green
Write-Host "  ║  If browser still shows a warning:                            ║" -ForegroundColor Green
Write-Host "  ║    Run: certmgr.msc > Trusted Root CAs > Certificates         ║" -ForegroundColor Green
Write-Host "  ║    Verify 'DS1 Hunter TLS' is present.                        ║" -ForegroundColor Green
Write-Host "  ║                                                               ║" -ForegroundColor Green
Write-Host "  ╠═══════════════════════════════════════════════════════════════╣" -ForegroundColor Green
Write-Host "  ║  SERVICE MANAGEMENT                                           ║" -ForegroundColor Green
Write-Host "  ║                                                               ║" -ForegroundColor Green
Write-Host "  ║  Start  : Start-Service DS1HunterAPI, DS1HunterUI             ║" -ForegroundColor Green
Write-Host "  ║  Stop   : Stop-Service  DS1HunterAPI, DS1HunterUI             ║" -ForegroundColor Green
Write-Host "  ║  Status : Get-Service   DS1HunterAPI, DS1HunterUI             ║" -ForegroundColor Green
Write-Host ("  ║  {0,-61}║" -f "  API log : Get-Content $LOG_DIR\api.log") -ForegroundColor Green
Write-Host ("  ║  {0,-61}║" -f "  UI log  : Get-Content $LOG_DIR\ui.log") -ForegroundColor Green
Write-Host "  ║                                                               ║" -ForegroundColor Green
Write-Host "  ╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""

