# DS1 Hunter — Windows Installation Guide

## Supported Systems

- Windows 10 Pro (21H2+)
- Windows 11 Pro
- Windows Server 2022+

## Requirements

- 4 GB RAM minimum (8 GB recommended)
- 5 GB free disk space
- Internet access during install
- Administrator privileges (Run as Administrator)

## Install

Open **PowerShell as Administrator**, then run:

```powershell
powershell -ExecutionPolicy Bypass -File ds1hunter-CE-v1.0.2-windows.ps1
```

The installer handles everything:

1. Installs Python 3.13+ and Node.js 22 via winget (Windows Package Manager)
2. Installs all Python dependencies in a virtual environment
3. Compiles Python bytecode for your exact Python version
4. Installs Playwright Chromium for Active Scanner and Spider
5. Installs `serve` for the React frontend
6. Generates a self-signed TLS certificate and installs it in the Windows Certificate Store
7. Generates a random admin password and randomized admin URL
8. Runs database migrations
9. Registers two Windows services (`DS1HunterAPI`, `DS1HunterUI`) via NSSM (bundled, no download needed)

At the end, credentials are displayed once. Save them before closing PowerShell.

## First Access

Open `https://127.0.0.1:13000` in your browser. Accept the certificate warning (or use Edge which trusts the Windows Certificate Store automatically), then log in with the displayed credentials.

## Service Management

```powershell
# Status
Get-Service DS1HunterAPI, DS1HunterUI

# Stop
Stop-Service DS1HunterAPI, DS1HunterUI

# Start
Start-Service DS1HunterAPI, DS1HunterUI

# Restart
Restart-Service DS1HunterAPI, DS1HunterUI

# Logs
Get-Content C:\ds1hunter\logs\api.log -Tail 50 -Wait
Get-Content C:\ds1hunter\logs\ui.log  -Tail 50 -Wait
```

## Verify SHA256

```powershell
Get-FileHash ds1hunter-CE-v1.0.2-windows.ps1 -Algorithm SHA256
# Compare with contents of ds1hunter-CE-v1.0.2-windows.ps1.sha256
```

## Troubleshooting

**winget not available:** The installer falls back to the winget community source automatically. If winget is completely unavailable, install Python 3.13 and Node.js 22 manually from their official websites, then re-run the installer.

**Antivirus blocking NSSM:** NSSM (the service manager) may be flagged by some antivirus products. Add `C:\ds1hunter\bin\nssm.exe` to your AV exclusion list.
