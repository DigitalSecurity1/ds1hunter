# DS1 Hunter — Windows Installation Guide

## Supported Systems

- Windows 10 version 21H2 or newer
- Windows 11
- Windows Server 2022+

## Requirements

- 4 GB RAM minimum
- 2 GB free disk space
- Internet access during install (downloads Python, Node.js)
- Administrator account

## Install

Open **PowerShell as Administrator**, then run:

```powershell
powershell -ExecutionPolicy Bypass -File ds1hunter-CE-v1.0.0-windows.ps1
```

To open PowerShell as Administrator: press `Win + X` and choose **Windows PowerShell (Admin)** or **Terminal (Admin)**.

The installer runs 12 steps automatically:

1. Checks for winget and installs Python 3.13 + Node.js LTS
2. Prepares `C:\ds1hunter`
3. Creates Python venv, installs all dependencies
4. Installs Playwright Chromium
5. Builds the React web UI, installs serve
6. Generates RSA 4096 TLS certificate using Windows PowerShell PKI
7. Auto-trusts the certificate in Windows Root CA store
8. Generates random credentials
9. Runs Django migrations and creates admin user
10. Adds Windows Defender exclusion for `C:\ds1hunter`
11. Installs `ds1hunter.exe` system-wide
12. Installs DS1HunterAPI and DS1HunterUI as auto-start Windows Services via NSSM

## After Install

| Service | URL |
|---------|-----|
| Web UI | https://127.0.0.1:13000 |
| API | https://127.0.0.1:18000 |
| CLI | `ds1hunter --help` (any terminal) |

## Browser Certificate

The certificate is auto-trusted in Windows Root CA during install.

If your browser still shows a warning, run this in PowerShell (as Administrator):

```powershell
certmgr.msc
```

Navigate to **Trusted Root Certification Authorities > Certificates** and verify **DS1 Hunter TLS** is listed.

## Service Management

Run these in **PowerShell as Administrator**:

```powershell
# Start
Start-Service DS1HunterAPI, DS1HunterUI

# Stop
Stop-Service DS1HunterAPI, DS1HunterUI

# Restart
Restart-Service DS1HunterAPI, DS1HunterUI

# Status
Get-Service DS1HunterAPI, DS1HunterUI

# Logs
Get-Content C:\ds1hunter\logs\api.log -Tail 50
Get-Content C:\ds1hunter\logs\api-error.log -Tail 50
```

You can also manage services from **Services** (`services.msc`).

## CLI

```powershell
ds1hunter https://target.com --depth normal
ds1hunter https://target.com --depth deep --think
ds1hunter --help
```

## Uninstall

Run in **PowerShell as Administrator**:

```powershell
Stop-Service DS1HunterAPI, DS1HunterUI -Force -ErrorAction SilentlyContinue
& "C:\ds1hunter\bin\nssm.exe" remove DS1HunterAPI confirm
& "C:\ds1hunter\bin\nssm.exe" remove DS1HunterUI  confirm
Remove-Item -Path "C:\ds1hunter" -Recurse -Force
Remove-Item -Path "C:\Windows\System32\ds1hunter.exe" -Force -ErrorAction SilentlyContinue
Remove-MpPreference -ExclusionPath "C:\ds1hunter" -ErrorAction SilentlyContinue
```
