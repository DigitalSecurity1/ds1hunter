# DS1 Hunter - Community Edition

> **"Hunt. Chain. Prove."** - by DigitalSecurity1

Advanced all-in-one web application security testing platform built for penetration testers.

At its core, **Hunt** is the flagship scanner: a 5-phase attack chain engine with Think Mode (adaptive deep analysis that pushes payload coverage to its maximum) and full proof-of-exploitation generation.

DS1 Hunter ships with **43 built-in attack modules** that cover everything from vulnerability scanning to dedicated testing tools:

- **Dedicated tools** - Active Scanner, API Security Audit, Code Review, Mobile App Pentesting
- **Web vulnerabilities** - SQLi, XSS, SSRF, SSTI, CORS, JWT, GraphQL, WebSocket, XXE, BOLA, and more
- **Advanced attacks** - HTTP Smuggling, Race Conditions, Prototype Pollution, Memory Corruption, Buffer Overflow
- **Recon and discovery** - Spider, JS Secret Scanner, Subdomain Takeover, Git Exposure, OpenAPI Scanner
- **Infrastructure** - Proxy with Intruder and Repeater, OAST, WAF Identifier, SSL Analyzer

All in a single install. No extra tools needed.

Free to download and use for security professionals and penetration testers.

---

## What it does

DS1 Hunter runs a structured 5-phase pipeline against a target:

1. **Endpoint Discovery** - spider, JS analysis, parameter mining
2. **Authorization Analysis** - BOLA, privilege escalation, auth bypass
3. **Attack Chain Mapping** - chains vulnerabilities into exploit paths
4. **Business Logic Testing** - race conditions, mass assignment, sequencer
5. **Exploit Proof Generation** - working PoC with report export

Supports 40+ vulnerability classes including SQLi, XSS, SSRF, SSTI, CORS, JWT, GraphQL, WebSocket, mobile, memory corruption, and more.

---

## System Requirements

| Platform | OS | RAM | Disk |
|----------|-----|-----|------|
| Linux | Kali 2024+, Debian 12, Ubuntu 22.04/24.04 | 4 GB+ | 2 GB+ |
| macOS | Ventura 13+, Sonoma 14+, Sequoia 15+ (Intel + Apple Silicon) | 4 GB+ | 2 GB+ |
| Windows | Windows 10 21H2+, Windows 11, Server 2022+ | 4 GB+ | 2 GB+ |

Python 3.10+ and Node.js 16+ are installed automatically by the installer.

---

## Download

Go to the [Releases](../../releases/latest) page and download the installer for your platform.

| Platform | File | Verify |
|----------|------|--------|
| Linux | `ds1hunter-v1.0.0-linux.run` | `.sha256` |
| macOS | `ds1hunter-v1.0.0-macos.run` | `.sha256` |
| Windows | `ds1hunter-v1.0.0-windows.ps1` | `.sha256` |

---

## Install

### Linux (Kali, Debian, Ubuntu)

```bash
sudo bash ds1hunter-v1.0.0-linux.run
```

See [docs/linux.md](docs/linux.md) for full details.

### macOS (Ventura, Sonoma, Sequoia)

```bash
sudo bash ds1hunter-v1.0.0-macos.run
```

If macOS Gatekeeper blocks it:
```bash
xattr -d com.apple.quarantine ds1hunter-v1.0.0-macos.run
sudo bash ds1hunter-v1.0.0-macos.run
```

See [docs/macos.md](docs/macos.md) for full details.

### Windows (PowerShell as Administrator)

```powershell
powershell -ExecutionPolicy Bypass -File ds1hunter-v1.0.0-windows.ps1
```

See [docs/windows.md](docs/windows.md) for full details.

---

## After Install

Once installed, open your browser:

| Service | URL |
|---------|-----|
| Web UI | https://127.0.0.1:13000 |
| API | https://127.0.0.1:18000 |

The installer prints your admin credentials once at the end. Save them.

CLI usage:
```bash
ds1hunter https://target.com --depth deep --think
ds1hunter https://target.com --depth aggressive --think --waf-bypass
ds1hunter --help
```

---

## Verify Your Download

Always verify the SHA256 checksum before running:

```bash
# Linux
sha256sum ds1hunter-v1.0.0-linux.run
cat ds1hunter-v1.0.0-linux.run.sha256

# macOS
shasum -a 256 ds1hunter-v1.0.0-macos.run
cat ds1hunter-v1.0.0-macos.run.sha256

# Windows (PowerShell)
Get-FileHash ds1hunter-v1.0.0-windows.ps1 -Algorithm SHA256
```

Compare the output. They must match exactly.

---

## Service Management

### Linux
```bash
systemctl start  ds1hunter-api ds1hunter-ui
systemctl stop   ds1hunter-api ds1hunter-ui
systemctl status ds1hunter-api ds1hunter-ui
journalctl -u ds1hunter-api -f
```

### macOS
```bash
launchctl load   /Library/LaunchDaemons/com.ds1hunter.api.plist
launchctl unload /Library/LaunchDaemons/com.ds1hunter.api.plist
tail -f /var/log/ds1hunter/api.log
```

### Windows (PowerShell as Administrator)
```powershell
Start-Service DS1HunterAPI, DS1HunterUI
Stop-Service  DS1HunterAPI, DS1HunterUI
Get-Service   DS1HunterAPI, DS1HunterUI
Get-Content   C:\ds1hunter\logs\api.log
```

---

## Legal Disclaimer

DS1 Hunter is designed for authorized security testing only.

You must have explicit written permission from the owner of any system before running DS1 Hunter against it. Using this tool against systems you do not own or do not have authorization to test is illegal and may result in criminal charges under computer crime laws in your country.

Authorized use includes:
- Testing systems you own
- Testing systems with written permission from the owner
- Penetration testing engagements with a signed scope of work
- Security research in isolated lab environments

DigitalSecurity1 and its contributors are not responsible for any damage, data loss, legal consequences, or misuse resulting from the use of this software. By downloading and using DS1 Hunter, you agree that you are solely responsible for how you use it and that you will only use it on systems you are authorized to test.

**Use it ethically. Use it legally. Use it responsibly.**

---

## License

Copyright (c) 2026 DigitalSecurity1. All rights reserved.

DS1 Hunter is free to download and use for authorized security testing purposes.
You may not redistribute, resell, or reverse engineer this software.
