# Changelog

## v1.0.2 — 2026-05-29

### Bug Fixes
- Fixed Python bytecode version mismatch on macOS (Python 3.14 bad magic number crash at migration step). Installers now compile `.pyc` bytecode using the target machine's Python version at install time instead of shipping pre-compiled bytecode from the build machine.
- Fixed all installer and release builder version references (v1.0.1 -> v1.0.2).

### Improvements
- CVE template library expanded to 1,792 templates covering 2002 through 2026 CISA KEV entries.
- Added automated CVE template generator (`generate_cve_templates.py`) that pulls from the CISA Known Exploited Vulnerabilities catalog and generates DS1 Hunter YAML templates for newly added entries.
- Added 30 high-value 2023-2026 CVE templates covering MOVEit, Ivanti, Palo Alto PAN-OS, Citrix Bleed, JetBrains TeamCity, ConnectWise ScreenConnect, Jenkins, Fortinet, GitLab, Apache OFBiz, aiohttp, SolarWinds, Apache Tomcat, and more.
- Added Practitioner's Guide (complete book in DOCX format, 21 chapters covering all 50+ tools).

### Platforms
- Kali Linux 2024+ (primary)
- macOS Ventura 13+ / Sonoma 14+ / Sequoia 15+ (Intel + Apple Silicon)
- Windows 10 Pro / Windows 11 Pro

---

## v1.0.1 — 2026-05-22

### Bug Fixes
- Fixed installer filename references in all documentation to use CE naming convention.
- Corrected service startup timing on slower machines.

### Improvements
- Improved WAF bypass payload coverage.
- Hunt chain mapper now handles edge cases with empty phase results.

---

## v1.0.0 — 2026-05-17

Initial public release.

### Platforms
- Linux (Kali 2024+, Debian 12, Ubuntu 22.04/24.04)
- macOS (Ventura 13+, Sonoma 14+, Sequoia 15+ — Intel + Apple Silicon)
- Windows (Windows 10 21H2+, Windows 11, Server 2022+)

### Core Features
- 5-phase attack chain pipeline (Discovery, Authorization, Chain Mapping, Business Logic, Proof Generation)
- Think Mode AI with deep (500 payloads/module) and aggressive (2000 payloads/module) budgets
- 40+ vulnerability modules including SQLi, XSS, SSRF, SSTI, CORS, JWT, GraphQL, WebSocket, mobile
- API Security Audit (verb tampering, auth bypass, mass assignment, rate limit detection)
- Proxy with Intruder, Repeater, and match/replace rules
- Hunt management with PDF/JSON report export
- HTTPS everywhere (self-signed cert, auto-trusted at install)
- CLI and Web UI interfaces
