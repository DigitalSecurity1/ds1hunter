# Changelog

## v1.0.2 — 2026-05-31

### New Features

**Active Scanner: Exploit Guide per finding**
- Every Active Scanner finding now shows an "Exploit Guide" button when expanded.
- The guide includes four sections: how to confirm the finding, step-by-step exploitation, real-world impact, and a copy-ready proof-of-concept command or payload.
- Covers 35+ vulnerability types: SQLi, XSS, SSTI, Path Traversal, Command Injection, SSRF, XXE, CORS, Host Header Injection, JWT attacks, BOLA, Mass Assignment, Prototype Pollution, Race Condition, Cache Poisoning, Verb Tampering, JSON Injection, and more.
- The same guide is shared with the Hunt vulnerability modal.

**Hunt: Re-verify Exploit button**
- The attack chain graph node detail panel now includes a "Re-verify Exploit" button.
- Clicking it fires a targeted confirmation probe against the specific finding endpoint and returns confirmed/denied with confidence score and evidence inline.
- New backend endpoint: `POST /api/hunts/{hunt_id}/verify-finding/`

**Hunt: Attack chain graph improvements**
- "Hidden Endpoint" nodes renamed to "Unconfirmed Endpoint" with the actual URL path shown.
- Trailing discovery-only nodes are stripped from chain edges to reduce noise.
- Chain format v1.4 (`chain.nodes`) now renders correctly alongside the legacy `chain.steps` format.

**Windows installer: Home edition support**
- Installer now works on Windows 10 Home and Windows 11 Home in addition to Pro editions.
- winget `--source winget` flag removed (community source not always available on Home).
- Direct download fallback added for Python 3.13 (python.org) and Node.js LTS (nodejs.org) when winget is absent or fails.

**Tor proxy: DNS leak prevention**
- SOCKS5 URLs now normalised to `socks5h://` (remote hostname resolution) at all call sites.
- `rdns=True` added to all ProxyConnector calls, ensuring no DNS queries leave the machine.
- Tor reachability timeout extended from 4 s to 12 s to allow circuit establishment.
- Proxy test timeout extended to 45 s for Tor with actionable error hints on failure.

### Bug Fixes
- Fixed Python `.venv` stripping bug: installer stripped `.py` files from the virtualenv itself, deleting Django and the editable install finder, causing `No module named django` crash on macOS Python 3.14. Strip is now scoped to `core/`, `cli/`, `web/` only.
- Fixed Python bytecode version mismatch on macOS (Python 3.14 bad magic number). Installers now compile `.pyc` using the target machine's Python at install time.

### Hunt Quality Improvements
- False positive confidence threshold raised from 0.25 to 0.50.
- Default assumed confidence lowered from 0.80 to 0.65 when scanner does not set explicit confidence.
- Unconfirmed `hidden_endpoint` findings excluded from the vulnerability list entirely.

### CVE Template Library
- Expanded to 1,792 templates covering CISA KEV entries from 2002 through 2026.
- Added automated generator (`generate_cve_templates.py`) pulling from the CISA Known Exploited Vulnerabilities catalog.
- Added 30 hand-written 2023-2026 templates: MOVEit, Ivanti, Palo Alto PAN-OS, Citrix Bleed, JetBrains TeamCity, ConnectWise ScreenConnect, Jenkins, Fortinet FortiOS, GitLab, Apache OFBiz, aiohttp, SolarWinds Serv-U, Apache Tomcat, and more.

### Documentation
- Added Complete Practitioner's Guide (DOCX, 21 chapters covering all 50+ tools).

### Platforms
- Kali Linux 2024+ (primary development and test platform)
- macOS Ventura 13+ / Sonoma 14+ / Sequoia 15+ (Intel + Apple Silicon)
- Windows 10 Home / Pro and Windows 11 Home / Pro

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
