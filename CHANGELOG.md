# Changelog

## v1.0.4 — 2026-06-18

### Accuracy Improvements (8 False-Positive Fixes)

**LDAP Injection — confirmation tightened**
- Confirmation now requires LDAP-specific keywords in the response body in addition to HTTP 500. Generic server errors no longer produce a finding.

**CORS Scanner — precision improved**
- Reflective CORS is only flagged when `Access-Control-Allow-Credentials: true` is set and the endpoint returns sensitive content. Public resources and non-credentialed wildcard responses are suppressed.

**Integer Overflow — evidence requirement raised**
- Both a status-code change and a meaningful response-body difference are now required. Status-only differences (e.g. 400 for any invalid integer) are no longer reported.

**S3 403 — false classification removed**
- A 403 from AWS S3 is correct, expected behaviour (public access blocked). Only publicly listable buckets (200) and CORS misconfigurations are now reported.

**CSS Injection — reflection no longer sufficient**
- Confirmation requires headless-browser evidence that the injected value was interpreted as CSS (visible render change). Verbatim reflection in the response body alone is suppressed.

**Public Subdomain Filtering**
- Findings against known CDN, analytics, tracking, and social-media subdomains that are referenced by the target but not owned by it are suppressed before reporting.

**Verifier Chain — two-signal requirement**
- The Verifier now requires two independent evidence channels before promoting a candidate to Confirmed. Single-signal findings land in Needs Review.

**Accuracy Scorer — threshold recalibration**
- Signal weights updated based on observed reliability. High-noise signals (minor timing < 200 ms, response-size diff only) receive lower weight. High-reliability signals (OOB callback, verbatim data extraction) receive increased weight.

### OOB Infrastructure

**Production VPS deployed**
- Dedicated out-of-band callback VPS now receives HTTP callbacks (port 8089) and DNS callbacks (port 53) from blind vulnerability probes.
- Poll API: `GET /poll/<token>` returns `{"received": true/false, "protocol": "http"/"dns", "time": ..., "src_ip": ...}`.
- DS1 Hunter's `get_callback()` polls the VPS before checking local Django cache, enabling reliable blind detection against external targets without the operator machine needing to be reachable.
- Token format: `{8-hex-scan-id}-{module-abbrev}-{4-digit-seq}` (e.g. `a1b2c3d4-ssrf-0012`).

### macOS Installer Fix

- **Homebrew root error resolved**: `brew update` / `brew install` now run via `sudo -u $SUDO_USER` so Homebrew always executes as the invoking non-root user. Eliminates the fatal "Running Homebrew as root is not supported" error when running `sudo bash install-macos.sh`.
- **Banner frame aligned**: the DS1 HUNTER installer banner line was 5 characters too short, causing the right border to appear detached. Fixed by correcting the trailing padding.

### No Schema Changes
- `manage.py migrate` runs in zero time — no database changes in this release.

---

## v1.0.3 — 2026-06-16

### Scanner Improvements

**Active Scanner: 7 scanner improvements**
- SQLi error regex expanded to 6 additional database stacks: DB2, Firebird, MSSQL OLE, Hibernate, JDBC, PDO
- Sensitive file list expanded from 20 to 100+ entries
- XSS: 8 payloads per parameter (WAF bypass variants added)
- Command injection: 12 payloads per parameter (was 3)
- NoSQL injection added as per-parameter check
- CRLF injection added as new vulnerability class
- Web Cache Deception added as new vulnerability class

**Verifier: Cloudflare false-positive fix**
- Host Header Injection: Cloudflare DNS error pages no longer counted as HHI hits. Only direct application-level header reflection is flagged.

**Knowledge Base Overhaul (core/knowledge.py)**
- 80 vulnerability types (was 53) — 27 new types added: csrf, bfla, mfa_bypass, saml_injection, ldap_injection, padding_oracle, xpath_injection, crlf_injection, websocket_injection, second_order_sqli, session_fixation, weak_session_token, ssl_tls_weak, file_upload_unrestricted, subdomain_takeover, prompt_injection, llm_data_exfiltration, bola, api_key_exposure, sensitive_data_exposure, html_injection, default_credentials, debug_mode_enabled, directory_listing, sensitive_file_exposure, weak_password_policy
- `exploit_poc` and `fix_code` added to every KB entry
- `generate_poc()` substitutes placeholders with actual finding data at runtime
- `enrich_findings_knowledge()` now attaches `exploit_poc` and `fix_code` to every finding

**Proxy UI**
- "Start Proxy" button added — proxy can now be restarted from the UI without restarting the server

**macOS launchd service fixes**
- Services now set PATH explicitly so Node.js (Homebrew) is found when running as daemon user — fixes ERR_CONNECTION_REFUSED on Chrome/Safari at :13000
- SSL key permissions changed from `chgrp _daemon` to `chown _ds1hunter` so the service user can read the key
- Certificate now also trusted in user Login Keychain — fixes Safari requiring manual cert trust

---

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
