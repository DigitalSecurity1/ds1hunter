# DS1 Hunter — Linux Installation Guide

## Supported Systems

- Kali Linux 2024+
- Debian 12 (Bookworm)
- Ubuntu 22.04 LTS / 24.04 LTS

## Requirements

- 4 GB RAM minimum
- 2 GB free disk space
- Internet access during install (downloads Python/Node packages)
- Root / sudo access

## Install

```bash
sudo bash ds1hunter-v1.0.0-linux.run
```

The installer runs 12 steps automatically:

1. Checks and installs system dependencies (python3, node, npm, openssl, git)
2. Copies files to `/opt/ds1hunter`
3. Creates the `ds1hunter` system service user
4. Creates Python venv, installs all dependencies
5. Installs Playwright Chromium (for active scanner and spider)
6. Builds the React web UI
7. Generates a self-signed RSA 4096 TLS certificate (825 days)
8. Generates random SECRET_KEY, admin password, and admin URL
9. Writes production `.env` (DEBUG=False, HTTPS CORS)
10. Runs Django migrations and creates the admin user
11. Sets file permissions
12. Creates and starts two systemd services

At the end, credentials are shown once. Save them.

## After Install

| Service | URL |
|---------|-----|
| Web UI | https://127.0.0.1:13000 |
| API | https://127.0.0.1:18000 |
| CLI | `ds1hunter --help` |

## Browser Certificate

The self-signed certificate is at `/opt/ds1hunter/deploy/certs/ds1hunter.crt`.

**Firefox:** Preferences > Privacy and Security > Certificates > View Certificates > Authorities > Import

**Chromium:** Settings > Privacy and Security > Manage Certificates > Authorities > Import

## Service Management

```bash
# Start
systemctl start ds1hunter-api ds1hunter-ui

# Stop
systemctl stop ds1hunter-api ds1hunter-ui

# Restart
systemctl restart ds1hunter-api ds1hunter-ui

# Status
systemctl status ds1hunter-api ds1hunter-ui

# Logs
journalctl -u ds1hunter-api -f
journalctl -u ds1hunter-ui -f
```

## CLI

```bash
ds1hunter https://target.com --depth normal
ds1hunter https://target.com --depth deep --think
ds1hunter https://target.com --depth aggressive --think --waf-bypass
ds1hunter --help
```

## Uninstall

```bash
systemctl stop ds1hunter-api ds1hunter-ui
systemctl disable ds1hunter-api ds1hunter-ui
rm /etc/systemd/system/ds1hunter-api.service
rm /etc/systemd/system/ds1hunter-ui.service
systemctl daemon-reload
rm -rf /opt/ds1hunter
userdel ds1hunter
rm /usr/local/bin/ds1hunter
```
