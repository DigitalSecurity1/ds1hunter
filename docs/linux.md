# DS1 Hunter — Linux Installation Guide

## Supported Systems

- Kali Linux 2024+ (primary development and test platform)
- Debian 12 (Bookworm)
- Ubuntu 22.04 LTS / 24.04 LTS

## Requirements

- 4 GB RAM minimum (8 GB recommended)
- 5 GB free disk space
- Internet access during install (downloads Python/Node packages)
- Root / sudo access

## Install

```bash
sudo bash ds1hunter-CE-v1.0.2-linux.run
```

That is the only command needed. The installer handles everything:

1. Checks and installs system dependencies (Python 3.10+, Node.js 16+)
2. Creates a dedicated `ds1hunter` service account
3. Sets up a Python virtual environment and installs all dependencies
4. Compiles Python bytecode for your Python version
5. Installs Playwright Chromium (used by Active Scanner and Spider)
6. Installs and configures the React frontend via `serve`
7. Generates a self-signed RSA 4096 TLS certificate (825 days)
8. Generates a random admin password and randomized admin URL
9. Runs database migrations
10. Registers and starts two systemd services (`ds1hunter-api`, `ds1hunter-ui`)

At the end, credentials are displayed once. Save them before closing the terminal.

## First Access

Open `https://127.0.0.1:13000` in your browser. Accept the self-signed certificate warning, then log in with the displayed credentials.

## Service Management

```bash
# Status
systemctl status ds1hunter-api ds1hunter-ui

# Stop
systemctl stop ds1hunter-api ds1hunter-ui

# Start
systemctl start ds1hunter-api ds1hunter-ui

# Restart
systemctl restart ds1hunter-api ds1hunter-ui

# Logs
journalctl -u ds1hunter-api -f
journalctl -u ds1hunter-ui -f
```

## Verify SHA256

```bash
sha256sum -c ds1hunter-CE-v1.0.2-linux.run.sha256
```
