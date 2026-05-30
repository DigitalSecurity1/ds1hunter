# DS1 Hunter — macOS Installation Guide

## Supported Systems

- macOS Ventura 13+
- macOS Sonoma 14+
- macOS Sequoia 15+
- Intel and Apple Silicon (M1/M2/M3/M4)

## Requirements

- 4 GB RAM minimum (8 GB recommended)
- 5 GB free disk space
- [Homebrew](https://brew.sh) (installer will prompt if missing)
- Internet access during install
- Administrator (sudo) access

## Install

```bash
sudo bash ds1hunter-CE-v1.0.2-macos.run
```

The installer handles everything:

1. Installs dependencies via Homebrew (Python 3.13+, Node.js, OpenSSL)
2. Creates a hidden system service account (`_ds1hunter`)
3. Sets up a Python virtual environment
4. Compiles Python bytecode for your exact Python version (fixes Python 3.14 compatibility)
5. Installs Playwright Chromium for Active Scanner and Spider
6. Configures `serve` for static HTTPS frontend
7. Generates a self-signed RSA 4096 TLS certificate and trusts it in the macOS System Keychain
8. Generates a random admin password and randomized admin URL
9. Runs database migrations
10. Registers and starts two launchd services

At the end, credentials are displayed once. Save them before closing the terminal.

## First Access

Open `https://127.0.0.1:13000` in your browser (Chrome or Firefox recommended). Log in with the displayed credentials.

## Service Management

```bash
# Stop
sudo launchctl unload /Library/LaunchDaemons/com.ds1hunter.api.plist
sudo launchctl unload /Library/LaunchDaemons/com.ds1hunter.ui.plist

# Start
sudo launchctl load /Library/LaunchDaemons/com.ds1hunter.api.plist
sudo launchctl load /Library/LaunchDaemons/com.ds1hunter.ui.plist

# Logs
tail -f /var/log/ds1hunter/api.log
tail -f /var/log/ds1hunter/ui.log
```

## Verify SHA256

```bash
shasum -a 256 -c ds1hunter-CE-v1.0.2-macos.run.sha256
```

## Note on Python Compatibility

v1.0.2 fixes the `bad magic number` crash that affected macOS users running Python 3.14. The installer now compiles Python bytecode using your installed Python version at install time.
