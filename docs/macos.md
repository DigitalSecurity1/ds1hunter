# DS1 Hunter — macOS Installation Guide

## Supported Systems

- macOS Ventura 13+
- macOS Sonoma 14+
- macOS Sequoia 15+
- Intel and Apple Silicon (M1/M2/M3/M4)

## Requirements

- 4 GB RAM minimum
- 2 GB free disk space
- Internet access during install (downloads Homebrew packages)
- Administrator access

## Install

```bash
sudo bash ds1hunter-CE-v1.0.0-macos.run
```

If macOS Gatekeeper blocks it:

```bash
xattr -d com.apple.quarantine ds1hunter-CE-v1.0.0-macos.run
sudo bash ds1hunter-CE-v1.0.0-macos.run
```

The installer runs 12 steps automatically:

1. Detects Homebrew (installs it if missing)
2. Installs dependencies via brew (python3, node, openssl, git)
3. Copies files to `/opt/ds1hunter`
4. Creates the `_ds1hunter` hidden system service user
5. Creates Python venv, installs all dependencies
6. Installs Playwright Chromium
7. Builds the React web UI
8. Generates self-signed RSA 4096 TLS certificate (compatible with LibreSSL and OpenSSL)
9. Auto-trusts the certificate in macOS System Keychain
10. Generates random credentials
11. Runs Django setup
12. Creates and loads two launchd services

## After Install

| Service | URL |
|---------|-----|
| Web UI | https://127.0.0.1:13000 |
| API | https://127.0.0.1:18000 |
| CLI | `ds1hunter --help` |

## Browser Certificate

The certificate is auto-added to the System Keychain during install.

If your browser still shows a warning:

1. Open **Keychain Access**
2. Select **System** keychain
3. Find **ds1hunter.local**
4. Double-click > **Trust** > **When using this certificate: Always Trust**

## Service Management

```bash
# Start
launchctl load /Library/LaunchDaemons/com.ds1hunter.api.plist
launchctl load /Library/LaunchDaemons/com.ds1hunter.ui.plist

# Stop
launchctl unload /Library/LaunchDaemons/com.ds1hunter.api.plist
launchctl unload /Library/LaunchDaemons/com.ds1hunter.ui.plist

# Logs
tail -f /var/log/ds1hunter/api.log
tail -f /var/log/ds1hunter/ui.log
```

## CLI

```bash
ds1hunter https://target.com --depth normal
ds1hunter https://target.com --depth deep --think
ds1hunter --help
```

## Uninstall

```bash
launchctl unload /Library/LaunchDaemons/com.ds1hunter.api.plist
launchctl unload /Library/LaunchDaemons/com.ds1hunter.ui.plist
rm /Library/LaunchDaemons/com.ds1hunter.api.plist
rm /Library/LaunchDaemons/com.ds1hunter.ui.plist
sudo rm -rf /opt/ds1hunter
sudo dscl . -delete /Users/_ds1hunter
sudo rm /usr/local/bin/ds1hunter
```
