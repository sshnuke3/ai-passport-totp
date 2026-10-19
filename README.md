[简体中文](README.zh_CN.md) · **English**

<h1 align="center">TotpPassport</h1>

<p align="center">
  <strong>Turn your FoloToy AI Passport into an offline two-factor authentication token.</strong><br>
  Codes work without internet. Secrets never leave the device.
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-64748b?style=flat-square" alt="MIT License"></a>
  <a href="docs/play-totp/changelog.zh_CN.md"><img src="https://img.shields.io/badge/version-M2-14b8a6?style=flat-square" alt="Version M2"></a>
  <img src="https://img.shields.io/badge/device_acceptance-NOT_RUN-e43b2f?style=flat-square" alt="Device acceptance not run">
</p>

---

## What this is

A play (game/firmware mode) for the FoloToy AI Passport (ESP32-C3).
The device has a 240×320 screen and three buttons — no touchscreen.

It answers one concrete problem: **your phone is charging, in your pocket, or
flat dead — how do you log in to a site that demands a second factor?**

TotpPassport produces codes with no network at all. Secrets live in device
flash; Wi-Fi is used only during time sync and account enrollment.

```
┌────────────────────────┐
│ synced · 3 accounts     │
├────────────────────────┤
│ ● 1. GitHub             │
│        4 8 2 9 1 5      │
│ ● 2. Cloudflare        │
│        1 1 0 2 4 8      │
│   + add account         │
│   re-sync time          │
│   set PIN lock          │
└────────────────────────┘
```

## Quick start

1. Download the merged firmware from [Releases](https://github.com/sshnuke3/ai-passport-totp/releases)
2. Flash it with the FoloToy web-flasher at offset `0x0`
   (**flash the full image — never the app partition alone**, it overwrites the bootloader)
3. Open the menu, pick TOTP, then join the `TotpPassport` hotspot and open
   `http://192.168.4.1`
4. Paste the `otpauth://` URI from the site's 2FA settings page

Full walkthrough: **[Usage guide](docs/play-totp/usage.zh_CN.md)**.

## Features

| | |
|---|---|
| Multi-account | Up to 24; SHA1/256/512, 6/8 digits, 30/60s periods |
| PIN lock | 4–8 digits, 5 strikes → 5-minute lockout (survives power cycles) |
| Auto blank | Screen blanks after 30s idle; PIN required to wake |
| Unsynced warning | Red badge when the clock is untrustworthy — no more failed logins from a stale code |
| Plain export | Standard otpauth URIs, re-importable |
| Encrypted backup | PBKDF2 (4096 rounds) + AES-256-CBC, passphrase you choose |

## Documentation

- [What it is (zh)](docs/play-totp/intro.zh_CN.md) — scope and boundaries
- [Usage guide (zh)](docs/play-totp/usage.zh_CN.md) — step-by-step, button map, troubleshooting
- [Changelog (zh)](docs/play-totp/changelog.zh_CN.md)

## ⚠️ Read this first

**This is not a YubiKey.** It does TOTP only — **no U2F/FIDO**.
If you need FIDO, buy a YubiKey.

**It does not defend against hardware extraction.** The shell is transparent and
secrets sit in flash unencrypted; physically desoldering the chip reads them out.
Its value is **isolating the phone's software attack surface** — a phishing page
cannot reach a box with no radio — not resisting disassembly.

**The enrollment portal is an open network.** The SoftAP has no password, so
anyone who joins can open the web page. Consequently `/export` (plaintext export
of every secret) has **no PIN protection**. Close the portal on the device right
after enrolling, and move or delete the plaintext export immediately.

**The PIN does not stop disassembly.** It is stored as an FNV-1a obfuscated hash;
a 4-digit PIN has 10,000 possibilities and is brute-forceable from an NVS dump.
This is by design. The PIN only deters casual snooping.

**Backup passphrases have no backdoor.** Lose it and the data is unrecoverable.

## Status

- M1 (core) ✅  ·  M2 (complete) ✅
- **Device acceptance: NOT RUN.** Everything is covered by host-side tests only.
  The key anchor — *does this device emit the same code as Google Authenticator
  at the same instant* — has **not been compared on real hardware**.
- Known gap: encrypted backup is **export-only**. There is no importer yet, so a
  lost device cannot currently be restored from a backup file.

## Development

```bash
# build (requires ESP-IDF 5.5.3)
idf.py set-target esp32c3 && idf.py build

# host tests (RFC 6238 vectors, AES official vectors, PIN state machine)
tools/run_host_tests.sh

# upstream gates
tools/validate.sh --all
```

The TOTP core (`main/totp_model.c`) is fully decoupled from ESP-IDF and LVGL, so
every official RFC 6238 test vector is verifiable on a host machine. The crypto
layer is pinned by FIPS-197 and NIST SP 800-38A vectors, with PBKDF2
cross-verified against Python `hashlib`.

## License

MIT. Derived from [FoloToy/ai-passport](https://gitee.com/FoloToy/ai-passport),
also under MIT.