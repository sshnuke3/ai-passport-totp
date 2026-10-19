**English** · [简体中文](intro.zh_CN.md)

# TotpPassport — Play Introduction

Turn an FoloToy AI Passport into an offline two-factor authentication token.

This is not "an Authenticator app shrunk onto a small screen". It answers one
specific question:

> Your phone is charging, sitting in your pocket, or simply dead.
> How do you log in to a site that demands a second factor?

TotpPassport's answer: **codes work with no network at all.** Secrets stay in
local flash. Wi-Fi is used only to sync the clock and enroll accounts; otherwise
the device stays completely offline.

## The problem it solves

1. **Physically isolates the phone's attack surface.** A phishing site that steals
   the Authenticator on your phone cannot reach a small box with no radio.
2. **No phone required.** Three button presses and the code is there — useful when
   your hands are already busy at a desk.
3. **Works offline.** TOTP needs no network. The device uses Wi-Fi only at boot for
   time sync and during enrollment, then disconnects immediately.
4. **Recoverable if lost.** Encrypted backup export plus a passphrase you choose
   lets you restore every account onto a replacement device.

## What it looks like

The main screen lists accounts: name on the left, current code on the right.

```
┌────────────────────────┐
│ synced · 3 accounts     │  ← status: time source + account count
├────────────────────────┤
│ ● 1. GitHub             │
│        4 8 2 9 1 5      │  ← turns red in the last 5 seconds
│ ● 2. Cloudflare        │
│        1 1 0 2 4 8      │
│ ● 3. ProtonMail         │
│   + add account         │  ← action rows
│   re-sync time          │
│   set PIN lock          │
├────────────────────────┤
│ OK open · up/down       │
└────────────────────────┘
       (the grass strip at the bottom is the device's own decoration)
```

Press OK for the detail view: a 44px code with a countdown bar underneath.

```
┌────────────────────────┐
│ GitHub · me@example.com │
│                        │
│    4 8 2 9 1 5         │  ← large font
│    refresh in 26s       │
│    ▓▓▓▓▓▓▓▓▓▓▓░░░      │  ← progress bar
│ synced · last sync 10-19 12:31 UTC │
├────────────────────────┤
│ OK back · up/down       │
└────────────────────────┘
```

## Supported

- **Algorithms**: SHA1 / SHA256 / SHA512 (auto-detected from the otpauth URI)
- **Digits**: 6 and 8 (also accepts 7/9/10)
- **Periods**: 30s and 60s (auto-detected)
- **Accounts**: up to 24
- **Secret length**: up to 64 bytes of base32 (covers SHA-512 long secrets)

## What it explicitly does not do

- **No enterprise-grade security claims.** The shell is transparent and secrets sit
  in flash unencrypted; physically desoldering the chip reads them out. TotpPassport
  defends the phone's software attack surface — not hardware extraction. This is a
  design trade-off, not a defect.
- **No cloud sync.** Secrets are never uploaded anywhere, including us.
- **No NFC enrollment.** There is no NFC module on the hardware.
- **No multi-language UI.** Chinese only.

## How it compares

- **vs. a phone app**: one more layer of physical isolation, minus cloud backup
  (which is why the local encrypted export exists).
- **vs. a YubiKey**: far cheaper, but **no U2F/FIDO** — TOTP only. If you need a
  FIDO key, buy a YubiKey.
- **vs. other AI Passport plays**: this is one of the few that target a practical
  utility. The hardware constraints (no touchscreen, 240×320, three buttons) happen
  to match the TOTP use case exactly.

## Security boundaries — please read

- The **PIN lock only deters casual snooping**, not disassembly. It is stored as an
  FNV-1a obfuscated hash; a 4-digit PIN has 10,000 possibilities and is
  brute-forceable from an NVS dump. That is by design.
- The **enrollment portal is an open network** (SoftAP, no password). Anyone who
  joins can open the page. After enrolling, exit the portal on the device.
- **`/export` is a plaintext export with no PIN protection.** Use it, then move or
  delete the file right away.
- **The backup passphrase has no backdoor.** Forget it and the data is gone.

## Project status

- **M1 (core)**: multi-account codes, time sync, AP enrollment — done
- **M2 (complete)**: PIN lock, encrypted backup, export — done
- **Device acceptance: NOT RUN.** Every feature is covered by host-side tests only.
  Agreement with Google Authenticator has not been compared on real hardware.

- Known gap: the encrypted backup is **export-only**. There is no importer yet, so a
  lost device cannot currently be restored from a backup file. Deliberate, not
  forgotten.

## License

MIT. Derived from FoloToy's `ai-passport`, also MIT.