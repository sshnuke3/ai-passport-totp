**English** · [简体中文](changelog.zh_CN.md)

# TotpPassport — Changelog

This file records version changes only. See the other documents for what the play
is and how to use it.

## M2 · 2026-10-19 — Complete build (security and experience)

### Added

- **PIN lock**: 4–8 digits, enabled from the list ("set PIN lock"), changeable at any
  time. Five wrong attempts lock the device for five minutes. The failure count and
  the lockout deadline are stored on the device, so a power cycle does not turn
  "locked" back into "unlimited tries".
- **30-second auto blank**: after 30 seconds without input the screen switches to a
  locked state and the PIN is required to see codes again. Without a PIN set the
  screen never blanks (it would hide nothing that anyone could reveal).
- **Unsynced warning badge**: when the current time deviates significantly from the
  last sync, the status line shows a red "unsynced" marker, and time can be re-synced
  in one press. This avoids failed logins caused by a code that drifted.
- **Web export**: the enrollment page now offers "export all accounts", downloading a
  plaintext list of otpauth links that can be re-imported on another device.
- **Encrypted backup**: the enrollment page now offers "download encrypted backup".
  You choose the passphrase; the downloaded file contains AES-256 encrypted account
  data, used when the device is lost and the secrets must be restored.
- **4-digit PINs are now actually settable**: after typing enough digits on the lock
  screen, long-pressing up or down submits — you are no longer forced to fill all 8
  positions.

### Changed

- The account export is now in standard otpauth URI format, which is far more
  compatible than the earlier internal format.
- The action list grew from two rows to three (add account / re-sync time / PIN lock).

### Fixed

- Fixed an out-of-bounds crash in AES key expansion (round 56 needs the 8th RCON
  constant, but the table only had 7). This crash fired on the first use of the
  encrypted backup.

## M1 · 2026-10-19 — Core build

### Added

- Offline two-factor codes, supporting SHA1/SHA256/SHA512 and 6/8 digit output.
- Silent Wi-Fi time sync at boot, disconnecting immediately after a successful sync.
- Enrollment: join the device hotspot `TotpPassport`, open `192.168.4.1` in a
  browser, paste `otpauth://` links (multiple links can be pasted at once).
- Large-font code with a remaining-time progress bar; turns red in the last 5 seconds.
- Accounts stored in NVS; nothing is lost on power-off.