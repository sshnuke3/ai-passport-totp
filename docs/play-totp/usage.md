**English** · [简体中文](usage.zh_CN.md)

# TotpPassport — Usage Guide

The device has two buttons plus OK: **up, down, OK**. This guide follows the real
operation order rather than grouping features.

## 1. Flash the firmware

Use the FoloToy web-flasher with the merged full image, offset `0x0`.

**Always flash the full image. Never flash the app partition alone** — it
overwrites the bootloader and the device will not boot.

After flashing, press any button to reach the menu, navigate to **TOTP**, press OK.

## 2. First run: enroll an account

With no accounts stored, the page opens a Wi-Fi hotspot and shows three lines:

```
1. Join Wi-Fi: TotpPassport
2. Open http://192.168.4.1
3. Paste your otpauth:// link
```

Steps:

1. Join the Wi-Fi network named **`TotpPassport`**.
   It has **no password** — that is expected.
2. Open **`http://192.168.4.1`** in a browser.
   Some phones report "cannot reach the internet"; choose "continue anyway",
   because this address does not use the internet.
3. Find the `otpauth` field on the page.

**Where do I get that link?**
Go to the two-factor setup page of the site you want to use. For GitHub:
avatar → Settings → Password and authentication → Two-factor authentication →
"setup key" shows a string beginning with `otpauth://totp/`.

Paste it and press **add**. **You can paste several, one per line** — they are
added in a batch.

4. While you are there, fill in your **home Wi-Fi** (SSID + password) in the form
   below and press **save and sync**. The device uses it to sync time silently at
   boot, then disconnects immediately. Once this is saved the device will no longer
   open a hotspot — it uses station mode instead.
5. Press **done** at the bottom of the page, then press OK on the device to close
   the portal.

## 3. Daily use

- **Read a code**: select the row with up/down, press OK for the large detail view.
- **Next account**: press up/down directly in the detail view.
- **Back**: press OK in the detail view.
- **Refresh**: automatic every 30 seconds; the progress bar shows the countdown.
- **Last 5 seconds**: the code turns red — use it now.

If the status line shows a red **"unsynced"** marker, the clock is untrustworthy
and the code is probably wrong. Select **re-sync time** and press OK, then wait
about ten seconds. If it fails, check your saved Wi-Fi.

## 4. Set the PIN lock

Select **set PIN lock** at the bottom of the list and press OK.

- **up / down**: change the digit at the current position
- **OK**: confirm this digit and move to the next
- **long press up/down**: submit

Type as many digits as you want (minimum 4), then long-press up or down to submit.
Type it once more to confirm. That guards against a mis-press.

Afterwards:

- Every cold boot into the TOTP page asks for the PIN.
- **The screen blanks after 30 seconds idle** and requires the PIN again. Without a
  PIN set, it never blanks (hiding nothing anyway).

**Five wrong attempts locks you out for five minutes.**
The lockout is stored on the device and **survives a power cycle** — there is no
reboot bypass.

While entering, the screen shows only dots (● ● ● ●), never the actual digits —
that is the anti-shoulder-surfing measure.

## 5. Export and backup

The enrollment page (`http://192.168.4.1`) has two entries:

**Export all accounts (plaintext)**
Downloads a text file of standard otpauth URIs. Use it to re-enroll on another
device or to keep a record.

⚠️ This file is plaintext. Anyone who has it has every secret. Move or delete it
immediately after use.
⚠️ The export asks for no PIN — the SoftAP itself is an open network.

**Download encrypted backup**
You set a passphrase; the device downloads a `.backup` file containing your
accounts encrypted with AES-256. The passphrase is the one you typed.

Use it when the device is lost and the secrets need recovering.

⚠️ **There is no backdoor.** A forgotten passphrase means unrecoverable data.
⚠️ The backup is currently **export-only** — no importer exists yet. If you lose the
device, you currently rely on the plaintext export or manual re-enrollment.
Adding the importer is on the roadmap.

## 6. Complete button map

| Screen | Up / Down | OK | Long press up/down |
|---|---|---|---|
| List | move selection | open detail / run action | — |
| Detail | switch account | back to list | — |
| Portal | — | close portal | — |
| PIN | change digit | confirm, next digit | submit |

On **any** screen: long press OK returns to the main menu (device-wide behavior).

## 7. Troubleshooting

**The page won't open / "cannot reach the internet"**
Expected. `192.168.4.1` is not on the internet — continue anyway or disable the
WLAN check.

**Time sync always fails**
The Wi-Fi must be **2.4 GHz** (the ESP32-C3 does not support 5 GHz). Check the
password. Campus/corporate networks requiring a captive portal will also fail.

**Codes don't match my phone**
Check the status line first. If it says "unsynced", the clock is off and so is the
code — re-sync first. If it still differs after syncing, please open an issue with
the account's algorithm (SHA1/256/512), digit count, and period.

**I forgot the PIN**
The only way out is a factory reset, which wipes NVS — accounts and PIN both gone.
That is the cost of "no backdoor".

**The device keeps opening a hotspot**
Your home Wi-Fi was not saved. Rejoin the hotspot, open the page, fill in the Wi-Fi,
and press **save and sync**.