// main/totp_store.h —— TOTP 玩法的 NVS 持久层。
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "totp_model.h"
#include "totp_pin.h"
#include "esp_err.h"

// 命名空间 "totp"：accounts(blob) / wifi_ssid / wifi_pass / cal_epoch(u64)

// 无记录时返回 ESP_OK 且 *count=0（首次使用的正常态）。
esp_err_t totp_store_load_accounts(totp_account_t *accs, uint8_t *count);
esp_err_t totp_store_save_accounts(const totp_account_t *accs, uint8_t count);

// *has=false 表示尚未配置 Wi-Fi。
esp_err_t totp_store_load_wifi(char *ssid, size_t ssid_cap,
                               char *pass, size_t pass_cap, bool *has);
esp_err_t totp_store_save_wifi(const char *ssid, const char *pass);

// 最近一次成功校时的 Unix epoch（用于"上次校准于"展示）。
esp_err_t totp_store_save_calibrated(int64_t epoch);
int64_t  totp_store_load_calibrated(void);   // 无记录返回 0

// PIN 锁状态持久化（哈希 + 失败计数 + 锁定截止时间）。
// 存的是 hash 不是明文；锁定截止时间必须持久化，否则断电重启会绕过 5 次限制。
esp_err_t totp_store_save_pin(const totp_pin_state_t *st);
esp_err_t totp_store_load_pin(totp_pin_state_t *st);
