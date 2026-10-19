// main/totp_store.c —— TOTP 玩法的 NVS 持久层实现。
// 命名空间 "totp"：
//   accounts : blob（totp_serialize 格式，含 magic/version）
//   wifi_ssid/wifi_pass : 校时与门户用的家庭 Wi-Fi 凭证
//   cal_epoch : 最近一次成功 NTP 校时的 Unix epoch（u64）
#include "totp_store.h"

#include "nvs_flash.h"
#include "nvs.h"
#include "esp_log.h"

#include <string.h>

static const char *TAG = "totp_store";

#define TOTP_NVS_NAMESPACE "totp"
#define KEY_ACCOUNTS  "accounts"
#define KEY_SSID      "wifi_ssid"
#define KEY_PASS      "wifi_pass"
#define KEY_CAL_EPOCH "cal_epoch"
#define KEY_PIN_HASH  "pin_hash"
#define KEY_PIN_FAILS "pin_fails"
#define KEY_PIN_LOCK  "pin_lock"

esp_err_t totp_store_load_accounts(totp_account_t *accs, uint8_t *count)
{
    if (!accs || !count) return ESP_ERR_INVALID_ARG;
    *count = 0;

    nvs_handle_t nvs;
    esp_err_t err = nvs_open(TOTP_NVS_NAMESPACE, NVS_READONLY, &nvs);
    if (err == ESP_ERR_NVS_NOT_FOUND) return ESP_OK;   // 命名空间不存在=首次使用
    if (err != ESP_OK) return err;

    size_t len = 0;
    err = nvs_get_blob(nvs, KEY_ACCOUNTS, NULL, &len);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        nvs_close(nvs);
        return ESP_OK;                                   // 无记录=正常空态
    }
    if (err != ESP_OK) { nvs_close(nvs); return err; }

    // 序列化缓冲按栈上静态尺寸分配：24 账户 × ~150B ≈ 3.6KB，堆上一次性分配更稳。
    uint8_t *blob = malloc(len ? len : 1);
    if (!blob) { nvs_close(nvs); return ESP_ERR_NO_MEM; }

    err = nvs_get_blob(nvs, KEY_ACCOUNTS, blob, &len);
    nvs_close(nvs);
    if (err != ESP_OK) { free(blob); return err; }

    int n = totp_deserialize(blob, len, accs, count);
    free(blob);
    if (n < 0) {
        ESP_LOGW(TAG, "accounts blob 损坏(len=%u)，按空处理", (unsigned)len);
        *count = 0;
        return ESP_OK;                                   // 损坏不阻塞启动，用户重新录入
    }
    return ESP_OK;
}

esp_err_t totp_store_save_accounts(const totp_account_t *accs, uint8_t count)
{
    if (!accs && count) return ESP_ERR_INVALID_ARG;
    if (count > TOTP_MAX_ACCOUNTS) return ESP_ERR_INVALID_ARG;

    static uint8_t blob[4096];
    size_t n = totp_serialize(accs, count, blob, sizeof(blob));
    if (n == 0) return ESP_ERR_NO_MEM;

    nvs_handle_t nvs;
    esp_err_t err = nvs_open(TOTP_NVS_NAMESPACE, NVS_READWRITE, &nvs);
    if (err != ESP_OK) return err;

    err = nvs_set_blob(nvs, KEY_ACCOUNTS, blob, n);
    if (err == ESP_OK) err = nvs_commit(nvs);
    nvs_close(nvs);
    return err;
}

esp_err_t totp_store_load_wifi(char *ssid, size_t ssid_cap,
                               char *pass, size_t pass_cap, bool *has)
{
    if (!ssid || !pass || !has || !ssid_cap || !pass_cap) return ESP_ERR_INVALID_ARG;
    *has = false;
    ssid[0] = '\0';
    pass[0] = '\0';

    nvs_handle_t nvs;
    esp_err_t err = nvs_open(TOTP_NVS_NAMESPACE, NVS_READONLY, &nvs);
    if (err == ESP_ERR_NVS_NOT_FOUND) return ESP_OK;
    if (err != ESP_OK) return err;

    size_t slen = ssid_cap, plen = pass_cap;
    err = nvs_get_str(nvs, KEY_SSID, ssid, &slen);
    if (err == ESP_ERR_NVS_NOT_FOUND) { nvs_close(nvs); return ESP_OK; }
    if (err != ESP_OK) { nvs_close(nvs); return err; }
    err = nvs_get_str(nvs, KEY_PASS, pass, &plen);
    nvs_close(nvs);
    if (err == ESP_ERR_NVS_NOT_FOUND) return ESP_OK;      // 只存了 ssid 也当未配置
    if (err != ESP_OK) return err;

    *has = true;
    return ESP_OK;
}

esp_err_t totp_store_save_wifi(const char *ssid, const char *pass)
{
    if (!ssid || !pass) return ESP_ERR_INVALID_ARG;

    nvs_handle_t nvs;
    esp_err_t err = nvs_open(TOTP_NVS_NAMESPACE, NVS_READWRITE, &nvs);
    if (err != ESP_OK) return err;

    err = nvs_set_str(nvs, KEY_SSID, ssid);
    if (err == ESP_OK) err = nvs_set_str(nvs, KEY_PASS, pass);
    if (err == ESP_OK) err = nvs_commit(nvs);
    nvs_close(nvs);
    return err;
}

esp_err_t totp_store_save_calibrated(int64_t epoch)
{
    nvs_handle_t nvs;
    esp_err_t err = nvs_open(TOTP_NVS_NAMESPACE, NVS_READWRITE, &nvs);
    if (err != ESP_OK) return err;

    err = nvs_set_u64(nvs, KEY_CAL_EPOCH, (uint64_t)epoch);
    if (err == ESP_OK) err = nvs_commit(nvs);
    nvs_close(nvs);
    return err;
}

int64_t totp_store_load_calibrated(void)
{
    nvs_handle_t nvs;
    esp_err_t err = nvs_open(TOTP_NVS_NAMESPACE, NVS_READONLY, &nvs);
    if (err != ESP_OK) return 0;

    uint64_t v = 0;
    err = nvs_get_u64(nvs, KEY_CAL_EPOCH, &v);
    nvs_close(nvs);
    if (err != ESP_OK) return 0;
    return (int64_t)v;
}

// PIN 锁：三个字段都存，否则断电会绕过「连错 5 次」
esp_err_t totp_store_save_pin(const totp_pin_state_t *st)
{
    if (!st) return ESP_ERR_INVALID_ARG;

    nvs_handle_t nvs;
    esp_err_t err = nvs_open(TOTP_NVS_NAMESPACE, NVS_READWRITE, &nvs);
    if (err != ESP_OK) return err;

    err = nvs_set_u64(nvs, KEY_PIN_HASH, (uint64_t)st->hash);
    if (err == ESP_OK) {
        err = nvs_set_u8(nvs, KEY_PIN_FAILS, st->fails);
    }
    if (err == ESP_OK) {
        err = nvs_set_i64(nvs, KEY_PIN_LOCK, st->lock_until);
    }
    if (err == ESP_OK) err = nvs_commit(nvs);
    nvs_close(nvs);
    return err;
}

esp_err_t totp_store_load_pin(totp_pin_state_t *st)
{
    if (!st) return ESP_ERR_INVALID_ARG;
    memset(st, 0, sizeof(*st));

    nvs_handle_t nvs;
    esp_err_t err = nvs_open(TOTP_NVS_NAMESPACE, NVS_READONLY, &nvs);
    if (err == ESP_ERR_NVS_NOT_FOUND) return ESP_OK;    // 首次使用=未设 PIN
    if (err != ESP_OK) return err;

    uint64_t hash = 0;
    err = nvs_get_u64(nvs, KEY_PIN_HASH, &hash);
    if (err == ESP_OK) st->hash = (uint64_t)hash;

    uint8_t fails = 0;
    if (nvs_get_u8(nvs, KEY_PIN_FAILS, &fails) == ESP_OK) st->fails = fails;

    int64_t lock_until = 0;
    if (nvs_get_i64(nvs, KEY_PIN_LOCK, &lock_until) == ESP_OK) st->lock_until = lock_until;

    nvs_close(nvs);
    return ESP_OK;
}
