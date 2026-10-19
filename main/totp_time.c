// main/totp_time.c —— 时间源实现。Wi-Fi STA 连接 + SNTP 校时 + 回退推定。
#include "totp_time.h"
#include "totp_store.h"

#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_sntp.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"
#include "nvs_flash.h"

#include <string.h>

static const char *TAG = "totp_time";

// SNTP 服务器：国内可达优先，官方池兜底。
static const char *NTP_SERVERS[] = { "ntp.aliyun.com", "cn.pool.ntp.org", "pool.ntp.org" };

// RTC 慢内存：软重启/深睡唤醒后仍保留（硬断电丢失）。
static RTC_DATA_ATTR int64_t s_rtc_epoch;

// base：本开机周期认定的 epoch 零点；now() = base + uptime。
static int64_t s_base;
static totp_time_status_t s_status = TOTP_TIME_UNSET;
static int64_t s_last_calibrated;   // 0=从未

static int64_t now_ms(void) { return esp_timer_get_time() / 1000; }

// epoch 合理性区间：2020-01-01 .. 2038-01-19（time_t 32 位上限前）。
static bool epoch_plausible(int64_t e)
{
    return e > 1577836800LL && e < 2145916800LL;
}

time_t totp_time_now(void)
{
    if (s_status == TOTP_TIME_UNSET) return 0;
    return (time_t)(s_base + now_ms() / 1000);
}

totp_time_status_t totp_time_status(void) { return s_status; }
int64_t totp_time_last_calibrated(void) { return s_last_calibrated; }

const char *totp_time_status_text(totp_time_status_t st)
{
    switch (st) {
    case TOTP_TIME_NTP:   return "已校准";
    case TOTP_TIME_RTC:   return "时间推定";
    case TOTP_TIME_NVS:   return "时间可能偏差";
    case TOTP_TIME_UNSET: return "未校时";
    }
    return "?";
}

static void set_base(int64_t epoch, totp_time_status_t st)
{
    s_base = epoch - now_ms() / 1000;
    s_status = st;
}

void totp_time_bootstrap(void)
{
    s_last_calibrated = totp_store_load_calibrated();

    if (epoch_plausible(s_rtc_epoch)) {
        set_base(s_rtc_epoch, TOTP_TIME_RTC);
        ESP_LOGI(TAG, "回退 RTC 推定 epoch=%lld", (long long)s_rtc_epoch);
        return;
    }
    if (epoch_plausible(s_last_calibrated)) {
        set_base(s_last_calibrated, TOTP_TIME_NVS);
        ESP_LOGW(TAG, "回退 NVS 上次校准 epoch=%lld（硬断电，可能有偏差）",
                 (long long)s_last_calibrated);
        return;
    }
    s_status = TOTP_TIME_UNSET;
    ESP_LOGW(TAG, "无可用时间源，等待校时");
}

// ---- Wi-Fi STA + SNTP ----
#define WIFI_GOT_IP_BIT BIT1

typedef struct {
    EventGroupHandle_t eg;
} wifi_wait_t;

static void on_wifi_event(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    (void)data;
    wifi_wait_t *w = (wifi_wait_t *)arg;
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        xEventGroupSetBits(w->eg, WIFI_GOT_IP_BIT);
    }
}

static void on_sntp_sync(struct timeval *tv)
{
    ESP_LOGI(TAG, "SNTP 同步完成 epoch=%lld", (long long)tv->tv_sec);
}

// 统一回收：按已建立的资源逆序拆除，允许部分失败。
static void wifi_teardown(esp_netif_t *sta,
                          esp_event_handler_instance_t h1,
                          esp_event_handler_instance_t h2,
                          bool handlers_registered,
                          EventGroupHandle_t eg)
{
    esp_wifi_disconnect();
    esp_wifi_stop();
    esp_wifi_deinit();
    if (handlers_registered) {
        esp_event_handler_instance_unregister(WIFI_EVENT, ESP_EVENT_ANY_ID, h1);
        esp_event_handler_instance_unregister(IP_EVENT, IP_EVENT_STA_GOT_IP, h2);
    }
    if (sta) {
        esp_wifi_clear_default_wifi_driver_and_handlers(sta);
        esp_netif_destroy_default_wifi(sta);
    }
    if (eg) vEventGroupDelete(eg);
}

bool totp_time_sync_wifi(void)
{
    char ssid[33] = { 0 }, pass[65] = { 0 };
    bool has = false;
    if (totp_store_load_wifi(ssid, sizeof(ssid), pass, sizeof(pass), &has) != ESP_OK || !has) {
        ESP_LOGI(TAG, "未配置 Wi-Fi，跳过校时");
        return false;
    }

    if (nvs_flash_init() != ESP_OK) return false;
    if (esp_netif_init() != ESP_OK) return false;
    if (esp_event_loop_create_default() != ESP_OK) return false;

    EventGroupHandle_t eg = xEventGroupCreate();
    if (!eg) return false;
    wifi_wait_t w = { .eg = eg };

    esp_netif_t *sta = esp_netif_create_default_wifi_sta();
    if (!sta) { vEventGroupDelete(eg); return false; }

    wifi_init_config_t wcfg = WIFI_INIT_CONFIG_DEFAULT();
    if (esp_wifi_init(&wcfg) != ESP_OK) { wifi_teardown(sta, NULL, NULL, false, eg); return false; }

    esp_event_handler_instance_t h1 = NULL, h2 = NULL;
    if (esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                            on_wifi_event, &w, &h1) != ESP_OK ||
        esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
                                            on_wifi_event, &w, &h2) != ESP_OK) {
        wifi_teardown(sta, h1, h2, h1 != NULL, eg);
        return false;
    }

    wifi_config_t cfg = { 0 };
    strncpy((char *)cfg.sta.ssid, ssid, sizeof(cfg.sta.ssid) - 1);
    strncpy((char *)cfg.sta.password, pass, sizeof(cfg.sta.password) - 1);
    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_set_config(WIFI_IF_STA, &cfg);
    esp_wifi_start();

    ESP_LOGI(TAG, "连接 Wi-Fi %s 校时…", ssid);
    EventBits_t bits = xEventGroupWaitBits(eg, WIFI_GOT_IP_BIT,
                                           pdFALSE, pdFALSE, pdMS_TO_TICKS(10000));
    if (!(bits & WIFI_GOT_IP_BIT)) {
        ESP_LOGW(TAG, "Wi-Fi 连接超时");
        wifi_teardown(sta, h1, h2, true, eg);
        return false;
    }

    // SNTP 轮询校时
    esp_sntp_setoperatingmode(SNTP_OPMODE_POLL);
    for (size_t i = 0; i < sizeof(NTP_SERVERS) / sizeof(NTP_SERVERS[0]); i++) {
        esp_sntp_setservername((u8_t)i, NTP_SERVERS[i]);
    }
    esp_sntp_set_time_sync_notification_cb(on_sntp_sync);
    esp_sntp_init();

    // 等墙钟被改写：轮询检查 time(NULL) 是否进入合理区间。
    bool synced = false;
    for (int i = 0; i < 100; i++) {          // 10s 超时
        if (epoch_plausible((int64_t)time(NULL))) { synced = true; break; }
        vTaskDelay(pdMS_TO_TICKS(100));
    }

    esp_sntp_stop();
    wifi_teardown(sta, h1, h2, true, eg);

    if (!synced) {
        ESP_LOGW(TAG, "SNTP 校时超时");
        return false;
    }

    time_t t = time(NULL);
    set_base((int64_t)t, TOTP_TIME_NTP);
    s_rtc_epoch = (int64_t)t;
    totp_store_save_calibrated((int64_t)t);
    ESP_LOGI(TAG, "校时成功 epoch=%lld", (long long)t);
    return true;
}
