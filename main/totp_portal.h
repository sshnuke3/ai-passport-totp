// main/totp_portal.h —— 录入门户：设备开 SoftAP + HTTP 服务，
// 手机连上后粘贴 otpauth:// 链接完成账户录入（三键设备输不了 base32）。
#pragma once

#include <stdbool.h>
#include "esp_err.h"

// 门户 AP 的 SSID（开放网络，无密码——设备本身不宣称防物理接触）。
#define TOTP_PORTAL_SSID "TotpPassport"
#define TOTP_PORTAL_IP   "192.168.4.1"

// 账户集合变化时回调（httpd 任务上下文；实现方只应置标志，由 UI 定时器落地刷新）。
typedef void (*totp_portal_change_cb_t)(void);
void totp_portal_set_change_cb(totp_portal_change_cb_t cb);

// 门户页面请求的后续动作（由 UI 定时器取出执行，httpd 任务本身不碰 Wi-Fi 栈）。
typedef enum {
    TOTP_PORTAL_ACTION_NONE = 0,
    TOTP_PORTAL_ACTION_WIFI_SYNC,   // /wifi：凭证已存，请求停止门户并校时
    TOTP_PORTAL_ACTION_DONE,        // /done：停止门户，返回账户页
} totp_portal_action_t;

totp_portal_action_t totp_portal_take_action(void);

// 启动/停止门户（AP netif + httpd）。重复启动返回 ESP_ERR_INVALID_STATE。
esp_err_t totp_portal_start(void);
esp_err_t totp_portal_stop(void);
bool totp_portal_running(void);
