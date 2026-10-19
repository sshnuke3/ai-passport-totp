// main/totp_time.h —— TOTP 玩法的时间源。
// ESP32-C3 无 RTC 备份电池：硬断电即丢墙钟。策略（见策划案）：
//   1. 开机静默连已存 Wi-Fi → SNTP 校时 → 立即断 Wi-Fi 省电；
//   2. 软重启/浅睡唤醒：RTC 慢内存留存 epoch + 运行毫秒推算；
//   3. 硬断电回退：NVS 里上次校准 epoch + 未知停机间隔（可能偏差）；
//   4. 全无：未校时态，UI 明示"码不可信"。
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

typedef enum {
    TOTP_TIME_NTP = 0,     // 本次开机 SNTP 校准成功（可信）
    TOTP_TIME_RTC,         // 软重启/唤醒，RTC 内存推定（秒级可信）
    TOTP_TIME_NVS,         // 硬断电回退，NVS 上次校准（可能偏差）
    TOTP_TIME_UNSET,       // 无任何时间源
} totp_time_status_t;

// 当前估计的 Unix epoch 秒。未初始化时返回 0。
time_t totp_time_now(void);

totp_time_status_t totp_time_status(void);

// 最近一次成功校准的 epoch（0=从未）。用于"上次校准于"展示。
int64_t totp_time_last_calibrated(void);

// 尝试用已存 Wi-Fi 凭证静默校时。成功返回 true 并持久化。
// 无凭证/连不上/超时都返回 false（此时回退到 RTC/NVS 推定）。
// 会自行完成 Wi-Fi 启停；不持 LVGL 锁，可在 lifecycle task 里调用。
bool totp_time_sync_wifi(void);

// 用 RTC/NVS 回退源初始化 base（不联网）。启动路径：
//   app 启动 → totp_time_bootstrap() → （有凭证则）totp_time_sync_wifi()。
void totp_time_bootstrap(void);

// 状态中文短描述（UI 直接用）。
const char *totp_time_status_text(totp_time_status_t st);
