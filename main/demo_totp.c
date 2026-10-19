// main/demo_totp.c —— TotpPassport 玩法主界面。
//
// 状态机（三键操作：上/下/确定，长按确定返回菜单由 main.c 统一拦截）：
//   PIN     锁屏（已设 PIN 且息屏/冷启动时先过这关）
//   LIST    账户列表（尾部三条动作行：录入账户 / 重新校时 / PIN 设置）
//   DETAIL  单账户大号码 + 倒计时条（最后 5 秒变红）
//   PORTAL  录入模式（SoftAP + 网页门户）
//
// 版式注意：ui_pixel_screen_create 自带标题牌（y8..41）与底部草地装饰
// （y286 起），内容区限定 y48..284。
//
// 线程模型：
//   LVGL 任务 —— enter/exit/key/tick 里操作 UI（key 自行加锁）
//   totp_work —— 唯一碰 Wi-Fi 栈的任务（校时/门户启停走命令队列，不阻塞 UI）
#include "demo.h"
#include "totp_crypto.h"
#include "totp_model.h"
#include "totp_pin.h"
#include "totp_portal.h"
#include "totp_store.h"
#include "totp_time.h"

#include "bsp_display.h"
#include "ui_pixel.h"

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"

#include "lvgl.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

static const char *TAG = "demo_totp";

// ---------------------------------------------------------------- 布局常量
#define ROW_H        44
#define ROW_GAP      4
#define ROW_VISIBLE  4
#define LIST_TOP     70

// 动作行（挂在账户列表尾部）
#define ACTION_ENROLL  0
#define ACTION_SYNC    1
#define ACTION_PIN     2
#define ACTION_COUNT   3

// 无操作自动息屏（秒）。到期后若已设 PIN，需重新输入才能看码。
#define IDLE_BLANK_SECONDS 30

// 时间漂移告警阈值（秒）：当前时间与「上次校准 + 已流逝」差这么多就不可信。
#define DRIFT_WARN_SECONDS 10

typedef enum {
    TOTP_UI_PIN = 0,
    TOTP_UI_LIST,
    TOTP_UI_DETAIL,
    TOTP_UI_PORTAL,
} totp_ui_state_t;

// ---------------------------------------------------------------- 静态状态
static lv_obj_t *s_scr;
static lv_obj_t *s_status;                 // 标题牌下方的状态行
static lv_obj_t *s_panel_list;
static lv_obj_t *s_panel_detail;
static lv_obj_t *s_panel_portal;
static lv_obj_t *s_rows[ROW_VISIBLE];
static lv_obj_t *s_row_name[ROW_VISIBLE];
static lv_obj_t *s_row_code[ROW_VISIBLE];
static lv_obj_t *s_list_footer;
static lv_obj_t *s_d_name;
static lv_obj_t *s_d_code;
static lv_obj_t *s_d_secs;
static lv_obj_t *s_d_bar;
static lv_obj_t *s_d_status;
static lv_obj_t *s_d_footer;
static lv_obj_t *s_p_lines[4];
static lv_obj_t *s_p_footer;
static lv_timer_t *s_timer;
// ---- PIN 锁屏 ----
static lv_obj_t *s_panel_pin;
static lv_obj_t *s_pin_title;
static lv_obj_t *s_pin_dots;
static lv_obj_t *s_pin_msg;
static lv_obj_t *s_pin_footer;

static totp_account_t s_accs[TOTP_MAX_ACCOUNTS];
static uint8_t s_count;
static int s_sel;                 // 列表选中项：0..count-1 账户；count+ACTION_* 动作行
static int s_scroll;              // 列表滚动偏移（首个可见行）
static int s_detail_idx;          // 详情页当前账户
static totp_ui_state_t s_state = TOTP_UI_LIST;
static char s_status_text[48];    // 上次渲染的状态行（变化才重绘）

// ---- PIN 锁 ----
static totp_pin_state_t s_pin;
static char s_pin_input[TOTP_PIN_MAX_DIGITS + 1];
static int  s_pin_len;
static bool s_unlocked;           // 本次会话是否已解锁
static bool s_pin_setup_mode;     // true=设新 PIN，false=解锁
static uint32_t s_idle_ticks;     // 无操作计数（tick 250ms 一次）
static bool s_blanked;            // 已息屏（遮住码，需重新解锁）
// 设 PIN 的「两次输入」中间态。必须是文件级：放函数里的 static 在退出页面后
// 仍保留，下次进来会被误判成「已经在输第二遍」。
static char s_pin_first[TOTP_PIN_MAX_DIGITS + 1];
static bool s_pin_has_first;

static volatile bool s_accounts_changed;   // 门户改了账户集合
static volatile bool s_sync_busy;          // 校时进行中

// 常驻 worker：唯一操作 Wi-Fi 栈的任务（校时/门户启停）
static QueueHandle_t s_cmd_queue;
static TaskHandle_t s_worker;

enum {
    TOTP_CMD_SYNC = 1,
    TOTP_CMD_PORTAL_ON,
    TOTP_CMD_PORTAL_OFF,
};

// 外部字体（assets/fonts 生成，见 tools/gen_totp_font.sh）
extern const lv_font_t font_totp_16;
extern const lv_font_t font_totp_44;

// ---------------------------------------------------------------- 小工具
// "123456" → "123 456"；"12345678" → "1234 5678"
static void format_code(char *dst, size_t cap, const char *src)
{
    size_t n = strlen(src), w = 0;
    size_t split = (n == 8) ? 4 : 3;
    for (size_t i = 0; i < n && w + 2 < cap; i++) {
        dst[w++] = src[i];
        if (i + 1 == split && i + 1 < n) dst[w++] = ' ';
    }
    dst[w] = '\0';
}

static uint32_t totp_remaining_of(const totp_account_t *a)
{
    time_t t = totp_time_now();
    if (t == 0) return 0;
    return totp_remaining(t, a->period);
}

// 当前时刻的码（未校时返回 false）
static bool totp_code_now(const totp_account_t *a, char *out, size_t cap)
{
    time_t t = totp_time_now();
    if (t == 0) return false;
    totp_code(a, t, out, cap);
    return true;
}

static int totp_item_count(void) { return (int)s_count + ACTION_COUNT; }

static bool totp_item_is_action(int idx) { return idx >= (int)s_count; }

static const char *totp_action_name(int idx)
{
    switch (idx - (int)s_count) {
    case ACTION_ENROLL: return "+ 录入账户";
    case ACTION_SYNC:   return "重新校时";
    case ACTION_PIN:    return s_pin.hash ? "修改 PIN 锁" : "设置 PIN 锁";
    default:            return "";
    }
}

// ---------------------------------------------------------------- worker
static void enqueue_cmd(uint32_t cmd)
{
    if (!s_cmd_queue) return;
    (void)xQueueSend(s_cmd_queue, &cmd, 0);
}

static void totp_worker(void *arg)
{
    (void)arg;
    uint32_t cmd;
    for (;;) {
        if (xQueueReceive(s_cmd_queue, &cmd, portMAX_DELAY) != pdTRUE) continue;
        switch (cmd) {
        case TOTP_CMD_SYNC:
            s_sync_busy = true;
            totp_time_sync_wifi();
            s_sync_busy = false;
            break;
        case TOTP_CMD_PORTAL_ON:
            totp_portal_start();
            break;
        case TOTP_CMD_PORTAL_OFF:
            totp_portal_stop();
            break;
        default:
            break;
        }
    }
}

static void worker_ensure_started(void)
{
    if (s_cmd_queue && s_worker) return;
    s_cmd_queue = xQueueCreate(8, sizeof(uint32_t));
    if (!s_cmd_queue) return;
    xTaskCreate(totp_worker, "totp_work", 4096, NULL, 4, &s_worker);
}

static void on_accounts_changed(void)
{
    s_accounts_changed = true;   // 由 LVGL tick 落地刷新
}

// ---------------------------------------------------------------- 数据加载
static void reload_accounts(void)
{
    uint8_t n = 0;
    if (totp_store_load_accounts(s_accs, &n) != ESP_OK) n = 0;
    s_count = n;
    if (s_sel >= totp_item_count()) s_sel = totp_item_count() - 1;
    if (s_sel < 0) s_sel = 0;
    if (s_detail_idx >= (int)s_count) s_detail_idx = (int)s_count - 1;
    if (s_detail_idx < 0) s_detail_idx = 0;
}

// ---------------------------------------------------------------- 状态切换
static void totp_ui_switch(totp_ui_state_t st)
{
    s_state = st;
    lv_obj_add_flag(s_panel_list, LV_OBJ_FLAG_HIDDEN);
    lv_obj_add_flag(s_panel_detail, LV_OBJ_FLAG_HIDDEN);
    lv_obj_add_flag(s_panel_portal, LV_OBJ_FLAG_HIDDEN);
    lv_obj_add_flag(s_panel_pin, LV_OBJ_FLAG_HIDDEN);
    switch (st) {
    case TOTP_UI_LIST:   lv_obj_clear_flag(s_panel_list, LV_OBJ_FLAG_HIDDEN); break;
    case TOTP_UI_DETAIL: lv_obj_clear_flag(s_panel_detail, LV_OBJ_FLAG_HIDDEN); break;
    case TOTP_UI_PORTAL: lv_obj_clear_flag(s_panel_portal, LV_OBJ_FLAG_HIDDEN); break;
    case TOTP_UI_PIN:    lv_obj_clear_flag(s_panel_pin, LV_OBJ_FLAG_HIDDEN); break;
    }
}

// ---------------------------------------------------------------- PIN 屏
// 遮罩显示已输入位数（不显示真实数字，防肩窥）
static void render_pin(void)
{
    static char dots[2 * TOTP_PIN_MAX_DIGITS + 1];
    size_t w = 0;
    for (int i = 0; i < s_pin_len && w + 1 < sizeof(dots); i++) {
        dots[w++] = (char)0xC2;   // '·'
        dots[w++] = (char)0xB7;
    }
    dots[w] = '\0';
    lv_label_set_text(s_pin_dots, dots);

    lv_label_set_text(s_pin_title,
                      s_pin_setup_mode ? "设置 PIN（4-8 位）" : "输入 PIN 解锁");

    // 锁定剩余时间优先于一切提示
    int32_t remain = 0;
    if (totp_pin_locked(&s_pin, (int64_t)totp_time_now(), &remain)) {
        char msg[48];
        snprintf(msg, sizeof(msg), "已锁定，请 %d 秒后重试", (int)(remain + 59) / 60);
        lv_label_set_text(s_pin_msg, msg);
        lv_obj_set_style_text_color(s_pin_msg, lv_color_hex(UI_RED), 0);
        lv_label_set_text(s_pin_footer, "");
        return;
    }

    if (s_pin_len == 0) {
        lv_label_set_text(s_pin_msg, "");
    }
    lv_label_set_text(s_pin_footer, s_pin_setup_mode
        ? "上下改数字 · OK 下一位 · 长按提交"
        : "上下改数字 · OK 下一位 · 长按提交");
}

// 输满/提交后调用。返回 true 表示应切走（已解锁或已完成设置）
static bool pin_try_submit(void)
{
    s_pin_input[s_pin_len] = '\0';

    if (s_pin_setup_mode) {
        // 设 PIN：第一次确认后要再输一遍，防止手滑
        if (!s_pin_has_first) {
            if (s_pin_len < TOTP_PIN_MIN_DIGITS) {
                lv_label_set_text(s_pin_msg, "至少 4 位");
                s_pin_len = 0;
                return false;
            }
            strncpy(s_pin_first, s_pin_input, sizeof(s_pin_first) - 1);
            s_pin_first[sizeof(s_pin_first) - 1] = '\0';
            s_pin_has_first = true;
            s_pin_len = 0;
            lv_label_set_text(s_pin_title, "再输一次确认");
            lv_label_set_text(s_pin_msg, "");
            return false;
        }
        if (strcmp(s_pin_first, s_pin_input) != 0) {
            lv_label_set_text(s_pin_msg, "两次不一致，请重设");
            s_pin_len = 0;
            s_pin_has_first = false;
            lv_label_set_text(s_pin_title, "设置 PIN（4-8 位）");
            return false;
        }
        totp_pin_set(&s_pin, s_pin_first);
        totp_store_save_pin(&s_pin);
        s_pin_has_first = false;
        s_pin_setup_mode = false;
        s_pin_len = 0;
        s_unlocked = true;
        return true;
    }

    totp_pin_result_t r = totp_pin_submit(&s_pin, s_pin_input, (int64_t)totp_time_now());
    totp_store_save_pin(&s_pin);   // 失败计数/锁定时间必须落盘，防断电绕过
    s_pin_len = 0;

    if (r == TOTP_PIN_OK) {
        s_unlocked = true;
        return true;
    }
    if (r == TOTP_PIN_LOCKED) {
        char msg[48];
        snprintf(msg, sizeof(msg), "错误次数过多，锁定 5 分钟");
        lv_label_set_text(s_pin_msg, msg);
        lv_obj_set_style_text_color(s_pin_msg, lv_color_hex(UI_RED), 0);
    } else {
        lv_label_set_text(s_pin_msg, totp_pin_result_text(r));
        lv_obj_set_style_text_color(s_pin_msg, lv_color_hex(UI_RED), 0);
    }
    return false;
}

// ---------------------------------------------------------------- 渲染
// 时间漂移检测：ESP32-C3 硬断电丢墙钟，软重启走 RTC 推算。
// 若「当前时间」明显偏离「上次校准时间 + 已流逝」，说明推定不可信 → 角标提示。
static bool time_drifted(void)
{
    int64_t cal = totp_time_last_calibrated();
    time_t now = totp_time_now();
    if (cal <= 0 || now == 0) return true;         // 从未校准 = 必然不可信

    // 允许单向偏差：断电期间设备不跑，now 只会比 cal 大；
    // 但若 now 反而小于 cal（时钟回拨）或差得离谱，都算漂移。
    int64_t diff = (int64_t)now - cal;
    if (diff < 0) return true;
    return diff > (int64_t)DRIFT_WARN_SECONDS * 60;  // 超过 10 分钟视为不可信
}

static void render_status(void)
{
    char text[48];
    const char *st = s_sync_busy ? "校时中" : totp_time_status_text(totp_time_status());
    bool drift = !s_sync_busy && time_drifted();
    snprintf(text, sizeof(text), "%s%s · %u 个账户",
             drift ? "未校时 " : "", st, (unsigned)s_count);
    if (strcmp(text, s_status_text) == 0) return;
    strncpy(s_status_text, text, sizeof(s_status_text) - 1);

    // 已校准=绿，推定/偏差=黄，未校时=红，校时中=蓝
    uint32_t color = UI_INK;
    if (s_sync_busy) color = UI_SKY_DARK;
    else if (drift) color = UI_RED;
    else switch (totp_time_status()) {
    case TOTP_TIME_NTP:   color = UI_GRASS_DARK; break;
    case TOTP_TIME_RTC:
    case TOTP_TIME_NVS:   color = UI_ORANGE; break;
    case TOTP_TIME_UNSET: color = UI_RED; break;
    }
    lv_obj_set_style_text_color(s_status, lv_color_hex(color), 0);
    lv_label_set_text(s_status, text);
}

static void render_row(int slot, int item_idx)
{
    if (item_idx < 0 || item_idx >= totp_item_count()) {
        lv_obj_add_flag(s_rows[slot], LV_OBJ_FLAG_HIDDEN);
        return;
    }
    lv_obj_clear_flag(s_rows[slot], LV_OBJ_FLAG_HIDDEN);

    char name[160], code[16];
    ui_pixel_set_selected(s_rows[slot], item_idx == s_sel, true);

    if (totp_item_is_action(item_idx)) {
        snprintf(name, sizeof(name), "%s", totp_action_name(item_idx));
        snprintf(code, sizeof(code), "%s",
                 item_idx - (int)s_count == ACTION_SYNC && s_sync_busy ? "···" : "");
    } else {
        const totp_account_t *a = &s_accs[item_idx];
        char shown[80];
        strncpy(shown, a->name, sizeof(shown) - 1);
        shown[sizeof(shown) - 1] = '\0';
        totp_normalize_display(shown);
        snprintf(name, sizeof(name), "%d. %s%s%s", item_idx + 1,
                 a->issuer[0] ? a->issuer : "",
                 a->issuer[0] ? " " : "", shown);

        char raw[16];
        if (totp_code_now(a, raw, sizeof(raw))) {
            format_code(code, sizeof(code), raw);
            // 最后 5 秒的码标红（ glanceable 紧迫感）
            if (totp_remaining_of(a) <= 5) {
                lv_obj_set_style_text_color(s_row_code[slot], lv_color_hex(UI_RED), 0);
            } else {
                lv_obj_set_style_text_color(s_row_code[slot], lv_color_hex(UI_SKY_DARK), 0);
            }
        } else {
            snprintf(code, sizeof(code), "------");
            lv_obj_set_style_text_color(s_row_code[slot], lv_color_hex(UI_MUTED), 0);
        }
    }

    lv_label_set_text(s_row_name[slot], name);
    lv_label_set_text(s_row_code[slot], code);
}

static void render_list(void)
{
    // 保持选中项可见
    if (s_sel < s_scroll) s_scroll = s_sel;
    if (s_sel >= s_scroll + ROW_VISIBLE) s_scroll = s_sel - ROW_VISIBLE + 1;

    for (int i = 0; i < ROW_VISIBLE; i++) {
        render_row(i, s_scroll + i);
    }

    lv_label_set_text(s_list_footer,
                      s_count == 0 ? "选「+ 录入账户」开始"
                                   : "OK 查看 · 上下选择 · 长按返回");
}

static void render_detail(void)
{
    if (s_detail_idx < 0 || s_detail_idx >= (int)s_count) {
        totp_ui_switch(TOTP_UI_LIST);
        render_list();
        return;
    }
    const totp_account_t *a = &s_accs[s_detail_idx];

    char shown[80], name[160];
    strncpy(shown, a->name, sizeof(shown) - 1);
    shown[sizeof(shown) - 1] = '\0';
    totp_normalize_display(shown);
    snprintf(name, sizeof(name), "%s%s%s", a->issuer[0] ? a->issuer : "",
             a->issuer[0] ? " · " : "", shown);
    lv_label_set_text(s_d_name, name);

    char raw[16], code[16];
    if (totp_code_now(a, raw, sizeof(raw))) {
        format_code(code, sizeof(code), raw);
        uint32_t r = totp_remaining_of(a);
        bool urgent = r <= 5;
        lv_label_set_text(s_d_code, code);
        lv_obj_set_style_text_color(s_d_code,
            lv_color_hex(urgent ? UI_RED : UI_INK), 0);
        char secs[24];
        snprintf(secs, sizeof(secs), "%u 秒", (unsigned)r);
        lv_label_set_text(s_d_secs, secs);
        lv_bar_set_range(s_d_bar, 0, (int32_t)a->period);
        lv_bar_set_value(s_d_bar, (int32_t)r, LV_ANIM_OFF);
        lv_obj_set_style_bg_color(s_d_bar,
            lv_color_hex(urgent ? UI_RED : UI_GRASS), LV_PART_INDICATOR);
    } else {
        lv_label_set_text(s_d_code, "------");
        lv_obj_set_style_text_color(s_d_code, lv_color_hex(UI_RED), 0);
        lv_label_set_text(s_d_secs, "未校时");
        lv_bar_set_value(s_d_bar, 0, LV_ANIM_OFF);
    }

    static char status[64];
    const char *st = s_sync_busy ? "校时中" : totp_time_status_text(totp_time_status());
    int64_t cal = totp_time_last_calibrated();
    if (cal > 0) {
        time_t tt = (time_t)cal;
        struct tm tmv;
        gmtime_r(&tt, &tmv);
        char date[16];
        strftime(date, sizeof(date), "%m-%d %H:%M UTC", &tmv);
        snprintf(status, sizeof(status), "%s · 上次校准 %s", st, date);
    } else {
        snprintf(status, sizeof(status), "%s · 尚未校准", st);
    }
    lv_label_set_text(s_d_status, status);
}

static void render_portal(void)
{
    static char lines[4][48];
    snprintf(lines[0], sizeof(lines[0]), "1. 手机连 Wi-Fi: %s", TOTP_PORTAL_SSID);
    snprintf(lines[1], sizeof(lines[1]), "2. 浏览器打开 http://%s", TOTP_PORTAL_IP);
    snprintf(lines[2], sizeof(lines[2]), "3. 粘贴 otpauth:// 链接");
    for (int i = 0; i < 3; i++) lv_label_set_text(s_p_lines[i], lines[i]);
    char cnt[32];
    snprintf(cnt, sizeof(cnt), "已录入 %u 个账户", (unsigned)s_count);
    lv_label_set_text(s_p_lines[3], cnt);
    lv_label_set_text(s_p_footer, totp_portal_running()
        ? "OK 退出录入 · 网页保存后自动刷新"
        : "门户正在关闭");
}

// ---------------------------------------------------------------- 定时器
// 息屏：IDLE_BLANK_SECONDS 内无操作 → 遮住码并切到 PIN 屏。
// 未设 PIN 时不息屏（遮了也没人能解锁）。
static void check_idle_blank(void)
{
    if (!s_pin.hash || s_state == TOTP_UI_PIN || s_blanked) return;
    if (++s_idle_ticks < (uint32_t)(IDLE_BLANK_SECONDS * 1000 / 250)) return;

    s_blanked = true;
    s_idle_ticks = 0;
    s_unlocked = false;
    s_pin_len = 0;
    s_state = TOTP_UI_PIN;
    totp_ui_switch(TOTP_UI_PIN);
    render_pin();
    ESP_LOGI(TAG, "无操作 %d 秒，自动息屏", IDLE_BLANK_SECONDS);
}

static void tick(lv_timer_t *timer)
{
    (void)timer;

    // 0. 锁屏期间只刷新锁定倒计时，不渲染码
    if (s_state == TOTP_UI_PIN) {
        render_pin();
        return;
    }

    // 1. 门户请求的后续动作（httpd 任务只置标志，这里落地）
    totp_portal_action_t act = totp_portal_take_action();
    if (act == TOTP_PORTAL_ACTION_WIFI_SYNC) {
        enqueue_cmd(TOTP_CMD_PORTAL_OFF);
        enqueue_cmd(TOTP_CMD_SYNC);
    } else if (act == TOTP_PORTAL_ACTION_DONE) {
        enqueue_cmd(TOTP_CMD_PORTAL_OFF);
    }

    // 2. 账户集合被门户改动 → 重载
    if (s_accounts_changed) {
        s_accounts_changed = false;
        reload_accounts();
    }

    // 3. 门户已停止 → 回列表
    if (s_state == TOTP_UI_PORTAL && !totp_portal_running()) {
        totp_ui_switch(TOTP_UI_LIST);
    }

    // 4. 首次使用：start() 已排队 PORTAL_ON，等它起来再切屏
    if (s_state == TOTP_UI_LIST && s_count == 0 && totp_portal_running()) {
        totp_ui_switch(TOTP_UI_PORTAL);
    }

    // 5. 息屏检测（tick 250ms 一次）
    check_idle_blank();

    render_status();
    switch (s_state) {
    case TOTP_UI_PIN:     render_pin(); break;
    case TOTP_UI_LIST:    render_list(); break;
    case TOTP_UI_DETAIL:  render_detail(); break;
    case TOTP_UI_PORTAL:  render_portal(); break;
    }
}

// ---------------------------------------------------------------- 按键
static void list_activate(void)
{
    if (totp_item_is_action(s_sel)) {
        int which = s_sel - (int)s_count;
        if (which == ACTION_ENROLL) {
            if (!totp_portal_running()) enqueue_cmd(TOTP_CMD_PORTAL_ON);
        } else if (which == ACTION_SYNC) {
            if (!s_sync_busy) enqueue_cmd(TOTP_CMD_SYNC);
        } else {   // ACTION_PIN
            s_pin_setup_mode = true;
            s_pin_len = 0;
            totp_ui_switch(TOTP_UI_PIN);
            render_pin();
        }
        return;
    }
    s_detail_idx = s_sel;
    totp_ui_switch(TOTP_UI_DETAIL);
    render_detail();
}

// PIN 屏按键：上/下改当前位数字，OK 前进一位（输满即提交）
static void pin_key(bsp_btn_t btn)
{
    if (btn == BSP_BTN_UP || btn == BSP_BTN_DOWN) {
        if (s_pin_len == 0) {
            s_pin_len = 1;             // 从未开始输，先落一位
            s_pin_input[0] = '0';
        }
        char *p = &s_pin_input[s_pin_len - 1];
        int delta = (btn == BSP_BTN_UP) ? 1 : 9;   // 上=+1，下=-1（mod 10）
        *p = (char)('0' + ((*p - '0') + delta) % 10);
        render_pin();
        return;
    }

    if (btn == BSP_BTN_OK) {
        if (s_pin_len == 0) {
            lv_label_set_text(s_pin_msg, "请先按上下选择数字");
            return;
        }
        if (s_pin_len < TOTP_PIN_MAX_DIGITS) {
            // 未输满：确认当前位，前进到下一位（默认 0）
            if (s_pin_len + 1 <= TOTP_PIN_MAX_DIGITS) {
                s_pin_input[s_pin_len] = '0';
                s_pin_len++;
                render_pin();
            }
            return;
        }
        // 输满 8 位 → 提交
        if (!pin_try_submit()) render_pin();
        else totp_ui_switch(TOTP_UI_LIST);
    }
}

void demo_totp_key(bsp_btn_t btn, bsp_btn_ev_t ev)
{
    // PIN 屏需要长按来「提前提交」：否则想设 4 位 PIN 也被迫输满 8 位。
    // main.c 只把 OK 的长当「返回菜单」，上/下的长按会原样送到 demo->key。
    if (s_state == TOTP_UI_PIN) {
        if (ev == BSP_BTN_LONG && (btn == BSP_BTN_UP || btn == BSP_BTN_DOWN)) {
            if (s_pin_len < TOTP_PIN_MIN_DIGITS) {
                lv_label_set_text(s_pin_msg, "至少 4 位");
                return;
            }
            if (!pin_try_submit()) render_pin();
            else totp_ui_switch(TOTP_UI_LIST);
            return;
        }
        if (ev != BSP_BTN_CLICK) return;
        s_idle_ticks = 0;
        pin_key(btn);
        return;
    }

    if (ev != BSP_BTN_CLICK) return;   // 长按由 main.c 统一返回菜单

    // 任何按键都算「有人在用」，重置息屏计时
    s_idle_ticks = 0;

    switch (s_state) {
    case TOTP_UI_LIST:
        if (btn == BSP_BTN_UP || btn == BSP_BTN_DOWN) {
            int n = totp_item_count();
            if (btn == BSP_BTN_UP) s_sel = (s_sel + n - 1) % n;
            else s_sel = (s_sel + 1) % n;
            if (!bsp_lvgl_lock(250)) return;
            render_list();
            bsp_lvgl_unlock();
        } else if (btn == BSP_BTN_OK) {
            if (!bsp_lvgl_lock(250)) return;
            list_activate();
            bsp_lvgl_unlock();
        }
        break;

    case TOTP_UI_DETAIL:
        if (btn == BSP_BTN_OK) {
            if (!bsp_lvgl_lock(250)) return;
            totp_ui_switch(TOTP_UI_LIST);
            render_list();
            bsp_lvgl_unlock();
        } else if ((btn == BSP_BTN_UP || btn == BSP_BTN_DOWN) && s_count > 0) {
            if (btn == BSP_BTN_UP) s_detail_idx = (s_detail_idx + s_count - 1) % s_count;
            else s_detail_idx = (s_detail_idx + 1) % s_count;
            if (!bsp_lvgl_lock(250)) return;
            render_detail();
            bsp_lvgl_unlock();
        }
        break;

    case TOTP_UI_PORTAL:
        if (btn == BSP_BTN_OK && totp_portal_running()) {
            enqueue_cmd(TOTP_CMD_PORTAL_OFF);
        }
        break;

    case TOTP_UI_PIN:
        break;   // 已在函数开头提前处理（需要长按提交）
    }
}

// ---------------------------------------------------------------- 生命周期
static lv_obj_t *make_text(lv_obj_t *parent, const lv_font_t *font,
                           uint32_t color, int x, int y, int w)
{
    lv_obj_t *lb = lv_label_create(parent);
    lv_obj_set_style_text_font(lb, font, 0);
    lv_obj_set_style_text_color(lb, lv_color_hex(color), 0);
    lv_obj_set_pos(lb, x, y);
    if (w > 0) {
        lv_obj_set_width(lb, w);
        lv_label_set_long_mode(lb, LV_LABEL_LONG_CLIP);
    }
    return lb;
}

void demo_totp_enter(void)
{
    s_scr = ui_pixel_screen_create("TOTP");

    // 标题牌下方的状态行（时间源 + 账户数）
    s_status = make_text(s_scr, &font_totp_16, UI_INK, 12, 46, 216);
    s_status_text[0] = '\0';

    // ---- 列表面板 ----
    s_panel_list = lv_obj_create(s_scr);
    lv_obj_remove_style_all(s_panel_list);
    lv_obj_set_size(s_panel_list, 240, 320);
    lv_obj_set_pos(s_panel_list, 0, 0);
    lv_obj_clear_flag(s_panel_list, LV_OBJ_FLAG_HIDDEN);

    for (int i = 0; i < ROW_VISIBLE; i++) {
        int y = LIST_TOP + i * (ROW_H + ROW_GAP);
        s_rows[i] = ui_pixel_panel_create(s_panel_list, 12, y, 216, ROW_H, UI_PAPER);
        s_row_name[i] = make_text(s_rows[i], &font_totp_16, UI_INK, 6, 2, 200);
        s_row_code[i] = make_text(s_rows[i], &lv_font_montserrat_20, UI_SKY_DARK, 6, 20, 200);
    }

    s_list_footer = make_text(s_panel_list, &font_totp_16, UI_INK, 12, 266, 216);

    // ---- 详情面板 ----
    s_panel_detail = lv_obj_create(s_scr);
    lv_obj_remove_style_all(s_panel_detail);
    lv_obj_set_size(s_panel_detail, 240, 320);
    lv_obj_set_pos(s_panel_detail, 0, 0);
    lv_obj_add_flag(s_panel_detail, LV_OBJ_FLAG_HIDDEN);

    s_d_name = make_text(s_panel_detail, &font_totp_16, UI_INK, 12, 52, 216);
    s_d_code = make_text(s_panel_detail, &font_totp_44, UI_INK, 12, 86, 216);
    s_d_secs = make_text(s_panel_detail, &font_totp_16, UI_SKY_DARK, 12, 146, 216);

    s_d_bar = lv_bar_create(s_panel_detail);
    lv_obj_set_size(s_d_bar, 216, 10);
    lv_obj_set_pos(s_d_bar, 12, 172);

    s_d_status = make_text(s_panel_detail, &font_totp_16, UI_INK, 12, 196, 216);
    s_d_footer = make_text(s_panel_detail, &font_totp_16, UI_INK, 12, 266, 216);
    lv_label_set_text(s_d_footer, "OK 返回 · 上下切换");

    // ---- 门户面板 ----
    s_panel_portal = lv_obj_create(s_scr);
    lv_obj_remove_style_all(s_panel_portal);
    lv_obj_set_size(s_panel_portal, 240, 320);
    lv_obj_set_pos(s_panel_portal, 0, 0);
    lv_obj_add_flag(s_panel_portal, LV_OBJ_FLAG_HIDDEN);

    for (int i = 0; i < 4; i++) {
        s_p_lines[i] = make_text(s_panel_portal, &font_totp_16, UI_INK, 12, 56 + i * 28, 216);
    }
    s_p_footer = make_text(s_panel_portal, &font_totp_16, UI_INK, 12, 266, 216);

    // ---- PIN 锁屏面板 ----
    s_panel_pin = lv_obj_create(s_scr);
    lv_obj_remove_style_all(s_panel_pin);
    lv_obj_set_size(s_panel_pin, 240, 320);
    lv_obj_set_pos(s_panel_pin, 0, 0);
    lv_obj_add_flag(s_panel_pin, LV_OBJ_FLAG_HIDDEN);

    s_pin_title = make_text(s_panel_pin, &font_totp_16, UI_INK, 12, 92, 216);
    s_pin_dots = make_text(s_panel_pin, &font_totp_44, UI_INK, 12, 128, 216);
    s_pin_msg = make_text(s_panel_pin, &font_totp_16, UI_RED, 12, 196, 216);
    s_pin_footer = make_text(s_panel_pin, &font_totp_16, UI_INK, 12, 266, 216);

    reload_accounts();
    // 载入 PIN 状态：已设 PIN 且本会话未解锁 → 先过锁屏
    totp_store_load_pin(&s_pin);
    s_pin_len = 0;
    s_pin_setup_mode = false;
    s_pin_has_first = false;
    s_pin_first[0] = '\0';
    s_idle_ticks = 0;
    s_blanked = false;
    s_unlocked = (s_pin.hash == 0);

    s_sel = 0;
    s_scroll = 0;
    s_detail_idx = 0;
    if (s_unlocked) {
        totp_ui_switch(TOTP_UI_LIST);
        render_status();
        render_list();
    } else {
        totp_ui_switch(TOTP_UI_PIN);
        render_pin();
    }

    s_timer = lv_timer_create(tick, 250, NULL);
    lv_screen_load(s_scr);
}

void demo_totp_exit(void)
{
    if (s_timer) {
        lv_timer_delete(s_timer);
        s_timer = NULL;
    }
    if (s_scr) {
        lv_obj_delete(s_scr);
        s_scr = NULL;
    }
    memset(s_rows, 0, sizeof(s_rows));
    memset(s_row_name, 0, sizeof(s_row_name));
    memset(s_row_code, 0, sizeof(s_row_code));
    memset(s_p_lines, 0, sizeof(s_p_lines));
    s_status = NULL;
    s_panel_list = s_panel_detail = s_panel_portal = NULL;
    s_panel_pin = NULL;
    s_pin_title = s_pin_dots = s_pin_msg = s_pin_footer = NULL;
    s_list_footer = s_d_name = s_d_code = s_d_secs = s_d_bar = s_d_status = NULL;
    s_d_footer = s_p_footer = NULL;
    s_timer = NULL;
}

esp_err_t demo_totp_start(void)
{
    totp_time_bootstrap();
    totp_portal_set_change_cb(on_accounts_changed);
    worker_ensure_started();

    if (s_count == 0) {
        // 首次使用：直接开门户，屏幕交给 tick 切换
        enqueue_cmd(TOTP_CMD_PORTAL_ON);
    } else {
        char ssid[33] = { 0 }, pass[65] = { 0 };
        bool has = false;
        if (totp_store_load_wifi(ssid, sizeof(ssid), pass, sizeof(pass), &has) == ESP_OK && has) {
            enqueue_cmd(TOTP_CMD_SYNC);   // 开机静默校时
        }
    }
    ESP_LOGI(TAG, "TOTP 页启动：%u 个账户，时间源=%s",
             (unsigned)s_count, totp_time_status_text(totp_time_status()));
    return ESP_OK;
}

esp_err_t demo_totp_stop(void)
{
    // worker 常驻不销毁；只确保门户与 Wi-Fi 收起来（异步，worker 执行）。
    if (totp_portal_running()) {
        enqueue_cmd(TOTP_CMD_PORTAL_OFF);
    }
    return ESP_OK;
}
