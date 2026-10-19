/* link_shims.c —— 本机（Windows/zig cc）跑 demo runtime host 测试用的链接垫片。
 *
 * 为什么需要它:
 *   tools/validate.sh 的 demo runtime 测试依赖 `-Wl,--gc-sections` 把
 *   demo_audio_enter / demo_low_power_enter 这类**测试从不调用**的界面函数
 *   连同其 LVGL 引用一起丢掉。GNU ld（CI 用的 gcc）确实会丢；
 *   zig cc 背后的 lld-link（COFF/PE）在本机不接受 /gc 与 -gc，
 *   --gc-sections 也不生效，于是这些死路径上的符号全部变成未定义引用。
 *
 * 等价性:
 *   下面这些函数在对应测试里都不可达（测试只测 worker 生命周期/状态机），
 *   补空实现与「节回收把它们丢掉」对测试断言毫无区别。桩里已定义的那些
 *   （lv_label_set_text / ui_pixel_mascot_jump / lv_obj_set_selected 等）
 *   仍然优先生效，本文件只补缺失的那批。
 *
 * 作用域: 仅由 tools/run_host_tests.sh 传入命令行，不参与固件构建，
 *         也不改动 tests/demo_stubs/ 下的任何桩文件。
 */
#include "demo_test_stubs.h"
#include "ui_pixel.h"

uint32_t lv_color_hex(uint32_t color) { return color; }
lv_obj_t *lv_obj_create(lv_obj_t *parent) { (void)parent; static lv_obj_t o; return &o; }
lv_obj_t *lv_label_create(lv_obj_t *parent) { (void)parent; static lv_obj_t o; return &o; }
void lv_obj_set_size(lv_obj_t *object, int width, int height) { (void)object; (void)width; (void)height; }
void lv_obj_set_width(lv_obj_t *object, int width) { (void)object; (void)width; }
void lv_obj_set_style_radius(lv_obj_t *object, int radius, int selector) { (void)object; (void)radius; (void)selector; }
void lv_obj_set_style_bg_color(lv_obj_t *object, uint32_t color, int selector) { (void)object; (void)color; (void)selector; }
void lv_obj_set_style_border_width(lv_obj_t *object, int width, int selector) { (void)object; (void)width; (void)selector; }
void lv_obj_set_style_text_color(lv_obj_t *object, uint32_t color, int selector) { (void)object; (void)color; (void)selector; }
void lv_obj_set_style_text_align(lv_obj_t *object, int align, int selector) { (void)object; (void)align; (void)selector; }
void lv_obj_set_style_text_font(lv_obj_t *object, const lv_font_t *font, int selector) { (void)object; (void)font; (void)selector; }
void lv_obj_center(lv_obj_t *object) { (void)object; }
void lv_obj_align(lv_obj_t *object, int align, int x, int y) { (void)object; (void)align; (void)x; (void)y; }
void lv_obj_delete(lv_obj_t *object) { (void)object; }
void lv_label_set_long_mode(lv_obj_t *object, int mode) { (void)object; (void)mode; }
void lv_label_set_text_fmt(lv_obj_t *object, const char *format, ...) { (void)object; (void)format; }
void lv_screen_load(lv_obj_t *screen) { (void)screen; }
lv_timer_t *lv_timer_create(void (*callback)(lv_timer_t *), unsigned period, void *data) {
    (void)callback; (void)period; (void)data; return NULL;
}
void lv_timer_delete(lv_timer_t *timer) { (void)timer; }

lv_obj_t *ui_pixel_screen_create(const char *title) { (void)title; static lv_obj_t o; return &o; }
lv_obj_t *ui_pixel_panel_create(lv_obj_t *parent, int x, int y, int w, int h, uint32_t color) {
    (void)parent; (void)x; (void)y; (void)w; (void)h; (void)color; static lv_obj_t o; return &o;
}
lv_obj_t *ui_pixel_mascot_create(lv_obj_t *parent, int x, int y) {
    (void)parent; (void)x; (void)y; static lv_obj_t o; return &o;
}

int esp_sleep_get_wakeup_cause(void) { return 0; }
esp_err_t esp_wifi_scan_get_ap_num(uint16_t *count) { if (count) *count = 0; return ESP_OK; }
esp_err_t esp_wifi_scan_get_ap_records(uint16_t *count, wifi_ap_record_t *records) {
    (void)count; (void)records; return ESP_OK;
}