// main/totp_portal.c —— SoftAP + HTTP 录入门户实现。
// 路由：GET / ｜ POST /add（otpauth URI，可多行批量）｜ POST /del ｜ POST /wifi
//       GET /export（明文 otpauth 导出）｜ POST /backup（PBKDF2+AES 加密备份）
//       POST /done
// 说明：HTTP 处理器只改 NVS 与置动作标志；Wi-Fi 栈切换由 UI 层执行（避免与门户 AP 争栈）。
#include "totp_portal.h"
#include "totp_crypto.h"
#include "totp_model.h"
#include "totp_store.h"

#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "nvs_flash.h"

#include "esp_http_server.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *TAG = "totp_portal";

static httpd_handle_t s_server;
static esp_netif_t *s_ap_netif;
static totp_portal_change_cb_t s_change_cb;
static volatile totp_portal_action_t s_pending_action;

// ---------------------------------------------------------------- 小工具
// 大小写不敏感比较（避免 POSIX strcasecmp，保持 -std=c11 纯净）。
static bool ci_eq(const char *a, const char *b)
{
    while (*a && *b) {
        char ca = *a, cb = *b;
        if (ca >= 'a' && ca <= 'z') ca = (char)(ca - 'a' + 'A');
        if (cb >= 'a' && cb <= 'z') cb = (char)(cb - 'a' + 'A');
        if (ca != cb) return false;
        a++; b++;
    }
    return *a == '\0' && *b == '\0';
}

// URL 解码到 dst（%XX 与 '+' → 空格）。
static void url_decode_to(const char *src, char *dst, size_t cap)
{
    size_t w = 0;
    for (const char *p = src; *p && w + 1 < cap; p++) {
        if (*p == '%' && p[1] && p[2]) {
            char hex[3] = { p[1], p[2], 0 };
            dst[w++] = (char)strtol(hex, NULL, 16);
            p += 2;
        } else if (*p == '+') {
            dst[w++] = ' ';
        } else {
            dst[w++] = *p;
        }
    }
    dst[w] = '\0';
}

// 从 application/x-www-form-urlencoded 里取指定字段（大小写不敏感）。
static bool form_field(const char *body, const char *key, char *out, size_t cap)
{
    size_t klen = strlen(key);
    const char *p = body;
    while (*p) {
        const char *amp = strchr(p, '&');
        size_t seg_len = amp ? (size_t)(amp - p) : strlen(p);
        const char *eq = memchr(p, '=', seg_len);
        if (eq && (size_t)(eq - p) == klen && klen < 32) {
            char kbuf[32];
            memcpy(kbuf, p, klen);
            kbuf[klen] = '\0';
            if (ci_eq(kbuf, key)) {
                char tmp[1024];
                size_t seg = seg_len - klen - 1;
                if (seg >= sizeof(tmp)) seg = sizeof(tmp) - 1;
                memcpy(tmp, eq + 1, seg);
                tmp[seg] = '\0';
                url_decode_to(tmp, out, cap);
                return true;
            }
        }
        if (!amp) break;
        p = amp + 1;
    }
    return false;
}

// 读取 POST body 到 buf（超长截断）。返回长度，失败 -1。
static int read_body(httpd_req_t *req, char *buf, size_t cap)
{
    size_t total = req->content_len;
    if (total >= cap) total = cap - 1;
    size_t got = 0;
    while (got < total) {
        int r = httpd_req_recv(req, buf + got, total - got);
        if (r <= 0) break;
        got += (size_t)r;
    }
    buf[got] = '\0';
    return (int)got;
}

// ---------------------------------------------------------------- 页面渲染
static const char *INDEX_HTML =
"<!DOCTYPE html><html lang=zh-CN><head><meta charset=utf-8>"
"<meta name=viewport content='width=device-width,initial-scale=1'>"
"<title>TotpPassport 录入</title><style>"
"body{font-family:-apple-system,sans-serif;margin:16px;background:#f4f4ea;color:#17202a}"
"h1{font-size:20px;margin:0 0 4px}h2{font-size:16px}"
"label{display:block;margin:12px 0 4px;font-weight:600}"
"textarea,input{width:100%;box-sizing:border-box;padding:8px;font-size:14px;"
"border:1px solid #ccc;border-radius:6px;font-family:monospace}"
"button{margin-top:10px;padding:10px 18px;font-size:15px;border:0;border-radius:6px;"
"background:#1689e8;color:#fff;width:100%}.gray{background:#8a97a3}"
".acc{background:#fff;border:1px solid #ddd;border-radius:6px;padding:8px;margin:6px 0;"
"display:flex;justify-content:space-between;align-items:center;gap:8px}"
".acc form{margin:0}.acc button{width:auto;margin:0;padding:4px 12px;font-size:13px;"
"background:#e43b2f}"
".tip{font-size:12px;color:#5a6b78;margin:4px 0}"
"</style></head><body>"
"<h1>TotpPassport</h1>"
"<p class=tip>粘贴各网站「两步验证」设置页给出的 otpauth:// 链接，一行一个。</p>"
"<form method=post action=/add>"
"<label>otpauth 链接</label>"
"<textarea name=uri rows=4 placeholder='otpauth://totp/GitHub:me?secret=...'></textarea>"
"<button type=submit>添加账户</button></form>"
"<h2>已录入 %d 个</h2>%s"
"<form method=post action=/wifi>"
"<label>家庭 Wi-Fi（用于自动校时）</label>"
"<input name=ssid placeholder='SSID'>"
"<input name=pass type=password placeholder='密码' style='margin-top:6px'>"
"<button type=submit>保存并校时</button></form>"
"<h2>导出与备份</h2>"
"<p class=tip>导出是明文 otpauth 链接，请立刻转存；加密备份需自设口令。</p>"
"<a href=/export><button type=button>导出全部账户（明文）</button></a>"
"<form method=post action=/backup style='margin-top:10px'>"
"<label>备份口令（用于加密，丢失无法恢复）</label>"
"<input name=pass type=password placeholder='自设备份口令'>"
"<button type=submit>下载加密备份</button></form>"
"<form method=post action=/done><button type=submit class=gray>完成，返回设备</button></form>"
"</body></html>";

// 账户列表片段（服务端渲染，含内联删除表单）
static void build_account_rows(char *out, size_t cap)
{
    totp_account_t accs[TOTP_MAX_ACCOUNTS];
    uint8_t count = 0;
    size_t used = 0;
    out[0] = '\0';
    if (totp_store_load_accounts(accs, &count) != ESP_OK) return;

    for (uint8_t i = 0; i < count; i++) {
        char shown[80];
        strncpy(shown, accs[i].name, sizeof(shown) - 1);
        shown[sizeof(shown) - 1] = '\0';
        totp_normalize_display(shown);   // 中文渲染成 ·，避免页面乱码

        char row[320];
        int w = snprintf(row, sizeof(row),
                         "<div class=acc><span>%s%s%s</span>"
                         "<form method=post action=/del>"
                         "<input type=hidden name=index value='%u'>"
                         "<button type=submit>删除</button></form></div>",
                         accs[i].issuer[0] ? accs[i].issuer : "",
                         accs[i].issuer[0] ? " · " : "",
                         shown, (unsigned)i);
        if (w < 0 || (size_t)w >= cap - used) break;
        memcpy(out + used, row, (size_t)w);
        used += (size_t)w;
        out[used] = '\0';
    }
}

static esp_err_t send_index(httpd_req_t *req)
{
    static char rows[3072];
    static char page[4600];
    build_account_rows(rows, sizeof(rows));

    totp_account_t accs[TOTP_MAX_ACCOUNTS];
    uint8_t count = 0;
    totp_store_load_accounts(accs, &count);

    int n = snprintf(page, sizeof(page), INDEX_HTML, (int)count, rows);
    if (n < 0 || (size_t)n >= sizeof(page)) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_send(req, page, n);
    return ESP_OK;
}

// ---------------------------------------------------------------- 处理器
static esp_err_t h_index(httpd_req_t *req) { return send_index(req); }

static esp_err_t h_add(httpd_req_t *req)
{
    static char body[2048];
    if (read_body(req, body, sizeof(body)) < 0) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    char uri[1200];
    if (!form_field(body, "uri", uri, sizeof(uri)) || uri[0] == '\0') {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing uri");
        return ESP_FAIL;
    }

    // 逐行解析（一行一个 otpauth URI），单行失败不影响其余
    totp_account_t accs[TOTP_MAX_ACCOUNTS];
    uint8_t count = 0;
    if (totp_store_load_accounts(accs, &count) != ESP_OK) count = 0;

    int added = 0;
    char *p = uri;
    while (*p && count < TOTP_MAX_ACCOUNTS) {
        char *eol = strpbrk(p, "\r\n");
        size_t len = eol ? (size_t)(eol - p) : strlen(p);
        char line[512];
        if (len >= sizeof(line)) len = sizeof(line) - 1;
        memcpy(line, p, len);
        line[len] = '\0';

        // 去前导空白
        char *lp = line;
        while (*lp == ' ' || *lp == '\t') lp++;
        if (strncmp(lp, "otpauth://", 10) == 0) {
            totp_account_t acc;
            if (totp_parse_uri(lp, &acc)) {
                accs[count++] = acc;
                added++;
            }
        }
        if (!eol) break;
        p = eol + 1;
    }

    if (added > 0) {
        esp_err_t err = totp_store_save_accounts(accs, count);
        if (err == ESP_OK) {
            if (s_change_cb) s_change_cb();
            ESP_LOGI(TAG, "门户添加 %d 个账户（共 %u）", added, count);
        } else {
            ESP_LOGE(TAG, "保存失败: %s", esp_err_to_name(err));
        }
    }

    httpd_resp_set_status(req, "303 See Other");   // PRG：避免刷新重复提交
    httpd_resp_set_hdr(req, "Location", "/");
    httpd_resp_send(req, NULL, 0);
    return ESP_OK;
}

static esp_err_t h_del(httpd_req_t *req)
{
    static char body[256];
    if (read_body(req, body, sizeof(body)) < 0) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }
    char idx_s[16];
    if (!form_field(body, "index", idx_s, sizeof(idx_s))) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing index");
        return ESP_FAIL;
    }
    int idx = atoi(idx_s);

    totp_account_t accs[TOTP_MAX_ACCOUNTS];
    uint8_t count = 0;
    if (totp_store_load_accounts(accs, &count) == ESP_OK &&
        idx >= 0 && idx < (int)count) {
        for (int i = idx; i < (int)count - 1; i++) accs[i] = accs[i + 1];
        count--;
        if (totp_store_save_accounts(accs, count) == ESP_OK) {
            if (s_change_cb) s_change_cb();
            ESP_LOGI(TAG, "门户删除账户 #%d（剩 %u）", idx, count);
        }
    }

    httpd_resp_set_status(req, "303 See Other");
    httpd_resp_set_hdr(req, "Location", "/");
    httpd_resp_send(req, NULL, 0);
    return ESP_OK;
}

static esp_err_t h_wifi(httpd_req_t *req)
{
    static char body[512];
    if (read_body(req, body, sizeof(body)) < 0) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }
    char ssid[33] = { 0 }, pass[65] = { 0 };
    if (!form_field(body, "ssid", ssid, sizeof(ssid)) || ssid[0] == '\0') {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing ssid");
        return ESP_FAIL;
    }
    form_field(body, "pass", pass, sizeof(pass));

    if (totp_store_save_wifi(ssid, pass) == ESP_OK) {
        ESP_LOGI(TAG, "门户保存 Wi-Fi %s，请求校时", ssid);
        s_pending_action = TOTP_PORTAL_ACTION_WIFI_SYNC;
    }
    httpd_resp_set_status(req, "303 See Other");
    httpd_resp_set_hdr(req, "Location", "/");
    httpd_resp_send(req, NULL, 0);
    return ESP_OK;
}

// ---------------------------------------------------------------- 导出与备份
// 把账户序列化成 otpauth URI 列表（导入端可直接再解析回设备）。
static size_t build_otpauth_list(char *out, size_t cap)
{
    totp_account_t accs[TOTP_MAX_ACCOUNTS];
    uint8_t count = 0;
    size_t used = 0;
    out[0] = '\0';
    if (totp_store_load_accounts(accs, &count) != ESP_OK) return 0;

    static const char *ALG[] = { "SHA1", "SHA256", "SHA512" };

    for (uint8_t i = 0; i < count; i++) {
        // secret 需 base32 编码回文本；显示用的 name 可能是中文，但
        // otpauth 的 label 允许 UTF-8 百分号编码之外的原样字符，
        // 这里原样输出（导入方按 URL 解码）。
        char b32[136];
        int b32len = totp_base32_encode(accs[i].secret, accs[i].secret_len,
                                   b32, sizeof(b32));
        if (b32len <= 0) continue;

        char row[420];
        const char *alg = (accs[i].alg <= TOTP_ALG_SHA512)
                              ? ALG[accs[i].alg] : "SHA1";
        int w = snprintf(row, sizeof(row),
                         "otpauth://totp/%s%s%s?secret=%s&issuer=%s"
                         "&algorithm=%s&digits=%u&period=%u\n",
                         accs[i].issuer[0] ? accs[i].issuer : "",
                         accs[i].issuer[0] ? ":" : "",
                         accs[i].name[0] ? accs[i].name : "account",
                         b32, accs[i].issuer[0] ? accs[i].issuer : "TotpPassport",
                         alg, (unsigned)accs[i].digits, (unsigned)accs[i].period);
        if (w < 0 || (size_t)w >= sizeof(row) || used + (size_t)w >= cap) break;
        memcpy(out + used, row, (size_t)w);
        used += (size_t)w;
        out[used] = '\0';
    }
    return used;
}

static esp_err_t h_export(httpd_req_t *req)
{
    static char buf[6144];
    size_t n = build_otpauth_list(buf, sizeof(buf));
    httpd_resp_set_type(req, "text/plain; charset=utf-8");
    httpd_resp_set_hdr(req, "Content-Disposition",
                       "attachment; filename=folotoy-totp.txt");
    httpd_resp_send(req, buf, n);
    return ESP_OK;
}

// 加密备份：用户口令 → PBKDF2 派生 AES-256 密钥 → 密文下载。
// 备份里带 salt 与 IV，导入端靠用户口令重算密钥即可解密。
static esp_err_t h_backup(httpd_req_t *req)
{
    static char body[256];
    if (read_body(req, body, sizeof(body)) < 0) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }
    char pass[129] = { 0 };
    if (!form_field(body, "pass", pass, sizeof(pass)) || pass[0] == '\0') {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing pass");
        return ESP_FAIL;
    }

    totp_account_t accs[TOTP_MAX_ACCOUNTS];
    uint8_t count = 0;
    if (totp_store_load_accounts(accs, &count) != ESP_OK) count = 0;

    char json[4608];
    size_t jlen = 0;
    jlen += (size_t)snprintf(json + jlen, sizeof(json) - jlen,
                             "{\"v\":1,\"accounts\":[");
    static const char *ALG[] = { "SHA1", "SHA256", "SHA512" };
    for (uint8_t i = 0; i < count && jlen < sizeof(json) - 400; i++) {
        char b32[136];
        if (totp_base32_encode(accs[i].secret, accs[i].secret_len, b32, sizeof(b32)) <= 0) {
            continue;
        }
        jlen += (size_t)snprintf(json + jlen, sizeof(json) - jlen,
                                 "%s{\"name\":\"%s\",\"issuer\":\"%s\",\"secret\":\"%s\","
                                 "\"algorithm\":\"%s\",\"digits\":%u,\"period\":%u}",
                                 i ? "," : "", accs[i].name, accs[i].issuer, b32,
                                 (accs[i].alg <= TOTP_ALG_SHA512) ? ALG[accs[i].alg] : "SHA1",
                                 (unsigned)accs[i].digits, (unsigned)accs[i].period);
    }
    jlen += (size_t)snprintf(json + jlen, sizeof(json) - jlen, "]}");

    uint8_t salt[TOTP_BACKUP_SALT_LEN], iv[TOTP_AES_IV_LEN];
    totp_random_bytes(salt, sizeof(salt));
    totp_random_bytes(iv, sizeof(iv));

    uint8_t key[TOTP_AES_KEY_LEN];
    if (!totp_pbkdf2_sha256(pass, salt, sizeof(salt), 4096, key, sizeof(key))) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "pbkdf2 failed");
        return ESP_FAIL;
    }

    uint8_t padded[4608];
    size_t plen = totp_pkcs7_pad((const uint8_t *)json, jlen, padded, sizeof(padded));
    if (plen == 0) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "pad failed");
        return ESP_FAIL;
    }

    uint8_t ct[4608];
    size_t ctlen = totp_aes256_cbc_encrypt(key, iv, padded, plen, ct);
    if (ctlen == 0) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "encrypt failed");
        return ESP_FAIL;
    }

    // 头部：明文放 salt(16) + iv(16) + 密文长度(4B 大端)，便于导入端定位
    uint8_t packet[16 + 16 + 4 + 4608];
    memcpy(packet, salt, sizeof(salt));
    memcpy(packet + 16, iv, sizeof(iv));
    packet[32] = (uint8_t)(ctlen >> 24);
    packet[33] = (uint8_t)(ctlen >> 16);
    packet[34] = (uint8_t)(ctlen >> 8);
    packet[35] = (uint8_t)(ctlen);
    memcpy(packet + 36, ct, ctlen);
    size_t plen_total = 36 + ctlen;

    httpd_resp_set_type(req, "application/octet-stream");
    httpd_resp_set_hdr(req, "Content-Disposition",
                       "attachment; filename=folotoy-totp.backup");
    httpd_resp_send(req, (const char *)packet, plen_total);
    ESP_LOGI(TAG, "已导出加密备份 %u 字节（PBKDF2 4096 轮 + AES-256-CBC）",
             (unsigned)plen_total);
    return ESP_OK;
}

static esp_err_t h_done(httpd_req_t *req)
{
    s_pending_action = TOTP_PORTAL_ACTION_DONE;
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_sendstr(req, "<meta charset=utf-8><body style='font-family:sans-serif;"
                             "text-align:center;padding-top:40px'>"
                             "已保存，可以回到设备操作了。</body>");
    return ESP_OK;
}

// ---------------------------------------------------------------- 生命周期
esp_err_t totp_portal_start(void)
{
    if (s_server) return ESP_ERR_INVALID_STATE;

    if (nvs_flash_init() != ESP_OK) return ESP_FAIL;
    if (esp_netif_init() != ESP_OK) return ESP_FAIL;
    if (esp_event_loop_create_default() != ESP_OK) return ESP_FAIL;

    s_ap_netif = esp_netif_create_default_wifi_ap();
    if (!s_ap_netif) return ESP_FAIL;

    wifi_init_config_t wcfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_err_t err = esp_wifi_init(&wcfg);
    if (err != ESP_OK) return err;

    wifi_config_t cfg = { 0 };
    strncpy((char *)cfg.ap.ssid, TOTP_PORTAL_SSID, sizeof(cfg.ap.ssid) - 1);
    cfg.ap.ssid_len = (uint8_t)strlen(TOTP_PORTAL_SSID);
    cfg.ap.max_connection = 2;
    cfg.ap.authmode = WIFI_AUTH_OPEN;

    err = esp_wifi_set_mode(WIFI_MODE_AP);
    if (err != ESP_OK) return err;
    err = esp_wifi_set_config(WIFI_IF_AP, &cfg);
    if (err != ESP_OK) return err;
    err = esp_wifi_start();
    if (err != ESP_OK) return err;

    httpd_config_t hcfg = HTTPD_DEFAULT_CONFIG();
    hcfg.lru_purge_enable = true;
    err = httpd_start(&s_server, &hcfg);
    if (err != ESP_OK) return err;

    static const httpd_uri_t uris[] = {
        { .uri = "/",     .method = HTTP_GET,  .handler = h_index },
        { .uri = "/add",  .method = HTTP_POST, .handler = h_add },
        { .uri = "/del",  .method = HTTP_POST, .handler = h_del },
        { .uri = "/wifi", .method = HTTP_POST, .handler = h_wifi },
        { .uri = "/export", .method = HTTP_GET,  .handler = h_export },
        { .uri = "/backup", .method = HTTP_POST, .handler = h_backup },
        { .uri = "/done", .method = HTTP_POST, .handler = h_done },
    };
    for (size_t i = 0; i < sizeof(uris) / sizeof(uris[0]); i++) {
        err = httpd_register_uri_handler(s_server, &uris[i]);
        if (err != ESP_OK) return err;
    }

    s_pending_action = TOTP_PORTAL_ACTION_NONE;
    ESP_LOGI(TAG, "门户已启动：连 Wi-Fi %s 打开 http://%s", TOTP_PORTAL_SSID, TOTP_PORTAL_IP);
    return ESP_OK;
}

esp_err_t totp_portal_stop(void)
{
    if (!s_server) return ESP_ERR_INVALID_STATE;
    httpd_stop(s_server);
    s_server = NULL;

    esp_wifi_stop();
    esp_wifi_deinit();
    if (s_ap_netif) {
        esp_wifi_clear_default_wifi_driver_and_handlers(s_ap_netif);
        esp_netif_destroy_default_wifi(s_ap_netif);
        s_ap_netif = NULL;
    }
    ESP_LOGI(TAG, "门户已停止");
    return ESP_OK;
}

bool totp_portal_running(void) { return s_server != NULL; }

totp_portal_action_t totp_portal_take_action(void)
{
    totp_portal_action_t a = s_pending_action;
    s_pending_action = TOTP_PORTAL_ACTION_NONE;
    return a;
}

void totp_portal_set_change_cb(totp_portal_change_cb_t cb) { s_change_cb = cb; }
