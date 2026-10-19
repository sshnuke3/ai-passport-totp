// main/totp_model.h —— TOTP 玩法的纯逻辑层。
// 与 ESP-IDF / LVGL 完全解耦（只用 C 标准库），便于 host tests 覆盖。
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TOTP_MAX_ACCOUNTS 24
#define TOTP_SECRET_MAX   64    // 解码后密钥字节数上限（RFC 6238 SHA-512 向量 64B；base32 103 字符）
#define TOTP_NAME_MAX     33    // 账户标签（UTF-8，含 '\0'）
#define TOTP_ISSUER_MAX   33

typedef enum {
    TOTP_ALG_SHA1 = 0,
    TOTP_ALG_SHA256,
    TOTP_ALG_SHA512,
} totp_alg_t;

typedef struct {
    char     name[TOTP_NAME_MAX];     // 账户标签，如 "john@example.com"
    char     issuer[TOTP_ISSUER_MAX]; // 发行方，如 "GitHub"
    uint8_t  secret[TOTP_SECRET_MAX]; // base32 解码后的密钥
    uint8_t  secret_len;
    uint8_t  digits;                  // 6 或 8（解析宽松时 6..10）
    uint8_t  period;                  // 秒，常见 30/60
    uint8_t  alg;                     // totp_alg_t
    uint8_t  used;                    // 槽位占用标志
} totp_account_t;

// ---- base32（RFC 4648，无填充）----
// 成功返回解码字节数（0 表示空串）；失败返回 -1。
int totp_base32_decode(const char *b32, uint8_t *out, size_t out_cap);
// 编码（decode 的逆运算，导出/备份用）。成功返回写入的字符数（不含 '\0'）；
// 空间不足返回 -1。
int totp_base32_encode(const uint8_t *in, size_t in_len, char *out, size_t out_cap);

// ---- TOTP（RFC 6238）----
// 把 t 秒时刻的码写入 out（ASCII 数字 + '\0'）。out_cap 至少 digits+1。
void totp_code(const totp_account_t *acc, time_t t, char *out, size_t out_cap);

// 距下次刷新的剩余秒数（1..period）。
uint32_t totp_remaining(time_t t, uint8_t period);

// ---- otpauth URI 解析 ----
// otpauth://totp/Label?secret=...&issuer=...&algorithm=...&digits=...&period=...
// Label 支持 "Issuer:account" 与 "account" 两种形式；query 参数缺失时用默认值。
// 成功填满 acc（含 used=1）并返回 true。
bool totp_parse_uri(const char *uri, totp_account_t *acc);

// ---- HMAC（供 totp_crypto 的 PBKDF2 复用，避免第二份 SHA-256 实现）----
void totp_hmac_sha256(const uint8_t *key, size_t key_len,
                      const uint8_t *msg, size_t msg_len,
                      uint8_t out[32]);

// ---- 显示名归一化 ----
// 运行期数据（用户录入的账户名）可能含中文，设备字库不覆盖。
// 把 UTF-8 非 ASCII 序列整体替换为 "·"（0xC2 0xB7），ASCII 原样保留。
void totp_normalize_display(char *s);

// ---- NVS blob 序列化（紧凑、版本化、显式字段，不依赖结构体 padding）----
// 返回写入字节数；空间不足返回 0。
size_t totp_serialize(const totp_account_t *accounts, uint8_t count,
                      uint8_t *out, size_t out_cap);
// 成功返回账户数；格式错误返回 -1。
int totp_deserialize(const uint8_t *blob, size_t len,
                     totp_account_t *accounts, uint8_t *count);

#ifdef __cplusplus
}
#endif
