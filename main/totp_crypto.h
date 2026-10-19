// main/totp_crypto.h —— 加密备份的纯逻辑层（只用 C 标准库，host 可测）。
//
// 用途：用户自设备份口令，把全部账户导出成 AES-256-CBC 密文 JSON。
// 威胁模型：防「备份文件明文被人看到 / 设备丢了备份文件落到别人手里」。
// 不防设备本体的物理拆解（见 totp_pin.h 的说明）。
//
// 为什么自己写 AES 而不是用 mbedtls：mbedtls 在 ESP-IDF 里当然有，但把它
// 拉进 host tests 需要整套 ESP-IDF 依赖栈，破坏「模型层与 IDF 解耦」的约定。
// AES-256 加密约 200 行，且用 NIST SP 800-38A 官方向量在 host 侧锁死正确性。
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TOTP_AES_BLOCK      16
#define TOTP_AES_KEY_LEN    32      // AES-256
#define TOTP_AES_IV_LEN     16
#define TOTP_BACKUP_SALT_LEN 16
#define TOTP_PBKDF2_MAX_SALT 64     // PBKDF2 输入盐上限（栈缓冲）

// PBKDF2-HMAC-SHA256 派生密钥。iterations 建议 >= 10000。
// ok_len 必须 <= 64。
bool totp_pbkdf2_sha256(const char *pass, const uint8_t *salt, size_t salt_len,
                        uint32_t iterations, uint8_t *out, size_t out_len);

// AES-256-CBC 加密。in_len 必须是 16 的倍数（调用方负责 PKCS#7 填充）。
// iv 会被复制进 ctx，不会被修改。返回写入 out 的字节数；失败返回 0。
size_t totp_aes256_cbc_encrypt(const uint8_t key[TOTP_AES_KEY_LEN],
                               const uint8_t iv[TOTP_AES_IV_LEN],
                               const uint8_t *in, size_t in_len,
                               uint8_t *out);

// AES-256-CBC 解密（用于 host 往返验证；设备端导出不需要）。
size_t totp_aes256_cbc_decrypt(const uint8_t key[TOTP_AES_KEY_LEN],
                               const uint8_t iv[TOTP_AES_IV_LEN],
                               const uint8_t *in, size_t in_len,
                               uint8_t *out);

// PKCS#7 填充。就地填充 src，返回填充后总长度（含 padding）。
// out_cap 不够时返回 0（不写入）。
size_t totp_pkcs7_pad(const uint8_t *src, size_t src_len,
                      uint8_t *out, size_t out_cap);
// 去 padding。填充非法（长度非 16 倍数或 padding 值越界）返回 -1。
int totp_pkcs7_unpad(const uint8_t *src, size_t src_len, uint8_t *out);

// 生成随机字节（设备端走 esp_random，host 测试走 /dev/urandom 或 rand）。
void totp_random_bytes(uint8_t *out, size_t len);

#ifdef __cplusplus
}
#endif