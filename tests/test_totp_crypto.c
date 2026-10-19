// tests/test_totp_crypto.c —— AES-256-CBC / PBKDF2 / PKCS#7 的 host 测试。
//
// 正确性锚点：
//   AES  —— FIPS-197 Appendix C.3（AES-256 单块 ECB 官方答案）
//   CBC  —— NIST SP 800-38A F.2.5（AES-256-CBC 前三块官方密文）
//   PBKDF2 —— Python hashlib.pbkdf2_hmac('sha256', ...) 交叉验证
//   填充  —— 往返 + 非法填充必须被拒
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "totp_crypto.h"

static void hexdump(const char *label, const uint8_t *p, size_t n)
{
    printf("%s", label);
    for (size_t i = 0; i < n; i++) printf(" %02x", p[i]);
    printf("\n");
}

static int hexeq(const uint8_t *got, const char *want_hex, size_t n)
{
    static const char *H = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        int hi = (unsigned char)((want_hex[i * 2] <= '9') ? want_hex[i * 2] - '0' : want_hex[i * 2] - 'a' + 10);
        int lo = (unsigned char)((want_hex[i * 2 + 1] <= '9') ? want_hex[i * 2 + 1] - '0' : want_hex[i * 2 + 1] - 'a' + 10);
        if (got[i] != (uint8_t)((hi << 4) | lo)) return 0;
    }
    (void)H;
    return 1;
}

// FIPS-197 C.3：AES-256 单块
static void test_aes256_ecb_fips(void)
{
    uint8_t key[32], pt[16], ct[16];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
    for (int i = 0; i < 16; i++) pt[i] = (uint8_t)(0x00 + i * 0x11);

    // ECB 模式 = IV 全 0 的单块 CBC
    uint8_t zero_iv[16] = { 0 };
    size_t n = totp_aes256_cbc_encrypt(key, zero_iv, pt, 16, ct);
    assert(n == 16);
    if (!hexeq(ct, "8ea2b7ca516745bfeafc49904b496089", 16)) {
        hexdump("FIPS-197 got: ", ct, 16);
        assert(0);
    }
    puts("AES-256 ECB (FIPS-197 C.3): PASS");
}

// NIST SP 800-38A F.2.5：AES-256-CBC 前三块
// 官方向量用 key=603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4、
// iv=000102030405060708090a0b0c0d0e0f。已用 openssl enc -aes-256-cbc 独立核对过。
static void test_aes256_cbc_nist(void)
{
    static const uint8_t KEY[32] = {
        0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
        0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4,
    };
    uint8_t iv[16], pt[48], ct[48];
    for (int i = 0; i < 16; i++) iv[i] = (uint8_t)i;
    // F.2.5 plaintext
    static const uint8_t P[48] = {
        0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
        0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,
        0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,
    };
    memcpy(pt, P, sizeof(pt));

    size_t n = totp_aes256_cbc_encrypt(KEY, iv, pt, 48, ct);
    assert(n == 48);
    if (!hexeq(ct, "f58c4c04d6e5f1ba779eabfb5f7bfbd6"
                   "9cfc4e967edb808d679f777bc6702c7d"
                   "39f23369a9d9bacfa530e26304231461", 48)) {
        hexdump("NIST got: ", ct, 48);
        assert(0);
    }

    // 解密往返
    uint8_t back[48];
    assert(totp_aes256_cbc_decrypt(KEY, iv, ct, 48, back) == 48);
    assert(memcmp(back, pt, 48) == 0);
    puts("AES-256-CBC (NIST SP 800-38A F.2.5) + roundtrip: PASS");
}

static void test_pbkdf2(void)
{
    // Python hashlib.pbkdf2_hmac('sha256', b'passwd', b'salt', 1000, 32)
    uint8_t k[32];
    assert(totp_pbkdf2_sha256("passwd", (const uint8_t *)"salt", 4, 1000, k, 32));
    if (!hexeq(k, "fa9c158e678bfe94189b0b1a707a0921672fdc9f11fa978805969df312c2c8ef", 32)) {
        hexdump("PBKDF2 got: ", k, 32);
        assert(0);
    }

    // 真实用法：用户口令 + 16B salt，4096 轮
    assert(totp_pbkdf2_sha256("my-passphrase", (const uint8_t *)"TotpPassport", 12, 4096, k, 32));
    if (!hexeq(k, "9cbc421075ae5a572eebd704330986b1b1e632f10496751c7f6f13db40b9e7d2", 32)) {
        hexdump("PBKDF2-4096 got: ", k, 32);
        assert(0);
    }

    // 输出长度 > 32 时跨块（RFC 8018 的 L>1 路径）
    // 注意：dkLen=64 时前 32 字节必须等于 dkLen=32 的结果（block1），第二块独立。
    uint8_t k_short[32], k64[64];
    assert(totp_pbkdf2_sha256("passwd", (const uint8_t *)"salt", 4, 1000, k_short, 32));
    assert(totp_pbkdf2_sha256("passwd", (const uint8_t *)"salt", 4, 1000, k64, 64));
    assert(memcmp(k64, k_short, 32) == 0);   // 前 32 字节 = block1
    assert(memcmp(k64, k64 + 32, 32) != 0);  // block2 必须不同

    // 与 hashlib 交叉验证 block2
    if (!hexeq(k64 + 32, "2c981020be9fda5485f3a5aa6b65e6b9941fca9df03878b1ff7283d685f50679", 32)) {
        hexdump("PBKDF2 block2 got: ", k64 + 32, 32);
        assert(0);
    }

    // 参数校验
    assert(!totp_pbkdf2_sha256("x", (const uint8_t *)"s", 1, 0, k, 32));
    assert(!totp_pbkdf2_sha256(NULL, (const uint8_t *)"s", 1, 10, k, 32));
    assert(!totp_pbkdf2_sha256("x", (const uint8_t *)"s", 0, 10, k, 32));
    assert(!totp_pbkdf2_sha256("x", (const uint8_t *)"s", 1, 10, k, 0));
    puts("PBKDF2-HMAC-SHA256 (cross-verified with hashlib): PASS");
}

static void test_pkcs7(void)
{
    uint8_t padded[64], out[64];
    // 恰好整块也要补一整块
    assert(totp_pkcs7_pad((const uint8_t *)"0123456789abcdef", 16, padded, sizeof(padded)) == 32);
    for (int i = 16; i < 32; i++) assert(padded[i] == 16);
    assert(totp_pkcs7_unpad(padded, 32, out) == 16);
    assert(memcmp(out, "0123456789abcdef", 16) == 0);

    assert(totp_pkcs7_pad((const uint8_t *)"abc", 3, padded, sizeof(padded)) == 16);
    assert(totp_pkcs7_unpad(padded, 16, out) == 3);
    assert(memcmp(out, "abc", 3) == 0);

    // 非整倍数输入被加密函数拒绝
    uint8_t key[32] = { 0 }, iv[16] = { 0 }, ct[64];
    assert(totp_aes256_cbc_encrypt(key, iv, padded, 15, ct) == 0);
    assert(totp_aes256_cbc_decrypt(key, iv, ct, 15, ct) == 0);

    // 非法 padding 必须被拒
    uint8_t bad[16];
    memset(bad, 0xAA, sizeof(bad));
    assert(totp_pkcs7_unpad(bad, 16, out) == -1);       // pad=0xAA 越界
    memset(bad, 0, sizeof(bad));
    assert(totp_pkcs7_unpad(bad, 16, out) == -1);       // pad=0
    memset(bad, 17, sizeof(bad));
    assert(totp_pkcs7_unpad(bad, 16, out) == -1);       // pad > block
    assert(totp_pkcs7_unpad(bad, 0, out) == -1);        // 空输入
    puts("PKCS#7 pad/unpad: PASS");
}

// 端到端：JSON 明文 → 填充 → 加密；再解密回来
static void test_end_to_end(void)
{
    const char *json = "{\"accounts\":[{\"name\":\"a@b.com\",\"secret\":\"JBSWY3DPEHPK3PXP\"}]}";
    size_t jlen = strlen(json);

    uint8_t salt[TOTP_BACKUP_SALT_LEN];
    memset(salt, 0x5A, sizeof(salt));
    uint8_t key[TOTP_AES_KEY_LEN];
    assert(totp_pbkdf2_sha256("user-pass", salt, sizeof(salt), 4096, key, sizeof(key)));

    uint8_t padded[256];
    size_t plen = totp_pkcs7_pad((const uint8_t *)json, jlen, padded, sizeof(padded));
    assert(plen > 0 && plen % 16 == 0);

    uint8_t iv[TOTP_AES_IV_LEN];
    memset(iv, 0x11, sizeof(iv));
    uint8_t ct[256];
    assert(totp_aes256_cbc_encrypt(key, iv, padded, plen, ct) == plen);

    // 密文里不应出现明文片段
    for (size_t i = 0; i + 8 < plen; i++) {
        if (memcmp(ct + i, "accounts", 8) == 0) assert(0);
    }

    uint8_t back[256];
    assert(totp_aes256_cbc_decrypt(key, iv, ct, plen, back) == plen);
    uint8_t plain[256];
    int n = totp_pkcs7_unpad(back, plen, plain);
    assert(n == (int)jlen);
    assert(memcmp(plain, json, jlen) == 0);

    // 错误口令派生的 key 解出来是垃圾
    uint8_t badkey[TOTP_AES_KEY_LEN];
    assert(totp_pbkdf2_sha256("wrong-pass", salt, sizeof(salt), 4096, badkey, sizeof(badkey)));
    assert(memcmp(badkey, key, sizeof(key)) != 0);
    puts("Backup encrypt/decrypt end-to-end: PASS");
}

int main(void)
{
    test_aes256_ecb_fips();
    test_aes256_cbc_nist();
    test_pbkdf2();
    test_pkcs7();
    test_end_to_end();
    puts("all totp_crypto tests: PASS");
    return 0;
}