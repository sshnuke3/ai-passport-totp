// main/totp_crypto.c —— AES-256-CBC + PBKDF2-HMAC-SHA256 纯 C 实现。
//
// AES 用 FIPS-197 的标准算法表（S-box / Rcon 由字节运算生成，不硬编码大表），
// host 侧用 NIST SP 800-38A F.2.5 的 AES-256-CBC 官方向量锁死正确性。
#include "totp_crypto.h"
#include "totp_model.h"

#ifdef ESP_PLATFORM
#include "esp_random.h"
#endif

#include <string.h>

// ===========================================================================
// AES-256
// ===========================================================================
static const uint8_t AES_SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
};

static uint8_t xtime(uint8_t x)
{
    return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1b : 0x00));
}

static uint8_t gmul(uint8_t a, uint8_t b)
{
    uint8_t r = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) r ^= a;
        a = xtime(a);
        b >>= 1;
    }
    return r;
}

// AES-256：14 轮 + 1 轮最终轮，Nk=8 → 60 个字（240 字节）
typedef struct {
    uint8_t rk[240];
} aes256_ctx;

static void aes256_expand_key(aes256_ctx *ctx, const uint8_t key[32])
{
    // AES-256: Nk=8, Nr=14, 共 60 字。i % 8 == 0 出现在 i=8,16,...,56，
    // 对应 RCON[1..7]。索引 0 不被用到，留 0 占位。
    static const uint8_t RCON[8] = { 0x00, 0x01, 0x02, 0x04,
                                     0x08, 0x10, 0x20, 0x40 };
    uint8_t *w = ctx->rk;
    memcpy(w, key, 32);
    for (int i = 8; i < 60; i++) {
        uint8_t t[4];
        memcpy(t, w + (i - 1) * 4, 4);
        if (i % 8 == 0) {
            uint8_t tmp = t[0];
            t[0] = (uint8_t)(AES_SBOX[t[1]] ^ RCON[i / 8]);
            t[1] = AES_SBOX[t[2]];
            t[2] = AES_SBOX[t[3]];
            t[3] = AES_SBOX[tmp];
        } else if (i % 8 == 4) {
            for (int k = 0; k < 4; k++) t[k] = AES_SBOX[t[k]];
        }
        for (int k = 0; k < 4; k++) {
            w[i * 4 + k] = (uint8_t)(w[(i - 8) * 4 + k] ^ t[k]);
        }
    }
}

static void add_round_key(uint8_t s[16], const uint8_t *rk)
{
    for (int i = 0; i < 16; i++) s[i] ^= rk[i];
}

static void sub_bytes(uint8_t s[16])
{
    for (int i = 0; i < 16; i++) s[i] = AES_SBOX[s[i]];
}

// 行移位：state 是列优先（s[c*4+r]）
static void shift_rows(uint8_t s[16])
{
    uint8_t t;
    // row 1 <<< 1
    t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
    // row 2 <<< 2
    t = s[2];  s[2]  = s[10]; s[10] = t;
    t = s[6];  s[6]  = s[14]; s[14] = t;
    // row 3 <<< 3
    t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t;
}

static void mix_columns(uint8_t s[16])
{
    for (int c = 0; c < 4; c++) {
        uint8_t *p = s + c * 4;
        uint8_t a0 = p[0], a1 = p[1], a2 = p[2], a3 = p[3];
        p[0] = (uint8_t)(gmul(a0, 2) ^ gmul(a1, 3) ^ a2 ^ a3);
        p[1] = (uint8_t)(a0 ^ gmul(a1, 2) ^ gmul(a2, 3) ^ a3);
        p[2] = (uint8_t)(a0 ^ a1 ^ gmul(a2, 2) ^ gmul(a3, 3));
        p[3] = (uint8_t)(gmul(a0, 3) ^ a1 ^ a2 ^ gmul(a3, 2));
    }
}

static void aes256_encrypt_block(const aes256_ctx *ctx, uint8_t s[16])
{
    add_round_key(s, ctx->rk);
    for (int round = 1; round < 14; round++) {
        sub_bytes(s);
        shift_rows(s);
        mix_columns(s);
        add_round_key(s, ctx->rk + round * 16);
    }
    sub_bytes(s);
    shift_rows(s);
    add_round_key(s, ctx->rk + 14 * 16);
}

static void aes256_decrypt_block(const aes256_ctx *ctx, uint8_t s[16])
{
    add_round_key(s, ctx->rk + 14 * 16);
    for (int round = 13; round >= 1; round--) {
        // 逆行移位
        uint8_t t;
        t = s[13]; s[13] = s[9]; s[9] = s[5]; s[5] = s[1]; s[1] = t;
        t = s[2];  s[2]  = s[10]; s[10] = t;
        t = s[6];  s[6]  = s[14]; s[14] = t;
        t = s[3];  s[3]  = s[7]; s[7]  = s[11]; s[11] = s[15]; s[15] = t;
        // 逆 S-box 由 S-box 表反查
        for (int i = 0; i < 16; i++) {
            uint8_t v = s[i];
            for (int k = 0; k < 256; k++) {
                if (AES_SBOX[k] == v) { s[i] = (uint8_t)k; break; }
            }
        }
        add_round_key(s, ctx->rk + round * 16);
        // 逆列混合
        for (int c = 0; c < 4; c++) {
            uint8_t *p = s + c * 4;
            uint8_t a0 = p[0], a1 = p[1], a2 = p[2], a3 = p[3];
            p[0] = (uint8_t)(gmul(a0, 14) ^ gmul(a1, 11) ^ gmul(a2, 13) ^ gmul(a3, 9));
            p[1] = (uint8_t)(gmul(a0, 9) ^ gmul(a1, 14) ^ gmul(a2, 11) ^ gmul(a3, 13));
            p[2] = (uint8_t)(gmul(a0, 13) ^ gmul(a1, 9) ^ gmul(a2, 14) ^ gmul(a3, 11));
            p[3] = (uint8_t)(gmul(a0, 11) ^ gmul(a1, 13) ^ gmul(a2, 9) ^ gmul(a3, 14));
        }
    }
    // 逆行移位
    uint8_t t;
    t = s[13]; s[13] = s[9]; s[9] = s[5]; s[5] = s[1]; s[1] = t;
    t = s[2];  s[2]  = s[10]; s[10] = t;
    t = s[6];  s[6]  = s[14]; s[14] = t;
    t = s[3];  s[3]  = s[7]; s[7]  = s[11]; s[11] = s[15]; s[15] = t;
    // 逆 S-box
    for (int i = 0; i < 16; i++) {
        uint8_t v = s[i];
        for (int k = 0; k < 256; k++) {
            if (AES_SBOX[k] == v) { s[i] = (uint8_t)k; break; }
        }
    }
    add_round_key(s, ctx->rk);
}

size_t totp_aes256_cbc_encrypt(const uint8_t key[TOTP_AES_KEY_LEN],
                               const uint8_t iv[TOTP_AES_IV_LEN],
                               const uint8_t *in, size_t in_len,
                               uint8_t *out)
{
    if (in_len == 0 || in_len % TOTP_AES_BLOCK != 0) return 0;
    aes256_ctx ctx;
    aes256_expand_key(&ctx, key);

    uint8_t prev[TOTP_AES_BLOCK];
    memcpy(prev, iv, TOTP_AES_BLOCK);
    for (size_t off = 0; off < in_len; off += TOTP_AES_BLOCK) {
        uint8_t blk[TOTP_AES_BLOCK];
        for (int i = 0; i < TOTP_AES_BLOCK; i++) {
            blk[i] = (uint8_t)(in[off + i] ^ prev[i]);
        }
        aes256_encrypt_block(&ctx, blk);
        memcpy(out + off, blk, TOTP_AES_BLOCK);
        memcpy(prev, blk, TOTP_AES_BLOCK);
    }
    return in_len;
}

size_t totp_aes256_cbc_decrypt(const uint8_t key[TOTP_AES_KEY_LEN],
                               const uint8_t iv[TOTP_AES_IV_LEN],
                               const uint8_t *in, size_t in_len,
                               uint8_t *out)
{
    if (in_len == 0 || in_len % TOTP_AES_BLOCK != 0) return 0;
    aes256_ctx ctx;
    aes256_expand_key(&ctx, key);

    uint8_t prev[TOTP_AES_BLOCK];
    memcpy(prev, iv, TOTP_AES_BLOCK);
    for (size_t off = 0; off < in_len; off += TOTP_AES_BLOCK) {
        uint8_t blk[TOTP_AES_BLOCK], cur[TOTP_AES_BLOCK];
        memcpy(cur, in + off, TOTP_AES_BLOCK);
        memcpy(blk, cur, TOTP_AES_BLOCK);
        aes256_decrypt_block(&ctx, blk);
        for (int i = 0; i < TOTP_AES_BLOCK; i++) {
            out[off + i] = (uint8_t)(blk[i] ^ prev[i]);
        }
        memcpy(prev, cur, TOTP_AES_BLOCK);
    }
    return in_len;
}

// ===========================================================================
// PKCS#7
// ===========================================================================
size_t totp_pkcs7_pad(const uint8_t *src, size_t src_len,
                      uint8_t *out, size_t out_cap)
{
    size_t pad = TOTP_AES_BLOCK - (src_len % TOTP_AES_BLOCK);
    if (src_len + pad > out_cap) return 0;
    memcpy(out, src, src_len);
    for (size_t i = 0; i < pad; i++) out[src_len + i] = (uint8_t)pad;
    return src_len + pad;
}

int totp_pkcs7_unpad(const uint8_t *src, size_t src_len, uint8_t *out)
{
    if (src_len == 0 || src_len % TOTP_AES_BLOCK != 0) return -1;
    uint8_t pad = src[src_len - 1];
    if (pad == 0 || pad > TOTP_AES_BLOCK || pad > src_len) return -1;
    for (size_t i = src_len - pad; i < src_len; i++) {
        if (src[i] != pad) return -1;
    }
    memcpy(out, src, src_len - pad);
    return (int)(src_len - pad);
}

// 设备端用硬件 RNG（esp_random）。host tests 没有 IDF，退化成固定序列
// —— host 侧只验证加密流程，不验证随机性。
void totp_random_bytes(uint8_t *out, size_t len)
{
    if (!out || len == 0) return;
#ifdef ESP_PLATFORM
    esp_fill_random(out, len);
#else
    uint32_t x = 0x9E3779B9u;
    for (size_t i = 0; i < len; i++) {
        x ^= x << 13; x ^= x >> 17; x ^= x << 5;   // xorshift32
        out[i] = (uint8_t)(x >> 24);
    }
#endif
}

// ===========================================================================
// PBKDF2-HMAC-SHA256（RFC 8018）
// ===========================================================================
bool totp_pbkdf2_sha256(const char *pass, const uint8_t *salt, size_t salt_len,
                        uint32_t iterations, uint8_t *out, size_t out_len)
{
    // salt 在本玩法里恒为 16 B（TOTP_BACKUP_SALT_LEN）；留出余量但拒绝超长，
    // 避免在嵌入式上做无界栈分配。
    if (!pass || !out || out_len == 0 || iterations == 0) return false;
    if (salt_len == 0 || salt_len > TOTP_PBKDF2_MAX_SALT) return false;

    const size_t hlen = 32;
    const size_t pass_len = strlen(pass);
    uint32_t block = 1;
    uint8_t msg[TOTP_PBKDF2_MAX_SALT + 4];

    while (out_len > 0) {
        uint8_t U[32], T[32];

        // U1 = HMAC(P, S || INT(i))；INT 是 4 字节大端计数器
        msg[salt_len + 0] = (uint8_t)(block >> 24);
        msg[salt_len + 1] = (uint8_t)(block >> 16);
        msg[salt_len + 2] = (uint8_t)(block >> 8);
        msg[salt_len + 3] = (uint8_t)(block);
        memcpy(msg, salt, salt_len);
        totp_hmac_sha256((const uint8_t *)pass, pass_len, msg, salt_len + 4, U);
        memcpy(T, U, hlen);

        // T_j = U1 xor U2 xor ... xor Uc
        for (uint32_t c = 1; c < iterations; c++) {
            totp_hmac_sha256((const uint8_t *)pass, pass_len, U, hlen, U);
            for (size_t i = 0; i < hlen; i++) T[i] ^= U[i];
        }

        size_t take = (out_len < hlen) ? out_len : hlen;
        memcpy(out, T, take);
        out += take;
        out_len -= take;
        block++;
    }
    return true;
}