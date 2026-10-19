// main/totp_model.c —— TOTP 纯逻辑实现（RFC 4648 base32 / RFC 2104 HMAC /
// RFC 3174 SHA-1 / FIPS 180-4 SHA-256/512 / RFC 6238 TOTP）。
// 只用 C 标准库，可在 host 与设备两端编译，便于单元测试。
#include "totp_model.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ===========================================================================
// SHA-1 (RFC 3174)
// ===========================================================================
typedef struct {
    uint32_t h[5];
    uint64_t total;      // 已处理字节数
    uint8_t  buf[64];
    size_t   buf_len;
} sha1_ctx;

static uint32_t rol32(uint32_t v, int n) { return (v << n) | (v >> (32 - n)); }

static void sha1_init(sha1_ctx *c) {
    c->h[0] = 0x67452301u; c->h[1] = 0xEFCDAB89u; c->h[2] = 0x98BADCFEu;
    c->h[3] = 0x10325476u; c->h[4] = 0xC3D2E1F0u;
    c->total = 0; c->buf_len = 0;
}

static void sha1_block(sha1_ctx *c, const uint8_t *p) {
    uint32_t w[80];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)p[i * 4] << 24) | ((uint32_t)p[i * 4 + 1] << 16) |
               ((uint32_t)p[i * 4 + 2] << 8) | (uint32_t)p[i * 4 + 3];
    }
    for (int i = 16; i < 80; i++) w[i] = rol32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

    uint32_t a = c->h[0], b = c->h[1], d = c->h[2], e = c->h[3], f = c->h[4];
    for (int i = 0; i < 80; i++) {
        uint32_t fn, k;
        if (i < 20)      { fn = (b & d) | ((~b) & e);          k = 0x5A827999u; }
        else if (i < 40) { fn = b ^ d ^ e;                     k = 0x6ED9EBA1u; }
        else if (i < 60) { fn = (b & d) | (b & e) | (d & e);   k = 0x8F1BBCDCu; }
        else             { fn = b ^ d ^ e;                     k = 0xCA62C1D6u; }
        uint32_t tmp = rol32(a, 5) + fn + f + k + w[i];
        f = e; e = d; d = rol32(b, 30); b = a; a = tmp;
    }
    c->h[0] += a; c->h[1] += b; c->h[2] += d; c->h[3] += e; c->h[4] += f;
}

static void sha1_update(sha1_ctx *c, const uint8_t *data, size_t len) {
    c->total += len;
    while (len > 0) {
        size_t take = 64 - c->buf_len;
        if (take > len) take = len;
        memcpy(c->buf + c->buf_len, data, take);
        c->buf_len += take; data += take; len -= take;
        if (c->buf_len == 64) { sha1_block(c, c->buf); c->buf_len = 0; }
    }
}

static void sha1_final(sha1_ctx *c, uint8_t out[20]) {
    uint64_t bits = c->total * 8;
    uint8_t pad = 0x80;
    sha1_update(c, &pad, 1);
    uint8_t zero = 0;
    while (c->buf_len != 56) sha1_update(c, &zero, 1);
    uint8_t lenbuf[8];
    for (int i = 0; i < 8; i++) lenbuf[i] = (uint8_t)(bits >> (56 - 8 * i));
    sha1_update(c, lenbuf, 8);
    for (int i = 0; i < 5; i++) {
        out[i * 4]     = (uint8_t)(c->h[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(c->h[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(c->h[i] >> 8);
        out[i * 4 + 3] = (uint8_t)(c->h[i]);
    }
}

// ===========================================================================
// SHA-256 (FIPS 180-4)
// ===========================================================================
typedef struct {
    uint32_t h[8];
    uint64_t total;
    uint8_t  buf[64];
    size_t   buf_len;
} sha256_ctx;

static const uint32_t K256[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
    0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
    0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
    0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
    0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
    0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};

static uint32_t ror32(uint32_t v, int n) { return (v >> n) | (v << (32 - n)); }

static void sha256_init(sha256_ctx *c) {
    c->h[0]=0x6a09e667u; c->h[1]=0xbb67ae85u; c->h[2]=0x3c6ef372u; c->h[3]=0xa54ff53au;
    c->h[4]=0x510e527fu; c->h[5]=0x9b05688cu; c->h[6]=0x1f83d9abu; c->h[7]=0x5be0cd19u;
    c->total = 0; c->buf_len = 0;
}

static void sha256_block(sha256_ctx *c, const uint8_t *p) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)p[i * 4] << 24) | ((uint32_t)p[i * 4 + 1] << 16) |
               ((uint32_t)p[i * 4 + 2] << 8) | (uint32_t)p[i * 4 + 3];
    }
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ror32(w[i-15],7) ^ ror32(w[i-15],18) ^ (w[i-15] >> 3);
        uint32_t s1 = ror32(w[i-2],17) ^ ror32(w[i-2],19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint32_t a=c->h[0],b=c->h[1],d=c->h[2],e=c->h[3],f=c->h[4],g=c->h[5],x=c->h[6],y=c->h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = ror32(f,6) ^ ror32(f,11) ^ ror32(f,25);
        uint32_t ch = (f & g) ^ ((~f) & x);
        uint32_t t1 = y + S1 + ch + K256[i] + w[i];
        uint32_t S0 = ror32(a,2) ^ ror32(a,13) ^ ror32(a,22);
        uint32_t mj = (a & b) ^ (a & d) ^ (b & d);
        uint32_t t2 = S0 + mj;
        y=x; x=g; g=f; f=e+t1; e=d; d=b; b=a; a=t1+t2;
    }
    c->h[0]+=a; c->h[1]+=b; c->h[2]+=d; c->h[3]+=e;
    c->h[4]+=f; c->h[5]+=g; c->h[6]+=x; c->h[7]+=y;
}

static void sha256_update(sha256_ctx *c, const uint8_t *data, size_t len) {
    c->total += len;
    while (len > 0) {
        size_t take = 64 - c->buf_len;
        if (take > len) take = len;
        memcpy(c->buf + c->buf_len, data, take);
        c->buf_len += take; data += take; len -= take;
        if (c->buf_len == 64) { sha256_block(c, c->buf); c->buf_len = 0; }
    }
}

static void sha256_final(sha256_ctx *c, uint8_t out[32]) {
    uint64_t bits = c->total * 8;
    uint8_t pad = 0x80;
    sha256_update(c, &pad, 1);
    uint8_t zero = 0;
    while (c->buf_len != 56) sha256_update(c, &zero, 1);
    uint8_t lenbuf[8];
    for (int i = 0; i < 8; i++) lenbuf[i] = (uint8_t)(bits >> (56 - 8 * i));
    sha256_update(c, lenbuf, 8);
    for (int i = 0; i < 8; i++) {
        out[i * 4]     = (uint8_t)(c->h[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(c->h[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(c->h[i] >> 8);
        out[i * 4 + 3] = (uint8_t)(c->h[i]);
    }
}

// ===========================================================================
// SHA-512 (FIPS 180-4)
// ===========================================================================
typedef struct {
    uint64_t h[8];
    uint64_t total_lo, total_hi;
    uint8_t  buf[128];
    size_t   buf_len;
} sha512_ctx;

static const uint64_t K512[80] = {
    0x428a2f98d728ae22ULL,0x7137449123ef65cdULL,0xb5c0fbcfec4d3b2fULL,0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL,0x59f111f1b605d019ULL,0x923f82a4af194f9bULL,0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL,0x12835b0145706fbeULL,0x243185be4ee4b28cULL,0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL,0x80deb1fe3b1696b1ULL,0x9bdc06a725c71235ULL,0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL,0xefbe4786384f25e3ULL,0x0fc19dc68b8cd5b5ULL,0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL,0x4a7484aa6ea6e483ULL,0x5cb0a9dcbd41fbd4ULL,0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL,0xa831c66d2db43210ULL,0xb00327c898fb213fULL,0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL,0xd5a79147930aa725ULL,0x06ca6351e003826fULL,0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL,0x2e1b21385c26c926ULL,0x4d2c6dfc5ac42aedULL,0x53380d139d95b3dfULL,
    0x650a73548baf63deULL,0x766a0abb3c77b2a8ULL,0x81c2c92e47edaee6ULL,0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL,0xa81a664bbc423001ULL,0xc24b8b70d0f89791ULL,0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL,0xd69906245565a910ULL,0xf40e35855771202aULL,0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL,0x1e376c085141ab53ULL,0x2748774cdf8eeb99ULL,0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL,0x4ed8aa4ae3418acbULL,0x5b9cca4f7763e373ULL,0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL,0x78a5636f43172f60ULL,0x84c87814a1f0ab72ULL,0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL,0xa4506cebde82bde9ULL,0xbef9a3f7b2c67915ULL,0xc67178f2e372532bULL,
    0xca273eceea26619cULL,0xd186b8c721c0c207ULL,0xeada7dd6cde0eb1eULL,0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL,0x0a637dc5a2c898a6ULL,0x113f9804bef90daeULL,0x1b710b35131c471bULL,
    0x28db77f523047d84ULL,0x32caab7b40c72493ULL,0x3c9ebe0a15c9bebcULL,0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL,0x597f299cfc657e2aULL,0x5fcb6fab3ad6faecULL,0x6c44198c4a475817ULL
};

static uint64_t ror64(uint64_t v, int n) { return (v >> n) | (v << (64 - n)); }

static void sha512_init(sha512_ctx *c) {
    c->h[0]=0x6a09e667f3bcc908ULL; c->h[1]=0xbb67ae8584caa73bULL;
    c->h[2]=0x3c6ef372fe94f82bULL; c->h[3]=0xa54ff53a5f1d36f1ULL;
    c->h[4]=0x510e527fade682d1ULL; c->h[5]=0x9b05688c2b3e6c1fULL;
    c->h[6]=0x1f83d9abfb41bd6bULL; c->h[7]=0x5be0cd19137e2179ULL;
    c->total_lo = 0; c->total_hi = 0; c->buf_len = 0;
}

static void sha512_block(sha512_ctx *c, const uint8_t *p) {
    uint64_t w[80];
    for (int i = 0; i < 16; i++) {
        uint64_t v = 0;
        for (int j = 0; j < 8; j++) v = (v << 8) | p[i * 8 + j];
        w[i] = v;
    }
    for (int i = 16; i < 80; i++) {
        uint64_t s0 = ror64(w[i-15],1) ^ ror64(w[i-15],8) ^ (w[i-15] >> 7);
        uint64_t s1 = ror64(w[i-2],19) ^ ror64(w[i-2],61) ^ (w[i-2] >> 6);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint64_t a=c->h[0],b=c->h[1],d=c->h[2],e=c->h[3],f=c->h[4],g=c->h[5],x=c->h[6],y=c->h[7];
    for (int i = 0; i < 80; i++) {
        uint64_t S1 = ror64(f,14) ^ ror64(f,18) ^ ror64(f,41);
        uint64_t ch = (f & g) ^ ((~f) & x);
        uint64_t t1 = y + S1 + ch + K512[i] + w[i];
        uint64_t S0 = ror64(a,28) ^ ror64(a,34) ^ ror64(a,39);
        uint64_t mj = (a & b) ^ (a & d) ^ (b & d);
        uint64_t t2 = S0 + mj;
        y=x; x=g; g=f; f=e+t1; e=d; d=b; b=a; a=t1+t2;
    }
    c->h[0]+=a; c->h[1]+=b; c->h[2]+=d; c->h[3]+=e;
    c->h[4]+=f; c->h[5]+=g; c->h[6]+=x; c->h[7]+=y;
}

static void sha512_update(sha512_ctx *c, const uint8_t *data, size_t len) {
    c->total_lo += len;
    if (c->total_lo < len) c->total_hi++;   // 进位
    while (len > 0) {
        size_t take = 128 - c->buf_len;
        if (take > len) take = len;
        memcpy(c->buf + c->buf_len, data, take);
        c->buf_len += take; data += take; len -= take;
        if (c->buf_len == 128) { sha512_block(c, c->buf); c->buf_len = 0; }
    }
}

static void sha512_final(sha512_ctx *c, uint8_t out[64]) {
    uint64_t bits_lo = c->total_lo << 3;
    uint64_t bits_hi = (c->total_hi << 3) | (c->total_lo >> 61);
    uint8_t pad = 0x80;
    sha512_update(c, &pad, 1);
    uint8_t zero = 0;
    while (c->buf_len != 112) sha512_update(c, &zero, 1);
    uint8_t lenbuf[16];
    for (int i = 0; i < 8; i++) lenbuf[i] = (uint8_t)(bits_hi >> (56 - 8 * i));
    for (int i = 0; i < 8; i++) lenbuf[8 + i] = (uint8_t)(bits_lo >> (56 - 8 * i));
    sha512_update(c, lenbuf, 16);
    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 8; j++) out[i * 8 + j] = (uint8_t)(c->h[i] >> (56 - 8 * j));
    }
}

// ===========================================================================
// HMAC (RFC 2104)
// ===========================================================================
static void hmac_sha(const uint8_t *key, size_t key_len,
                     const uint8_t *msg, size_t msg_len,
                     uint8_t alg, uint8_t *out, size_t *out_len) {
    uint8_t k[128];
    uint8_t pad[128];
    uint8_t inner[64];   // 最大 64（SHA-512 输出）
    uint8_t outer[64];
    size_t block = (alg == TOTP_ALG_SHA512) ? 128 : 64;
    size_t olen = (alg == TOTP_ALG_SHA1) ? 20 : (alg == TOTP_ALG_SHA256) ? 32 : 64;

    memset(k, 0, sizeof(k));
    if (key_len > block) {
        // 长密钥先哈希
        if (alg == TOTP_ALG_SHA1) {
            sha1_ctx c1; sha1_init(&c1); sha1_update(&c1, key, key_len); sha1_final(&c1, k);
        } else if (alg == TOTP_ALG_SHA256) {
            sha256_ctx c2; sha256_init(&c2); sha256_update(&c2, key, key_len); sha256_final(&c2, k);
        } else {
            sha512_ctx c3; sha512_init(&c3); sha512_update(&c3, key, key_len); sha512_final(&c3, k);
        }
    } else {
        memcpy(k, key, key_len);
    }

    for (size_t i = 0; i < block; i++) pad[i] = k[i] ^ 0x36;
    if (alg == TOTP_ALG_SHA1) {
        sha1_ctx c1; sha1_init(&c1); sha1_update(&c1, pad, block); sha1_update(&c1, msg, msg_len); sha1_final(&c1, inner);
    } else if (alg == TOTP_ALG_SHA256) {
        sha256_ctx c2; sha256_init(&c2); sha256_update(&c2, pad, block); sha256_update(&c2, msg, msg_len); sha256_final(&c2, inner);
    } else {
        sha512_ctx c3; sha512_init(&c3); sha512_update(&c3, pad, block); sha512_update(&c3, msg, msg_len); sha512_final(&c3, inner);
    }

    for (size_t i = 0; i < block; i++) pad[i] = k[i] ^ 0x5c;
    if (alg == TOTP_ALG_SHA1) {
        sha1_ctx c1; sha1_init(&c1); sha1_update(&c1, pad, block); sha1_update(&c1, inner, olen); sha1_final(&c1, outer);
    } else if (alg == TOTP_ALG_SHA256) {
        sha256_ctx c2; sha256_init(&c2); sha256_update(&c2, pad, block); sha256_update(&c2, inner, olen); sha256_final(&c2, outer);
    } else {
        sha512_ctx c3; sha512_init(&c3); sha512_update(&c3, pad, block); sha512_update(&c3, inner, olen); sha512_final(&c3, outer);
    }

    memcpy(out, outer, olen);
    *out_len = olen;
}

// 公开的 HMAC-SHA256（totp_crypto 的 PBKDF2 复用，避免第二份 SHA-256 实现）。
void totp_hmac_sha256(const uint8_t *key, size_t key_len,
                      const uint8_t *msg, size_t msg_len,
                      uint8_t out[32])
{
    size_t olen = 0;
    hmac_sha(key, key_len, msg, msg_len, TOTP_ALG_SHA256, out, &olen);
}

// ===========================================================================
// base32 (RFC 4648)
// ===========================================================================
static const char B32_ALPHABET[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

static int b32_value(char c) {
    if (c >= 'a' && c <= 'z') c = (char)(c - 'a' + 'A');
    for (int i = 0; i < 32; i++) if (B32_ALPHABET[i] == c) return i;
    return -1;
}

int totp_base32_decode(const char *b32, uint8_t *out, size_t out_cap) {
    if (!b32 || !out) return -1;
    uint64_t acc = 0;
    int bits = 0;
    size_t n = 0;
    for (const char *p = b32; *p; p++) {
        char c = *p;
        if (c == '=') break;                       // 填充：其后忽略
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') continue;
        int v = b32_value(c);
        if (v < 0) return -1;
        acc = (acc << 5) | (uint64_t)v;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            if (n >= out_cap) return -1;
            out[n++] = (uint8_t)((acc >> bits) & 0xFF);
        }
    }
    return (int)n;
}

int totp_base32_encode(const uint8_t *in, size_t in_len, char *out, size_t out_cap) {
    if (!in || !out || out_cap == 0) return -1;
    // 无填充：输出长度 = ceil(in_len*8/5)。用 in_len/5*8 + 余数处理，
    // 每满 5 字节出 8 字符，最后不足 5 字节的部分单独补齐。
    size_t need = (in_len / 5) * 8;
    size_t rem = in_len % 5;
    if (rem) need += (rem * 8 + 4) / 5;
    if (out_cap < need + 1) return -1;

    uint32_t acc = 0;
    int bits = 0;
    size_t n = 0;
    for (size_t i = 0; i < in_len; i++) {
        acc = (acc << 8) | in[i];
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            out[n++] = B32_ALPHABET[(acc >> bits) & 0x1F];
        }
    }
    if (bits > 0) {                      // 补齐剩余位（补零）
        out[n++] = B32_ALPHABET[(acc << (5 - bits)) & 0x1F];
    }
    out[n] = '\0';
    return (int)n;
}

// ===========================================================================
// TOTP (RFC 6238)
// ===========================================================================
void totp_code(const totp_account_t *acc, time_t t, char *out, size_t out_cap) {
    if (!acc || !out || out_cap == 0) return;
    uint8_t digits = acc->digits ? acc->digits : 6;
    if (digits < 6) digits = 6;
    if (digits > 10) digits = 10;
    uint8_t period = acc->period ? acc->period : 30;

    uint64_t counter = (uint64_t)t / period;
    uint8_t msg[8];
    for (int i = 0; i < 8; i++) msg[i] = (uint8_t)(counter >> (56 - 8 * i));

    uint8_t mac[64];
    size_t mac_len = 0;
    hmac_sha(acc->secret, acc->secret_len, msg, sizeof(msg), acc->alg, mac, &mac_len);
    if (mac_len == 0) { out[0] = '\0'; return; }

    int offset = mac[mac_len - 1] & 0x0F;
    uint32_t binary = ((uint32_t)(mac[offset] & 0x7F) << 24) |
                      ((uint32_t)(mac[offset + 1] & 0xFF) << 16) |
                      ((uint32_t)(mac[offset + 2] & 0xFF) << 8) |
                      (uint32_t)(mac[offset + 3] & 0xFF);

    // 10^digits，digits<=10 时用 uint32 不会溢出（10^10 = 1e10 < 2^34? 不，> 2^32）
    // digits 实际取值 6..10；10 位时 10^10 = 10000000000 超 uint32。
    // 稳妥：digits>8 时用 uint64 取模。
    uint64_t code;
    if (digits <= 8) {
        static const uint32_t POW10[9] = {1,10,100,1000,10000,100000,1000000,10000000,100000000};
        code = (uint64_t)binary % POW10[digits];
    } else {
        uint64_t pow10 = 1000000000ULL;   // 9 位
        if (digits == 10) pow10 = 10000000000ULL;
        code = (uint64_t)binary % pow10;
    }

    // 右对齐零填充输出
    if (out_cap < (size_t)digits + 1) {
        // 目标太小：至少安全截断
        digits = (uint8_t)(out_cap - 1);
    }
    for (int i = digits - 1; i >= 0; i--) {
        out[i] = (char)('0' + (int)(code % 10));
        code /= 10;
    }
    out[digits] = '\0';
}

uint32_t totp_remaining(time_t t, uint8_t period) {
    if (period == 0) period = 30;
    uint32_t r = (uint32_t)(((uint64_t)t % period));
    return period - r;   // 1..period
}

// ===========================================================================
// URL 解码与 otpauth URI 解析
// ===========================================================================
static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// 大小写不敏感相等比较（避免 POSIX strcasecmp，保持 -std=c11 纯净）。
static bool ci_eq(const char *a, const char *b) {
    while (*a && *b) {
        char ca = *a, cb = *b;
        if (ca >= 'a' && ca <= 'z') ca = (char)(ca - 'a' + 'A');
        if (cb >= 'a' && cb <= 'z') cb = (char)(cb - 'a' + 'A');
        if (ca != cb) return false;
        a++; b++;
    }
    return *a == '\0' && *b == '\0';
}

// 就地 URL 解码（%XX 与 '+' → 空格）。返回解码后长度。
static size_t url_decode(char *s) {
    char *w = s;
    for (const char *r = s; *r; r++) {
        if (*r == '%' && hexval(r[1]) >= 0 && hexval(r[2]) >= 0) {
            *w++ = (char)((hexval(r[1]) << 4) | hexval(r[2]));
            r += 2;
        } else if (*r == '+') {
            *w++ = ' ';
        } else {
            *w++ = *r;
        }
    }
    *w = '\0';
    return (size_t)(w - s);
}

static void copy_bounded(char *dst, size_t dst_cap, const char *src) {
    size_t n = strlen(src);
    if (n >= dst_cap) n = dst_cap - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

bool totp_parse_uri(const char *uri, totp_account_t *acc) {
    if (!uri || !acc) return false;
    const char *PREFIX = "otpauth://totp/";
    size_t plen = strlen(PREFIX);
    if (strncmp(uri, PREFIX, plen) != 0) return false;

    memset(acc, 0, sizeof(*acc));
    acc->digits = 6;
    acc->period = 30;
    acc->alg = TOTP_ALG_SHA1;
    acc->used = 1;

    const char *p = uri + plen;
    const char *qmark = strchr(p, '?');

    // ---- label ----
    char label[160];
    size_t llen = qmark ? (size_t)(qmark - p) : strlen(p);
    if (llen >= sizeof(label)) llen = sizeof(label) - 1;
    memcpy(label, p, llen);
    label[llen] = '\0';
    url_decode(label);

    // label 形如 "Issuer:account"（issuer 不含 ':'）；无 ':' 时整串为 account
    char *colon = strchr(label, ':');
    if (colon) {
        *colon = '\0';
        copy_bounded(acc->issuer, sizeof(acc->issuer), label);
        copy_bounded(acc->name, sizeof(acc->name), colon + 1);
    } else {
        copy_bounded(acc->name, sizeof(acc->name), label);
    }

    // ---- query ----
    bool got_secret = false;
    if (qmark) {
        char query[384];
        copy_bounded(query, sizeof(query), qmark + 1);
        char *save = NULL;
        for (char *tok = strtok_r(query, "&", &save); tok; tok = strtok_r(NULL, "&", &save)) {
            char *eq = strchr(tok, '=');
            if (!eq) continue;
            *eq = '\0';
            char *key = tok;
            char *val = eq + 1;
            url_decode(val);
            if (ci_eq(key, "secret")) {
                int n = totp_base32_decode(val, acc->secret, sizeof(acc->secret));
                if (n <= 0) return false;
                acc->secret_len = (uint8_t)n;
                got_secret = true;
            } else if (ci_eq(key, "issuer")) {
                copy_bounded(acc->issuer, sizeof(acc->issuer), val);
            } else if (ci_eq(key, "algorithm")) {
                if (ci_eq(val, "SHA256")) acc->alg = TOTP_ALG_SHA256;
                else if (ci_eq(val, "SHA512")) acc->alg = TOTP_ALG_SHA512;
                else acc->alg = TOTP_ALG_SHA1;
            } else if (ci_eq(key, "digits")) {
                int d = atoi(val);
                if (d < 6) d = 6;
                if (d > 10) d = 10;
                acc->digits = (uint8_t)d;
            } else if (strcasecmp(key, "period") == 0) {
                int pd = atoi(val);
                if (pd < 15) pd = 15;
                if (pd > 255) pd = 255;
                acc->period = (uint8_t)pd;
            }
        }
    }
    if (!got_secret || acc->secret_len == 0) return false;
    if (acc->name[0] == '\0') copy_bounded(acc->name, sizeof(acc->name), "未命名");
    return true;
}

void totp_normalize_display(char *s) {
    if (!s) return;
    const char *r = s;      // 源指针
    char *w = s;            // 写指针（同缓冲，写 <= 读，安全）
    while (*r) {
        uint8_t c = (uint8_t)*r;
        if (c < 0x80) {
            *w++ = *r++;
        } else {
            // 跳过整个 UTF-8 序列（按前导字节判长度；截断时只吃剩余有效字节）
            size_t seq = 1;
            if ((c & 0xE0) == 0xC0) seq = 2;
            else if ((c & 0xF0) == 0xE0) seq = 3;
            else if ((c & 0xF8) == 0xF0) seq = 4;
            size_t i = 0;
            while (i < seq && r[i]) i++;
            r += i;
            *w++ = (char)0xC2;   // '·' UTF-8
            *w++ = (char)0xB7;
        }
    }
    *w = '\0';
}

// ===========================================================================
// NVS blob 序列化
// ===========================================================================
#define TOTP_BLOB_MAGIC   0xA5
#define TOTP_BLOB_VERSION 0x01

typedef struct {
    const uint8_t *p;
    size_t len;
    size_t pos;
} blob_reader;

static bool rd_u8(blob_reader *r, uint8_t *v) {
    if (r->pos + 1 > r->len) return false;
    *v = r->p[r->pos++];
    return true;
}

static bool rd_bytes(blob_reader *r, uint8_t *dst, size_t n) {
    if (r->pos + n > r->len) return false;
    memcpy(dst, r->p + r->pos, n);
    r->pos += n;
    return true;
}

typedef struct {
    uint8_t *p;
    size_t cap;
    size_t pos;
    bool overflow;
} blob_writer;

static void wr_u8(blob_writer *w, uint8_t v) {
    if (w->pos + 1 > w->cap) { w->overflow = true; return; }
    w->p[w->pos++] = v;
}

static void wr_bytes(blob_writer *w, const uint8_t *src, size_t n) {
    if (w->pos + n > w->cap) { w->overflow = true; return; }
    memcpy(w->p + w->pos, src, n);
    w->pos += n;
}

size_t totp_serialize(const totp_account_t *accounts, uint8_t count,
                      uint8_t *out, size_t out_cap) {
    if (!accounts || !out) return 0;
    if (count > TOTP_MAX_ACCOUNTS) count = TOTP_MAX_ACCOUNTS;
    blob_writer w = { out, out_cap, 0, false };
    wr_u8(&w, TOTP_BLOB_MAGIC);
    wr_u8(&w, TOTP_BLOB_VERSION);
    wr_u8(&w, count);
    for (uint8_t i = 0; i < count && !w.overflow; i++) {
        const totp_account_t *a = &accounts[i];
        if (!a->used) { wr_u8(&w, 0); continue; }   // 空槽：仅 name_len=0 标记
        size_t nl = strnlen(a->name, sizeof(a->name));
        size_t il = strnlen(a->issuer, sizeof(a->issuer));
        wr_u8(&w, (uint8_t)nl);
        wr_bytes(&w, (const uint8_t *)a->name, nl);
        wr_u8(&w, (uint8_t)il);
        wr_bytes(&w, (const uint8_t *)a->issuer, il);
        wr_u8(&w, a->secret_len);
        wr_bytes(&w, a->secret, a->secret_len);
        wr_u8(&w, a->digits);
        wr_u8(&w, a->period);
        wr_u8(&w, a->alg);
    }
    if (w.overflow) return 0;
    return w.pos;
}

int totp_deserialize(const uint8_t *blob, size_t len,
                     totp_account_t *accounts, uint8_t *count) {
    if (!blob || !accounts || !count) return -1;
    if (len < 3) return -1;
    if (blob[0] != TOTP_BLOB_MAGIC) return -1;
    if (blob[1] != TOTP_BLOB_VERSION) return -1;
    uint8_t n = blob[2];
    if (n > TOTP_MAX_ACCOUNTS) return -1;

    blob_reader r = { blob, len, 3 };
    for (uint8_t i = 0; i < n; i++) {
        totp_account_t *a = &accounts[i];
        memset(a, 0, sizeof(*a));
        uint8_t nl = 0;
        if (!rd_u8(&r, &nl)) return -1;
        if (nl == 0) { a->used = 0; continue; }     // 空槽
        if (nl >= sizeof(a->name)) return -1;
        if (!rd_bytes(&r, (uint8_t *)a->name, nl)) return -1;
        a->name[nl] = '\0';
        uint8_t il = 0;
        if (!rd_u8(&r, &il)) return -1;
        if (il >= sizeof(a->issuer)) return -1;
        if (!rd_bytes(&r, (uint8_t *)a->issuer, il)) return -1;
        a->issuer[il] = '\0';
        if (!rd_u8(&r, &a->secret_len)) return -1;
        if (a->secret_len == 0 || a->secret_len > sizeof(a->secret)) return -1;
        if (!rd_bytes(&r, a->secret, a->secret_len)) return -1;
        uint8_t digits = 0, period = 0, alg = 0;
        if (!rd_u8(&r, &digits)) return -1;
        if (!rd_u8(&r, &period)) return -1;
        if (!rd_u8(&r, &alg)) return -1;
        if (digits < 6 || digits > 10) return -1;
        if (period < 15) return -1;
        if (alg > TOTP_ALG_SHA512) return -1;
        a->digits = digits; a->period = period; a->alg = alg;
        a->used = 1;
    }
    *count = n;
    return (int)n;
}
