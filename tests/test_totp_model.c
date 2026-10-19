// TOTP 纯逻辑 host 测试：RFC 4648 base32 / RFC 6238 TOTP 官方测试向量 /
// otpauth URI 解析 / 显示名归一化 / NVS blob 序列化往返。
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "totp_model.h"

// RFC 6238 Appendix B 各算法使用不同长度的密钥（ASCII 明文）
static const char *RFC6238_KEY_SHA1   = "12345678901234567890";
static const char *RFC6238_KEY_SHA256 = "12345678901234567890123456789012";
static const char *RFC6238_KEY_SHA512 =
    "1234567890123456789012345678901234567890123456789012345678901234";

static const char *rfc6238_key(uint8_t alg) {
    switch (alg) {
        case TOTP_ALG_SHA256: return RFC6238_KEY_SHA256;
        case TOTP_ALG_SHA512: return RFC6238_KEY_SHA512;
        default:              return RFC6238_KEY_SHA1;
    }
}

static totp_account_t make_account(uint8_t alg, uint8_t digits, uint8_t period) {
    totp_account_t a;
    memset(&a, 0, sizeof(a));
    const char *k = rfc6238_key(alg);
    size_t klen = strlen(k);
    assert(klen <= sizeof(a.secret));
    memcpy(a.secret, k, klen);
    a.secret_len = (uint8_t)klen;
    a.alg = alg;
    a.digits = digits;
    a.period = period;
    a.used = 1;
    return a;
}

static void expect_code(const totp_account_t *a, time_t t, const char *want) {
    char got[16];
    totp_code(a, t, got, sizeof(got));
    if (strcmp(got, want) != 0) {
        printf("FAIL: t=%lld alg=%u digits=%u got=%s want=%s\n",
               (long long)t, a->alg, a->digits, got, want);
        fflush(stdout);
        assert(0);
    }
}

static void test_base32(void) {
    uint8_t out[32];

    // RFC 4648 标准向量
    assert(totp_base32_decode("", out, sizeof(out)) == 0);
    assert(totp_base32_decode("MY======", out, sizeof(out)) == 1 && out[0] == 'f');
    assert(totp_base32_decode("MZXQ====", out, sizeof(out)) == 2 && memcmp(out, "fo", 2) == 0);
    assert(totp_base32_decode("MZXW6===", out, sizeof(out)) == 3 && memcmp(out, "foo", 3) == 0);
    assert(totp_base32_decode("MZXW6YQ=", out, sizeof(out)) == 4 && memcmp(out, "foob", 4) == 0);
    assert(totp_base32_decode("MZXW6YTB", out, sizeof(out)) == 5 && memcmp(out, "fooba", 5) == 0);
    assert(totp_base32_decode("MZXW6YTBOI======", out, sizeof(out)) == 6 && memcmp(out, "foobar", 6) == 0);

    // 小写等价、空格容错
    assert(totp_base32_decode("mzxw6ytb", out, sizeof(out)) == 5 && memcmp(out, "fooba", 5) == 0);
    assert(totp_base32_decode("MZ XW\t6Y\nTB", out, sizeof(out)) == 5 && memcmp(out, "fooba", 5) == 0);

    // 非法字符与截断
    assert(totp_base32_decode("MZX1", out, sizeof(out)) == -1);   // '1' 不在字母表
    assert(totp_base32_decode("MZXW6YTBOI======", out, 3) == -1); // 输出空间不足

    // 常见 2FA 密钥长度（16/26/32 字符 → 10/16/20 字节）
    assert(totp_base32_decode("JBSWY3DPEHPK3PXP", out, sizeof(out)) == 10);
    puts("base32 tests: PASS");
}

// 编码是导出的基础（/export 与加密备份都要把 secret 编回文本），
// 必须与 decode 严格互逆，否则导出的密钥再导入就变了。
static void test_base32_encode(void) {
    char b32[64];

    // RFC 4648 标准向量反向
    assert(totp_base32_encode((const uint8_t *)"f", 1, b32, sizeof(b32)) == 2
           && strcmp(b32, "MY") == 0);
    assert(totp_base32_encode((const uint8_t *)"fo", 2, b32, sizeof(b32)) == 4
           && strcmp(b32, "MZXQ") == 0);
    assert(totp_base32_encode((const uint8_t *)"foo", 3, b32, sizeof(b32)) == 5
           && strcmp(b32, "MZXW6") == 0);
    assert(totp_base32_encode((const uint8_t *)"foob", 4, b32, sizeof(b32)) == 7
           && strcmp(b32, "MZXW6YQ") == 0);
    assert(totp_base32_encode((const uint8_t *)"fooba", 5, b32, sizeof(b32)) == 8
           && strcmp(b32, "MZXW6YTB") == 0);
    assert(totp_base32_encode((const uint8_t *)"foobar", 6, b32, sizeof(b32)) == 10
           && strcmp(b32, "MZXW6YTBOI") == 0);

    // 真实 2FA 密钥往返
    uint8_t sec[20], back[32];
    assert(totp_base32_encode(sec, 20, b32, sizeof(b32)) == 32);
    assert(totp_base32_decode(b32, back, sizeof(back)) == 20);
    assert(memcmp(sec, back, 20) == 0);

    // 全部长度 1..64 的往返（无填充编码对任意字节数都必须可逆）
    uint8_t src[64], dec[64];
    for (size_t i = 0; i < sizeof(src); i++) src[i] = (uint8_t)(i * 7 + 3);
    for (size_t n = 1; n <= sizeof(src); n++) {
        char e[128];              // 64 字节 → 104 字符
        int w = totp_base32_encode(src, n, e, sizeof(e));
        assert(w > 0);
        assert((size_t)w == (n / 5) * 8 + (((n % 5) * 8 + 4) / 5));
        assert(totp_base32_decode(e, dec, sizeof(dec)) == (int)n);
        assert(memcmp(src, dec, n) == 0);
    }

    // 容量不足必须返回 -1 而不是溢出
    assert(totp_base32_encode(src, 20, b32, 8) == -1);
    assert(totp_base32_encode(NULL, 5, b32, sizeof(b32)) == -1);
    assert(totp_base32_encode(src, 5, NULL, sizeof(b32)) == -1);
    puts("base32 encode/roundtrip tests: PASS");
}

static void test_totp_rfc6238(void) {
    // 8 位官方向量（三种算法全覆盖）
    struct { time_t t; uint8_t alg; const char *code; } vec8[] = {
        { 59,          TOTP_ALG_SHA1,   "94287082" },
        { 59,          TOTP_ALG_SHA256, "46119246" },
        { 59,          TOTP_ALG_SHA512, "90693936" },
        { 1111111109,  TOTP_ALG_SHA1,   "07081804" },
        { 1111111109,  TOTP_ALG_SHA256, "68084774" },
        { 1111111109,  TOTP_ALG_SHA512, "25091201" },
        { 1111111111,  TOTP_ALG_SHA1,   "14050471" },
        { 1111111111,  TOTP_ALG_SHA256, "67062674" },
        { 1111111111,  TOTP_ALG_SHA512, "99943326" },
        { 1234567890,  TOTP_ALG_SHA1,   "89005924" },
        { 1234567890,  TOTP_ALG_SHA256, "91819424" },
        { 1234567890,  TOTP_ALG_SHA512, "93441116" },
        { 2000000000,  TOTP_ALG_SHA1,   "69279037" },
        { 2000000000,  TOTP_ALG_SHA256, "90698825" },
        { 2000000000,  TOTP_ALG_SHA512, "38618901" },
        { 20000000000LL, TOTP_ALG_SHA1, "65353130" },
        { 20000000000LL, TOTP_ALG_SHA256, "77737706" },
        { 20000000000LL, TOTP_ALG_SHA512, "47863826" },
    };
    for (size_t i = 0; i < sizeof(vec8) / sizeof(vec8[0]); i++) {
        totp_account_t a = make_account(vec8[i].alg, 8, 30);
        expect_code(&a, vec8[i].t, vec8[i].code);
    }

    // 6 位 = 同向量取低 6 位（前导零必须保留）
    totp_account_t a6 = make_account(TOTP_ALG_SHA1, 6, 30);
    expect_code(&a6, 59,         "287082");
    expect_code(&a6, 1111111109, "081804");
    expect_code(&a6, 1234567890, "005924");   // 前导零
    expect_code(&a6, 2000000000, "279037");
    expect_code(&a6, 20000000000LL, "353130");

    // 同一 30s 窗口内不变，跨窗口变化（60/89 同属 counter=2，90 进入 counter=3）
    expect_code(&a6, 60, "359152");
    expect_code(&a6, 89, "359152");
    char w1[16], w2[16];
    totp_code(&a6, 89, w1, sizeof(w1));
    totp_code(&a6, 90, w2, sizeof(w2));
    assert(strcmp(w1, w2) != 0);

    // 60s 周期：窗口内不变、跨窗口变化（10/59 同属 counter=0，60 进入 counter=1）
    totp_account_t a60 = make_account(TOTP_ALG_SHA1, 8, 60);
    totp_code(&a60, 10, w1, sizeof(w1));
    totp_code(&a60, 59, w2, sizeof(w2));       // 10/59 同属 counter=0
    assert(strcmp(w1, w2) == 0);
    totp_code(&a60, 60, w2, sizeof(w2));       // 60 → counter=1
    assert(strcmp(w1, w2) != 0);

    // 剩余秒数
    assert(totp_remaining(59, 30) == 1);
    assert(totp_remaining(60, 30) == 30);
    assert(totp_remaining(89, 30) == 1);
    assert(totp_remaining(0, 30) == 30);
    assert(totp_remaining(59, 60) == 1);
    assert(totp_remaining(60, 60) == 60);
    puts("TOTP RFC 6238 tests: PASS");
}

static void test_parse_uri(void) {
    totp_account_t a;

    // Google 风格完整 URI（label 带 issuer 前缀 + query issuer 参数）
    assert(totp_parse_uri(
        "otpauth://totp/ACME%20Co:john@example.com?secret=JBSWY3DPEHPK3PXP"
        "&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30", &a));
    assert(strcmp(a.issuer, "ACME Co") == 0);
    assert(strcmp(a.name, "john@example.com") == 0);
    assert(a.secret_len == 10 && memcmp(a.secret, "Hello!\xde\xad\xbe\xef", 10) == 0);
    assert(a.alg == TOTP_ALG_SHA1 && a.digits == 6 && a.period == 30 && a.used == 1);

    // 无 query issuer：label 前缀当 issuer
    assert(totp_parse_uri("otpauth://totp/GitHub:sshnuke?secret=JBSWY3DPEHPK3PXP", &a));
    assert(strcmp(a.issuer, "GitHub") == 0);
    assert(strcmp(a.name, "sshnuke") == 0);
    assert(a.digits == 6 && a.period == 30 && a.alg == TOTP_ALG_SHA1);   // 默认值

    // 无冒号 label：query issuer 生效
    assert(totp_parse_uri("otpauth://totp/me@x.com?secret=JBSWY3DPEHPK3PXP&issuer=Dropbox", &a));
    assert(strcmp(a.issuer, "Dropbox") == 0);
    assert(strcmp(a.name, "me@x.com") == 0);

    // SHA256 / SHA512 / digits=8 / period=60
    assert(totp_parse_uri("otpauth://totp/A:b?secret=JBSWY3DPEHPK3PXP"
                          "&algorithm=sha512&digits=8&period=60", &a));
    assert(a.alg == TOTP_ALG_SHA512 && a.digits == 8 && a.period == 60);
    assert(totp_parse_uri("otpauth://totp/A:b?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256", &a));
    assert(a.alg == TOTP_ALG_SHA256);

    // 解析结果可直接算出正确码（RFC 向量密钥）
    assert(totp_parse_uri(
        "otpauth://totp/RFC:6238?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8", &a));
    expect_code(&a, 1111111109, "07081804");

    // 坏输入全部拒绝
    assert(!totp_parse_uri("https://example.com/totp/x?secret=JBSWY3DPEHPK3PXP", &a));
    assert(!totp_parse_uri("otpauth://hotp/A:b?secret=JBSWY3DPEHPK3PXP", &a));   // hotp 不支持
    assert(!totp_parse_uri("otpauth://totp/A:b", &a));                            // 无 secret
    assert(!totp_parse_uri("otpauth://totp/A:b?secret=!!!", &a));                 // 坏 base32
    assert(!totp_parse_uri("otpauth://totp/A:b?secret=", &a));                    // 空 secret
    puts("otpauth URI parse tests: PASS");
}

static void test_normalize(void) {
    char buf[64];

    // 纯 ASCII 原样
    strcpy(buf, "GitHub");
    totp_normalize_display(buf);
    assert(strcmp(buf, "GitHub") == 0);

    // 纯中文 → 每字一个 '·'
    strcpy(buf, "\xE5\xBE\xAE\xE4\xBF\xA1");                 // 微信
    totp_normalize_display(buf);
    assert(strcmp(buf, "\xC2\xB7\xC2\xB7") == 0);

    // 混合：ASCII 保留、中文替换
    strcpy(buf, "Git\xE5\xBE\xAE\xE4\xBF\xA1hub");           // Git微信hub
    totp_normalize_display(buf);
    assert(strcmp(buf, "Git\xC2\xB7\xC2\xB7hub") == 0);

    // 邮箱与常见 ASCII 符号不受影响
    strcpy(buf, "john.doe+test@example.com");
    totp_normalize_display(buf);
    assert(strcmp(buf, "john.doe+test@example.com") == 0);

    // emoji（4 字节序列）整体替换
    strcpy(buf, "\xF0\x9F\x8E\x89ok");                        // 🎉ok
    totp_normalize_display(buf);
    assert(strcmp(buf, "\xC2\xB7ok") == 0);

    // 空串与 NULL 安全
    strcpy(buf, "");
    totp_normalize_display(buf);
    assert(buf[0] == '\0');
    totp_normalize_display(NULL);
    puts("normalize tests: PASS");
}

static void test_serialize(void) {
    totp_account_t accs[TOTP_MAX_ACCOUNTS];
    memset(accs, 0, sizeof(accs));

    totp_account_t *a0 = &accs[0];
    totp_parse_uri("otpauth://totp/GitHub:sshnuke?secret=JBSWY3DPEHPK3PXP", a0);
    totp_account_t *a1 = &accs[1];
    totp_parse_uri("otpauth://totp/Google:me@x.com?secret=MZXW6YTBOI======"
                   "&algorithm=SHA256&digits=8&period=60", a1);

    uint8_t blob[512];
    size_t len = totp_serialize(accs, 2, blob, sizeof(blob));
    assert(len > 3);

    totp_account_t back[TOTP_MAX_ACCOUNTS];
    uint8_t count = 0;
    int n = totp_deserialize(blob, len, back, &count);
    assert(n == 2 && count == 2);

    assert(back[0].used && strcmp(back[0].issuer, "GitHub") == 0);
    assert(strcmp(back[0].name, "sshnuke") == 0);
    assert(back[0].secret_len == a0->secret_len);
    assert(memcmp(back[0].secret, a0->secret, a0->secret_len) == 0);
    assert(back[0].digits == 6 && back[0].period == 30 && back[0].alg == TOTP_ALG_SHA1);

    assert(back[1].used && strcmp(back[1].issuer, "Google") == 0);
    assert(back[1].secret_len == a1->secret_len);
    assert(back[1].digits == 8 && back[1].period == 60 && back[1].alg == TOTP_ALG_SHA256);

    // 往返后码一致
    char c1[16], c2[16];
    totp_code(a0, 1000000, c1, sizeof(c1));
    totp_code(&back[0], 1000000, c2, sizeof(c2));
    assert(strcmp(c1, c2) == 0);

    // 空库往返
    len = totp_serialize(accs, 0, blob, sizeof(blob));
    assert(len == 3);
    assert(totp_deserialize(blob, len, back, &count) == 0 && count == 0);

    // 空槽（used=0）不占序列化空间且可反序列化
    memset(accs, 0, sizeof(accs));
    totp_parse_uri("otpauth://totp/A:b?secret=JBSWY3DPEHPK3PXP", &accs[0]);
    accs[1].used = 0;
    totp_parse_uri("otpauth://totp/C:d?secret=JBSWY3DPEHPK3PXP", &accs[2]);
    len = totp_serialize(accs, 3, blob, sizeof(blob));
    assert(totp_deserialize(blob, len, back, &count) == 3);
    assert(back[0].used && !back[1].used && back[2].used);

    // 损坏 blob 一律拒绝
    assert(totp_deserialize(blob, 2, back, &count) == -1);        // 太短
    blob[0] = 0x00;
    assert(totp_deserialize(blob, len, back, &count) == -1);      // 坏 magic
    blob[0] = 0xA5; blob[1] = 0x99;
    assert(totp_deserialize(blob, len, back, &count) == -1);      // 坏版本
    blob[1] = 0x01; blob[2] = 0xFF;
    assert(totp_deserialize(blob, len, back, &count) == -1);      // count 越界
    blob[2] = 0x03;
    assert(totp_deserialize(blob, len - 1, back, &count) == -1);  // 截断

    // 序列化空间不足返回 0
    assert(totp_serialize(accs, 3, blob, 4) == 0);
    puts("serialize tests: PASS");
}

int main(void) {
    test_base32();
    test_base32_encode();
    test_totp_rfc6238();
    test_parse_uri();
    test_normalize();
    test_serialize();
    puts("all totp_model tests: PASS");
    return 0;
}
