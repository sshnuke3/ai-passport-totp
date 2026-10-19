// tests/test_totp_pin.c —— PIN 锁逻辑的 host 测试。
//
// 覆盖：格式校验、哈希一致性、正确/错误分支、5 次锁定阈值、锁定到期放行、
// 剩余秒数、修改 PIN、关闭 PIN。
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "totp_pin.h"

static void test_format(void)
{
    assert(totp_pin_format_valid("1234"));
    assert(totp_pin_format_valid("00000000"));
    assert(totp_pin_format_valid("12345678"));
    assert(!totp_pin_format_valid("123"));        // 少于 4 位
    assert(!totp_pin_format_valid("123456789"));  // 多于 8 位
    assert(!totp_pin_format_valid("12a4"));       // 非数字
    assert(!totp_pin_format_valid(""));
    assert(!totp_pin_format_valid(NULL));
    assert(!totp_pin_format_valid(" 1234"));      // 含空格
    assert(!totp_pin_format_valid("1234 "));
    assert(!totp_pin_format_valid("1234\n"));
    puts("PIN format tests: PASS");
}

static void test_hash(void)
{
    uint64_t a = totp_pin_hash("1234");
    uint64_t b = totp_pin_hash("1234");
    uint64_t c = totp_pin_hash("1235");
    assert(a == b);            // 同输入同输出
    assert(a != c);            // 单字符差异即不同
    assert(a != 0);            // 0 是未设 PIN 的哨兵，哈希不能为 0
    assert(totp_pin_hash("1111") != 0);
    // FNV-1a 已知向量："a" 与 "foobar"（标准 64 位 FNV-1a 测试向量）
    assert(totp_pin_hash("a") == 0xaf63dc4c8601ec8cULL);
    assert(totp_pin_hash("foobar") == 0x85944171f73967e8ULL);
    puts("PIN hash tests: PASS");
}

static void test_ok_and_wrong(void)
{
    totp_pin_state_t st = { 0 };
    assert(totp_pin_set(&st, "1234"));
    assert(st.hash != 0);

    assert(totp_pin_submit(&st, "1234", 1000) == TOTP_PIN_OK);
    assert(st.fails == 0 && st.lock_until == 0);

    assert(totp_pin_submit(&st, "9999", 1000) == TOTP_PIN_WRONG);
    assert(st.fails == 1);
    assert(!totp_pin_locked(&st, 1000, NULL));

    // 输对后计数归零
    assert(totp_pin_submit(&st, "1234", 1000) == TOTP_PIN_OK);
    assert(st.fails == 0);
    puts("PIN ok/wrong branch tests: PASS");
}

static void test_lockout_threshold(void)
{
    totp_pin_state_t st = { 0 };
    assert(totp_pin_set(&st, "1234"));
    const int64_t now = 100000;

    for (int i = 1; i < TOTP_PIN_MAX_FAILS; i++) {
        assert(totp_pin_submit(&st, "0000", now) == TOTP_PIN_WRONG);
        assert(st.fails == (uint8_t)i);
    }
    // 第 5 次触发锁定
    assert(totp_pin_submit(&st, "0000", now) == TOTP_PIN_LOCKED);
    assert(st.lock_until == now + TOTP_PIN_LOCK_SECONDS);
    // 锁定后连**正确**的 PIN 也拒
    assert(totp_pin_submit(&st, "1234", now) == TOTP_PIN_LOCKED);
    assert(totp_pin_submit(&st, "1234", now + 1) == TOTP_PIN_LOCKED);
    puts("PIN lockout threshold tests: PASS");
}

static void test_locked_remaining(void)
{
    totp_pin_state_t st = { 0 };
    assert(totp_pin_set(&st, "1234"));
    const int64_t now = 5000;
    for (int i = 0; i < TOTP_PIN_MAX_FAILS; i++) {
        (void)totp_pin_submit(&st, "0000", now);
    }

    int32_t remain = 0;
    assert(totp_pin_locked(&st, now, &remain));
    assert(remain == TOTP_PIN_LOCK_SECONDS);

    assert(totp_pin_locked(&st, now + 299, &remain));
    assert(remain == 1);

    // 到点自动放行
    assert(!totp_pin_locked(&st, now + 300, &remain));
    assert(remain == 0);
    assert(totp_pin_submit(&st, "1234", now + 300) == TOTP_PIN_OK);

    // 锁定到期后失败计数已重置，重新给满 5 次
    assert(st.fails == 0);
    for (int i = 1; i < TOTP_PIN_MAX_FAILS; i++) {
        assert(totp_pin_submit(&st, "0000", now + 400) == TOTP_PIN_WRONG);
    }
    puts("PIN locked-remaining tests: PASS");
}

static void test_format_submit_and_disabled(void)
{
    totp_pin_state_t st = { 0 };
    assert(totp_pin_set(&st, "1234"));

    // 格式非法不消耗次数（否则误按上/下键就能把自己锁在外面）
    assert(totp_pin_submit(&st, "12", 1000) == TOTP_PIN_FORMAT);
    assert(st.fails == 0);
    assert(totp_pin_submit(&st, "abcd", 1000) == TOTP_PIN_FORMAT);
    assert(st.fails == 0);

    // 未启用 PIN 时提交一律拒绝（上层不该走到这里）
    totp_pin_state_t off = { 0 };
    assert(totp_pin_submit(&off, "1234", 1000) == TOTP_PIN_FORMAT);
    assert(!totp_pin_locked(&off, 1000, NULL));
    puts("PIN format-submit/disabled tests: PASS");
}

static void test_change_and_disable(void)
{
    totp_pin_state_t st = { 0 };
    assert(totp_pin_set(&st, "1234"));
    assert(totp_pin_submit(&st, "9999", 1000) == TOTP_PIN_WRONG);

    // 改 PIN 会清零失败计数与锁定
    assert(totp_pin_set(&st, "87654321"));
    assert(st.fails == 0 && st.lock_until == 0);
    assert(totp_pin_submit(&st, "1234", 1000) == TOTP_PIN_WRONG);   // 旧 PIN 失效
    assert(totp_pin_submit(&st, "87654321", 1000) == TOTP_PIN_OK);

    // 非法 PIN 不能覆盖已设的
    uint64_t keep = st.hash;
    assert(!totp_pin_set(&st, "123"));
    assert(st.hash == keep);

    totp_pin_disable(&st);
    assert(st.hash == 0 && st.fails == 0 && st.lock_until == 0);
    puts("PIN change/disable tests: PASS");
}

int main(void)
{
    test_format();
    test_hash();
    test_ok_and_wrong();
    test_lockout_threshold();
    test_locked_remaining();
    test_format_submit_and_disabled();
    test_change_and_disable();
    puts("all totp_pin tests: PASS");
    return 0;
}