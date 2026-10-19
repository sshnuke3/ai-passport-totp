// main/totp_pin.c —— PIN 锁纯逻辑实现（只用 C 标准库，host 可测）。
#include "totp_pin.h"

#include <string.h>

bool totp_pin_format_valid(const char *pin)
{
    if (!pin) return false;
    size_t n = strlen(pin);
    if (n < TOTP_PIN_MIN_DIGITS || n > TOTP_PIN_MAX_DIGITS) return false;
    for (size_t i = 0; i < n; i++) {
        if (pin[i] < '0' || pin[i] > '9') return false;
    }
    return true;
}

uint64_t totp_pin_hash(const char *pin)
{
    // FNV-1a 64 位。offset basis / prime 都是标准常量。
    // （tests/test_totp_pin.c 用 FNV 官方向量锁死这两个常量，写错一位就会被抓到）
    uint64_t h = 14695981039346656037ULL;   // 0xcbf29ce484222325
    for (const unsigned char *p = (const unsigned char *)pin; *p; p++) {
        h ^= (uint64_t)*p;
        h *= 1099511628211ULL;             // 0x100000001b3
    }
    // 避免结果恰为 0（0 是「未设 PIN」的哨兵值）
    return h ? h : 1ULL;
}

bool totp_pin_locked(const totp_pin_state_t *st, int64_t now, int32_t *locked_remaining)
{
    if (locked_remaining) *locked_remaining = 0;
    if (!st || st->lock_until <= now) return false;
    if (locked_remaining) *locked_remaining = (int32_t)(st->lock_until - now);
    return true;
}

totp_pin_result_t totp_pin_submit(totp_pin_state_t *st, const char *pin, int64_t now)
{
    if (!st || !st->hash) return TOTP_PIN_FORMAT;    // 没启用 PIN
    if (totp_pin_locked(st, now, NULL)) return TOTP_PIN_LOCKED;
    if (!totp_pin_format_valid(pin)) return TOTP_PIN_FORMAT;

    if (totp_pin_hash(pin) == st->hash) {
        st->fails = 0;
        st->lock_until = 0;
        return TOTP_PIN_OK;
    }

    if (st->fails < 255) st->fails++;
    if (st->fails >= TOTP_PIN_MAX_FAILS) {
        st->lock_until = now + TOTP_PIN_LOCK_SECONDS;
        st->fails = 0;              // 锁定期结束后重新给 5 次机会
        return TOTP_PIN_LOCKED;
    }
    return TOTP_PIN_WRONG;
}

bool totp_pin_set(totp_pin_state_t *st, const char *pin)
{
    if (!st || !totp_pin_format_valid(pin)) return false;
    st->hash = totp_pin_hash(pin);
    st->fails = 0;
    st->lock_until = 0;
    return true;
}

void totp_pin_disable(totp_pin_state_t *st)
{
    if (!st) return;
    st->hash = 0;
    st->fails = 0;
    st->lock_until = 0;
}

const char *totp_pin_result_text(totp_pin_result_t r)
{
    switch (r) {
    case TOTP_PIN_OK:      return "已解锁";
    case TOTP_PIN_WRONG:   return "PIN 错误";
    case TOTP_PIN_LOCKED:  return "已锁定";
    default:               return "PIN 需 4-8 位数字";
    }
}