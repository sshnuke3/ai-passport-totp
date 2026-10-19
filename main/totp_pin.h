// main/totp_pin.h —— PIN 锁的纯逻辑层（与 ESP-IDF 解耦，可 host tests 覆盖）。
//
// 威胁模型（见策划案第七节）：PIN 只挡「顺手翻看 / 肩窥」，不挡拆芯片取
// flash 明文密钥。因此这里刻意不做重运算 KDF —— 4-8 位数字的熵上限本身
// 就低，套 PBKDF2 只是给人「已加密」的错觉，却让设备每次校验多花几百毫秒。
// 存的是 FNV-1a 64 位混淆哈希，防的是「翻出 NVS 备份直接看到明文 PIN」。
//
// 计数器与锁定截止时间由上层持久化（NVS），本模块只管状态推进 —— 这样
// 断电重启不会因为 RAM 清零而把「已锁 5 分钟」变成「可无限试」。
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TOTP_PIN_MIN_DIGITS     4      // 策划案：4-8 位
#define TOTP_PIN_MAX_DIGITS     8
#define TOTP_PIN_MAX_FAILS      5      // 连错 5 次
#define TOTP_PIN_LOCK_SECONDS   300    // 锁 5 分钟

// PIN 校验结果。UI 据此区分「输错了」与「锁住了还剩多久」。
typedef enum {
    TOTP_PIN_OK = 0,
    TOTP_PIN_WRONG,             // 输错，且未达锁定阈值
    TOTP_PIN_LOCKED,            // 处于锁定期
    TOTP_PIN_FORMAT,            // 长度/字符不合法
} totp_pin_result_t;

// 输入缓冲校验：只接受 4-8 位 ASCII 数字，无前导空格。
bool totp_pin_format_valid(const char *pin);

// FNV-1a 64 位混淆哈希（输入含 '\0'）。hash=0 表示「未设 PIN」。
uint64_t totp_pin_hash(const char *pin);

// 可变状态机。UI 每次输完一位/提交都喂进来，锁定到期自动放行。
typedef struct {
    uint64_t hash;              // 正确 PIN 的哈希（0 = 未启用）
    uint8_t  fails;             // 连续错误次数
    int64_t  lock_until;        // 锁定截止 epoch 秒（<= now 即未锁）
} totp_pin_state_t;

// 是否处于锁定期；locked_remaining 返回剩余秒数（未锁为 0）。
bool totp_pin_locked(const totp_pin_state_t *st, int64_t now, int32_t *locked_remaining);

// 提交一次输入。正确则清零计数器；错误则累加，达阈值写入锁定截止时间。
totp_pin_result_t totp_pin_submit(totp_pin_state_t *st, const char *pin, int64_t now);

// 设置/修改 PIN（须先校验格式）。会清零失败计数与锁定。
bool totp_pin_set(totp_pin_state_t *st, const char *pin);

// 关闭 PIN 锁（st->hash 置 0）。
void totp_pin_disable(totp_pin_state_t *st);

// 结果的中文短描述（UI 直接用）。
const char *totp_pin_result_text(totp_pin_result_t r);

#ifdef __cplusplus
}
#endif