<a href="README.md">**English**</a> · [简体中文](README.zh_CN.md)

<p align="center">
  <strong>把 FoloToy AI Passport 变成离线的两步验证码硬件令牌。</strong><br>
  不联网也能出码。密钥留在设备本地。
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-64748b?style=flat-square" alt="MIT 许可证"></a>
  <a href="docs/play-totp/changelog.zh_CN.md"><img src="https://img.shields.io/badge/版本-M2-14b8a6?style=flat-square" alt="版本 M2"></a>
  <img src="https://img.shields.io/badge/真机验收-未执行-e43b2f?style=flat-square" alt="真机验收未执行">
</p>

---

## 这是什么

一个跑在 FoloToy AI Passport（ESP32-C3）上的玩法（play）。
设备形态是 240×320 小屏 + 三个按键，没有触屏。

它解决一个具体问题：**手机在充电、放兜里、或者干脆没电的时候，
登录需要二次验证的网站怎么办？**

TotpPassport 的答案是不联网也能出码。密钥存在设备本地，
只在开机校时和录入账户时短暂用 Wi-Fi，平时彻底离线。

```
┌────────────────────────┐
│ 已校时 · 3 个账户        │
├────────────────────────┤
│ ● 1. GitHub             │
│        4 8 2 9 1 5      │
│ ● 2. Cloudflare        │
│        1 1 0 2 4 8      │
│   + 录入账户            │
│   重新校时              │
│   设置 PIN 锁           │
└────────────────────────┘
```

## 快速开始

1. 从 [Releases](https://github.com/sshnuke3/ai-passport-totp/releases) 下载整包固件
2. 用 FoloToy web-flasher 烧录，偏移填 `0x0`
   （**烧整包，不要单独烧 app 分区** —— 会覆盖 bootloader）
3. 进菜单选 TOTP，按提示连热点 `TotpPassport`，浏览器打开 `http://192.168.4.1`
4. 粘贴网站给的 `otpauth://` 链接，添加账户

详细步骤见 **[使用方法](docs/play-totp/usage.zh_CN.md)**。

## 功能

| | |
|---|---|
| 多账户 | 最多 24 个，支持 SHA1/256/512、6/8 位、30/60 秒周期 |
| PIN 锁 | 4-8 位，输错 5 次锁 5 分钟（断电重启仍锁着） |
| 自动息屏 | 无操作 30 秒息屏，需重新输 PIN |
| 未校时告警 | 时间不可信时显示红色角标，避免拿漂移的码去登录 |
| 离线导出 | 导出标准 otpauth 链接，可重新导入 |
| 加密备份 | PBKDF2(4096 轮) + AES-256-CBC，口令自设 |

## 文档

- [玩法介绍](docs/play-totp/intro.zh_CN.md) —— 它解决什么问题、边界在哪
- [使用方法](docs/play-totp/usage.zh_CN.md) —— 逐步操作 + 按键表 + 排障
- [更新日志](docs/play-totp/changelog.zh_CN.md)

## ⚠️ 请先读这段

**这不是 yubikey。** 它只能做 TOTP，**没有 U2F/FIDO 功能**。
需要 FIDO 硬件密钥请买 yubikey。

**它不是防硬件提取的。** 设备是透明外壳，密钥在 flash 里是明文，
物理拆芯片可以读出密钥。它的价值在于**隔离手机端的软件攻击面**
（钓鱼网站骗不走桌上这个没有无线能力的小盒子），不是防拆机。

**录入门户是开放网络。** SoftAP 无密码，任何连上的人都能打开网页，
所以 `/export`（明文导出全部密钥）**没有 PIN 保护**。
用完请立刻在设备上按 OK 关闭门户，明文导出文件请立刻转存并删除。

**PIN 挡不住拆芯片。** PIN 存的是 FNV-1a 混淆哈希，4 位只有 1 万种，
拿到 NVS dump 可离线爆破——这在设计预期内。PIN 只防顺手翻看和肩窥。

**加密备份的口令没有后门。** 丢了就解不开。

## 项目状态

- M1（核心）✅　M2（完整）✅
- **真机验收：未执行。** 全部功能只有主机侧测试覆盖，
  「与 Google Authenticator 同账户同时刻码值一致」这条关键锚点**还没在真机上比对过**。
- 已知缺口：加密备份**只有导出、没有导入端**，设备丢失后暂时无法从备份文件恢复。

## 开发

```bash
# 编译固件（需要 ESP-IDF 5.5.3）
idf.py set-target esp32c3 && idf.py build

# 主机侧测试（含 RFC 6238 官方向量、AES 官方向量、PIN 状态机）
tools/run_host_tests.sh

# 官方门禁
tools/validate.sh --all
```

TOTP 的纯逻辑层（`main/totp_model.c`）与 ESP-IDF / LVGL 完全解耦，
RFC 6238 的全部官方测试向量可在主机上验证。
加密部分的正确性用 FIPS-197 与 NIST SP 800-38A 官方向量锁死，
PBKDF2 与 Python `hashlib` 交叉验证。

## 许可

MIT。本项目派生自 [FoloToy/ai-passport](https://gitee.com/FoloToy/ai-passport)，同为 MIT 许可。