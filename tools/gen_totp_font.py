#!/usr/bin/env python3
# TotpPassport 字库生成：从设备渲染文案自动抽取符号 → lv_font_conv 生成子集字库。
#
# 设计约束（来自 folotoy play-develop skill 的字库章节，全部是本仓库实测过的坑）：
#   1. 字体源必须是完整 SourceHanSansSC-Normal.otf；tests 下那个 NotoSansSC
#      是截断 stub，用了会静默全空白。
#   2. 用 -r 逐码位/连续段声明，不要用 --symbols（非 ASCII 会被整段丢弃）。
#   3. 必须 --no-compress：本工程 sdkconfig 关掉了 LV_USE_FONT_COMPRESSED，
#      RLE 位图取不到会整屏空白。
#   4. --lv-include lvgl.h：产物 #else 分支默认写 "lvgl/lvgl.h"，本仓库解析不到。
#   5. 只扫「设备真正渲染」的源文件（demo_totp.c 的 LVGL 文案），并剔除
#      ESP_LOG* 实参（串口走 UART，不经字体）与注释；运行期数据（账户名）不在
#      源码里，靠 totp_normalize_display 归一化成 '·'（U+00B7），以 RUNTIME_CHARS
#      显式声明并断言有字形。
#
# 用法：python tools/gen_totp_font.py
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "main" / "demo_totp.c"          # 唯一在设备上渲染中文的源文件
OUT_DIR = ROOT / "assets" / "fonts"
OTF = ROOT / "managed_components" / "lvgl__lvgl" / "scripts" / "built_in_font" / "SourceHanSansSC-Normal.otf"
FONT_CONV = Path("C:/Users/Administrator/.workbuddy/binaries/node/workspace/node_modules/lv_font_conv/lv_font_conv.js")
NODE = Path("C:/Users/Administrator/.workbuddy/binaries/node/versions/22.22.2-6/node.exe")

RUNTIME_CHARS = "·"     # 归一化骨架（0xC2 0xB7），账户名里的中文/emoji 都变成它
ASCII_RANGE = (0x20, 0x7E)

# ---------------------------------------------------------------- 源码抽取
def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    text = re.sub(r"//[^\n]*", " ", text)
    return text


def strip_logs(text: str) -> str:
    """整段删除 ESP_LOGx(...) 实参（串口日志不经 LVGL 字体，不该进字库）。"""
    pat = re.compile(r"\bESP_LOG[A-Z]*\s*\(")
    while True:
        m = pat.search(text)
        if not m:
            return text
        i = m.end() - 1          # '(' 的位置
        depth, j = 0, i
        while j < len(text):
            if text[j] == "(":
                depth += 1
            elif text[j] == ")":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        text = text[:m.start()] + " " + text[j + 1:]


def unescape(s: str) -> str:
    out, k = [], 0
    while k < len(s):
        if s[k] == "\\" and k + 1 < len(s):
            c = s[k + 1]
            mapping = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\", "0": "\0"}
            out.append(mapping.get(c, c))
            k += 2
        else:
            out.append(s[k])
            k += 1
    return "".join(out)


def extract_symbols():
    text = strip_logs(strip_comments(SRC.read_text(encoding="utf-8")))
    cps = set()
    # 字符串字面量（正则正确处理转义引号，不按裸引号配对）
    for m in re.finditer(r'"((?:[^"\\\n]|\\.)*)"', text):
        for ch in unescape(m.group(1)):
            cps.add(ord(ch))
    # 字符字面量
    for m in re.finditer(r"'((?:[^'\\\n]|\\.))'", text):
        cps.add(ord(unescape(m.group(1))))
    for ch in RUNTIME_CHARS:
        cps.add(ord(ch))
    # 过滤控制字符：'\0'/'%d' 之类字符字面量与转义不是可渲染字形
    cps = {cp for cp in cps if 0x20 <= cp <= 0x7E or cp > 0x7F}
    return cps


# ---------------------------------------------------------------- 区间压缩
def build_ranges(cps):
    """把码点集合压成连续区间（跨度 >64 的截断，避免误吃大段无用字形）。"""
    ranges = []
    start = prev = None
    for cp in sorted(cps):
        if start is None:
            start = prev = cp
            continue
        if cp == prev + 1 and cp - start <= 64:
            prev = cp
            continue
        ranges.append((start, prev))
        start = prev = cp
    if start is not None:
        ranges.append((start, prev))
    return ranges


def range_args(cps):
    args = []
    for lo, hi in build_ranges(cps):
        args += ["-r", f"0x{lo:X}-0x{hi:X}" if hi > lo else f"0x{lo:X}"]
    return args


# ---------------------------------------------------------------- 生成
def run_conv(size, cps, name):
    out = OUT_DIR / f"{name}.c"
    cmd = [
        str(NODE), str(FONT_CONV),
        "--font", str(OTF),
        "--size", str(size),
        "--bpp", "4",
        "--format", "lvgl",
        "--no-compress",
        "--lv-include", "lvgl.h",
        "--lv-font-name", name,
        *range_args(cps),
        "-o", str(out),
    ]
    print(f"[gen] {name}: {' '.join(cmd[4:])}")
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout)
        print(r.stderr)
        sys.exit(1)
    text = out.read_text(encoding="utf-8")
    if 'lvgl/lvgl.h' in text:
        # 双保险：万一 lv_font_conv 版本忽略了 --lv-include
        text = text.replace('#include "lvgl/lvgl.h"', '#include "lvgl.h"')
        out.write_text(text, encoding="utf-8")
        print(f"[gen] {name}: 已把 lvgl/lvgl.h 归一为 lvgl.h")
    print(f"[gen] {name}: {out.stat().st_size} bytes")


def main():
    if not OTF.exists():
        sys.exit(f"字体源缺失: {OTF}")
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    cps = extract_symbols()
    cjk = [cp for cp in cps if cp > 0x7F]
    print(f"[sym] 抽取 {len(cps)} 码点（非 ASCII {len(cjk)} 个）")

    # 字表入库归档（唯一事实来源）
    sym_file = OUT_DIR / "totp_font_symbols.txt"
    sym_file.write_text(
        "\n".join(f"0x{cp:04X}" for cp in sorted(cps)) + "\n", encoding="utf-8")
    print(f"[sym] 字表已归档 {sym_file}")

    run_conv(16, cps, "font_totp_16")
    # 大号码字体：数字 + 分组空格
    run_conv(44, set(range(0x30, 0x3A)) | {0x20}, "font_totp_44")
    print("[gen] 完成。记得跑 tools/check_totp_font.py 复验。")


if __name__ == "__main__":
    main()
