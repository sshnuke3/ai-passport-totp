#!/usr/bin/env python3
# TotpPassport 字库覆盖检查：按 LVGL 真实查表路径复验，双向 + 自证。
#
# 正向：assets/fonts/totp_font_symbols.txt 里的每个码位都能在生成的字库里
#       查到字形（gid != 0 且 adv_w != 0）——抓 stub 字体 / range_length=0 /
#       unicode_list 被写成绝对码点这三类「假绿」事故。
# 反向：main/demo_totp.c 当前 UI 文案里出现的码位都在字表内——抓「改了文案
#       忘了重跑字库」（字表是归档快照，与当前源码比对才发现漂移）。
#
# 自证（--mutate-* 两个开关必须让检查 FAIL，否则检查本身没在干活）：
#   --mutate-range-length-zero   把 cmap.range_length 改 0 → 必须 FAIL
#   --mutate-absolute-codepoints 把 unicode_list 换成绝对码点 → 必须 FAIL
#
# 用法：python tools/check_totp_font.py [--mutate-range-length-zero|--mutate-absolute-codepoints]
import re
import sys
from bisect import bisect_left
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from gen_totp_font import extract_symbols  # 与生成脚本同一套抽取逻辑

ROOT = Path(__file__).resolve().parent.parent
SYMBOLS = ROOT / "assets" / "fonts" / "totp_font_symbols.txt"

SPARSE_TINY = "SPARSE_TINY"


# ---------------------------------------------------------------- 字体解析
def strip_c_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    text = re.sub(r"//[^\n]*", " ", text)
    return text


def parse_font(path: Path, mutate_range_length_zero=False, mutate_absolute=False):
    text = strip_c_comments(path.read_text(encoding="utf-8"))

    # glyph_dsc：保留 id=0 的 reserved 项（gid 就是数组下标）
    m = re.search(r"glyph_dsc\[\]\s*=\s*\{(.*?)\};", text, flags=re.S)
    if not m:
        sys.exit(f"FAIL: {path.name} 找不到 glyph_dsc")
    glyphs = []
    for g in re.finditer(r"\{([^{}]*)\}", m.group(1)):
        adv = re.search(r"\.adv_w\s*=\s*(\d+)", g.group(1))
        glyphs.append(int(adv.group(1)) if adv else 0)

    # unicode_list（相对偏移；SPARSE_TINY 段，可能多段，按序收集）
    unicode_lists = []
    for um in re.finditer(r"unicode_list_\d+\[\]\s*=\s*\{(.*?)\};", text, flags=re.S):
        vals = [int(x, 16) if x.lower().startswith("0x") else int(x)
                for x in re.findall(r"0x[0-9a-fA-F]+|\b\d+\b", um.group(1))]
        unicode_lists.append(vals)

    # cmaps：range_start / range_length / glyph_id_start / list_length / type
    # unicode_list 可能是 NULL（FORMAT0_TINY 连续段直接映射，无稀疏表）
    cmaps = []
    for cm in re.finditer(r"\.range_start\s*=\s*(\d+),\s*\.range_length\s*=\s*(\d+),\s*"
                          r"\.glyph_id_start\s*=\s*(\d+),\s*"
                          r"\.unicode_list\s*=\s*(\w+|NULL),\s*"
                          r"\.glyph_id_ofs_list\s*=\s*(\w+|NULL),\s*"
                          r"\.list_length\s*=\s*(\d+),\s*\.type\s*=\s*(\w+)",
                          text):
        cmaps.append({
            "range_start": int(cm.group(1)),
            "range_length": int(cm.group(2)),
            "glyph_id_start": int(cm.group(3)),
            "list_name": cm.group(4),
            "list_length": int(cm.group(6)),
            "type": cm.group(7),
        })

    if not cmaps:
        sys.exit(f"FAIL: {path.name} 解析不到 cmaps")
    for c in cmaps:
        if mutate_range_length_zero:
            c["range_length"] = 0
        if mutate_absolute:
            c["list_name"] = c["list_name"] + "!abs"   # 换绝对码点表（见下）
    if mutate_absolute:
        # 相对表 + range_start 还原成绝对码点（经典豆腐坑）
        unicode_lists = [[v + 32 for v in unicode_lists[0]]] if unicode_lists else []
    return glyphs, unicode_lists, cmaps


def lookup(cp: int, glyphs, unicode_lists, cmaps):
    """复刻 LVGL get_glyph_dsc_id 的查表路径，返回 gid（0=找不到）。"""
    for c in cmaps:
        rcp = cp - c["range_start"]
        if rcp < 0 or rcp >= c["range_length"]:
            continue
        if "FORMAT0_TINY" in c["type"]:
            return c["glyph_id_start"] + rcp        # 连续段直接映射
        if SPARSE_TINY not in c["type"]:
            continue
        if not c["list_name"].startswith("unicode_list_"):
            continue
        idx = int(c["list_name"].split("!")[0].replace("unicode_list_", ""))
        if idx >= len(unicode_lists):
            continue
        ul = unicode_lists[idx][:c["list_length"]]
        # 严格升序前提下的二分
        pos = bisect_left(ul, rcp)
        if pos >= len(ul) or ul[pos] != rcp:
            continue
        return c["glyph_id_start"] + pos
    return 0


# ---------------------------------------------------------------- 主流程
def main():
    mutate = None
    if "--mutate-range-length-zero" in sys.argv:
        mutate = "range_length_zero"
    if "--mutate-absolute-codepoints" in sys.argv:
        mutate = "absolute_codepoints"

    if not SYMBOLS.exists():
        sys.exit(f"FAIL: 字表缺失 {SYMBOLS}（先跑 tools/gen_totp_font.py）")
    symbols = [int(x, 16) for x in SYMBOLS.read_text(encoding="utf-8").split()]

    failures = []

    # 每个字库承诺覆盖的码位集合
    expected = {
        "font_totp_16": set(symbols),                          # 全部 UI 文案 + 骨架
        "font_totp_44": {0x20} | set(range(0x30, 0x3A)),       # 数字 + 分组空格
    }

    for name in ("font_totp_16", "font_totp_44"):
        path = ROOT / "assets" / "fonts" / f"{name}.c"
        if not path.exists():
            sys.exit(f"FAIL: {path} 缺失（先跑 tools/gen_totp_font.py）")
        glyphs, uls, cmaps = parse_font(
            path,
            mutate_range_length_zero=(mutate == "range_length_zero"),
            mutate_absolute=(mutate == "absolute_codepoints"))

        # 正向：承诺集合里每个码位都查到字形，且 adv_w != 0
        hit = 0
        for cp in sorted(expected[name]):
            gid = lookup(cp, glyphs, uls, cmaps)
            if gid == 0:
                failures.append(f"[正向] {name}: 0x{cp:04X} 查不到字形")
                continue
            if gid >= len(glyphs) or glyphs[gid] == 0:
                failures.append(f"[正向] {name}: 0x{cp:04X} gid={gid} adv_w=0")
                continue
            hit += 1
        print(f"[ok] {name}: 字形 {len(glyphs)} 个，承诺码位命中 {hit}/{len(expected[name])}")

    # 反向：当前源码 UI 文案 ⊆ 归档字表
    current = extract_symbols()
    drifted = sorted(cp for cp in current if cp not in symbols)
    for cp in drifted:
        failures.append(f"[反向] 源码出现字表外码位 0x{cp:04X}"
                        f"（改了文案？重跑 tools/gen_totp_font.py）")

    # 运行期骨架字符必须有字形
    for cp in (0xB7,):
        if cp not in symbols:
            failures.append(f"[运行期] 骨架字符 0x{cp:04X} 不在字表")

    if failures:
        print(f"字体覆盖检查 FAIL（{len(failures)} 项）：")
        for f in failures[:20]:
            print("  " + f)
        sys.exit(1)
    print("字体覆盖检查 PASS：正向+反向+运行期骨架全绿")


if __name__ == "__main__":
    main()
