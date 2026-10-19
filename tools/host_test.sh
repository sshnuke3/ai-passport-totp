#!/usr/bin/env bash
# host tests 一键编译运行（zig cc 充当 host C 编译器）
# 用法：./tools/host_test.sh tests/test_totp_model.c [main/totp_pin.c ...]
# 不传实现源时，按测试文件名推断要一起编的模型层源文件。
set -e
cd "$(dirname "$0")/.."
ZIG=/c/Tools/zig-x86_64-windows-0.17.0/zig.exe
SRC="$1"; shift || true
if [[ $# -gt 0 ]]; then
    IMPLS=("$@")
else
    case "$(basename "$SRC" .c)" in
    test_totp_model) IMPLS=(main/totp_model.c) ;;
    test_totp_pin)   IMPLS=(main/totp_pin.c) ;;
    test_totp_crypto) IMPLS=(main/totp_crypto.c main/totp_model.c) ;;
    *) IMPLS=(main/totp_model.c) ;;
    esac
fi
OUT=/tmp/$(basename "$SRC" .c)
$ZIG cc -std=c11 -Wall -Wextra -Werror -I main "${IMPLS[@]}" "$SRC" -o "$OUT"
"$OUT"