#!/usr/bin/env bash
# cc.sh —— 本机没有 gcc/clang，用 zig cc 顶替（zig cc 兼容 gcc 参数）。
exec /c/Tools/zig-x86_64-windows-0.17.0/zig.exe cc "$@"
