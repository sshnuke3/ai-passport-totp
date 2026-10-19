#!/usr/bin/env bash
# TotpPassport 构建入口：固化 cd 与环境，避免每次手敲路径踩「cwd 重置」坑。
# 用法：bash tools/build.sh [idf.py 额外参数...]
set -e
cd "$(dirname "$0")/.."
PY=/c/Users/Administrator/.espressif/python_env/idf5.5_py3.13_env/Scripts/python.exe
IDF_RUN=/c/Users/Administrator/WorkBuddy/2026-10-19-09-55-57/idf-run.py
export IDF_PYTHON_ENV_PATH="C:\\Users\\Administrator\\.espressif\\python_env\\idf5.5_py3.13_env"
exec "$PY" "$IDF_RUN" build "$@"
