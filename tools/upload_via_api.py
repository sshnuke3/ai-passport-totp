# tools/upload_via_api.py —— 通过 GitHub Git Data API 上传仓库内容。
#
# 为什么需要它：本机网络到 api.github.com 通，但到 github.com 的 git 端点
# （443 的 git-upload-pack）连接会被重置，所以 git push 走不通。
# Git Data API 走的是 api.github.com，本机可达。
#
# 原理：git ls-files 列出文件 → 逐个建 blob → 建完整 tree → 建 commit
#      → 强制更新 main ref。三个提交会被压成一个（历史会平掉）。
#
# 用法：python3 tools/upload_via_api.py [--dry-run]
"""通过 GitHub API 上传仓库（绕过 git push 的网络限制）。"""
import base64
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request

REPO = "sshnuke3/ai-passport-totp"
API = f"https://api.github.com/repos/{REPO}"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CRED = os.path.expanduser("~/.git-credentials")


def token() -> str:
    with open(CRED, encoding="utf-8") as f:
        raw = f.read().strip()
    return "ghp_" + raw.split("ghp_")[1].split("@")[0]


TOKEN = token()


def api(method: str, path: str, body=None, raw: bytes = None):
    headers = {
        "Authorization": f"token {TOKEN}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "ai-passport-totp-uploader",
    }
    data = raw if raw is not None else (json.dumps(body).encode() if body else None)
    if raw is not None:
        headers["Content-Type"] = "application/octet-stream"
    elif body is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(f"{API}{path}", data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=120) as r:
        txt = r.read().decode()
        return json.loads(txt) if txt else {}


def tracked_files() -> list:
    out = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True,
                         text=True, check=True).stdout
    return [f for f in out.split("\n") if f.strip()]


def main() -> int:
    dry = "--dry-run" in sys.argv
    files = tracked_files()
    print(f"待上传 {len(files)} 个文件（git ls-files，不含被 gitignore 的构建产物）")
    if dry:
        for f in files[:15]:
            print("  ", f)
        print("  ...")
        return 0

    blobs = []
    total = 0
    for i, rel in enumerate(files, 1):
        with open(os.path.join(ROOT, rel), "rb") as f:
            content = f.read()
        total += len(content)
        blob = api("POST", "/git/blobs",
                   {"content": base64.b64encode(content).decode(),
                    "encoding": "base64"})
        blobs.append({"path": rel, "mode": "100644", "type": "blob",
                      "sha": blob["sha"]})
        if i % 60 == 0 or i == len(files):
            print(f"  blob {i}/{len(files)}")

    print(f"上传字节 {total:,}")
    tree = api("POST", "/git/trees", {"tree": blobs})

    parent = api("GET", "/git/ref/heads/main")["object"]["sha"]
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT,
                          capture_output=True, text=True, check=True).stdout.strip()

    commit = api("POST", "/git/commits", {
        "message": "TotpPassport M1+M2: 离线两步验证码玩法（PIN 锁 / 加密备份 / 导出）\n\n"
                   "由 Git Data API 上传（git push 在本机网络不可达）。\n"
                   "本地仓库保留了完整的三次提交历史。",
        "tree": tree["sha"],
        "parents": [parent],
    })

    api("PATCH", "/git/refs/heads/main", {"sha": commit["sha"], "force": True})
    print(f"\n完成。远端 main = {commit['sha'][:7]}（本地 HEAD {head[:7]}）")
    print(f"https://github.com/{REPO}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())