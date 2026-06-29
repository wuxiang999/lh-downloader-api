#!/usr/bin/env python3
"""
update.json 签名工具

用法:
    python3 sign_update.py <unsigned.json> [--output signed.json]

在 GitHub API 仓库中运行，对 update.json 进行 HMAC-SHA256 签名：
1. 读取 update.json (格式: { version_code: ..., ... })
2. 包装为 { data: {...}, ts: ..., sign: "..." }
3. 计算 HMAC-SHA256(data.ts, key)
4. 输出 signed.json

将 signed.json 上传到 GitHub 作为新的 update.json 即可生效。
"""

import sys
import json
import hmac
import hashlib
import base64
import time

# ====== 必须与 Android 端 SignedPayload.kt 中的密钥一致 ======
# 密钥: "LhD0wnl04d3rSgn3dP4yl04d!@#$%^&"
SIGN_KEY = b"LhD0wnl04d3rSgn3dP4yl04d!@#$%^&"


def sign_message(message: str) -> str:
    """HMAC-SHA256 签名，返回 Base64 URL-safe"""
    h = hmac.new(SIGN_KEY, message.encode("utf-8"), hashlib.sha256)
    sig = base64.urlsafe_b64encode(h.digest()).rstrip(b"=").decode("ascii")
    return sig


def sign_update(input_path: str, output_path: str = None):
    """读取 update.json 并签名"""
    with open(input_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    ts = int(time.time())
    data_str = json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    message = f"{data_str}.{ts}"
    signature = sign_message(message)

    signed = {
        "data": data,
        "sign": signature,
        "ts": ts
    }

    if output_path is None:
        output_path = input_path

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(signed, f, indent=2, ensure_ascii=False)

    print(f"✅ 签名完成")
    print(f"   数据: {input_path}")
    print(f"   输出: {output_path}")
    print(f"   时间戳: {ts}")
    print(f"   签名: {signature[:32]}...")
    print(f"\n   提交到 GitHub 后客户端将自动验证签名。")
    print(f"   注意: 时间戳窗口为 5 分钟，如果超时需要重新签名！")


def verify_update(input_path: str):
    """验证已签名的 update.json"""
    with open(input_path, "r", encoding="utf-8") as f:
        signed = json.load(f)

    data = signed.get("data")
    sign = signed.get("sign")
    ts = signed.get("ts")

    if not data or not sign or not ts:
        print("❌ 无效格式：缺少 data/sign/ts 字段")
        return False

    data_str = json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    message = f"{data_str}.{ts}"
    expected = sign_message(message)

    now = int(time.time())
    age = now - ts

    if sign == expected:
        print(f"✅ 签名验证通过")
        print(f"   时间戳: {ts} ({age} 秒前)")
        if age > 300:
            print(f"   ⚠️ 警告：时间戳已超过 5 分钟窗口，需要重新签名")
        return True
    else:
        print(f"❌ 签名验证失败！")
        print(f"   期望: {expected}")
        print(f"   实际: {sign}")
        return False


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法:")
        print("  python3 sign_update.py <file.json>         # 签名")
        print("  python3 sign_update.py --verify <file.json> # 验证")
        print("  python3 sign_update.py <file.json> -o <out> # 指定输出")
        sys.exit(1)

    if sys.argv[1] == "--verify":
        verify_update(sys.argv[2])
    else:
        input_file = sys.argv[1]
        output_file = None
        if len(sys.argv) > 2 and sys.argv[2] == "-o":
            output_file = sys.argv[3]
        sign_update(input_file, output_file)
