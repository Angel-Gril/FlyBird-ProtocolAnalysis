#!/usr/bin/env python3
"""apxs_decrypt.py — APXS v2 离线解密（纯本地，不需要证书 / 账号 / 网络）

格式（实测确认）：
    [0:4]    "APXS"
    [4]      版本 = 0x02
    [5:9]    BE u32 aesID
    [9:13]   BE u32 signID
    [13:25]  nonce (12B)
    [25:]    密文（AES-256-CTR，计数器从 nonce||0x00000002 起）
    尾部      16B + 64B（校验/签名，解密不需要）

用法：
    python3 apxs_decrypt.py sample.apxs              # 输出 sample.yaml
    python3 apxs_decrypt.py sample.apxs out.yaml
    python3 apxs_decrypt.py -f sample.apxs           # 覆盖已存在文件
    python3 apxs_decrypt.py --key <base64> in.apxs   # 换密钥（轮换时用）

依赖：cryptography / pycryptodome / openssl 三者有其一即可。
"""
from __future__ import annotations

import argparse
import base64
import subprocess
import sys
from pathlib import Path

# 内置常量（从客户端二进制提取，全体用户共用）
KEY_APXS = "fCA3jkvhXpLEpDVuqPstNUS/kXewk7yGL5o8Fbh3uSc="   # AES-256
KEY_SIGN = "lmzs43izW9GHIOOq+avbwhWh0TG/ldT3kipGkrQ4RiE="   # Ed25519 公钥
KEY_OSS = "xZ//fP0AfP+8yW4OAZOrcKHe7dO78+Gpwu1ewno/fd8="    # OSS 模式
TRAILER = 16 + 64


def aes_ctr(key: bytes, iv: bytes, data: bytes) -> bytes:
    """AES-CTR 解密：cryptography → pycryptodome → openssl 三级回退"""
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        d = Cipher(algorithms.AES(key), modes.CTR(iv)).decryptor()
        return d.update(data) + d.finalize()
    except ImportError:
        pass
    try:
        from Crypto.Cipher import AES
        from Crypto.Util import Counter
        ctr = Counter.new(32, prefix=iv[:12], initial_value=2, little_endian=False)
        return AES.new(key, AES.MODE_CTR, counter=ctr).decrypt(data)
    except ImportError:
        p = subprocess.run(
            ["openssl", "enc", "-d", "-aes-256-ctr", "-K", key.hex(), "-iv", iv.hex()],
            input=data, capture_output=True, check=True)
        return p.stdout


def decrypt(blob: bytes, key_b64: str = KEY_APXS) -> tuple[bytes, int, int]:
    if len(blob) < 25 + TRAILER:
        raise ValueError(f"太短：{len(blob)} B（APXS 至少要 {25 + TRAILER} B）")
    if blob[:4] != b"APXS":
        raise ValueError(f"不是 APXS（前 4 字节 {blob[:4]!r}）")
    if blob[4] != 0x02:
        raise ValueError(f"不支持的版本 0x{blob[4]:02x}")
    aes_id = int.from_bytes(blob[5:9], "big")
    sign_id = int.from_bytes(blob[9:13], "big")
    nonce = blob[13:25]
    ct = blob[25:len(blob) - TRAILER]
    out = aes_ctr(base64.b64decode(key_b64), nonce + b"\x00\x00\x00\x02", ct)
    return out, aes_id, sign_id


def main() -> int:
    ap = argparse.ArgumentParser(description="APXS v2 离线解密（无需证书/账号/网络）")
    ap.add_argument("input", help="APXS 文件（.bin/.apxs/.dat 均可）")
    ap.add_argument("output", nargs="?", help="输出文件，默认同名 .yaml")
    ap.add_argument("-f", "--force", action="store_true", help="覆盖已存在的输出文件")
    ap.add_argument("--key", default=KEY_APXS, help="AES-256 密钥（base64），默认内置 k1")
    a = ap.parse_args()

    src = Path(a.input)
    if not src.exists():
        print(f"找不到文件：{src}", file=sys.stderr)
        return 2
    dst = Path(a.output) if a.output else src.with_suffix(".yaml")
    if dst.exists() and not a.force:
        print(f"输出已存在：{dst}（加 -f 覆盖）", file=sys.stderr)
        return 2

    try:
        raw = src.read_bytes()
        out, aes_id, sign_id = decrypt(raw, a.key)
    except Exception as e:
        print(f"解密失败：{type(e).__name__}: {e}", file=sys.stderr)
        return 1

    dst.write_bytes(out)
    print(f"{src} -> {dst}")
    print(f"  aesID={aes_id} signID={sign_id} 密文={len(raw) - 25 - TRAILER}B 明文={len(out)}B")
    head = out.split(b"\n", 1)[0].decode("utf-8", "replace")
    print(f"  首行: {head}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
