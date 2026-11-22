#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""apxs_verify.py — APXS v2 全量校验（tag + 签名），7.3.1 真实信封实测通过。

完整规格（2026-11-23 由 Aotopsy 反汇编 + 真实信封回归确认）：

    偏移        长度   内容
    [0:4]       4     "APXS"
    [4]         1     版本 = 0x02
    [5:9]       4     BE u32 aesKeyID
    [9:13]      4     BE u32 signKeyID
    [13:25]     12    nonce
    [25:L-80]   n     AES-256-GCM 密文（数据段等价于 CTR，计数器 = nonce‖0x00000002）
    [L-80:L-64] 16    GCM tag
    [L-64:L]    64    Ed25519 签名

    AAD    = "apex-sub-v2\0"      ‖ body[0:25]
    tag    = AES-GCM(k1, nonce, ct, AAD)
    sig    = Ed25519(k2, "apex-sub-sign-v2\0" ‖ body[0:L-64])

关键细节（此前一直没对上的两处）：
  * 两个前缀都带**结尾 NUL**（`\0`），漏掉就永远验不过；
  * GCM 的 AAD 不是空，而是 `"apex-sub-v2\0" + body[0:25]`。

用法：
    python apxs_verify.py sub.apxs
    python apxs_verify.py sub.apxs --aes-key <b64> --sign-key <b64> --json
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import struct
import sys

DEFAULT_AES_KEY = "fCA3jkvhXpLEpDVuqPstNUS/kXewk7yGL5o8Fbh3uSc="
DEFAULT_SIGN_KEY = "lmzs43izW9GHIOOq+avbwhWh0TG/ldT3kipGkrQ4RiE="

AAD_PREFIX = b"apex-sub-v2\x00"
SIG_PREFIX = b"apex-sub-sign-v2\x00"
HEADER = 13
NONCE = 12
TRAILER = 16 + 64
MIN_LEN = HEADER + NONCE + TRAILER + 1
MAX_LEN = 16_777_321


def _gf_mul(x: int, y: int) -> int:
    z, v = 0, y
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= v
        v = (v >> 1) ^ 0xE1000000000000000000000000000000 if v & 1 else v >> 1
    return z


def _ghash(h: bytes, aad: bytes, ct: bytes) -> bytes:
    H = int.from_bytes(h, "big")
    y = 0
    for blk in [aad[i:i + 16].ljust(16, b"\x00") for i in range(0, len(aad), 16)]:
        y = _gf_mul(y ^ int.from_bytes(blk, "big"), H)
    for blk in [ct[i:i + 16].ljust(16, b"\x00") for i in range(0, len(ct), 16)]:
        y = _gf_mul(y ^ int.from_bytes(blk, "big"), H)
    lens = (len(aad) * 8).to_bytes(8, "big") + (len(ct) * 8).to_bytes(8, "big")
    return _gf_mul(y ^ int.from_bytes(lens, "big"), H).to_bytes(16, "big")


def _ecb(key: bytes, data: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    return Cipher(algorithms.AES(key), modes.ECB()).encryptor().update(data)


def gcm_tag(key: bytes, nonce: bytes, ct: bytes, aad: bytes) -> bytes:
    j0 = nonce + b"\x00\x00\x00\x01" if len(nonce) == 12 else _ghash(_ecb(key, b"\x00" * 16), b"", nonce)
    s = _ghash(_ecb(key, b"\x00" * 16), aad, ct)
    return bytes(a ^ b for a, b in zip(_ecb(key, j0), s))


def decrypt(blob: bytes, aes_key_b64: str = DEFAULT_AES_KEY) -> bytes:
    ct = blob[25:len(blob) - TRAILER]
    key = base64.b64decode(aes_key_b64)
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    d = Cipher(algorithms.AES(key), modes.CTR(blob[13:25] + b"\x00\x00\x00\x02")).decryptor()
    return d.update(ct) + d.finalize()


def verify(blob: bytes, aes_key_b64: str = DEFAULT_AES_KEY,
           sign_key_b64: str = DEFAULT_SIGN_KEY) -> dict:
    info: dict = {"length": len(blob), "sha256": hashlib.sha256(blob).hexdigest()}
    if len(blob) < MIN_LEN or len(blob) > MAX_LEN:
        info.update(ok=False, error=f"长度越界 {len(blob)}")
        return info
    if blob[:4] != b"APXS":
        info.update(ok=False, error=f"magic 不是 APXS: {blob[:4]!r}")
        return info
    if blob[4] != 0x02:
        info.update(ok=False, error=f"版本 0x{blob[4]:02x} 不支持")
        return info

    aes_id, sign_id = struct.unpack(">II", blob[5:13])
    nonce = blob[13:25]
    ct = blob[25:len(blob) - TRAILER]
    tag = blob[len(blob) - TRAILER:len(blob) - 64]
    sig = blob[len(blob) - 64:]

    aad = AAD_PREFIX + blob[:25]
    key = base64.b64decode(aes_key_b64)
    expected = gcm_tag(key, nonce, ct, aad)
    tag_ok = expected == tag

    sig_ok = False
    sig_err = None
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(sign_key_b64))
        pub.verify(sig, SIG_PREFIX + blob[:len(blob) - 64])
        sig_ok = True
    except InvalidSignature:
        sig_err = "Ed25519 验签失败"
    except Exception as e:  # noqa: BLE001
        sig_err = f"{type(e).__name__}: {e}"

    info.update({
        "version": blob[4], "aes_id": aes_id, "sign_id": sign_id,
        "nonce": nonce.hex(), "ct_len": len(ct),
        "tag": tag.hex(), "tag_expected": expected.hex(), "tag_ok": tag_ok,
        "sig_ok": sig_ok, "sig_error": sig_err,
        "aad": aad.hex(), "aad_len": len(aad),
    })
    info["ok"] = bool(tag_ok and sig_ok)
    return info


def main() -> int:
    ap = argparse.ArgumentParser(description="APXS v2 校验（GCM tag + Ed25519 签名）")
    ap.add_argument("file", help="APXS 文件")
    ap.add_argument("--aes-key", default=DEFAULT_AES_KEY)
    ap.add_argument("--sign-key", default=DEFAULT_SIGN_KEY)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--out", default=None, help="验通后把明文写到该路径")
    a = ap.parse_args()

    blob = open(a.file, "rb").read()
    info = verify(blob, a.aes_key, a.sign_key)
    if a.out and info["ok"]:
        open(a.out, "wb").write(decrypt(blob, a.aes_key))
        info["out"] = a.out
    if a.json:
        print(json.dumps(info, ensure_ascii=False, indent=2))
    else:
        print(f"文件 {a.file}  {info['length']:,} B")
        if "error" in info:
            print("错误:", info["error"])
        else:
            print(f"aesID={info['aes_id']} signID={info['sign_id']} ct={info['ct_len']:,} B")
            print(f"AAD  = {info['aad'][:48]}… ({info['aad_len']} B)")
            print(f"tag  = {'OK' if info['tag_ok'] else 'FAIL'}")
            print(f"签名 = {'OK' if info['sig_ok'] else 'FAIL'}" + (f" ({info['sig_error']})" if info['sig_error'] else ""))
    return 0 if info.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
