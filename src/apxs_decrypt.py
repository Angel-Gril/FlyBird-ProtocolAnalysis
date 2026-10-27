"""apxs_decrypt.py — APXS v2 离线解密（纯协议，不需官方客户端）

格式（实测确认）：
    [0:4]    "APXS"
    [4]      版本 = 0x02
    [5:9]    BE u32 aesID
    [9:13]   BE u32 signID
    [13:25]  nonce (12B)
    [25:]    密文（AES-256-CTR，计数器 = nonce||0x00000002 起）
    尾部      16B + 64B（校验/签名，解密不需要）

密钥：内置常量 k1（base64）= AES-256 key
      即 xZ//... 为 OSS 模式密钥，fCA3... 为 APXS 密钥
"""
import base64
import sys
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util import Counter

# 内置常量（官方包 pp 中 0x276c8/0x276d0 附近）
KEY_APXS = "fCA3jkvhXpLEpDVuqPstNUS/kXewk7yGL5o8Fbh3uSc="
KEY_SIGN = "lmzs43izW9GHIOOq+avbwhWh0TG/ldT3kipGkrQ4RiE="
KEY_OSS = "xZ//fP0AfP+8yW4OAZOrcKHe7dO78+Gpwu1ewno/fd8="
TRAILER = 16 + 64


def decrypt(blob: bytes, key_b64: str = KEY_APXS) -> bytes:
    if blob[:4] != b"APXS":
        raise ValueError("不是 APXS")
    if blob[4] != 0x02:
        raise ValueError(f"不支持的版本 0x{blob[4]:02x}")
    aes_id = int.from_bytes(blob[5:9], "big")
    sign_id = int.from_bytes(blob[9:13], "big")
    nonce = blob[13:25]
    ct = blob[25:len(blob) - TRAILER]
    key = base64.b64decode(key_b64)
    ctr = Counter.new(32, prefix=nonce, initial_value=2, little_endian=False)
    return AES.new(key, AES.MODE_CTR, counter=ctr).decrypt(ct), aes_id, sign_id


if __name__ == "__main__":
    src = Path(sys.argv[1])
    dst = Path(sys.argv[2]) if len(sys.argv) > 2 else src.with_suffix(".yaml")
    raw = src.read_bytes()
    out, aes_id, sign_id = decrypt(raw)
    dst.write_bytes(out)
    print(f"{src} -> {dst}")
    print(f"  aesID={aes_id} signID={sign_id} 密文={len(raw)-25-TRAILER} 明文={len(out)}")
    print("  首行:", out.split(b"\n", 1)[0].decode("utf-8", "replace"))
