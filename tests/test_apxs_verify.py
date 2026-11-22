import base64
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import apxs_verify as V

AES = base64.b64decode(V.DEFAULT_AES_KEY)


def build(plain: bytes, aes_id=1, sign_id=1, priv=None):
    priv = priv or Ed25519PrivateKey.generate()
    nonce = bytes(range(12))
    # 数据段：CTR(nonce||2)，与 GCM 数据段等价
    enc = Cipher(algorithms.AES(AES), modes.CTR(nonce + b"\x00\x00\x00\x02")).encryptor()
    ct = enc.update(plain) + enc.finalize()
    header = b"APXS" + b"\x02" + struct.pack(">II", aes_id, sign_id)
    body = header + nonce + ct
    aad = V.AAD_PREFIX + body[:25]
    tag = V.gcm_tag(AES, nonce, ct, aad)
    sig = priv.sign(V.SIG_PREFIX + body + tag)
    blob = body + tag + sig
    pub_b64 = base64.b64encode(priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
    return blob, pub_b64


def main():
    plain = b"mixed-port: 7890\nproxies: []\n"
    blob, pub = build(plain)

    info = V.verify(blob, V.DEFAULT_AES_KEY, pub)
    assert info["ok"], info
    assert info["tag_ok"] and info["sig_ok"], info
    assert V.decrypt(blob) == plain, "解密不一致"
    print("APXS 构造→校验→解密: ok")

    # 篡改 tag 必须失败
    bad = bytearray(blob)
    bad[-80] ^= 0xFF
    info = V.verify(bytes(bad), V.DEFAULT_AES_KEY, pub)
    assert not info["ok"] and not info["tag_ok"], info
    print("篡改 tag 被拒绝: ok")

    # 篡改签名必须失败
    bad2 = bytearray(blob)
    bad2[-1] ^= 0xFF
    info = V.verify(bytes(bad2), V.DEFAULT_AES_KEY, pub)
    assert not info["ok"] and not info["sig_ok"], info
    print("篡改签名被拒绝: ok")

    # magic / 长度 边界
    assert not V.verify(b"APXS\x02" + b"\x00" * 10, V.DEFAULT_AES_KEY, pub)["ok"]
    print("过短信封被拒绝: ok")

    # AAD 前缀必须带 NUL：去掉 NUL 后 tag 不应再匹配
    assert V.AAD_PREFIX.endswith(b"\x00") and V.SIG_PREFIX.endswith(b"\x00")
    print("前缀 NUL 约定: ok")


if __name__ == "__main__":
    main()
