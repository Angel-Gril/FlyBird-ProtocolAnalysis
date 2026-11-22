import base64
import importlib.util
import json
import os
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = os.path.dirname(os.path.abspath(__file__))
MOD = os.path.join(HERE, "..", "tools", "windows", "fetch_config.py")
spec = importlib.util.spec_from_file_location("fetch_config", MOD)
fc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fc)


def make_env(priv, payload=b'{"a":1}'):
    p = base64.b64encode(payload).decode()
    msg = fc.CONFIG_SIG_PREFIX + payload
    sig = base64.b64encode(priv.sign(msg)).decode()
    return {"format": "apex-config-v1", "payload": p, "signature": sig}


def pub_of(priv):
    return base64.b64encode(priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()


def main():
    priv = Ed25519PrivateKey.generate()
    key = [("test", base64.b64decode(pub_of(priv)))]

    env = make_env(priv)
    status, detail = fc.verify_signature(env, key)
    assert status == "verified", (status, detail)
    print("正确签名 -> verified: ok")

    # 全零签名（审查中提到的绕过点）必须被拒
    zero = dict(env)
    zero["signature"] = base64.b64encode(b"\x00" * 64).decode()
    status, _ = fc.verify_signature(zero, key)
    assert status != "verified", status
    print("全零签名 -> 拒绝: ok")

    # 篡改 payload
    bad = dict(env)
    raw = bytearray(base64.b64decode(bad["payload"]))
    raw[0] ^= 0xFF
    bad["payload"] = base64.b64encode(bytes(raw)).decode()
    status, _ = fc.verify_signature(bad, key)
    assert status != "verified", status
    print("篡改 payload -> 拒绝: ok")

    # 长度不对的签名
    short = dict(env)
    short["signature"] = base64.b64encode(b"\x01" * 32).decode()
    status, detail = fc.verify_signature(short, key)
    assert status == "unverified" and "64" in detail, (status, detail)
    print("非 64 字节签名 -> 拒绝: ok")

    # 无 signature 字段按旧格式处理
    old = {"format": "apex-config-v1", "payload": env["payload"]}
    status, _ = fc.verify_signature(old, key)
    assert status == "absent", status
    print("旧格式（无签名）-> absent: ok")

    # 内置 k3 与错误公钥都不应验通过
    status, _ = fc.verify_signature(env, [("wrong", b"\x02" * 32)])
    assert status != "verified", status
    print("错误公钥 -> 拒绝: ok")


if __name__ == "__main__":
    main()
