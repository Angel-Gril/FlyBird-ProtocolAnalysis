#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_protocol_vectors.py — docs/11 的 conformance 向量（离线、无网络、无真实凭据）。

向量文件：tests/vectors.json（由 tests/gen_vectors_json.py 生成，固定测试私钥 00..1f，
固定 nonce，因此 tag / 签名 / 密文全部可复现）。改动向量需同步 docs/11 §7。
"""
import base64
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))

import apex_protocol as P

V = json.load(open(os.path.join(HERE, "vectors.json"), encoding="utf-8"))


def test_envelope():
    blob = bytes.fromhex(V["envelope_hex"])
    assert len(blob) == V["envelope_len"] == 134

    p = P.parse(blob)
    assert (p["aes_id"], p["sign_id"]) == (1, 1)
    assert p["nonce"].hex() == V["nonce_hex"]
    assert p["tag"].hex() == V["tag_hex"]
    assert p["sig"].hex() == V["sig_hex"]
    assert P.build_aad(p["header25"]).hex() == V["aad_hex"]
    assert P.keystream_block(p["nonce"]).hex() == V["keystream_block0_hex"]

    assert P.decrypt(blob).hex() == V["plain_hex"]

    v = P.verify(blob, sign_key_b64=V["test_pubkey_b64"])
    assert v == {"ok": True, "tag_ok": True, "sig_ok": True, "aes_id": 1,
                 "sign_id": 1, "ct_len": 29, "length": 134}, v
    print("信封向量: ok（tag / 签名 / 解密 全部匹配）")


def test_envelope_tamper():
    blob = bytes.fromhex(V["envelope_hex"])
    bad_tag = bytearray(blob)
    bad_tag[-80] ^= 0xFF
    assert P.verify(bytes(bad_tag), sign_key_b64=V["test_pubkey_b64"])["tag_ok"] is False

    bad_sig = bytearray(blob)
    bad_sig[-1] ^= 0xFF
    assert P.verify(bytes(bad_sig), sign_key_b64=V["test_pubkey_b64"])["sig_ok"] is False

    short = blob[:50]
    try:
        P.parse(short)
    except P.ProtocolError:
        pass
    else:
        raise AssertionError("过短信封应被拒绝")

    # 前缀必须带 NUL：少一个字节就应验不过
    assert P.SIG_PREFIX.endswith(b"\x00") and P.AAD_PREFIX.endswith(b"\x00")
    print("篡改 / 边界拒绝: ok")


def test_config():
    env, cfg, key = P.decode_config(V["config_body_b64"].encode(),
                                    V["config_xor_key_ascii"].encode())
    assert cfg == json.loads(V["config_expect_json"]), cfg
    assert key == V["config_xor_key_ascii"].encode()
    assert env["payload"] == V["config_payload_b64"]
    assert env["signature"] == V["config_signature_b64"]
    assert P.verify_config(env, V["test_pubkey_b64"]) is True

    bad = dict(env)
    bad["signature"] = base64.b64encode(b"\x00" * 64).decode()
    assert P.verify_config(bad, V["test_pubkey_b64"]) is False
    print("配置向量: ok（解码 + 验签 + 全零签名拒绝）")


def test_build_deterministic():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(V["test_priv_seed_hex"]))
    pub = base64.b64encode(priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
    assert pub == V["test_pubkey_b64"]

    blob = P.build(bytes.fromhex(V["plain_hex"]), priv,
                   nonce=bytes.fromhex(V["nonce_hex"]))
    assert blob.hex() == V["envelope_hex"], "Ed25519 是确定性签名，构造结果应与向量一致"
    print("构造一致性: ok")


def main():
    test_envelope()
    test_envelope_tamper()
    test_config()
    test_build_deterministic()
    print("全部通过")


if __name__ == "__main__":
    main()
