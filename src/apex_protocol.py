#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""apex_protocol.py — 飞鸟（Apex）面板/订阅协议的**参考实现**（层 ①）。

覆盖范围（与 docs/11-protocol-spec.md 一一对应）：

    §3  登录 / access-token / 下载（mTLS + UA，404 伪装语义）
    §4  APXS v2 信封：GCM 数据段、tag、Ed25519 签名
    §5  apex-config-v1：base64 → repeating-XOR → JSON，Ed25519 验签（k3）

设计原则：
  * 只用 `cryptography` 一个依赖；
  * 传输层可注入（`Transport`），便于离线单测与自建客户端；
  * 默认**验签 + 验 tag**，失败即抛；需要“只解密”时显式调用 `decrypt()`。

密钥（公开常量，见文档）：
    k1 = AES-256 数据键
    k2 = 订阅签名公钥（Ed25519）
    k3 = 配置签名公钥（Ed25519）
"""
from __future__ import annotations

import base64
import hashlib
import json
import struct
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ------------------------------------------------------------------ 常量
K1 = "fCA3jkvhXpLEpDVuqPstNUS/kXewk7yGL5o8Fbh3uSc="
K2 = "lmzs43izW9GHIOOq+avbwhWh0TG/ldT3kipGkrQ4RiE="
K3 = "xZ//fP0AfP+8yW4OAZOrcKHe7dO78+Gpwu1ewno/fd8="

MAGIC = b"APXS"
VERSION = 0x02
HEADER_LEN = 13          # magic(4) + ver(1) + aesID(4) + signID(4)
NONCE_LEN = 12
TAG_LEN = 16
SIG_LEN = 64
TRAILER_LEN = TAG_LEN + SIG_LEN
MIN_LEN = HEADER_LEN + NONCE_LEN + TRAILER_LEN + 1
MAX_LEN = 16_777_321

AAD_PREFIX = b"apex-sub-v2\x00"
SIG_PREFIX = b"apex-sub-sign-v2\x00"
CONFIG_PREFIX = b"apex-config-v1\x00"
CONFIG_FORMAT = "apex-config-v1"

DEFAULT_UA = "ua.net.fbclient.app.apex/7.3.1"


class ProtocolError(Exception):
    """协议层错误（长度/magic/版本/校验不通过）。"""


# ------------------------------------------------------------------ 工具
def b64d(s: str | bytes) -> bytes:
    s = s.encode() if isinstance(s, str) else s
    s = s.strip()
    return base64.b64decode(s + b"=" * (-len(s) % 4))


# ------------------------------------------------------------------ §4 APXS v2
def _ecb(key: bytes, data: bytes) -> bytes:
    return Cipher(algorithms.AES(key), modes.ECB()).encryptor().update(data)


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


def keystream_block(nonce: bytes) -> bytes:
    """数据段首块：AES-ECB(k1, nonce‖0x00000002)。等价于 CTR 的首块。"""
    return _ecb(b64d(K1), nonce + b"\x00\x00\x00\x02")


def build_aad(header25: bytes) -> bytes:
    """AAD = "apex-sub-v2\\0" ‖ body[0:25]（37 B）。"""
    if len(header25) != 25:
        raise ValueError("header25 必须是信封前 25 字节")
    return AAD_PREFIX + header25


def gcm_tag(nonce: bytes, ct: bytes, aad: bytes, key_b64: str = K1) -> bytes:
    key = b64d(key_b64)
    j0 = nonce + b"\x00\x00\x00\x01"
    s = _ghash(_ecb(key, b"\x00" * 16), aad, ct)
    return bytes(a ^ b for a, b in zip(_ecb(key, j0), s))


def parse(blob: bytes) -> dict:
    """只做结构性解析，不做校验。"""
    if len(blob) < MIN_LEN or len(blob) > MAX_LEN:
        raise ProtocolError(f"长度越界：{len(blob)}")
    if blob[:4] != MAGIC:
        raise ProtocolError(f"magic 不是 APXS：{blob[:4]!r}")
    if blob[4] != VERSION:
        raise ProtocolError(f"不支持的版本 0x{blob[4]:02x}")
    aes_id, sign_id = struct.unpack(">II", blob[5:13])
    body_end = len(blob) - TRAILER_LEN
    return {
        "aes_id": aes_id,
        "sign_id": sign_id,
        "nonce": blob[13:25],
        "ct": blob[25:body_end],
        "tag": blob[body_end:body_end + TAG_LEN],
        "sig": blob[len(blob) - SIG_LEN:],
        "header25": blob[:25],
        "signed_body": blob[:len(blob) - SIG_LEN],
    }


def decrypt(blob: bytes, key_b64: str = K1) -> bytes:
    p = parse(blob)
    d = Cipher(algorithms.AES(b64d(key_b64)),
               modes.CTR(p["nonce"] + b"\x00\x00\x00\x02")).decryptor()
    return d.update(p["ct"]) + d.finalize()


def verify(blob: bytes, aes_key_b64: str = K1, sign_key_b64: str = K2) -> dict:
    p = parse(blob)
    tag_ok = gcm_tag(p["nonce"], p["ct"], build_aad(p["header25"]), aes_key_b64) == p["tag"]
    sig_ok = False
    try:
        Ed25519PublicKey.from_public_bytes(b64d(sign_key_b64)).verify(
            p["sig"], SIG_PREFIX + p["signed_body"])
        sig_ok = True
    except InvalidSignature:
        pass
    return {"ok": tag_ok and sig_ok, "tag_ok": tag_ok, "sig_ok": sig_ok,
            "aes_id": p["aes_id"], "sign_id": p["sign_id"],
            "ct_len": len(p["ct"]), "length": len(blob)}


def build(plain: bytes, priv, aes_key_b64: str = K1, aes_id: int = 1, sign_id: int = 1,
          nonce: bytes | None = None) -> bytes:
    """构造信封（对称于 verify）。priv 为 Ed25519PrivateKey，供测试/联调使用。"""
    nonce = nonce or bytes(range(12))
    enc = Cipher(algorithms.AES(b64d(aes_key_b64)),
                 modes.CTR(nonce + b"\x00\x00\x00\x02")).encryptor()
    ct = enc.update(plain) + enc.finalize()
    header = MAGIC + bytes([VERSION]) + struct.pack(">II", aes_id, sign_id)
    body = header + nonce + ct
    tag = gcm_tag(nonce, ct, build_aad(body[:25]), aes_key_b64)
    sig = priv.sign(SIG_PREFIX + body + tag)
    return body + tag + sig


# ------------------------------------------------------------------ §5 apex-config-v1
def decode_config(body: bytes, xor_key: bytes | None = None) -> tuple[dict, dict, bytes]:
    """HTTP body = base64( XOR( JSON ) )；返回 (envelope, config, xor_key)。"""
    stage1 = b64d(body)
    if xor_key is None:
        xor_key = recover_config_key(stage1)
        if xor_key is None:
            raise ProtocolError("XOR 键反推失败，请显式提供 xor_key")
    env = json.loads(bytes(c ^ xor_key[i % len(xor_key)]
                           for i, c in enumerate(stage1)).decode("utf-8"))
    payload = env.get("payload", "")
    cfg = json.loads(b64d(payload.encode()).decode("utf-8")) if payload else env
    return env, cfg, xor_key


def recover_config_key(stage1: bytes) -> bytes | None:
    """用已知明文反推 repeating-XOR 键（键长必须 < 已知明文长度才可验证）。"""
    for kp in (CONFIG_PREFIX + b'payload":"eyJ', CONFIG_PREFIX + b"payload"):
        for klen in range(1, min(64, len(kp) - 2) + 1):
            key = bytes(stage1[i] ^ kp[i] for i in range(klen))
            if all(stage1[i] ^ key[i % klen] == kp[i] for i in range(len(kp))):
                return key
    return None


def config_sig_message(env: dict) -> bytes:
    return CONFIG_PREFIX + b64d(env.get("payload", "").encode())


def verify_config(env: dict, sign_key_b64: str = K3) -> bool:
    sig_b64 = env.get("signature")
    if not sig_b64:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(b64d(sign_key_b64)).verify(
            base64.b64decode(sig_b64), config_sig_message(env))
        return True
    except (InvalidSignature, ValueError):
        return False


# ------------------------------------------------------------------ §3 传输
class Transport:
    """最小传输抽象：给定 host/path/headers/mTLS 证书，返回 (status, body)。

    默认实现走标准库 HTTPS；自建客户端可替换为 requests/httpx/内部网关。
    """

    def __init__(self, cert: tuple[str, str] | None = None, verify: bool = True,
                 ca: str | None = None, timeout: int = 20):
        self.cert = cert
        self.verify = verify
        self.ca = ca
        self.timeout = timeout

    def request(self, method: str, host: str, path: str, headers: dict | None = None,
                body: bytes | None = None) -> tuple[int, bytes]:
        import http.client
        import ssl

        if self.verify:
            ctx = ssl.create_default_context(cafile=self.ca) if self.ca else ssl.create_default_context()
        else:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        if self.cert:
            ctx.load_cert_chain(*self.cert)
        c = http.client.HTTPSConnection(host, 443, context=ctx, timeout=self.timeout)
        try:
            c.request(method, path, body=body, headers=headers or {})
            r = c.getresponse()
            return r.status, r.read()
        finally:
            try:
                c.close()
            except Exception:
                pass


@dataclass
class ApexClient:
    api_host: str
    sub_host: str
    ua: str = DEFAULT_UA
    api_cert: tuple[str, str] | None = None
    sub_cert: tuple[str, str] | None = None
    verify_tls: bool = True
    ca: str | None = None
    extra_headers: dict = field(default_factory=dict)

    # -- 基础请求 ---------------------------------------------------
    def _call(self, method, cert, host, path, headers=None, body=None, ctype=None):
        h = {"User-Agent": self.ua, "Accept": "application/json", "Connection": "close"}
        if body is not None:
            h["Content-Type"] = ctype or "application/json; charset=utf-8"
        h.update(self.extra_headers)
        h.update(headers or {})
        return Transport(cert, self.verify_tls, self.ca).request(method, host, path, h, body)

    # -- §3.1 登录 ---------------------------------------------------
    def login(self, email: str, password: str) -> dict:
        st, body = self._call("POST", self.api_cert, self.api_host, "/v2/auth/token",
                              body=json.dumps({"email": email, "password": password}).encode())
        if st != 200:
            raise ProtocolError(f"登录失败 HTTP {st}：{body[:120]!r}")
        data = json.loads(body).get("data") or {}
        if not data.get("auth_data"):
            raise ProtocolError(f"登录响应缺 auth_data：{sorted(data)}")
        return data

    # -- §3.2 access-token（账户/套餐/订阅凭据）----------------------
    def access_token(self, jwt: str) -> dict:
        st, body = self._call("GET", self.api_cert, self.api_host, "/v2/feed/access-token",
                              headers={"Authorization": jwt})  # 裸 JWT，不加 Bearer
        if st != 200:
            raise ProtocolError(f"access-token 失败 HTTP {st}：{body[:120]!r}")
        return json.loads(body).get("data") or {}

    # -- §3.3 下载订阅 ----------------------------------------------
    def download(self, access_key: str, jwt: str | None = None) -> bytes:
        st, body = self._call("GET", self.sub_cert, self.sub_host,
                              f"/v2/feed/download?access_key={access_key}",
                              headers={"Accept": "*/*", **({"Authorization": jwt} if jwt else {})})
        if st != 200:
            raise ProtocolError(f"下载失败 HTTP {st}（{len(body)}B）")
        return body

    # -- 全链路 -----------------------------------------------------
    def fetch(self, email: str, password: str, require_signature: bool = True) -> tuple[str, dict]:
        auth = self.login(email, password)
        jwt = auth["auth_data"]
        info = self.access_token(jwt)
        key = info.get("token") or auth.get("token")
        if not key:
            raise ProtocolError("未拿到 access_key")
        blob = self.download(key, jwt)
        info_v = verify(blob)
        if require_signature and not info_v["ok"]:
            raise ProtocolError(f"订阅校验失败：{info_v}")
        text = decrypt(blob).decode("utf-8", "replace")
        return text, {"envelope": info_v, "account": {k: info.get(k) for k in
                                                      ("email", "plan_id", "u", "d", "expired_at")}}


# ------------------------------------------------------------------ 自检
def selftest() -> dict:
    """离线自检：构造 → 校验 → 解密 → 篡改拒绝；返回可用于文档的向量。"""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv = Ed25519PrivateKey.generate()
    pub = base64.b64encode(priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
    plain = b"mixed-port: 7890\nproxies: []\n"
    blob = build(plain, priv, nonce=bytes(range(12)))
    v = verify(blob, sign_key_b64=pub)
    assert v["ok"] and decrypt(blob) == plain, v

    bad = bytearray(blob)
    bad[-1] ^= 1
    assert not verify(bytes(bad), sign_key_b64=pub)["sig_ok"]
    bad2 = bytearray(blob)
    bad2[-80] ^= 1
    assert not verify(bytes(bad2), sign_key_b64=pub)["tag_ok"]
    return {"pub": pub, "blob_len": len(blob), "tag": blob[-80:-64].hex(),
            "keystream0": keystream_block(bytes(range(12))).hex()}


if __name__ == "__main__":
    import json as _json
    print(_json.dumps(selftest(), indent=2))
    print("selftest ok")
