#!/usr/bin/env python3
"""apex_fetch.py — 飞鸟订阅纯协议抓取（无需官方客户端 / 无需 netns / 无需关 swap）

流程：
    POST {API}/v2/auth/token                 (api 客户端证书)      -> auth_data(JWT) + access_key
    GET  {API}/v2/feed/access-token          (api 证书 + 裸 JWT)    -> 账户/套餐信息
    GET  {SUB}/v2/feed/download?access_key=  (subscription 证书)    -> APXS
    本地解密：AES-256-CTR，key=k1，计数器 = nonce||0x00000002

用法：
    apex_fetch.py --config /etc/apex-fetch/config --out /var/lib/apex-fetch/sub.yaml
    apex_fetch.py --config ... --test          # 只验证连通性与证书，不落盘
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

# ---- APXS v2 格式常量 ----
APXS_MAGIC = b"APXS"
APXS_VERSION = 0x02
TRAILER = 16 + 64          # 尾部校验 + 签名（解密不需要）
KEY_APXS_DEFAULT = "fCA3jkvhXpLEpDVuqPstNUS/kXewk7yGL5o8Fbh3uSc="

DEFAULT_UA = "ua.net.fbclient.app.apex/v7.2.4"
DEFAULT_API = "https://fbaxapi.apiv2.a047.com"
DEFAULT_SUB = "https://fbaxsub.web.ak005.com"


def log(msg: str):
    print(f"{time.strftime('%H:%M:%S')} {msg}", flush=True)


def load_config(path: Path) -> dict:
    cfg = {}
    if not path.exists():
        return cfg
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        v = v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
            v = v[1:-1]
        cfg[k.strip()] = v
    return cfg


def http(url: str, method="GET", headers=None, body: bytes | None = None,
         cert: tuple[str, str] | None = None, insecure=False, timeout=30):
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if cert and cert[0]:
        ctx.load_cert_chain(cert[0], cert[1])
    req = urllib.request.Request(url, data=body, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def aes_ctr(key: bytes, iv: bytes, data: bytes) -> bytes:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        d = Cipher(algorithms.AES(key), modes.CTR(iv)).decryptor()
        return d.update(data) + d.finalize()
    except ImportError:
        p = subprocess.run(
            ["openssl", "enc", "-aes-256-ctr", "-K", key.hex(), "-iv", iv.hex()],
            input=data, capture_output=True, check=True)
        return p.stdout


def decrypt_apxs(blob: bytes, key_b64: str) -> bytes:
    if len(blob) < 25 + TRAILER or blob[:4] != APXS_MAGIC:
        raise RuntimeError(f"不是 APXS（前 4 字节 {blob[:4]!r}，长度 {len(blob)}）")
    if blob[4] != APXS_VERSION:
        raise RuntimeError(f"不支持的 APXS 版本 0x{blob[4]:02x}")
    aes_id = int.from_bytes(blob[5:9], "big")
    sign_id = int.from_bytes(blob[9:13], "big")
    nonce = blob[13:25]
    ct = blob[25:len(blob) - TRAILER]
    key = base64.b64decode(key_b64)
    plain = aes_ctr(key, nonce + b"\x00\x00\x00\x02", ct)
    return plain, aes_id, sign_id


def validate_yaml(text: str, min_nodes: int) -> tuple[int, int, int]:
    try:
        import yaml
    except ImportError:
        yaml = None
    if yaml:
        doc = yaml.safe_load(text)
        if not isinstance(doc, dict):
            raise RuntimeError("解密结果不是 YAML 映射")
        proxies = doc.get("proxies") or []
        groups = doc.get("proxy-groups") or []
        rules = doc.get("rules") or []
        if len(proxies) < min_nodes:
            raise RuntimeError(f"节点数 {len(proxies)} < 阈值 {min_nodes}")
        for p in proxies:
            for f in ("name", "type", "server", "port"):
                if f not in p:
                    raise RuntimeError(f"节点缺少字段 {f}: {p}")
        return len(proxies), len(groups), len(rules)
    n = len(re.findall(r"(?m)^\s*- name:", text))
    if n < min_nodes:
        raise RuntimeError(f"节点数 {n} < 阈值 {min_nodes}（无 PyYAML，按行数粗判）")
    return n, text.count("proxy-groups:"), text.count("rules:")


def publish(text: str, out: Path):
    out.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(out.parent), prefix=".sub-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, out)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="/etc/apex-fetch/config")
    ap.add_argument("--out", default=None)
    ap.add_argument("--test", action="store_true", help="只验证，不写文件")
    ap.add_argument("--insecure", action="store_true", help="跳过服务端证书校验（不推荐）")
    a = ap.parse_args()

    cfg = load_config(Path(a.config))
    email = cfg.get("APEX_EMAIL") or os.environ.get("APEX_EMAIL", "")
    password = cfg.get("APEX_PASSWORD") or os.environ.get("APEX_PASSWORD", "")
    if not email or not password:
        log("错误：缺少 APEX_EMAIL / APEX_PASSWORD")
        return 2

    api = cfg.get("API_BASE", DEFAULT_API).rstrip("/")
    sub = cfg.get("SUB_BASE", DEFAULT_SUB).rstrip("/")
    ua = cfg.get("UA", DEFAULT_UA)
    key_b64 = cfg.get("APXS_KEY", KEY_APXS_DEFAULT)
    min_nodes = int(cfg.get("MIN_NODES", "20"))
    out = Path(a.out or cfg.get("OUT", "/var/lib/apex-fetch/sub.yaml"))

    certs = Path(cfg.get("CERT_DIR", "/etc/apex-fetch/certs"))
    api_cert = (cfg.get("API_CERT", str(certs / "api.crt")), cfg.get("API_KEY", str(certs / "api.key")))
    sub_cert = (cfg.get("SUB_CERT", str(certs / "sub.crt")), cfg.get("SUB_KEY", str(certs / "sub.key")))
    for name, pair in (("api", api_cert), ("sub", sub_cert)):
        for f in pair:
            if not Path(f).exists():
                log(f"错误：缺少 {name} 证书文件 {f}")
                return 2

    hdr = {"user-agent": ua, "accept": "application/json",
           "content-type": "application/json; charset=utf-8"}

    # 1) 登录
    try:
        st, body = http(f"{api}/v2/auth/token", "POST", hdr,
                        json.dumps({"email": email, "password": password}).encode(),
                        cert=api_cert, insecure=a.insecure)
    except Exception as e:
        log(f"登录请求失败：{type(e).__name__} {e}")
        return 1
    if st != 200:
        log(f"登录失败：HTTP {st}（{len(body)}B）—— 检查账号密码与 api 证书")
        return 1
    try:
        data = json.loads(body)["data"]
    except Exception:
        log(f"登录响应无法解析：{body[:120]!r}")
        return 1
    auth_data = data.get("auth_data")
    access_key = data.get("token")
    if not auth_data or not access_key:
        log(f"登录响应缺字段：{list(data.keys())}")
        return 1
    log(f"登录成功，access_key={access_key}")

    # 2) 账户信息（附带刷新 access_key）
    st, body = http(f"{api}/v2/feed/access-token", "GET",
                    {"user-agent": ua, "accept": "application/json",
                     "authorization": auth_data}, cert=api_cert, insecure=a.insecure)
    if st == 200:
        try:
            d2 = json.loads(body).get("data") or {}
            plan = (d2.get("plan") or {}).get("name", "")
            log(f"账户：{d2.get('email', '?')} 套餐={plan} 已用={d2.get('d', 0)} 到期={d2.get('expired_at', 0)}")
            access_key = d2.get("token") or access_key
        except Exception:
            log("账户信息解析失败（忽略）")
    else:
        log(f"access-token 返回 HTTP {st}（继续尝试下载）")

    # 3) 下载 APXS
    st, body = http(f"{sub}/v2/feed/download?access_key={access_key}", "GET",
                    {"user-agent": ua, "accept": "*/*"}, cert=sub_cert, insecure=a.insecure)
    if st != 200:
        log(f"下载失败：HTTP {st}（{len(body)}B）—— 检查 subscription 证书与 UA")
        return 1
    log(f"下载成功：{len(body)}B")

    # 4) 解密
    try:
        plain, aes_id, sign_id = decrypt_apxs(body, key_b64)
    except Exception as e:
        log(f"解密失败：{e}")
        return 1
    text = plain.decode("utf-8", "replace")
    log(f"解密成功：aesID={aes_id} signID={sign_id} 明文 {len(plain)}B")

    # 5) 校验
    try:
        n, g, r = validate_yaml(text, min_nodes)
    except Exception as e:
        log(f"校验失败：{e}")
        return 1
    log(f"校验通过：{n} 节点 / {g} 分组 / {r} 条规则")

    if a.test:
        log("--test 模式，不写文件")
        return 0

    # 6) 原子发布
    publish(text, out)
    log(f"已发布：{out}（{out.stat().st_size}B）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
