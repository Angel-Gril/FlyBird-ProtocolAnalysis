#!/usr/bin/env python3
"""apex_fetch.py — 订阅抓取（纯协议，无需官方客户端 / 无需 netns / 无需关 swap）

服务端在同一账号下提供两条**互不重叠**的订阅线路，本脚本都支持：

  v2（主线路，默认）
      POST {API}/v2/auth/token                  api 证书         -> JWT + access_key
      GET  {API}/v2/feed/access-token           api 证书 + 裸JWT -> 套餐信息
      GET  {SUB}/v2/feed/download?access_key=   sub 证书         -> APXS
      本地解密：AES-256-CTR，key=k1，计数器 = nonce||0x00000002
      产物：完整 mihomo 配置（proxies + dns + 分组 + 规则）

  v1（遗留明文线路）
      POST {API}/api/v1/passport/auth/login     api 证书         -> token
      GET  {API}/api/v1/client/subscribe?token= api 证书 + apex UA
      -> 纯文本 URI（trojan / ss），无需任何解密
      产物：由 URI 渲染的 Clash 配置

用法：
    apex_fetch.py --config /etc/apex-fetch/config --out sub.yaml
    apex_fetch.py --config ... --source v1|v2|both
    apex_fetch.py --config ... --test            # 只验证，不落盘
    apex_fetch.py --config ... --raw-v1 raw.txt  # 额外导出 v1 原始文本
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

sys.path.insert(0, str(Path(__file__).resolve().parent))
import v1_legacy  # noqa: E402

# ---- APXS v2 格式常量 ----
APXS_MAGIC = b"APXS"
APXS_VERSION = 0x02
TRAILER = 16 + 64          # 尾部校验 + 签名（解密不需要）
KEY_APXS_DEFAULT = "fCA3jkvhXpLEpDVuqPstNUS/kXewk7yGL5o8Fbh3uSc="

DEFAULT_UA = "ua.net.fbclient.app.apex/v7.2.5"
DEFAULT_API = "https://fbaxapi.apiv2.a047.com"
DEFAULT_SUB = "https://fbaxsub.web.ak005.com"

SOURCES = ("v2", "v1", "both")


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


def decrypt_apxs(blob: bytes, key_b64: str) -> tuple[bytes, int, int]:
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
            raise RuntimeError("结果不是 YAML 映射")
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


# ------------------------------------------------------------------ 两条线路

def fetch_v2(api, sub, ua, email, password, api_cert, sub_cert, key_b64, insecure) -> str:
    """v2 主线路：登录 → access-token → APXS → 解密"""
    hdr = {"user-agent": ua, "accept": "application/json",
           "content-type": "application/json; charset=utf-8"}

    st, body = http(f"{api}/v2/auth/token", "POST", hdr,
                    json.dumps({"email": email, "password": password}).encode(),
                    cert=api_cert, insecure=insecure)
    if st != 200:
        raise RuntimeError(f"v2 登录失败 HTTP {st}（{len(body)}B）—— 检查账号密码与 api 证书")
    try:
        data = json.loads(body)["data"]
    except Exception:
        raise RuntimeError(f"v2 登录响应无法解析：{body[:120]!r}")
    auth_data, access_key = data.get("auth_data"), data.get("token")
    if not auth_data or not access_key:
        raise RuntimeError(f"v2 登录响应缺字段：{list(data.keys())}")
    log(f"v2 登录成功，access_key={access_key}")

    st, body = http(f"{api}/v2/feed/access-token", "GET",
                    {"user-agent": ua, "accept": "application/json",
                     "authorization": auth_data}, cert=api_cert, insecure=insecure)
    if st == 200:
        try:
            d2 = json.loads(body).get("data") or {}
            plan = (d2.get("plan") or {}).get("name", "")
            log(f"v2 账户：{d2.get('email', '?')} 套餐={plan} 已用={d2.get('d', 0)} 到期={d2.get('expired_at', 0)}")
            access_key = d2.get("token") or access_key
        except Exception:
            log("v2 账户信息解析失败（忽略）")
    else:
        log(f"v2 access-token HTTP {st}（继续尝试下载）")

    st, body = http(f"{sub}/v2/feed/download?access_key={access_key}", "GET",
                    {"user-agent": ua, "accept": "*/*"}, cert=sub_cert, insecure=insecure)
    if st != 200:
        raise RuntimeError(f"v2 下载失败 HTTP {st}（{len(body)}B）—— 检查 subscription 证书与 UA")
    log(f"v2 下载成功：{len(body)}B")

    plain, aes_id, sign_id = decrypt_apxs(body, key_b64)
    log(f"v2 解密成功：aesID={aes_id} signID={sign_id} 明文 {len(plain)}B")
    return plain.decode("utf-8", "replace")


def fetch_v1(api, ua, email, password, api_cert, insecure) -> tuple[str, dict]:
    """v1 遗留线路：登录 → 明文 URI 列表（无需解密）"""
    hdr = {"user-agent": ua, "accept": "application/json",
           "content-type": "application/json; charset=utf-8"}
    st, body = http(f"{api}/api/v1/passport/auth/login", "POST", hdr,
                    json.dumps({"email": email, "password": password}).encode(),
                    cert=api_cert, insecure=insecure)
    if st != 200:
        raise RuntimeError(f"v1 登录失败 HTTP {st}（{len(body)}B）—— 该部署可能已下线 v1 接口")
    try:
        data = json.loads(body)["data"]
    except Exception:
        raise RuntimeError(f"v1 登录响应无法解析：{body[:120]!r}")
    token = data.get("token")
    if not token:
        raise RuntimeError(f"v1 登录响应缺 token：{list(data.keys())}")
    log(f"v1 登录成功，token={token}")

    st, body = http(f"{api}/api/v1/client/subscribe?token={token}", "GET",
                    {"user-agent": ua, "accept": "*/*"}, cert=api_cert, insecure=insecure)
    if st != 200:
        raise RuntimeError(f"v1 订阅失败 HTTP {st}（{len(body)}B）—— 需要 api 证书 + apex UA")
    text = body.decode("utf-8", "replace")
    log(f"v1 拉取成功：{len(body)}B（明文，未加密）")
    return text, data


# ------------------------------------------------------------------------ CLI

def main() -> int:
    ap = argparse.ArgumentParser(description="订阅抓取：v2(APXS) / v1(明文) / both")
    ap.add_argument("--config", default="/etc/apex-fetch/config")
    ap.add_argument("--out", default=None)
    ap.add_argument("--source", choices=SOURCES, default=None,
                    help="v2=APXS 主线路（默认）；v1=遗留明文线路；both=合并")
    ap.add_argument("--test", action="store_true", help="只验证，不写文件")
    ap.add_argument("--insecure", action="store_true", help="跳过服务端证书校验（不推荐）")
    ap.add_argument("--raw-v1", default=None, help="把 v1 原始明文另存一份")
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
    source = (a.source or cfg.get("SOURCE") or "v2").lower()
    if source not in SOURCES:
        log(f"错误：SOURCE={source} 无效，可选 {SOURCES}")
        return 2

    certs = Path(cfg.get("CERT_DIR", "/etc/apex-fetch/certs"))
    api_cert = (cfg.get("API_CERT", str(certs / "api.crt")), cfg.get("API_KEY", str(certs / "api.key")))
    sub_cert = (cfg.get("SUB_CERT", str(certs / "sub.crt")), cfg.get("SUB_KEY", str(certs / "sub.key")))
    need = [("api", api_cert)] + ([("sub", sub_cert)] if source in ("v2", "both") else [])
    for name, pair in need:
        for f in pair:
            if not Path(f).exists():
                log(f"错误：缺少 {name} 证书文件 {f}")
                return 2

    log(f"线路：{source}")

    v2_text = None
    v1_text = None
    v1_proxies: list[dict] = []
    v1_meta: dict = {}

    if source in ("v2", "both"):
        try:
            v2_text = fetch_v2(api, sub, ua, email, password, api_cert, sub_cert,
                               key_b64, a.insecure)
        except Exception as e:
            if source == "v2":
                log(f"失败：{e}")
                return 1
            log(f"v2 失败（{e}），继续仅用 v1")

    if source in ("v1", "both"):
        try:
            v1_text, _ = fetch_v1(api, ua, email, password, api_cert, a.insecure)
            v1_proxies, v1_meta, skipped = v1_legacy.parse_plaintext(v1_text)
            v1_proxies, dns_skipped = v1_legacy.filter_globally_resolvable(v1_proxies)
            skipped += dns_skipped
            kinds: dict[str, int] = {}
            for p in v1_proxies:
                kinds[p["type"]] = kinds.get(p["type"], 0) + 1
            log(f"v1 解析：{len(v1_proxies)} 节点 {kinds}，跳过 {skipped}"
                f"，流量剩余={v1_meta.get('remaining', '?')} 到期={v1_meta.get('expire_at', '?')}")
            if not v1_proxies:
                raise RuntimeError("v1 节点没有全球可达的 DNS 地址（遗留线路可能已下线）")
            if a.raw_v1:
                Path(a.raw_v1).write_text(v1_text, encoding="utf-8")
                log(f"v1 原文已另存：{a.raw_v1}")
        except Exception as e:
            if source == "v1":
                log(f"失败：{e}")
                return 1
            log(f"v1 失败（{e}），继续仅用 v2")

    # ---- 组装 ----
    if source == "v2":
        if not v2_text:
            log("失败：没有 v2 内容")
            return 1
        text = v2_text
    elif source == "v1":
        if not v1_proxies:
            log("失败：没有解析到 v1 节点")
            return 1
        text = v1_legacy.build_config(v1_proxies, v1_meta)
    else:  # both
        if v2_text and v1_proxies:
            try:
                text = v1_legacy.merge_into_config(v2_text, v1_proxies)
                log(f"合并：v2 + v1 = {len(v1_proxies)} 个 v1 节点已并入")
            except Exception as e:
                log(f"合并失败（{e}），退化为仅 v2")
                text = v2_text
        else:
            text = v2_text or v1_legacy.build_config(v1_proxies, v1_meta)

    # ---- 校验 ----
    try:
        n, g, r = validate_yaml(text, min_nodes)
    except Exception as e:
        log(f"校验失败：{e}")
        return 1
    log(f"校验通过：{n} 节点 / {g} 分组 / {r} 条规则")

    if a.test:
        log("--test 模式，不写文件")
        return 0

    publish(text, out)
    log(f"已发布：{out}（{out.stat().st_size}B）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
