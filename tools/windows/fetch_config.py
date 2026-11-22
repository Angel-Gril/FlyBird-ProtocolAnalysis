#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fetch_config.py — 拉取并解码 fb_apexv2.json（远程配置）。

结论性的两件事（7.3.1 实测）：
  1) 配置 CDN 走 **oss 用途**的 mTLS 门禁：api / subscription 证书一律 404，oss 证书才 200。
  2) 层序是 base64( XOR( JSON ) )：先 base64 解码，再按 32 字节 repeating-XOR 还原。

用法:
    python fetch_config.py --certs C:\\rev\\creds --out cfg
    python fetch_config.py --certs ... --key CAQxDFqU0GFjI55caeVzZ9GdxzGQ8njL   # 已知键
    python fetch_config.py --body cfg\\raw.bin --out cfg                       # 只解码本地样本

不给 --key 时用已知明文 `{"format":"apex-config-v1"` 反推（需要 key 长度 < 26）。
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import socket
import ssl
import sys

UA = "ua.net.fbclient.app.apex/7.3.1"

# host -> (解析候选 IP, 路径)。IP 来自 DoH 复核（系统 DNS 在这些域名上会给出被污染的地址）。
TARGETS = [
    ("apisa-ax.cnossfile.com", ["52.69.163.183"], "/apos/fb_apexv2.json"),
    ("tcdn-ax.getxlx.com", ["222.186.134.196"], "/saos/apos/fb_apexv2.json"),
    ("cdno01-ax.llguanglisf.com", ["222.186.134.196"], "/apos/fb_apexv2.json"),
    ("ocdn01-ax.llguangli25o.com", ["103.236.73.19"], "/apos/fb_apexv2.json"),
]

KP = b'{"format":"apex-config-v1"'
# 更长的已知明文：足以验证 32 字节级键长（payload 紧跟其后，且以 base64 的 'eyJ' 起头）
KP_LONG = b'{"format":"apex-config-v1","payload":"eyJ'


def b64d(b: bytes) -> bytes:
    b = b.strip()
    return base64.b64decode(b + b"=" * (-len(b) % 4))


def xor(data: bytes, key: bytes) -> bytes:
    return bytes(c ^ key[i % len(key)] for i, c in enumerate(data))


def recover_key(ct: bytes, kps=(KP_LONG, KP)):
    """已知明文反推 repeating-XOR 键（键长必须 < 已知明文长度才可验证）。"""
    for kp in kps:
        for klen in range(1, min(64, len(kp) - 2) + 1):
            key = bytes(ct[i] ^ kp[i] for i in range(klen))
            if all(ct[i] ^ key[i % klen] == kp[i] for i in range(len(kp))):
                return key
    return None


def fetch(host: str, ip: str, path: str, cert: tuple[str, str]) -> bytes:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.load_cert_chain(cert[0], cert[1])
    sock = socket.create_connection((ip, 443), timeout=12)
    s = ctx.wrap_socket(sock, server_hostname=host)
    s.sendall((f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {UA}\r\n"
               f"Accept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n").encode())
    buf = b""
    while True:
        try:
            chunk = s.recv(65536)
        except Exception:
            break
        if not chunk:
            break
        buf += chunk
    s.close()
    head, _, body = buf.partition(b"\r\n\r\n")
    status = head.split(b"\r\n")[0].decode("latin-1") if head else "?"
    if " 200 " not in status:
        raise RuntimeError(f"{host}{path} -> {status} ({len(body)}B)")
    return body


def decode(body: bytes, key: bytes | None):
    stage1 = b64d(body)
    if key is None:
        key = recover_key(stage1)
        if key is None:
            raise RuntimeError("未能从已知明文反推 XOR 键（键长可能 ≥ 26，请用 --key 指定）")
        print(f"[+] 反推 XOR_KEY = {key.decode('latin-1')}  ({len(key)}B)")
    env = json.loads(xor(stage1, key).decode("utf-8"))
    payload = env.get("payload", "")
    cfg = json.loads(b64d(payload.encode()).decode("utf-8")) if payload else env
    return env, cfg, key


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--certs", help="含 oss.crt / oss.key 的目录")
    ap.add_argument("--out", default="cfg")
    ap.add_argument("--key", default=None, help="32 字节 XOR 键（明文）")
    ap.add_argument("--body", default=None, help="离线解码已有的原始体")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)

    if a.body:
        body = open(a.body, "rb").read()
        print(f"[i] 离线体 {a.body} ({len(body)}B)")
    else:
        if not a.certs:
            print("需要 --certs（含 oss.crt/oss.key）或 --body")
            return 2
        cert = (os.path.join(a.certs, "oss.crt"), os.path.join(a.certs, "oss.key"))
        body = None
        for host, ips, path in TARGETS:
            for ip in ips:
                try:
                    body = fetch(host, ip, path, cert)
                    print(f"[+] {host}{path} 200 ({len(body)}B)")
                    break
                except Exception as e:
                    print(f"[-] {host} @{ip}: {e}")
            if body:
                break
        if not body:
            print("全部镜像未取到")
            return 1

    env, cfg, key = decode(body, a.key.encode() if a.key else None)
    open(os.path.join(a.out, "raw.bin"), "wb").write(body)
    open(os.path.join(a.out, "envelope.json"), "w", encoding="utf-8").write(
        json.dumps(env, ensure_ascii=False, indent=2))
    p = os.path.join(a.out, "fb_apexv2.plain.json")
    open(p, "w", encoding="utf-8").write(json.dumps(cfg, ensure_ascii=False, indent=2))

    print(f"\n信封键: {list(env)}  format={env.get('format')}  "
          f"signature={'有' if env.get('signature') else '无'}")
    print(f"domains         : {cfg.get('domains')}")
    print(f"subscribe_domain: {cfg.get('subscribe_domain')}")
    print(f"路径映射        : {len(cfg.get('subscribe_path') or {})} 条")
    print(f"features        : {sorted((cfg.get('features') or {}).keys())}")
    print(f"-> {p}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
