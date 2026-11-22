#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""node_dns_probe.py — 探测订阅下发的**私有 DoH** 能否解析节点域名。

⚠️ 这是**探测工具，不是生产组件**。截至 2026-11-23，本网络对该端点不可达，
   因此仓库不提供"自动解决节点超时"的实现。拿到可达网络后再用它复核。

背景：7.3.1 订阅的 `dns.proxy-server-nameserver` 里带一条按账号、按订阅轮换的 DoH URL：

    dns:
      proxy-server-nameserver:
        - "https://fbcg02.web.ak005.com/api-v2/<per-fetch-token>"

它与内核里的 `dns.apexBootstrapClient` + `purpose=doh` 证书对应；节点域名在公共 DNS 上是
CNAME → NXDOMAIN，必须靠这条通道解析。

用法：
    python node_dns_probe.py --sub sub.yaml --certs ./certs [--node axbtapp-….llguanglisf.com]
                             [--cert oss|doh|sub|api|none] [--insecure]

退出码：0 解析成功；1 全部尝试失败；2 参数问题。
"""
from __future__ import annotations

import argparse
import http.client
import os
import re
import socket
import ssl
import struct
import sys

try:
    import yaml
except ImportError:  # pragma: no cover
    print("需要 pyyaml：pip install pyyaml")
    raise SystemExit(2)


def extract_doh(sub_path: str) -> list[tuple[str, str]]:
    doc = yaml.safe_load(open(sub_path, encoding="utf-8"))
    dns = (doc or {}).get("dns") or {}
    urls = []
    for value in (dns.get("proxy-server-nameserver") or []):
        if isinstance(value, str) and value.startswith("https://"):
            m = re.match(r"https://([^/]+)(/.*)$", value)
            if m:
                urls.append((m.group(1), m.group(2)))
    return urls


def first_node(sub_path: str) -> str | None:
    doc = yaml.safe_load(open(sub_path, encoding="utf-8"))
    proxies = (doc or {}).get("proxies") or []
    return proxies[0].get("server") if proxies else None


def dns_query(name: str, qtype: int = 1, qid: int = 0x1234) -> bytes:
    q = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    for part in name.split("."):
        q += bytes([len(part)]) + part.encode()
    return q + b"\x00" + struct.pack(">HH", qtype, 1)


def parse_dns(buf: bytes):
    if len(buf) < 12:
        return None
    qd = struct.unpack(">H", buf[4:6])[0]
    an = struct.unpack(">H", buf[6:8])[0]
    i = 12
    for _ in range(qd):
        while i < len(buf) and buf[i]:
            i += buf[i] + 1
        i += 5
    out = []
    for _ in range(an):
        if i >= len(buf):
            break
        if buf[i] & 0xC0 == 0xC0:
            i += 2
        else:
            while i < len(buf) and buf[i]:
                i += buf[i] + 1
            i += 1
        rtype, _, ttl, rdlen = struct.unpack(">HHIH", buf[i:i + 10])
        i += 10
        rd = buf[i:i + rdlen]
        i += rdlen
        if rtype == 1 and rdlen == 4:
            out.append(("A", ".".join(str(b) for b in rd), ttl))
        elif rtype == 28 and rdlen == 16:
            out.append(("AAAA", socket.inet_ntop(socket.AF_INET6, rd), ttl))
        elif rtype == 5:
            j, labels = i - rdlen, []
            while j < len(buf) and buf[j]:
                n = buf[j]
                labels.append(buf[j + 1:j + 1 + n].decode("latin-1"))
                j += n + 1
            out.append(("CNAME", ".".join(labels), ttl))
    return out


def attempt(host, path, node, cert, insecure, method):
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if cert:
        ctx.load_cert_chain(cert[0], cert[1])
    c = http.client.HTTPSConnection(host, 443, context=ctx, timeout=10)
    if method == "GET":
        url = f"{path}?name={node}&type=A"
        c.request("GET", url, headers={"accept": "application/dns-json",
                                       "user-agent": "ua.net.fbclient.app.apex/7.3.1",
                                       "connection": "close"})
    else:
        c.request("POST", path, body=dns_query(node),
                  headers={"content-type": "application/dns-message",
                           "accept": "application/dns-message",
                           "user-agent": "ua.net.fbclient.app.apex/7.3.1",
                           "connection": "close"})
    r = c.getresponse()
    body = r.read(4000)
    c.close()
    return r.status, body


def main() -> int:
    ap = argparse.ArgumentParser(description="私有 DoH 解析探测（非生产组件）")
    ap.add_argument("--sub", required=True, help="解出来的订阅 YAML")
    ap.add_argument("--certs", default=None, help="证书目录（含 oss.crt/doh.crt/sub.crt/api.crt）")
    ap.add_argument("--cert", default="doh", choices=["none", "doh", "oss", "sub", "api"])
    ap.add_argument("--node", default=None, help="要解析的域名（默认取订阅第一个节点）")
    ap.add_argument("--insecure", action="store_true")
    a = ap.parse_args()

    node = a.node or first_node(a.sub)
    if not node:
        print("订阅里没有节点域名")
        return 2
    endpoints = extract_doh(a.sub)
    if not endpoints:
        print("订阅里没有可用的 https DoH（dns.proxy-server-nameserver 为空）")
        return 2

    print(f"节点域名: {node}")
    print(f"私有 DoH: {[(h, p[:24] + '…') for h, p in endpoints]}")
    cert = None
    if a.cert != "none":
        if not a.certs:
            print("需要 --certs")
            return 2
        cert = (os.path.join(a.certs, f"{a.cert}.crt"), os.path.join(a.certs, f"{a.cert}.key"))
        if not all(os.path.exists(f) for f in cert):
            print(f"缺少证书 {cert}")
            return 2

    ok = False
    for host, path in endpoints:
        for method in ("GET", "POST"):
            try:
                st, body = attempt(host, path, node, cert, a.insecure, method)
            except Exception as e:  # noqa: BLE001
                print(f"  [{method}] {host} -> {type(e).__name__}: {str(e)[:80]}")
                continue
            parsed = parse_dns(body) if method == "POST" and st == 200 else None
            print(f"  [{method}] {host} -> {st} {len(body)}B")
            if parsed:
                print("        解析:", parsed)
                ok = True
            elif st == 200:
                print("        body:", body[:160])
    print("\n结果:", "解析成功" if ok else "未成功（端点不可达或令牌过期）")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
