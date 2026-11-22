#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""node_dns_probe.py — 探测订阅下发的**私有 DoH** 能否解析节点域名。

⚠️ 这是**探测工具，不是生产组件**。截至 2026-11-23：
   本网络对该端点 TCP 层就不通（`103.239.185.80` 的 80/443/8443/8080 全超时），
   因此仓库不提供"自动解决节点超时"的实现。拿到可达网络后再用它复核。

背景与已确认的事实
------------------
* 订阅 `dns.proxy-server-nameserver` 里带一条按账号、按订阅轮换的 DoH URL：
      dns:
        proxy-server-nameserver:
          - "https://fbcg02.web.ak005.com/api-v2/<per-fetch-token>"
* 该主机的 CNAME 链：`fbcg02.web.ak005.com` → `doh-aws.llguangli25n.com`
  → `dsapi-sdcm02.llguanglisf.com` → `103.239.185.80`（AAAA 为空）。
* 7.3.1 内核里没有 `/api-v2/` 字面量 → **URL 完全由配置驱动**，不存在隐藏端点；
  相关实现是 `dns.apexDohTLS`（加载 `purpose=doh` 证书）+ `dns.(*dnsOverHTTPS).createClient.apexDohRedirect`
  + 字面量 `application/dns-message` → **RFC8484 POST over mTLS**（HTTP/1.1 与 HTTP/2 都可能）。
* 节点域名在公共 DNS 上是 CNAME → NXDOMAIN，必须靠这条通道。

用法
----
    python node_dns_probe.py --sub sub.yaml --certs ./certs
    python node_dns_probe.py --sub sub.yaml --certs ./certs --http2
    python node_dns_probe.py --sub sub.yaml --certs ./certs --cert none --node <域名>

退出码：0 解析成功；1 全部尝试失败；2 参数问题。
"""
from __future__ import annotations

import argparse
import base64
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


# ---------------------------------------------------------------- 订阅解析
def load_sub(path: str) -> dict:
    return yaml.safe_load(open(path, encoding="utf-8")) or {}


def extract_doh(doc: dict) -> list[tuple[str, str]]:
    dns = doc.get("dns") or {}
    urls = []
    for value in (dns.get("proxy-server-nameserver") or []):
        if isinstance(value, str) and value.startswith("https://"):
            m = re.match(r"https://([^/]+)(/.*)$", value)
            if m:
                urls.append((m.group(1), m.group(2)))
    return urls


def first_node(doc: dict) -> str | None:
    proxies = doc.get("proxies") or []
    return proxies[0].get("server") if proxies else None


# ---------------------------------------------------------------- DNS 报文
def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def dns_query(name: str, qtype: int = 1, qid: int = 0) -> bytes:
    q = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    for part in name.split("."):
        q += bytes([len(part)]) + part.encode()
    return q + b"\x00" + struct.pack(">HH", qtype, 1)


def parse_dns(buf: bytes):
    if len(buf) < 12:
        return None
    qd, an = struct.unpack(">HH", buf[4:8])
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


# ---------------------------------------------------------------- 传输
def tls_ctx(cert, insecure: bool):
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if cert:
        ctx.load_cert_chain(cert[0], cert[1])
    return ctx


def http1(host, path, node, cert, insecure, qtype=28):
    """GET ?dns=<base64url(wireformat)> —— 与官方客户端一致。qtype: 28=AAAA, 1=A。"""
    ctx = tls_ctx(cert, insecure)
    query = dns_query(node, qtype=qtype)
    c = http.client.HTTPSConnection(host, 443, context=ctx, timeout=10)
    c.request("GET", f"{path}?dns={b64url(query)}",
              headers={"accept": "application/dns-message",
                       "user-agent": "ua.net.fbclient.app.apex/7.3.1",
                       "connection": "close"})
    r = c.getresponse()
    body = r.read(4000)
    c.close()
    return r.status, body, None


def http2(host, path, node, cert, insecure):
    """按 mihomo 的形态发：HTTP/2 + mTLS + POST application/dns-message。"""
    try:
        import h2.config
        import h2.connection
        import h2.events
    except ImportError:
        return None, b"", "缺 h2 库（pip install h2）"
    ctx = tls_ctx(cert, insecure)
    ctx.set_alpn_protocols(["h2"])
    try:
        sock = socket.create_connection((host, 443), timeout=10)
        s = ctx.wrap_socket(sock, server_hostname=host)
    except Exception as e:  # noqa: BLE001
        return None, b"", f"{type(e).__name__}: {str(e)[:80]}"
    conn = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=True))
    conn.initiate_connection()
    s.sendall(conn.data_to_send())
    conn.send_headers(1, [(":method", "GET"), (":scheme", "https"), (":authority", host),
                          (":path", f"{path}?dns={b64url(dns_query(node, qtype=28))}"),
                          ("accept", "application/dns-message"),
                          ("user-agent", "ua.net.fbclient.app.apex/7.3.1")],
                      end_stream=True)
    s.sendall(conn.data_to_send())
    status, body, done = None, b"", False
    for _ in range(20):
        try:
            data = s.recv(65536)
        except Exception:
            break
        if not data:
            break
        for ev in conn.receive_data(data):
            if isinstance(ev, h2.events.ResponseReceived):
                status = dict(ev.headers).get(":status")
            elif isinstance(ev, h2.events.DataReceived):
                body += ev.data
                conn.acknowledge_received_data(ev.flow_controlled_length, ev.stream_id)
            elif isinstance(ev, h2.events.StreamEnded):
                done = True
        s.sendall(conn.data_to_send())
        if done:
            break
    s.close()
    return status, body, None


def main() -> int:
    ap = argparse.ArgumentParser(description="私有 DoH 解析探测（非生产组件）")
    ap.add_argument("--sub", required=True, help="解出来的订阅 YAML")
    ap.add_argument("--certs", default=None, help="证书目录（含 oss.crt/doh.crt/sub.crt/api.crt）")
    ap.add_argument("--cert", default="doh", choices=["none", "doh", "oss", "sub", "api"])
    ap.add_argument("--node", default=None, help="要解析的域名（默认取订阅第一个节点）")
    ap.add_argument("--http2", action="store_true", help="用 HTTP/2 + POST 发（更接近客户端）")
    ap.add_argument("--insecure", action="store_true")
    a = ap.parse_args()

    doc = load_sub(a.sub)
    node = a.node or first_node(doc)
    if not node:
        print("订阅里没有节点域名")
        return 2
    endpoints = extract_doh(doc)
    if not endpoints:
        print("订阅里没有 https DoH（dns.proxy-server-nameserver 为空）")
        return 2

    print(f"节点域名: {node}")
    for h, p in endpoints:
        print(f"  私有 DoH: https://{h}{p[:28]}…")

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
        if a.http2:
            st, body, err = http2(host, path, node, cert, a.insecure)
            print(f"  [h2 POST] {host} -> {st if st else 'FAIL'} {err or ''} {len(body)}B")
            parsed = parse_dns(body) if st == "200" else None
            if parsed:
                print("        解析:", parsed)
                ok = True
            elif body:
                print("        body:", body[:160])
            continue
        for qtype, label in ((28, "AAAA"), (1, "A")):
            try:
                st, body, _ = http1(host, path, node, cert, a.insecure, qtype=qtype)
            except Exception as e:  # noqa: BLE001
                print(f"  [{label}] {host} -> {type(e).__name__}: {str(e)[:80]}")
                continue
            parsed = parse_dns(body) if st == 200 else None
            print(f"  [{label}] {host} -> {st} {len(body)}B")
            if parsed:
                print("        解析:", parsed)
                ok = True
            elif body:
                print("        body:", body[:160])

    print("\n结果:", "解析成功" if ok else "未成功（本网络对端点 TCP 不通，或令牌已过期）")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
