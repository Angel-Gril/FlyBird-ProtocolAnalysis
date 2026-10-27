#!/usr/bin/env python3
"""mitm_observe.py — TLS 终止 + 转发观察代理

目的：在客户端**完全不知情**的前提下，记录它发出的真实请求
（方法、Host、路径、UA、Authorization、X-Client-*、响应码、响应体）。

原理：
    hosts/DNS 把目标域名指到一个假 IP  →  iptables DNAT 到 127.0.0.1:8443
    →  本脚本用自签证书终止 TLS  →  带上客户端证书重建到真实服务器的连接
    →  原样回传（同时记录）

前置：
    1) 自签 CA + 目标域名的 SAN 证书（脚本会自动生成）
    2) 客户端信任该 CA —— 建议只在测试进程的 mount namespace 里替换
       /etc/ssl/certs/ca-certificates.crt，不要污染宿主机
    3) DNAT 规则：
       iptables -t nat -A OUTPUT -d <FAKE_IP> -p tcp --dport 443 \
                -j DNAT --to-destination 127.0.0.1:8443

用法：
    python3 mitm_observe.py --port 8443 --cert-dir /tmp/probe \
        --api-cert api.crt --api-key api.key \
        --sub-cert sub.crt --sub-key sub.key
"""
from __future__ import annotations

import argparse
import json
import socket
import ssl
import threading
import time
from pathlib import Path

import requests
import urllib3

urllib3.disable_warnings()

lock = threading.Lock()
CFG = {}


def log_json(rec: dict):
    with lock:
        with open(Path(CFG["cert_dir"]) / "flow.log", "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def pick_cert(host: str):
    """按 purpose 选客户端证书：订阅域用 sub，其余用 api。"""
    if "sub" in host:
        return CFG["sub_cert"], CFG["sub_key"]
    return CFG["api_cert"], CFG["api_key"]


def handle(conn: socket.socket, addr):
    try:
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = conn.recv(65536)
            if not chunk:
                return
            data += chunk
        head, _, body = data.partition(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n")
        method, path, _ = lines[0].split(" ", 2)
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()
        host = headers.get("Host", "").split(":")[0]

        clen = int(headers.get("Content-Length", "0") or 0)
        while len(body) < clen:
            chunk = conn.recv(65536)
            if not chunk:
                break
            body += chunk

        fwd = {k: v for k, v in headers.items()
               if k.lower() not in ("host", "connection", "content-length", "accept-encoding")}
        cert, key = pick_cert(host)
        t0 = time.time()
        try:
            r = requests.request(method, f"https://{host}{path}", headers=fwd,
                                 data=body or None, cert=(cert, key), verify=False,
                                 timeout=30, allow_redirects=False)
            status, rbody, rhdr = r.status_code, r.content, r.headers
        except Exception as e:
            status, rbody, rhdr = 599, str(e).encode(), {}
        dt = time.time() - t0

        log_json({
            "t": time.strftime("%H:%M:%S"), "peer": f"{addr[0]}:{addr[1]}",
            "method": method, "host": host, "path": path,
            "status": status, "bytes": len(rbody), "ms": int(dt * 1000),
            "req_headers": {k: v for k, v in headers.items()
                            if k.lower() in ("user-agent", "authorization",
                                             "x-client-platform", "x-client-environment",
                                             "x-client-runtime-abi", "content-type")},
            "resp_head": rbody[:120].decode("latin-1"),
        })

        resp = [f"HTTP/1.1 {status} X"]
        skip = {"connection", "transfer-encoding", "content-encoding", "content-length"}
        for k, v in rhdr.items():
            if k.lower() not in skip:
                resp.append(f"{k}: {v}")
        resp.append(f"Content-Length: {len(rbody)}")
        resp.append("Connection: close")
        conn.sendall(("\r\n".join(resp) + "\r\n\r\n").encode("latin-1") + rbody)
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def ensure_cert(cert_dir: Path, domains: list[str]):
    """生成 CA 与 SAN 证书（已存在则复用）。"""
    crt, key = cert_dir / "server.crt", cert_dir / "server.key"
    if crt.exists() and key.exists():
        return
    import subprocess
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", str(cert_dir / "ca.key"), "-out", str(cert_dir / "ca.crt"),
                    "-days", "2", "-subj", "/CN=Observe-Lab-CA"], check=True,
                   capture_output=True)
    subprocess.run(["openssl", "req", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", str(key), "-out", str(cert_dir / "server.csr"),
                    "-subj", "/CN=observe"], check=True, capture_output=True)
    san = ",".join(f"DNS:{d}" for d in domains)
    ext = cert_dir / "ext.cnf"
    ext.write_text(f"subjectAltName={san}\n"
                   "basicConstraints=CA:FALSE\n"
                   "keyUsage=digitalSignature,keyEncipherment\n"
                   "extendedKeyUsage=serverAuth\n")
    subprocess.run(["openssl", "x509", "-req", "-in", str(cert_dir / "server.csr"),
                    "-CA", str(cert_dir / "ca.crt"), "-CAkey", str(cert_dir / "ca.key"),
                    "-CAcreateserial", "-out", str(crt), "-days", "2",
                    "-extfile", str(ext)], check=True, capture_output=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--cert-dir", default="/tmp/probe")
    ap.add_argument("--api-cert", required=True)
    ap.add_argument("--api-key", required=True)
    ap.add_argument("--sub-cert", required=True)
    ap.add_argument("--sub-key", required=True)
    ap.add_argument("--domain", action="append", default=[])
    a = ap.parse_args()

    cert_dir = Path(a.cert_dir)
    cert_dir.mkdir(parents=True, exist_ok=True)
    CFG.update(cert_dir=str(cert_dir), api_cert=a.api_cert, api_key=a.api_key,
               sub_cert=a.sub_cert, sub_key=a.sub_key)

    domains = a.domain or ["api.example.com", "sub.example.com"]
    ensure_cert(cert_dir, domains)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert_dir / "server.crt"), str(cert_dir / "server.key"))
    ctx.set_alpn_protocols(["http/1.1"])

    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", a.port))
    srv.listen(64)
    print(f"[*] listening 127.0.0.1:{a.port}  log={cert_dir/'flow.log'}", flush=True)
    print(f"[*] 记得加 DNAT：iptables -t nat -A OUTPUT -d <FAKE_IP> -p tcp "
          f"--dport 443 -j DNAT --to-destination 127.0.0.1:{a.port}", flush=True)
    while True:
        c, addr = srv.accept()
        try:
            cc = ctx.wrap_socket(c, server_side=True)
            threading.Thread(target=handle, args=(cc, addr), daemon=True).start()
        except Exception:
            try:
                c.close()
            except Exception:
                pass


if __name__ == "__main__":
    main()
