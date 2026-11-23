#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""diagnose_export.py — 判断"官方 App 能连、导出配置在 FlClash 连不上"的根因。

用法:
    python diagnose_export.py --sub exported.yaml [--json]

检查项（每条都对应一个已知失败面）：
  1. 节点数与类型（7.3.1 起是 anytls；旧模板 vless 字段会全部失效）
  2. 节点 `server` 能否在**公共 DNS** 解析（飞鸟的节点域名只在私有 DoH 里有记录）
  3. `dns.proxy-server-nameserver` 是否还在、指向哪、令牌是否像"每次下载轮换"的那种
  4. `ip-version` 是否要求 IPv6（`ipv6-prefer` 在纯 IPv4 网络会退化甚至失败）
  5. 导出的 YAML 是否混入旧版字段（vless 的 uuid/flow/network 与 anytls 的 password 并存）

退出码：0 未发现阻断项；1 发现会导致"连不上"的项；2 参数问题。
"""
from __future__ import annotations

import argparse
import json
import re
import socket
import sys

try:
    import yaml
except ImportError:  # pragma: no cover
    print("需要 pyyaml：pip install pyyaml")
    raise SystemExit(2)

LEGACY_FIELDS = ("uuid", "flow", "network", "servername", "alterId", "cipher")
MODERN_FIELDS = ("password", "sni", "client-fingerprint")


def _doh_json(provider: str, host: str, qtype: str = "A"):
    import urllib.request
    if provider == "alidns":
        url = f"https://dns.alidns.com/resolve?name={host}&type={qtype}"
    else:
        url = f"https://doh.pub/dns-query?name={host}&type={qtype}"
    req = urllib.request.Request(url, headers={"accept": "application/dns-json"})
    with urllib.request.urlopen(req, timeout=8) as r:
        return json.loads(r.read())


def public_a(host: str) -> dict:
    """多解析器对照：不同解析器/不同时刻的答案可能不同（实测会变）。"""
    out: dict[str, list[str]] = {"system": [], "alidns": [], "doh.pub": []}
    try:
        out["system"] = sorted({i[4][0] for i in socket.getaddrinfo(
            host, None, proto=socket.IPPROTO_TCP)})
    except Exception:
        pass
    for prov in ("alidns", "doh.pub"):
        try:
            j = _doh_json(prov, host)
            ips, cnames = [], []
            for a in j.get("Answer", []):
                if a.get("type") == 1:
                    ips.append(a["data"])
                elif a.get("type") == 5:
                    cnames.append(a["data"].rstrip("."))
            out[prov] = ips or (["CNAME:" + c for c in cnames] if cnames else [])
        except Exception:
            out[prov] = []
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="导出配置连通性诊断")
    ap.add_argument("--sub", required=True)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    doc = yaml.safe_load(open(a.sub, encoding="utf-8")) or {}
    proxies = doc.get("proxies") or []
    findings: list[dict] = []

    types: dict[str, int] = {}
    servers: dict[str, int] = {}
    fields: set[str] = set()
    for p in proxies:
        types[p.get("type", "?")] = types.get(p.get("type", "?"), 0) + 1
        servers[p.get("server", "?")] = servers.get(p.get("server", "?"), 0) + 1
        fields |= set(p)

    findings.append({"check": "节点", "ok": bool(proxies),
                     "detail": f"{len(proxies)} 个，类型 {types}"})
    legacy = [f for f in LEGACY_FIELDS if f in fields]
    modern = [f for f in MODERN_FIELDS if f in fields]
    findings.append({"check": "字段风格", "ok": not (legacy and modern),
                     "detail": f"legacy={legacy} modern={modern}"
                               + ("（混用：旧模板套新数据，节点会被核心丢弃）" if legacy and modern else "")})

    # server 解析
    dns_rows = []
    for host in list(servers)[:3]:
        res = public_a(host)
        distinct = {ip for ips in res.values() for ip in ips if not ip.startswith("CNAME:")}
        resolved = any(not x.startswith("CNAME:") for ips in res.values() for x in ips)
        dns_rows.append({"server": host, "resolvers": res})
        detail = "；".join(f"{k}={v or '∅'}" for k, v in res.items())
        if len(distinct) > 1:
            detail += f"  ← 解析结果不一致（{len(distinct)} 个不同 IP）"
        findings.append({"check": f"公共DNS {host[:28]}", "ok": resolved, "detail": detail})

    # 私有 DoH
    dns_cfg = doc.get("dns") or {}
    psn = dns_cfg.get("proxy-server-nameserver") or []
    doh_hosts = []
    for v in psn:
        if isinstance(v, str) and v.startswith("https://"):
            m = re.match(r"https://([^/]+)(/.*)?", v)
            if m:
                doh_hosts.append((m.group(1), (m.group(2) or "")))
    findings.append({"check": "私有 DoH", "ok": bool(doh_hosts),
                     "detail": (f"{doh_hosts[0][0]} 路径前缀 {doh_hosts[0][1][:18]}…；"
                                f"令牌随每次下载轮换，导出后即可能失效") if doh_hosts
                               else "缺失：节点域名将无法解析"})

    # ip-version
    iv = {p.get("ip-version") for p in proxies if p.get("ip-version")}
    findings.append({"check": "ip-version", "ok": "ipv6-prefer" not in iv or _has_ipv6(),
                     "detail": f"{sorted(iv) or '未设置'}"
                               + ("；本机无 IPv6，ipv6-prefer 会退化/失败" if "ipv6-prefer" in iv and not _has_ipv6() else "")})

    ok = all(f["ok"] for f in findings)
    report = {"file": a.sub, "proxies": len(proxies), "types": types,
              "servers": dns_rows, "dns_proxy_server_nameserver": psn,
              "findings": findings, "ok": ok}

    if a.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(f"文件 {a.sub}  节点 {len(proxies)}  类型 {types}\n")
        for f in findings:
            print(f"  [{'OK ' if f['ok'] else '!! '}] {f['check']}: {f['detail']}")
        print("\n结论:", "未发现阻断项" if ok else "存在会导致连不上的项（见 !! 行）")
        if not ok:
            print("提示：节点域名若只存在于私有 DoH，标准 mihomo/FlClash 无法解析——")
            print("      需要在下载会话内用官方通道解析成 IP 写回 YAML（保留 sni）。")
    return 0 if ok else 1


def _has_ipv6() -> bool:
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.connect(("2001:4860:4860::8888", 53))
        s.close()
        return True
    except Exception:
        return False


if __name__ == "__main__":
    sys.exit(main())
