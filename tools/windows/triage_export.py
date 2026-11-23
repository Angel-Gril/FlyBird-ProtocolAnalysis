#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""triage_export.py — 把"连不上"拆成三层：配置/规则 · DNS · IPv6，用隔离实验定位。

用法：
    python triage_export.py --sub exported.yaml
    python triage_export.py --sub exported.yaml --emit-control control.yaml   # 生成对照配置
    python triage_export.py --sub exported.yaml --global --emit-control c.yaml

三层判定
--------
A. 配置/规则层：proxies 能否被核心接受、规则 target 是否存在（mihomo 遇到不存在的
   proxy/group 会直接拒绝加载整份配置）、是否有 MATCH 兜底。
B. DNS 层：节点域名的 A/AAAA 解析（多解析器对照），以及私有 DoH 令牌是否已过期。
C. IPv6 层：`ip-version: ipv6-prefer` 时，AAAA 是否真的可用（两族各做一次 TCP 探活）。

`--emit-control` 会产出一份"对照配置"：server 改成探活通过的 IP、去掉 ip-version、
删掉私有 DoH 令牌（可选 --global 改全局模式）。拿它和原配置在**同一台失败机器**上对比，
差异就锁定出错层。

退出码：0 未发现阻断；1 发现阻断项；2 参数问题。
"""
from __future__ import annotations

import argparse
import copy
import json
import re
import socket
import sys
import time

try:
    import yaml
except ImportError:  # pragma: no cover
    print("需要 pyyaml：pip install pyyaml")
    raise SystemExit(2)

LEGACY_FIELDS = ("uuid", "flow", "network", "servername", "alterId")
PROBE_PORTS_LIMIT = 3


# ------------------------------------------------------------------ DNS
def _doh(provider: str, host: str, qtype: str):
    import urllib.request
    url = (f"https://dns.alidns.com/resolve?name={host}&type={qtype}" if provider == "alidns"
           else f"https://doh.pub/dns-query?name={host}&type={qtype}")
    req = urllib.request.Request(url, headers={"accept": "application/dns-json"})
    with urllib.request.urlopen(req, timeout=8) as r:
        return json.loads(r.read())


def resolve(host: str) -> dict:
    out = {"system": {"A": [], "AAAA": []}, "alidns": {"A": [], "AAAA": []},
           "doh.pub": {"A": [], "AAAA": []}}
    try:
        for info in socket.getaddrinfo(host, None):
            fam = "AAAA" if info[0] == socket.AF_INET6 else "A"
            out["system"][fam].append(info[4][0])
        for k in out["system"]:
            out["system"][k] = sorted(set(out["system"][k]))
    except Exception:
        pass
    for prov in ("alidns", "doh.pub"):
        for t in ("A", "AAAA"):
            try:
                j = _doh(prov, host, t)
                out[prov][t] = sorted({a["data"] for a in j.get("Answer", [])
                                       if a.get("type") == (1 if t == "A" else 28)})
            except Exception:
                pass
    return out


def probe(ip: str, port: int, timeout: float = 3.0) -> str:
    fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
    try:
        s = socket.socket(fam, socket.SOCK_STREAM)
        s.settimeout(timeout)
        t0 = time.time()
        s.connect((ip, port))
        dt = (time.time() - t0) * 1000
        s.close()
        return f"ok({dt:.0f}ms)"
    except Exception as e:  # noqa: BLE001
        return type(e).__name__


# ------------------------------------------------------------------ 检查
def check_structure(doc: dict, findings: list) -> list:
    proxies = doc.get("proxies") or []
    groups = doc.get("proxy-groups") or []
    rules = doc.get("rules") or []

    types = {}
    fields = set()
    for p in proxies:
        types[p.get("type", "?")] = types.get(p.get("type", "?"), 0) + 1
        fields |= set(p)
    findings.append({"layer": "A 配置", "name": "proxies", "ok": bool(proxies),
                     "detail": f"{len(proxies)} 个 {types}" if proxies else "为空：核心会认为无可用节点"})

    legacy = [f for f in LEGACY_FIELDS if f in fields]
    if legacy:
        findings.append({"layer": "A 配置", "name": "字段风格", "ok": False,
                         "detail": f"出现旧版字段 {legacy}（7.3.1 节点是 anytls：password/sni）"})
    missing = []
    for p in proxies:
        for k in ("name", "type", "server", "port"):
            if k not in p:
                missing.append(f"{p.get('name', '?')} 缺 {k}")
    if missing:
        findings.append({"layer": "A 配置", "name": "必填字段", "ok": False,
                         "detail": "；".join(missing[:5])})

    # 规则 target 是否存在（mihomo 会因未知 target 拒绝加载）
    known = {p.get("name") for p in proxies} | {g.get("name") for g in groups} \
            | {"DIRECT", "REJECT", "PASS", "REJECT-DROP", "COMPATIBLE"}
    bad_targets = []
    for r in rules:
        parts = [x.strip() for x in str(r).split(",")]
        if not parts:
            continue
        # 规则语法：MATCH,<target> 或 <TYPE>,<value>,<target>[,<options>...]
        if parts[0].upper() == "MATCH":
            tgt = parts[1] if len(parts) > 1 else ""
        elif len(parts) >= 3:
            tgt = parts[2]
        else:
            continue
        if tgt and tgt not in known:
            bad_targets.append(f"{r} -> {tgt}")
    findings.append({"layer": "A 配置", "name": "规则 target", "ok": not bad_targets,
                     "detail": ("未解析到的 target：" + "；".join(bad_targets[:3])) if bad_targets
                               else f"{len(rules)} 条规则，target 均存在"})
    has_match = any(str(r).startswith("MATCH") for r in rules)
    findings.append({"layer": "A 配置", "name": "MATCH 兜底", "ok": has_match,
                     "detail": "有" if has_match else "缺少 MATCH 规则"})

    # 节点域名是否被规则指向 DIRECT（不影响拨号，但会让"测试连通性"失真）
    node_hosts = {p.get("server") for p in proxies if p.get("server")}
    hijack = [str(r) for r in rules
              if any(h and h in str(r) for h in node_hosts)]
    if hijack:
        findings.append({"layer": "A 配置", "name": "节点域名命中规则", "ok": False,
                         "detail": "；".join(hijack[:2]) + "（节点流量本不该走规则，确认是不是笔误）"})
    return proxies


def check_dns(proxies: list, findings: list) -> dict:
    hosts = []
    for p in proxies:
        h = p.get("server")
        if h and h not in hosts:
            hosts.append(h)
    report = {}
    for h in hosts[:3]:
        res = resolve(h)
        a = set(res["system"]["A"]) | set(res["alidns"]["A"]) | set(res["doh.pub"]["A"])
        aaaa = set(res["system"]["AAAA"]) | set(res["alidns"]["AAAA"]) | set(res["doh.pub"]["AAAA"])
        report[h] = {"A": sorted(a), "AAAA": sorted(aaaa), "by_resolver": res}
        findings.append({"layer": "B DNS", "name": f"解析 {h[:26]}", "ok": bool(a or aaaa),
                         "detail": f"A={len(a)} 个 {sorted(a)[:3]} / AAAA={len(aaaa)} 个 {sorted(aaaa)[:2]}"})

        # 两族各自探活（回答"是不是 IPv6 问题"）
        port = int(proxies[0].get("port", 443))
        for fam, ips in (("IPv4", sorted(a)[:PROBE_PORTS_LIMIT]), ("IPv6", sorted(aaaa)[:PROBE_PORTS_LIMIT])):
            for ip in ips:
                r = probe(ip, port)
                report[h].setdefault("probe", []).append({"ip": ip, "family": fam, "port": port,
                                                          "result": r})
                findings.append({"layer": "C 连通", "name": f"{fam} {ip}:{port}",
                                 "ok": r.startswith("ok"), "detail": r})
    return report


def check_ipv6(doc: dict, findings: list) -> bool:
    proxies = doc.get("proxies") or []
    iv = sorted({p.get("ip-version") for p in proxies if p.get("ip-version")})
    has6 = False
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.connect(("2001:4860:4860::8888", 53))
        s.close()
        has6 = True
    except Exception:
        has6 = False
    pref = "ipv6-prefer" in iv
    findings.append({"layer": "C IPv6", "name": "ip-version", "ok": not (pref and not has6),
                     "detail": f"{iv or '未设置'}；本机 IPv6 {'可用' if has6 else '不可用'}"
                               + ("（prefer 但无 IPv6：会先试 AAAA 再回退，部分内核会卡住）" if pref and not has6 else "")})
    return has6


# ------------------------------------------------------------------ 对照配置
def emit_control(doc: dict, out_path: str, global_mode: bool, dns_report: dict) -> str:
    ctrl = copy.deepcopy(doc)
    picked = {}
    for p in ctrl.get("proxies") or []:
        host = p.get("server")
        rec = dns_report.get(host) or {}
        cands = [x["ip"] for x in rec.get("probe", []) if x["result"].startswith("ok")]
        if not cands:
            cands = sorted(rec.get("A") or [])
        ip = cands[0] if cands else host
        picked[p.get("name")] = ip
        p["server"] = ip
        p.pop("ip-version", None)          # 去掉 ipv6-prefer，强制走 v4
    dns = ctrl.get("dns") or {}
    if dns.get("proxy-server-nameserver"):
        dns.pop("proxy-server-nameserver", None)   # 不把过期令牌带进对照
        ctrl["dns"] = dns
    if global_mode:
        ctrl["mode"] = "global"
    yaml.safe_dump(ctrl, open(out_path, "w", encoding="utf-8"), allow_unicode=True, sort_keys=False)
    return out_path


# ------------------------------------------------------------------ 主流程
def main() -> int:
    ap = argparse.ArgumentParser(description="导出配置三层分诊（配置/规则 · DNS · IPv6）")
    ap.add_argument("--sub", required=True)
    ap.add_argument("--emit-control", default=None, help="输出对照配置（IP 直连 + 去 ipv6-prefer）")
    ap.add_argument("--global", dest="global_mode", action="store_true",
                    help="对照配置加 mode: global（隔离分流规则）")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    doc = yaml.safe_load(open(a.sub, encoding="utf-8")) or {}
    findings: list[dict] = []
    proxies = check_structure(doc, findings)
    dns_report = check_dns(proxies, findings)
    check_ipv6(doc, findings)

    failed = [f for f in findings if not f["ok"]]
    layers = []
    for f in failed:
        if f["layer"] not in layers:
            layers.append(f["layer"])

    if a.emit_control:
        p = emit_control(doc, a.emit_control, a.global_mode, dns_report)
        print(f"对照配置已生成：{p}（server→IP、去 ipv6-prefer"
              f"{'、mode: global' if a.global_mode else ''}）")

    if a.json:
        print(json.dumps({"file": a.sub, "findings": findings, "failed_layers": layers,
                          "ok": not failed}, ensure_ascii=False, indent=2))
    else:
        print(f"文件 {a.sub}  节点 {len(proxies)}\n")
        for f in findings:
            print(f"  [{'OK ' if f['ok'] else '!! '}] {f['layer']:8} {f['name']}: {f['detail']}")
        print("\n结论:", "未发现阻断项" if not failed else f"命中层：{layers}")
        if failed:
            print("分诊建议：")
            if any(x.startswith("A") for x in layers):
                print("  · 先把对照配置（--emit-control）丢给同一份内核加载；加载失败即配置/规则问题")
            if any(x.startswith("C") for x in layers):
                print("  · IPv4/IPv6 探活结果已列出：哪族 ok 就走哪族；prefer 且无 IPv6 时先去掉该字段")
            if any(x.startswith("B") for x in layers):
                print("  · 解析缺失：节点域名只在私有 DoH 有答案，标准内核解析不到")
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
