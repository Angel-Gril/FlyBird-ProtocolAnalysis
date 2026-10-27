#!/usr/bin/env python3
"""extract_nodes.py — 全内存扫描，逐个还原订阅节点（每块是独立分配的小字符串）。"""
import argparse
import re
import sys
import time
from pathlib import Path

FIELD_PATTERNS = {
    "flow": re.compile(r"flow:\s*(\S+)"),
    "name": re.compile(r"name:\s*([^\n\r\x00]{2,40})"),
    "network": re.compile(r"network:\s*(\S+)"),
    "port": re.compile(r"port:\s*(\d{2,5})"),
    "server": re.compile(r"server:\s*([a-z0-9.\-]{4,80})"),
    "servername": re.compile(r"servername:\s*([a-z0-9.\-]{8,80})"),
    "skip": re.compile(r"skip-cert-verify:\s*(true|false)"),
    "tls": re.compile(r"tls:\s*(true|false)"),
    "type": re.compile(r"type:\s*(vless|vmess|trojan|ss|hysteria2?|tuic)"),
    "udp": re.compile(r"udp:\s*(true|false)"),
    "uuid": re.compile(r"uuid:\s*([0-9a-fA-F\-]{36})"),
}


def find_pid(hint="-apex-openwrt"):
    for p in Path("/proc").iterdir():
        if not p.name.isdigit():
            continue
        try:
            cmd = (p / "cmdline").read_bytes().replace(b"\x00", b" ").decode("utf-8", "replace")
        except Exception:
            continue
        if hint in cmd:
            return int(p.name)
    return None


def parse_block(text: str):
    out = {}
    for k, rx in FIELD_PATTERNS.items():
        m = rx.search(text)
        if not m:
            return None
        out[k] = m.group(1).strip()
    if "." not in out["server"] or len(out["servername"]) < 8:
        return None
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, default=0)
    ap.add_argument("--out", default="/tmp/sub_final.yaml")
    ap.add_argument("--seconds", type=float, default=25)
    a = ap.parse_args()
    pid = a.pid or find_pid()
    if not pid:
        print("no pid", file=sys.stderr)
        return 2
    nodes = {}
    t0 = time.time()
    rounds = 0
    while time.time() - t0 < a.seconds:
        rounds += 1
        try:
            with open(f"/proc/{pid}/mem", "rb", buffering=0) as mem, open(f"/proc/{pid}/maps") as maps:
                for line in maps:
                    parts = line.split()
                    if len(parts) < 2 or "r" not in parts[1]:
                        continue
                    if len(parts) >= 6 and parts[5].startswith("/"):
                        continue
                    lo_s, hi_s = parts[0].split("-")
                    lo, hi = int(lo_s, 16), int(hi_s, 16)
                    if hi - lo < 4096:
                        continue
                    try:
                        mem.seek(lo)
                        blob = mem.read(hi - lo)
                    except Exception:
                        continue
                    idx = blob.find(b"xtls-rprx-vision")
                    while idx >= 0:
                        seg = blob[idx - 40:idx + 400].decode("utf-8", "replace")
                        n = parse_block(seg)
                        if n:
                            nodes[n["name"]] = n
                        idx = blob.find(b"xtls-rprx-vision", idx + 1)
        except Exception as e:
            print("  err", type(e).__name__, e)
        print(f"  round {rounds} @{time.time()-t0:.1f}s nodes={len(nodes)}", flush=True)
        time.sleep(1.0)

    if not nodes:
        print("no nodes", file=sys.stderr)
        return 1
    ordered = [nodes[k] for k in sorted(nodes)]
    lines = ["mixed-port: 7890", "allow-lan: true", "mode: rule", "log-level: info", "proxies:"]
    for n in ordered:
        lines += [
            f"  - flow: {n['flow']}",
            f"    name: {n['name']}",
            f"    network: {n['network']}",
            f"    port: {n['port']}",
            f"    server: {n['server']}",
            f"    servername: {n['servername']}",
            f"    skip-cert-verify: {n['skip']}",
            f"    tls: {n['tls']}",
            f"    type: {n['type']}",
            f"    udp: {n['udp']}",
            f"    uuid: {n['uuid']}",
        ]
    names = [n["name"] for n in ordered]
    lines += (["proxy-groups:",
               "  - name: AUTO", "    type: url-test",
               "    url: http://www.gstatic.com/generate_204",
               "    interval: 300", "    proxies:"]
              + [f"      - {x}" for x in names]
              + ["rules:", "  - MATCH,AUTO"])
    Path(a.out).write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"WROTE {a.out} nodes={len(ordered)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
