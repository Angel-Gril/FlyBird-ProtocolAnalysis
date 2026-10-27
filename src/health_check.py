"""
health_check.py — 缓存 YAML 的"可用性/新鲜度"体检（给缓存分发模式兜底）

在上游 404 期间，服务器只能发 last-good。本脚本回答三个问题：
  1) 这份 YAML 还能用吗？（可解析、节点数、重名）
  2) 它有多旧？（mtime / 可选的内嵌时间戳）
  3) 节点还活着吗？（抽样 DNS + TCP 443）

用法：
  python health_check.py --yaml out/fb_clash.yaml
  python health_check.py --yaml out/fb_clash.yaml --max-age-hours 12 --min-nodes 10 --sample 5 --json health.json

退出码：0=健康；2=过期/节点过少（可发但需告警）；3=不可用（应拒绝分发）
"""
from __future__ import annotations

import argparse
import datetime
import json
import re
import socket
import sys
import time
from pathlib import Path

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None

LINE_PROXY = re.compile(r"^\s*-\s*(\{.*\}|name:\s*['\"]?([^,'\"\n]+))", re.M)


def parse_proxies(text: str) -> list[dict]:
    """优先 PyYAML；没有就退回行内正则（兼容 - {name: ..., server: ...} 与 - name: ...）"""
    if yaml is not None:
        try:
            doc = yaml.safe_load(text)
            if isinstance(doc, dict) and isinstance(doc.get("proxies"), list):
                return [p for p in doc["proxies"] if isinstance(p, dict)]
        except Exception:
            pass
    out = []
    for m in re.finditer(r"^\s*-\s*\{(.*)\}\s*$", text, re.M):
        body = m.group(1)
        item = {}
        for kv in re.split(r",\s*(?=[a-zA-Z0-9_-]+\s*:)", body):
            if ":" in kv:
                k, v = kv.split(":", 1)
                item[k.strip().strip("'\"")] = v.strip().strip("'\"")
        if item:
            out.append(item)
    return out


def tcp_ok(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except Exception:
        return False


def dns_ok(host: str) -> bool:
    try:
        socket.getaddrinfo(host, None)
        return True
    except Exception:
        return False


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--yaml", required=True)
    ap.add_argument("--max-age-hours", type=float, default=24)
    ap.add_argument("--min-nodes", type=int, default=1)
    ap.add_argument("--sample", type=int, default=3, help="抽样做 DNS/TCP 的节点数")
    ap.add_argument("--json", default="")
    a = ap.parse_args()

    p = Path(a.yaml)
    report: dict = {"file": str(p), "checked_at": datetime.datetime.now().isoformat(timespec="seconds")}
    if not p.exists():
        report.update(ok=False, reason="missing")
        print(json.dumps(report, ensure_ascii=False, indent=2))
        sys.exit(3)

    text = p.read_text(encoding="utf-8", errors="replace")
    age_h = (time.time() - p.stat().st_mtime) / 3600
    report["age_hours"] = round(age_h, 2)

    proxies = parse_proxies(text)
    names = [str(x.get("name", "")) for x in proxies]
    servers = [str(x.get("server", "")) for x in proxies if x.get("server")]
    dup = sorted({n for n in names if n and names.count(n) > 1})

    report.update(node_count=len(proxies), duplicate_names=dup[:10], distinct_servers=len(set(servers)))
    report["types"] = sorted({str(x.get("type", "")) for x in proxies if x.get("type")})

    # 抽样连通性
    checks = []
    for x in proxies[: max(0, a.sample)]:
        host = str(x.get("server", ""))
        port = int(x.get("port", 443) or 443)
        if not host:
            continue
        item = {"name": x.get("name"), "server": host, "port": port}
        if not re.fullmatch(r"[0-9.]+", host):
            item["dns"] = dns_ok(host)
        item["tcp443"] = tcp_ok(re.sub(r"^\[|\]$", "", host), port)
        checks.append(item)
    report["sample_checks"] = checks

    # 判定
    reasons = []
    if report["node_count"] < a.min_nodes:
        reasons.append(f"node_count {report['node_count']} < {a.min_nodes}")
    if age_h > a.max_age_hours:
        reasons.append(f"stale {age_h:.1f}h > {a.max_age_hours}h")
    if dup:
        reasons.append(f"duplicate names: {dup[:3]}")
    if checks and not any(c.get("tcp443") for c in checks):
        reasons.append("所有抽样节点 TCP 不可达")

    hard = report["node_count"] == 0
    report["ok"] = not hard and not reasons
    report["reasons"] = reasons
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if a.json:
        Path(a.json).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    if hard:
        sys.exit(3)
    sys.exit(0 if report["ok"] else 2)


if __name__ == "__main__":
    main()
