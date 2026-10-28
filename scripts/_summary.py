#!/usr/bin/env python3
"""_summary.py — 汇总输出目录里的订阅（供 local.sh / local.ps1 调用）"""
import collections
import sys
from pathlib import Path


def main() -> int:
    d = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    files = sorted(d.glob("*.yaml"))
    if not files:
        print("  （没有产物）")
        return 0

    try:
        import yaml
    except ImportError:
        yaml = None

    for p in files:
        size = p.stat().st_size
        if not yaml:
            print(f"  {p.name:10} {size} B（无 PyYAML，跳过统计）")
            continue
        try:
            doc = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        except Exception as e:
            print(f"  {p.name:10} 解析失败：{e}")
            continue
        proxies = doc.get("proxies") or []
        kinds = collections.Counter(x.get("type") for x in proxies)
        groups = len(doc.get("proxy-groups") or [])
        rules = len(doc.get("rules") or [])
        detail = " ".join(f"{k}:{v}" for k, v in sorted(kinds.items(), key=lambda kv: -kv[1]))
        print(f"  {p.name:10} {len(proxies):4} 节点  [{detail}]  分组 {groups} / 规则 {rules}  {size} B")
    return 0


if __name__ == "__main__":
    sys.exit(main())
