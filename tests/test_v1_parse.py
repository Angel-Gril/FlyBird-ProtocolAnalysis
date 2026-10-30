#!/usr/bin/env python3
"""test_v1_parse.py — v1 明文解析与合并的离线单测（无需网络）"""
import sys
from subprocess import CompletedProcess
from unittest.mock import patch
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import v1_legacy as V  # noqa: E402

SAMPLE = (ROOT / "samples" / "v1-subscription.sample.txt").read_text(encoding="utf-8")

V2_STUB = """mixed-port: 7890
proxies:
  - {name: Hong Kong-01, type: vless, server: v2.example.com, port: 10301, uuid: 00000000-0000-0000-0000-000000000001}
  - {name: Hong Kong-02, type: vless, server: v2.example.com, port: 10302, uuid: 00000000-0000-0000-0000-000000000001}
proxy-groups:
  - {name: 节点选择, type: select, proxies: [AUTO]}
  - {name: AUTO, type: url-test, proxies: [Hong Kong-01, Hong Kong-02]}
rules:
  - MATCH,节点选择
"""


def test_parse():
    proxies, meta, skipped = V.parse_plaintext(SAMPLE)
    assert len(proxies) == 6, len(proxies)
    assert skipped == 1, "「单端口承载」提示行应被跳过"
    assert meta["remaining"] == "105000000000"
    assert meta["expire_at"].startswith("2027-02-11")

    types = [p["type"] for p in proxies]
    assert types.count("trojan") == 3
    assert types.count("ss") == 3

    t = next(p for p in proxies if p["type"] == "trojan")
    assert t["port"] == 443 and t["password"].startswith("0000")
    assert t["sni"].startswith("sni-")

    s = next(p for p in proxies if p["type"] == "ss")
    assert s["port"] == 11011 and s["cipher"] == "aes-256-cfb"
    assert s["name"].startswith("[SS] ")
    print("parse ok:", len(proxies), "proxies")


def test_build_config():
    import yaml
    proxies, meta, _ = V.parse_plaintext(SAMPLE)
    doc = yaml.safe_load(V.build_config(proxies, meta))
    assert len(doc["proxies"]) == 6
    assert any(g["name"] == "PROXY" for g in doc["proxy-groups"])
    assert doc["rules"][-1].startswith("MATCH")
    print("build_config ok")


def test_merge():
    import yaml
    proxies, _, _ = V.parse_plaintext(SAMPLE)
    doc = yaml.safe_load(V.merge_into_config(V2_STUB, proxies))
    assert len(doc["proxies"]) == 8, len(doc["proxies"])
    names = [g["name"] for g in doc["proxy-groups"]]
    assert "v1-trojan" in names and "v1-ss" in names
    # 新分组要挂到第一个 select 的最前面
    assert doc["proxy-groups"][0]["proxies"][:2] == ["v1-ss", "v1-trojan"]
    print("merge ok")


def test_bad_input():
    proxies, meta, skipped = V.parse_plaintext("garbage\nnot a uri\n")
    assert proxies == [] and skipped == 2
    print("bad input ok")


def test_dns_gate_rejects_benchmark_addresses():
    proxies = [{"name": "dead", "type": "trojan", "server": "legacy.example", "port": 443}]
    fake = CompletedProcess(["getent"], 0, "198.18.0.19 STREAM legacy.example\n", "")
    with patch.object(V.subprocess, "run", return_value=fake):
        filtered, skipped = V.filter_globally_resolvable(proxies)
    assert filtered == [] and skipped == 1
    print("dns gate ok")


if __name__ == "__main__":
    test_parse()
    try:
        import yaml  # noqa: F401
        test_build_config()
        test_merge()
    except ImportError:
        print("skip yaml tests (PyYAML 未安装)")
    test_bad_input()
    test_dns_gate_rejects_benchmark_addresses()
    print("ALL OK")
