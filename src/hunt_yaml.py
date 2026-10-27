#!/usr/bin/env python3
"""hunt_yaml.py — 在运行中的 OpenWrt 客户端（Go）内存里抓解密后的订阅明文。

用法（在服务器上，root 或同用户）：
    python3 hunt_yaml.py --seconds 120 --out /tmp/cap.yaml
    # 另开一个终端执行 /start（或 apex.sh enable）触发下载+解密

原理：OpenAPXS 解密后的 YAML 会进入 mihomo 的 config 解析；原始字节或解析后的
字符串会短暂/长期驻留在 Go 堆里。本脚本高频轮询 /proc/<pid>/mem 的匿名可写区，
命中 "proxies:" / "xtls-rprx-vision" / "servername:" 等标记就落盘并尝试解析。
"""
from __future__ import annotations

import argparse
import re
import sys
import time
import traceback
from pathlib import Path

MARKERS = [b"proxies:", b"proxy-groups:", b"xtls-rprx-vision", b"servername:", b"mixed-port:"]
WINDOW = 1 << 20  # 命中点前后各 512KB
CHUNK = 4 << 20


def find_pid(name_hint: str = "-apex-openwrt") -> int | None:
    best = None
    for p in Path("/proc").iterdir():
        if not p.name.isdigit():
            continue
        try:
            cmd = (p / "cmdline").read_bytes().replace(b"\x00", b" ").decode("utf-8", "replace")
        except Exception:
            continue
        if name_hint in cmd:
            best = int(p.name)
    return best


def anonymous_rw_regions(pid: int):
    regions = []
    try:
        with open(f"/proc/{pid}/maps") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 2:
                    continue
                rng, perms = parts[0], parts[1]
                if "r" not in perms or "w" not in perms:
                    continue
                # 跳过文件映射（.so / 字体等），只看匿名堆
                if len(parts) >= 6 and parts[5] != "[heap]":
                    path = parts[5]
                    if path.startswith("/"):
                        continue
                start_s, end_s = rng.split("-")
                start, end = int(start_s, 16), int(end_s, 16)
                if end - start > (512 << 20):
                    continue
                regions.append((start, end))
    except Exception:
        pass
    return regions


def read_mem(f, addr: int, size: int) -> bytes:
    try:
        f.seek(addr)
        return f.read(size)
    except Exception:
        return b""


def try_parse(blob: bytes):
    try:
        import yaml
    except Exception:
        return None, 0
    text = blob.decode("utf-8", "ignore")
    # 从 "proxies:" 开始截取
    idx = text.find("proxies:")
    if idx > 0:
        text = text[idx:]
    for cut in range(0, min(len(text), 4 << 20), 4096):
        try:
            data = yaml.safe_load(text[: len(text) - cut] if cut else text)
        except Exception:
            continue
        if isinstance(data, dict) and isinstance(data.get("proxies"), list) and data["proxies"]:
            return data, len(data["proxies"])
    return None, 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, default=0)
    ap.add_argument("--seconds", type=float, default=120)
    ap.add_argument("--out", default="/tmp/cap.yaml")
    ap.add_argument("--interval", type=float, default=0.2)
    ap.add_argument("--dump-all", action="store_true", help="命中即落盘原始窗口，便于离线分析")
    a = ap.parse_args()

    pid = a.pid or find_pid()
    if not pid:
        print("[!] 找不到 -apex-openwrt 进程", file=sys.stderr)
        return 2
    print(f"[*] pid={pid}，轮询 {a.seconds:.0f}s，间隔 {a.interval}s", flush=True)

    out = Path(a.out)
    hits_dir = out.parent / "hits"
    if a.dump_all:
        hits_dir.mkdir(parents=True, exist_ok=True)

    t0 = time.time()
    rounds = 0
    best_nodes = 0
    try:
        mem = open(f"/proc/{pid}/mem", "rb", buffering=0)
    except PermissionError:
        print("[!] 无权限读取 /proc/<pid>/mem（用 root 或同用户，且未开 yama ptrace_scope=3）", file=sys.stderr)
        return 3

    with mem:
        while time.time() - t0 < a.seconds:
            rounds += 1
            regions = anonymous_rw_regions(pid)
            for start, end in regions:
                addr = start
                carry = b""
                while addr < end:
                    size = min(CHUNK, end - addr)
                    blob = read_mem(mem, addr, size)
                    if not blob:
                        addr += size
                        carry = b""
                        continue
                    data = carry + blob
                    for mk in MARKERS:
                        i = data.find(mk)
                        if i < 0:
                            continue
                        lo = max(0, i - WINDOW // 2)
                        hi = min(len(data), i + WINDOW // 2)
                        win = data[lo:hi]
                        if a.dump_all:
                            p = hits_dir / f"hit_{int(time.time()*1000)}_{addr:x}.bin"
                            p.write_bytes(win)
                        data_parsed, n = try_parse(win)
                        if data_parsed and n >= best_nodes:
                            best_nodes = n
                            out.write_text(
                                __import__("yaml").safe_dump(data_parsed, allow_unicode=True, sort_keys=False),
                                encoding="utf-8")
                            print(f"[+] 命中 {n} 节点 -> {out}（第 {rounds} 轮，{time.time()-t0:.1f}s）", flush=True)
                            if n >= 10:
                                return 0
                        break
                    carry = data[-256:]
                    addr += len(blob)
            if rounds % 10 == 0:
                print(f"    round {rounds} @{time.time()-t0:.1f}s regions={len(regions)}", flush=True)
            time.sleep(a.interval)

    print(f"[*] 结束，{rounds} 轮，最多命中 {best_nodes} 节点", flush=True)
    return 0 if best_nodes else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
    except Exception:
        traceback.print_exc()
        raise SystemExit(1)
