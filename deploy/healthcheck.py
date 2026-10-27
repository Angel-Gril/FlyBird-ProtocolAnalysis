#!/usr/bin/env python3
"""healthcheck.py — 容器健康检查：产物存在且未过期。"""
import os
import sys
import time

path = os.environ.get("OUT", "/output/sub.yaml")
interval = int(os.environ.get("INTERVAL", "21600"))
limit = interval * 2 + 3600

if not os.path.exists(path):
    print(f"unhealthy: {path} 不存在")
    sys.exit(1)

age = time.time() - os.path.getmtime(path)
size = os.path.getsize(path)
print(f"age={age:.0f}s size={size}B limit={limit}s")
sys.exit(0 if age < limit and size > 1024 else 1)
