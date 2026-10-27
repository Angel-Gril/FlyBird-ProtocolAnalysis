"""oss_probe.py — 从本地（中国出口）测 OSS 配置端点。"""
import time

import requests
import urllib3

urllib3.disable_warnings()
UA = "ua.net.fbclient.app.apex/v7.2.4"
T = int(time.time() * 1000)
HDR = {"user-agent": UA, "cache-control": "no-cache, no-store", "pragma": "no-cache",
       "accept-encoding": "gzip"}
HOSTS = ["tcdn-ax.getxlx.com", "oss-aws01.llguangli25n.com", "cdn01.llguangli25o.com"]
PATHS = ["/saos/apos/fb_apexv2.json", "/apos/fb_apexv2.json", "/saos/apos/fb_apex.json"]

for h in HOSTS:
    for p in PATHS:
        try:
            r = requests.get(f"https://{h}{p}?t={T}", headers=HDR, timeout=15, verify=False)
            ct = r.headers.get("content-type", "")
            print(f"{h:32}{p:26} -> {r.status_code} {len(r.content):6}B {ct}")
            if r.status_code == 200 and len(r.content) > 50:
                open("http/oss_cfg_" + h.split(".")[0] + ".json", "wb").write(r.content)
                print("    saved; head:", r.content[:300])
        except Exception as e:
            print(f"{h:32}{p:26} -> ERR {type(e).__name__} {str(e)[:60]}")
