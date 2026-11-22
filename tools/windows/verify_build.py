#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
verify_build.py — 对 Windows 客户端安装目录做一次「协议常量是否仍然成立」的回归核对。

用法:
    python verify_build.py "C:\\rev\\apex-7.3.1"            # 目录或 app.so 均可
    python verify_build.py <dir> --json out.json

检查项:
  1) k1 / k2 / k3 三常量是否仍为已知值（默认值来自 7.2.3 起沿用的内置常量）
  2) APXS / apex-sub-v2 / apex-sub-sign-v2 / apex-config-v1 / apex UA 标记
  3) mTLS 证书包（裸 JSON 或 base64(JSON) 两种序列化都认）→ CN / 序列号 / 指纹
  4) APXS v2 信封：k1 + CTR(nonce‖0x00000002) 构造→解密往返自测
  5) apex-windows-components.json 与 ApexCore.exe / Apex.exe 实测 sha256 是否自洽

退出码: 0 全部通过 / 1 有不一致 / 2 输入不成立
依赖: cryptography（标准安装即可）
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import struct
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.x509.oid import ExtensionOID

# 7.2.3 起沿用的内置常量（公开值，见 docs/04）
K1 = "fCA3jkvhXpLEpDVuqPstNUS/kXewk7yGL5o8Fbh3uSc="
K2 = "lmzs43izW9GHIOOq+avbwhWh0TG/ldT3kipGkrQ4RiE="
K3 = "xZ//fP0AfP+8yW4OAZOrcKHe7dO78+Gpwu1ewno/fd8="

MARKERS = [
    "APXS", "apex-sub-v2", "apex-sub-sign-v2", "apex-config-v1",
    "ua.net.fbclient.app.apex", "xorBase64Deobfuscate", "enable_api_path_mapping",
]

# 7.2.3 记录的三张客户端证书指纹前缀，用于判断是否轮换
PRIOR_FP = {
    "api": "99bd6d087af29dbc",
    "subscription": "d2cb3a9144c1e08c",
    "oss": "584e70ac53b67bf1",
}


def locate(root: str) -> str:
    p = os.path.abspath(root)
    candidates = [
        p,
        os.path.join(p, "app", "data", "app.so"),
        os.path.join(p, "data", "app.so"),
        os.path.join(p, "installed", "data", "app.so"),
    ]
    for c in candidates:
        if os.path.isfile(c) and c.endswith("app.so"):
            return c
    raise SystemExit(f"在 {root} 下找不到 data/app.so（先跑 unpack_installer.ps1）")


class Result:
    def __init__(self):
        self.checks: dict[str, dict] = {}
        self.ok = True

    def put(self, key, passed, detail):
        self.checks[key] = {"ok": bool(passed), "detail": detail}
        if not passed:
            self.ok = False


def check_constants(text, res):
    for name, val in (("k1", K1), ("k2", K2), ("k3", K3)):
        off = text.find(val)
        if off < 0:
            res.put(name, False, "未找到（常量可能已更换，需要重新抓）")
            continue
        raw = base64.b64decode(val)
        res.put(name, True, {"offset": hex(off), "raw_len": len(raw),
                             "hex16": raw.hex()[:32] + "..."})


def check_markers(text, res):
    found = {m: hex(text.find(m)) for m in MARKERS if m in text}
    missing = [m for m in MARKERS if m not in text]
    res.put("markers", not missing, {"found": found, "missing": missing})


def iter_bundles(text):
    """兼容两种序列化：裸 JSON（7.2.3）与 base64(JSON)（7.3.1+）。"""
    for m in re.finditer(r'\{"version":\s*\d+,\s*"profile_id".{0,12000}?\}', text, re.S):
        try:
            yield m.start(), json.loads(m.group(0))
        except Exception:
            continue
    for m in re.finditer(r"eyJ[A-Za-z0-9+/]{500,}={0,2}", text):
        s = m.group(0)
        cut = len(s) - len(s) % 4
        try:
            raw = base64.b64decode(s[:cut])
        except Exception:
            continue
        if b"client_cert_pem" not in raw:
            continue
        try:
            yield m.start(), json.loads(raw)
        except Exception:
            continue


def check_mtls(text, res, outdir):
    bundles = {}
    for off, o in iter_bundles(text):
        purpose = o.get("purpose") or "?"
        try:
            c = x509.load_pem_x509_certificate(o["client_cert_pem"].encode())
            k = serialization.load_pem_private_key(o["client_key_pem"].encode(), password=None)
        except Exception as e:
            bundles[purpose] = {"error": str(e), "bundle_offset": hex(off)}
            continue
        try:
            eku = [e._name for e in c.extensions.get_extension_for_oid(
                ExtensionOID.EXTENDED_KEY_USAGE).value]
        except Exception:
            eku = []
        fp = c.fingerprint(hashes.SHA256()).hex()
        bundles[purpose] = {
            "bundle_offset": hex(off),
            "cn": c.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value,
            "issuer_cn": c.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value,
            "serial": format(c.serial_number, "x"),
            "not_before": str(c.not_valid_before_utc),
            "not_after": str(c.not_valid_after_utc),
            "eku": eku,
            "key_bits": getattr(k, "key_size", None),
            "sha256_fp": fp,
            "rotated_vs_7223": not fp.startswith(PRIOR_FP.get(purpose, "?")),
        }
        for suffix, blob in (("crt", o["client_cert_pem"]), ("key", o["client_key_pem"])):
            with open(os.path.join(outdir, f"profile5_{purpose}_client.{suffix}.pem"), "wb") as f:
                f.write(blob.encode())

    complete = set(bundles) >= {"api", "subscription", "oss"}
    rotated = [p for p, v in bundles.items() if v.get("rotated_vs_7223")]
    res.put("mtls_bundles", complete and not rotated,
            {"bundles": bundles, "rotated": rotated})


def check_envelope(res):
    """synthetic APXS：构造 → 解密，验证 k1 与 nonce‖0x00000002 这条唯一正确路径。"""
    plain = b"mixed-port: 7890\nproxies:\n  - name: Hong Kong-01\n    type: vless\n"
    nonce = bytes(range(12))
    enc = Cipher(algorithms.AES(base64.b64decode(K1)),
                 modes.CTR(nonce + b"\x00\x00\x00\x02")).encryptor()
    ct = enc.update(plain) + enc.finalize()
    env = b"APXS" + b"\x02" + struct.pack(">II", 1, 1) + nonce + ct + b"\x00" * 16 + b"\x00" * 64

    aes_id, sign_id = struct.unpack(">II", env[5:13])
    dec = Cipher(algorithms.AES(base64.b64decode(K1)),
                 modes.CTR(env[13:25] + b"\x00\x00\x00\x02")).decryptor()
    got = dec.update(env[25:len(env) - 80]) + dec.finalize()
    res.put("apxs_roundtrip", got == plain and aes_id == 1 and sign_id == 1,
            {"envelope_len": len(env), "plain_len": len(plain),
             "aesID": aes_id, "signID": sign_id})


def check_manifest(appdir, res):
    man_path = os.path.join(appdir, "apex-windows-components.json")
    if not os.path.exists(man_path):
        res.put("component_manifest", True, "无清单（此版本未引入组件校验）")
        return
    man = json.load(open(man_path, encoding="utf-8"))
    entry = {f["path"]: f["sha256"] for f in man.get("files", [])}

    def sha(p):
        return hashlib.sha256(open(p, "rb").read()).hexdigest() if os.path.exists(p) else None

    core_actual = sha(os.path.join(appdir, "ApexCore.exe"))
    gui_actual = sha(os.path.join(appdir, "Apex.exe"))
    detail = {
        "schema": man.get("schema"),
        "service_name": man.get("service_name"),
        "files": len(man.get("files", [])),
        "core_sha256_manifest": man.get("core_sha256"),
        "core_sha256_actual": core_actual,
        "core_match": core_actual == man.get("core_sha256"),
        "apex_exe_manifest": entry.get("Apex.exe"),
        "apex_exe_actual": gui_actual,
        "wintun_sha256": man.get("wintun_sha256"),
        "wintun_bytes": man.get("wintun_bytes"),
    }
    res.put("component_manifest",
            detail["core_match"] and detail["apex_exe_manifest"] == gui_actual, detail)


def _core_version_near_go(t: str) -> str | None:
    """Go 构建把自身版本号写在 runtime 版本串旁边（'go1.25.2 … v1.19.33'），
    比"全库最大版本号"可靠（依赖 tag 会污染最大值）。"""
    m = re.search(r"go1\.\d+(?:\.\d+)?", t)
    if not m:
        return None
    window = t[max(0, m.start() - 256): m.start() + 256]
    cand = re.findall(r"v1\.\d{1,2}\.\d{1,2}", window)
    if cand:
        return max(cand, key=lambda s: tuple(int(x) for x in s[1:].split(".")))
    cnt = {}
    for v in re.findall(r"v1\.\d{1,2}\.\d{1,2}", t):
        cnt[v] = cnt.get(v, 0) + 1
    return max(cnt, key=cnt.get) if cnt else None


def check_core_features(appdir, res):
    """内核里有没有 APXS 能力、有没有私有 apex 传输 —— 决定"改 core / 换内核"两条路线的可行性。"""
    core = os.path.join(appdir, "ApexCore.exe")
    helper = os.path.join(appdir, "ApexHelperService.exe")
    if not os.path.exists(core):
        res.put("core_features", True, "无内核（跳过）")
        return
    b = open(core, "rb").read()
    t = b.decode("latin-1")
    ht = open(helper, "rb").read().decode("latin-1") if os.path.exists(helper) else ""
    feats = {
        "apxs_in_core": any(x in t for x in ("APXS", "OpenAPXS", "key32")),
        "apex_transport": "transport/apex" in t,
        "apex_outbound": "outbound.Apex" in t,
        "manifest_hook_in_helper": "components.json" in ht,
        "go_version": (re.search(r"go1\.\d+(?:\.\d+)?", t).group(0)
                       if re.search(r"go1\.\d+(?:\.\d+)?", t) else None),
        "mihomo_version": _core_version_near_go(t),
        "size": len(b),
        "sha256": hashlib.sha256(b).hexdigest(),
    }
    res.put("core_features", True, feats)


def main() -> int:
    ap = argparse.ArgumentParser(description="7.3.x 构建的协议常量回归核对")
    ap.add_argument("target", help="安装目录 或 data/app.so")
    ap.add_argument("--json", default=None, help="结论输出路径（默认写在 app.so 同级）")
    a = ap.parse_args()

    appso = locate(a.target)
    # <app>\data\app.so 与"扁平证据目录\app.so"两种布局都要认
    appdir = os.path.dirname(appso)
    if not os.path.exists(os.path.join(appdir, "ApexCore.exe")):
        parent = os.path.dirname(appdir)
        if os.path.exists(os.path.join(parent, "ApexCore.exe")):
            appdir = parent
    out = a.json or os.path.join(appdir, "verify_build.json")

    blob = open(appso, "rb").read()
    text = blob.decode("latin-1")
    res = Result()
    res.put("app_so", True, {"path": appso, "size": len(blob),
                             "sha256": hashlib.sha256(blob).hexdigest()})

    check_constants(text, res)
    check_markers(text, res)
    check_mtls(text, res, appdir)
    check_envelope(res)
    check_manifest(appdir, res)
    check_core_features(appdir, res)

    payload = {"target": appdir, "app_so": res.checks.pop("app_so")["detail"],
               "ok": res.ok, "checks": res.checks}
    with open(out, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)

    print(f"app.so  {payload['app_so']['size']:,} B  sha256={payload['app_so']['sha256']}\n")
    for k, v in payload["checks"].items():
        print(f"[{'PASS' if v['ok'] else 'FAIL'}] {k}")
        d = v["detail"]
        if isinstance(d, dict):
            for kk, vv in d.items():
                if isinstance(vv, dict):
                    if "cn" in vv:
                        print(f"        {kk}: CN={vv['cn']}")
                        print(f"            serial={vv['serial']} key_bits={vv.get('key_bits')} "
                              f"rotated={vv.get('rotated_vs_7223')}")
                        print(f"            fp={vv['sha256_fp']}")
                    else:
                        # 例如 mtls_bundles: {"bundles": {purpose: {...}}, "rotated": []}
                        print(f"        {kk}:")
                        for pk, pv in vv.items():
                            if isinstance(pv, dict) and "cn" in pv:
                                print(f"            {pk}: CN={pv['cn']} bits={pv.get('key_bits')} "
                                      f"rotated={pv.get('rotated_vs_7223')}")
                                print(f"                fp={pv['sha256_fp']}")
                            else:
                                print(f"            {pk}: {pv}")
                elif isinstance(vv, list):
                    print(f"        {kk}: {vv}")
                else:
                    print(f"        {kk}: {vv}")
        else:
            print(f"        {d}")
    print(f"\n总体: {'全部通过' if payload['ok'] else '存在不一致'}  -> {out}")
    return 0 if payload["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
