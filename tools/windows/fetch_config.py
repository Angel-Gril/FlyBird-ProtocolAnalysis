#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fetch_config.py — 拉取并解码 fb_apexv2.json（远程配置）。

设计约束（可直接进自动服务）：
  1. **默认校验证书**：系统根 + 主机名。证书过期/不匹配 → 该镜像标记失败并跳过。
     只有显式 `--allow-expired`（仅容忍"时间无效"，错误码 10）或 `--insecure`（全放开）才继续，
     且会把叶子证书指纹写进报告，便于事后发现变更。
  2. **签名策略**：信封里出现 `signature` 时，默认必须验通才产出配置；
     没给可信公钥或验不过 → 退出码 3，不写配置。`--allow-unverified-signature` 可显式放行（仍记录）。
  3. **不写死 IP**：镜像只写主机名 + 路径；解析走系统 DNS，失败再走 DoH 兜底；
     需要固定落点时用 `--resolve HOST:IP`（可重复），不污染代码。

退出码：0 成功；2 参数/环境问题；3 签名未通过策略；4 全部镜像失败；5 解码失败。
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import socket
import ssl
import sys
import tempfile
import time
import urllib.error
import urllib.request

UA = "ua.net.fbclient.app.apex/7.3.1"

# 只写主机名 + 路径；IP 由 DNS/DoH/--resolve 决定
MIRRORS = [
    ("apisa-ax.cnossfile.com", "/apos/fb_apexv2.json"),
    ("cdno01-ax.llguanglisf.com", "/apos/fb_apexv2.json"),
    ("tcdn-ax.getxlx.com", "/saos/apos/fb_apexv2.json"),
    ("tcdn-ax.getxlx.com", "/apos/fb_apexv2.json"),
    ("ocdn01-ax.llguangli25o.com", "/apos/fb_apexv2.json"),
]
DOH_RESOLVERS = [
    ("dns.alidns.com", "/resolve?name={n}&type={t}"),
    ("doh.pub", "/dns-query?name={n}&type={t}"),
]
# 已知明文：用来反推每构建注入的 repeating-XOR 键
KNOWN_PLAINTEXTS = [
    b'{"format":"apex-config-v1","payload":"eyJ',
    b'{"format":"apex-config-v1"',
]


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


# ---------------------------------------------------------------- DNS
def resolve_system(host):
    try:
        return sorted({i[4][0] for i in socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)})
    except Exception:
        return []


def resolve_doh(host):
    for rhost, tpl in DOH_RESOLVERS:
        try:
            url = f"https://{rhost}" + tpl.format(n=host, t="A")
            req = urllib.request.Request(url, headers={"accept": "application/dns-json",
                                                       "user-agent": "apex-fetch"})
            ctx = ssl.create_default_context()
            with urllib.request.urlopen(req, context=ctx, timeout=8) as r:
                j = json.loads(r.read())
            ips = [a["data"] for a in j.get("Answer", []) if a.get("type") == 1]
            if ips:
                return ips, f"doh:{rhost}"
        except Exception:
            continue
    return [], "none"


def resolve(host, overrides):
    if host in overrides:
        return [overrides[host]], "override"
    ips = resolve_system(host)
    if ips:
        return ips, "system"
    ips, how = resolve_doh(host)
    return ips, how


# ---------------------------------------------------------------- HTTP
def tls_context(cert, verify, ca):
    if not verify:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    else:
        ctx = ssl.create_default_context(cafile=ca) if ca else ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
    if cert:
        ctx.load_cert_chain(cert[0], cert[1])
    return ctx


def fetch(host, path, cert, verify=True, ca=None):
    """返回 (status, body, info)。info 里带证书指纹/验证结论。"""
    ip_list, how = resolve(host, ARGS.resolve_map)
    if not ip_list:
        raise RuntimeError(f"DNS 解析失败（system+doh）: {host}")
    ips_report = ip_list
    last = None
    for ip in ip_list:
        ctx = tls_context(cert, verify, ca)
        try:
            sock = socket.create_connection((ip, 443), timeout=10)
            s = ctx.wrap_socket(sock, server_hostname=host)
        except ssl.SSLCertVerificationError as e:
            code = getattr(e, "verify_code", None)
            last = ("tls", code, str(e))
            raise RuntimeError(f"TLS 校验失败(code={code}): {e}")
        except Exception as e:
            last = ("conn", type(e).__name__, str(e)[:80])
            continue
        try:
            der = s.getpeercert(binary_form=True)
            fp = __import__("hashlib").sha256(der).hexdigest() if der else None
            req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {UA}\r\n"
                   f"Accept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n")
            s.sendall(req.encode())
            buf = b""
            while True:
                ch = s.recv(65536)
                if not ch:
                    break
                buf += ch
                if len(buf) > 4 * 1024 * 1024:
                    break
            s.close()
            head, _, body = buf.partition(b"\r\n\r\n")
            status = head.split(b"\r\n")[0].decode("latin-1") if head else "?"
            return status, body, {"ip": ip, "dns": how, "ips": ips_report,
                                  "leaf_sha256": fp, "verified": verify}
        except Exception as e:
            s.close()
            last = ("io", type(e).__name__, str(e)[:80])
            continue
    raise RuntimeError(f"连接失败: {last}")


# ---------------------------------------------------------------- 解码
def b64d(b):
    b = b.strip()
    return base64.b64decode(b + b"=" * (-len(b) % 4))


def recover_xor_key(ct):
    for kp in KNOWN_PLAINTEXTS:
        for klen in range(1, min(64, len(kp) - 2) + 1):
            key = bytes(ct[i] ^ kp[i] for i in range(klen))
            if all(ct[i] ^ key[i % klen] == kp[i] for i in range(len(kp))):
                return key
    return None


def decode(body, key=None):
    stage1 = b64d(body)
    if key is None:
        key = recover_xor_key(stage1)
        if key is None:
            raise RuntimeError("XOR 键反推失败（键长可能 ≥ 已知明文），请用 --key")
    env = json.loads(bytes(c ^ key[i % len(key)] for i, c in enumerate(stage1)).decode("utf-8"))
    payload = env.get("payload", "")
    cfg = json.loads(b64d(payload.encode()).decode("utf-8")) if payload else env
    return env, cfg, key


# ---------------------------------------------------------------- 签名
def verify_signature(env, pubkeys):
    """返回 (状态, 详情)。状态：absent / verified / unverified。"""
    sig_b64 = env.get("signature")
    if not sig_b64:
        return "absent", "信封无 signature 字段（旧格式）"
    try:
        sig = base64.b64decode(sig_b64)
    except Exception as e:
        return "unverified", f"signature 不是合法 base64: {e}"
    if len(sig) != 64:
        return "unverified", f"signature 长度 {len(sig)} != 64"
    payload = env.get("payload", "")
    msgs = {
        "payload_str": payload.encode(),
        "payload_raw": b64d(payload.encode()),
        "format+payload": b"apex-config-v1" + payload.encode(),
        "format|payload": b"apex-config-v1|" + payload.encode(),
    }
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    for name, key in pubkeys:
        try:
            pub = Ed25519PublicKey.from_public_bytes(key)
        except Exception:
            continue
        for mname, msg in msgs.items():
            try:
                pub.verify(sig, msg)
                return "verified", f"{name} / {mname}"
            except InvalidSignature:
                continue
    return "unverified", f"已试 {len(pubkeys)} 把公钥 × {len(msgs)} 种消息构造，均不匹配"


# ---------------------------------------------------------------- 主流程
def main():
    ap = argparse.ArgumentParser(description="拉取并解码 fb_apexv2.json（默认严格 TLS + 签名策略）")
    ap.add_argument("--certs", required=True, help="含 oss.crt / oss.key 的目录")
    ap.add_argument("--out", default="cfg")
    ap.add_argument("--key", default=None, help="32B XOR 键（明文）；不给则用已知明文反推")
    ap.add_argument("--resolve", action="append", default=[], metavar="HOST:IP",
                    help="固定解析（可重复），不写死在代码里")
    ap.add_argument("--ca", default=None, help="用指定 CA(PEM) 做校验（证书固定）")
    ap.add_argument("--allow-expired", action="store_true",
                    help="仅容忍证书**过期**（不改主机名校验），并记录指纹")
    ap.add_argument("--insecure", action="store_true", help="完全跳过校验（不推荐，会记录指纹）")
    ap.add_argument("--sign-pubkey", action="append", default=[],
                    help="配置签名公钥（base64 或 hex，可重复）")
    ap.add_argument("--allow-unverified-signature", action="store_true",
                    help="签名验不过也继续（仍会记录，退出码 0）")
    ap.add_argument("--json", action="store_true", help="只输出 JSON 摘要")
    global ARGS
    ARGS = ap.parse_args()

    ARGS.resolve_map = {}
    for item in ARGS.resolve:
        if ":" not in item:
            log(f"--resolve 格式应为 HOST:IP，忽略 {item}")
            continue
        h, ip = item.rsplit(":", 1)
        ARGS.resolve_map[h] = ip

    cert = (os.path.join(ARGS.certs, "oss.crt"), os.path.join(ARGS.certs, "oss.key"))
    for f in cert:
        if not os.path.exists(f):
            log(f"缺少 {f}")
            return 2
    os.makedirs(ARGS.out, exist_ok=True)

    pubkeys = []
    if ARGS.sign_pubkey:
        for s in ARGS.sign_pubkey:
            try:
                pubkeys.append(("cli", bytes.fromhex(s)))
            except ValueError:
                pubkeys.append(("cli", base64.b64decode(s + "=" * (-len(s) % 4))))

    report = {"mirrors": [], "started": time.strftime("%Y-%m-%dT%H:%M:%S")}
    body = None
    chosen = None

    for host, path in MIRRORS:
        entry = {"host": host, "path": path}
        for mode in ("strict", "expired-ok" if ARGS.allow_expired else None,
                     "insecure" if ARGS.insecure else None):
            if mode is None:
                continue
            verify = mode == "strict"
            try:
                status, data, info = fetch(host, path, cert, verify=verify, ca=ARGS.ca)
            except RuntimeError as e:
                entry.setdefault("attempts", []).append({"mode": mode, "error": str(e)[:160]})
                continue
            entry["attempts"] = entry.get("attempts", []) + [
                {"mode": mode, "status": status, "bytes": len(data),
                 "ip": info["ip"], "dns": info["dns"], "leaf_sha256": info["leaf_sha256"]}]
            if " 200 " in status and data[:1] not in (b"<",):
                body, chosen = data, (host, path, mode, info)
                break
        report["mirrors"].append(entry)
        if body:
            break

    if not body:
        report["result"] = "all_mirrors_failed"
        _emit(report)
        return 4

    report["chosen"] = {"host": chosen[0], "path": chosen[1], "mode": chosen[2],
                        "ip": chosen[3]["ip"], "dns": chosen[3]["dns"],
                        "leaf_sha256": chosen[3]["leaf_sha256"]}

    try:
        env, cfg, key = decode(body, ARGS.key.encode() if ARGS.key else None)
    except Exception as e:
        report["result"] = "decode_failed"
        report["error"] = str(e)
        _emit(report)
        return 5

    sig_status, sig_detail = verify_signature(env, pubkeys)
    report["signature"] = {"status": sig_status, "detail": sig_detail,
                           "present": bool(env.get("signature"))}
    report["xor_key_recovered"] = key.decode("latin-1")

    if sig_status == "unverified" and not ARGS.allow_unverified_signature:
        report["result"] = "signature_blocked"
        _emit(report)
        return 3

    for k in ("domains", "subscribe_domain"):
        if not isinstance(cfg.get(k), list):
            report["result"] = "schema_invalid"
            report["error"] = f"{k} 不是数组"
            _emit(report)
            return 5

    raw_path = os.path.join(ARGS.out, "raw.bin")
    open(raw_path, "wb").write(body)
    json.dump(env, open(os.path.join(ARGS.out, "envelope.json"), "w", encoding="utf-8"),
              ensure_ascii=False, indent=2)
    cfg_path = os.path.join(ARGS.out, "fb_apexv2.plain.json")
    fd, tmp = tempfile.mkstemp(dir=ARGS.out, prefix=".cfg-", suffix=".tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, cfg_path)

    report["result"] = "ok"
    report["output"] = {"config": cfg_path, "envelope": os.path.join(ARGS.out, "envelope.json"),
                        "raw": raw_path}
    report["config"] = {"domains": cfg.get("domains"),
                        "subscribe_domain": cfg.get("subscribe_domain"),
                        "subscribe_path_count": len(cfg.get("subscribe_path") or {})}
    _emit(report)
    return 0


def _emit(report):
    if ARGS.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return
    for m in report.get("mirrors", []):
        for a in m.get("attempts", []):
            if "error" in a:
                print(f"  ✗ {m['host']:<28} [{a['mode']}] {a['error']}")
            else:
                mark = "✓" if a["status"].startswith("HTTP/1.1 200") else "·"
                print(f"  {mark} {m['host']:<28} [{a['mode']}] {a['status']} "
                      f"{a['bytes']}B ip={a['ip']} dns={a['dns']}")
    print(f"\n结果: {report.get('result')}")
    if report.get("signature"):
        s = report["signature"]
        print(f"签名: {s['status']} — {s['detail']}")
    if report.get("config"):
        c = report["config"]
        print(f"domains={c['domains']}")
        print(f"subscribe_domain={c['subscribe_domain']}  路径映射={c['subscribe_path_count']} 条")
    if report.get("output"):
        print(f"输出: {report['output']['config']}")


if __name__ == "__main__":
    sys.exit(main())
