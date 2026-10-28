#!/usr/bin/env python3
"""v1_legacy.py — 遗留明文订阅接口（/api/v1/client/subscribe）的解析与转换

背景
----
服务端在同一账号下同时提供两条订阅线路：

  v1（本模块）  GET  {API}/api/v1/client/subscribe?token=<access_key>
                需 api 客户端证书 + apex UA，返回 **纯文本 URI 列表**
  v2（主线路）  GET  {SUB}/v2/feed/download?access_key=<access_key>
                需 subscription 客户端证书 + apex UA，返回 **APXS 加密信封**

两者节点集完全不同（见 docs/09），本模块负责 v1 的解析、Clash 渲染与合并。

格式
----
v1 响应体是「注释 + URI 行」：

    # remaining: 105055509255
    # expire_at: 2027-02-11T10:32:15Z
    trojan://<uuid>@<host>:443?sni=<sni>&allowInsecure=1#Hong+Kong-01
    ss://<base64(method:password@host:port)>#%5BSS%5D+Hong+Kong-01

- 注释行携带流量/到期信息（不是 HTTP 头）；
- trojan 行：密码即 UUID，端口固定 443，靠 SNI 区分节点；
- ss 行：**旧式 SIP002**，`method:password@host:port` 整体 base64；
- 另有 1 条「Ss密码单端口承载」提示行（host 为纯数字），不是节点，跳过。
"""
from __future__ import annotations

import base64
import binascii
import re
import urllib.parse as up

# 注释行 → 元数据字段（小写，原样保留）
META_PREFIX = "# "

SS_LEGACY_RE = re.compile(r"^([^:]+):(.*)@([^:\s]+):(\d+)$")
HOSTPORT_RE = re.compile(r"@([^:/?#\s\[\]]+):(\d+)")


def _b64(s: str) -> bytes:
    s = s.strip().replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s)
    except (binascii.Error, ValueError):
        return b""


def _unquote(s: str) -> str:
    return up.unquote_plus(s or "").strip()


def _split_fragment(line: str) -> tuple[str, str]:
    """拆出 #name，返回 (主体, 名称)"""
    if "#" in line:
        body, frag = line.split("#", 1)
        return body, _unquote(frag)
    return line, ""


def _qsv(query: str) -> dict:
    return {k: v[0] for k, v in up.parse_qs(query, keep_blank_values=True).items()}


def parse_trojan(line: str, name: str) -> dict | None:
    u = up.urlsplit(line)
    if not u.hostname:
        return None
    qs = _qsv(u.query)
    sni = qs.get("sni") or qs.get("peer") or u.hostname
    insecure = str(qs.get("allowInsecure") or qs.get("insecure") or "0").lower()
    return {
        "name": name or f"trojan-{u.hostname}",
        "type": "trojan",
        "server": u.hostname,
        "port": u.port or 443,
        "password": _unquote(u.username or ""),
        "sni": sni,
        "skip-cert-verify": insecure in ("1", "true", "yes"),
        "udp": True,
    }


def parse_ss(line: str, name: str) -> dict | None:
    """兼容 SIP002（userinfo@host:port）与旧式（整段 base64）"""
    body = line[len("ss://"):]
    body, frag_name = _split_fragment(body)
    name = name or frag_name

    method = password = host = None
    port = 0

    if "@" in body:
        userinfo, _, hp = body.rpartition("@")
        hp = _unquote(hp)
        m = HOSTPORT_RE.match("@" + hp)
        if not m:
            return None
        host, port = m.group(1), int(m.group(2))
        # userinfo 可能是 base64(method:password) 或明文
        decoded = _b64(userinfo).decode("utf-8", "replace") if ":" not in userinfo else userinfo
        if ":" not in decoded:
            return None
        method, _, password = decoded.partition(":")
    else:
        raw = _b64(_unquote(body)).decode("utf-8", "replace")
        m = SS_LEGACY_RE.match(raw)
        if not m:
            return None
        method, password, host, port = m.group(1), m.group(2), m.group(3), int(m.group(4))
        # 「单端口承载」提示行：host 是纯数字端口而非域名
        if host.isdigit():
            return None

    if not host or not port or not method:
        return None
    return {
        "name": name or f"ss-{host}",
        "type": "ss",
        "server": host,
        "port": port,
        "cipher": method,
        "password": password,
        "udp": True,
    }


PARSERS = {"trojan": parse_trojan, "ss": parse_ss}


def parse_plaintext(text: str) -> tuple[list[dict], dict, int]:
    """解析 v1 明文 → (proxies, meta, skipped)"""
    proxies: list[dict] = []
    meta: dict = {}
    skipped = 0

    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#"):
            if line.startswith(META_PREFIX) and ":" in line:
                k, v = line[len(META_PREFIX):].split(":", 1)
                meta[k.strip().lower()] = v.strip()
            continue
        if "://" not in line:
            skipped += 1
            continue
        scheme = line.split("://", 1)[0].lower()
        fn = PARSERS.get(scheme)
        if not fn:
            skipped += 1
            continue
        body, name = _split_fragment(line)
        try:
            p = fn(body if scheme != "ss" else line, name)
        except Exception:
            skipped += 1
            continue
        if not p:
            skipped += 1
            continue
        proxies.append(p)

    # 重名去重（同名加序号）
    seen: dict[str, int] = {}
    for p in proxies:
        n = p["name"]
        if n in seen:
            seen[n] += 1
            p["name"] = f"{n} #{seen[n]}"
        else:
            seen[n] = 1
    return proxies, meta, skipped


def prefix_names(proxies: list[dict], prefix: str) -> list[dict]:
    if not prefix:
        return proxies
    out = []
    for p in proxies:
        q = dict(p)
        q["name"] = f"{prefix}{p['name']}"
        out.append(q)
    return out


# ---------------------------------------------------------------- 渲染 / 合并

def _scalar(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    s = str(v)
    if s == "" or re.search(r"[:#\[\]{}&*!|>'\"%@`,]|^\s|\s$", s) or s.lower() in (
            "true", "false", "yes", "no", "on", "off", "null", "~"):
        return "'" + s.replace("'", "''") + "'"
    return s


def _inline(p: dict) -> str:
    parts = []
    for k, v in p.items():
        if isinstance(v, dict):
            sub = ", ".join(f"{_scalar(kk)}: {_scalar(vv)}" for kk, vv in v.items())
            parts.append(f"{k}: {{{sub}}}")
        elif isinstance(v, list):
            parts.append(f"{k}: [{', '.join(_scalar(x) for x in v)}]")
        else:
            parts.append(f"{k}: {_scalar(v)}")
    return "{" + ", ".join(parts) + "}"


def build_config(proxies: list[dict], meta: dict, mixed_port: int = 7890,
                 ctrl_port: int = 9090) -> str:
    """v1-only 时生成一份最小可用配置"""
    names = [p["name"] for p in proxies]
    lines = ["# 由 v1 明文线路生成（无 APXS 解密）"]
    if meta.get("remaining", "").isdigit():
        lines.append(f"# remaining: {meta['remaining']} B")
    if meta.get("expire_at"):
        lines.append(f"# expire_at: {meta['expire_at']}")
    lines += [
        f"# nodes: {len(proxies)}",
        "",
        f"mixed-port: {mixed_port}",
        "allow-lan: false",
        "bind-address: 127.0.0.1",
        "mode: rule",
        "log-level: info",
    ]
    if ctrl_port:
        lines.append(f"external-controller: 127.0.0.1:{ctrl_port}")
    lines += ["", "proxies:"]
    for p in proxies:
        lines.append("  - " + _inline(p))
    lines += [
        "",
        "proxy-groups:",
        "  - name: PROXY",
        "    type: select",
        "    proxies:",
        "      - AUTO",
    ]
    for n in names:
        lines.append(f"      - {_scalar(n)}")
    lines += [
        "      - DIRECT",
        "  - name: AUTO",
        "    type: url-test",
        "    url: http://www.gstatic.com/generate_204",
        "    interval: 300",
        "    proxies:",
    ]
    for n in names:
        lines.append(f"      - {_scalar(n)}")
    lines += ["", "rules:", "  - GEOIP,LAN,DIRECT,no-resolve", "  - GEOIP,CN,DIRECT",
              "  - MATCH,PROXY", ""]
    return "\n".join(lines)


def merge_into_config(v2_text: str, proxies: list[dict],
                      group_prefix: str = "v1") -> str:
    """把 v1 节点合并进 v2 的完整配置（需要 PyYAML）"""
    try:
        import yaml
    except ImportError as e:
        raise RuntimeError("合并模式需要 PyYAML：pip install pyyaml") from e

    doc = yaml.safe_load(v2_text)
    if not isinstance(doc, dict):
        raise RuntimeError("v2 配置不是映射结构")

    existing = doc.get("proxies") or []
    seen = {p.get("name") for p in existing}
    added = []
    for p in proxies:
        if p["name"] in seen:
            p = dict(p, name=f"{p['name']} #dup")
        seen.add(p["name"])
        added.append(p)
    doc["proxies"] = list(existing) + added

    groups = doc.get("proxy-groups") or []
    by_type: dict[str, list[str]] = {}
    for p in added:
        by_type.setdefault(p["type"], []).append(p["name"])

    new_groups = []
    for typ, names in sorted(by_type.items()):
        gname = f"{group_prefix}-{typ}"
        new_groups.append({
            "name": gname,
            "type": "url-test",
            "url": "http://www.gstatic.com/generate_204",
            "interval": 300,
            "proxies": names,
        })
    doc["proxy-groups"] = groups + new_groups

    # 把新分组挂到第一个 select 分组的最前面，保证默认策略能选到
    for g in doc["proxy-groups"]:
        if g.get("type") == "select":
            g["proxies"] = [x["name"] for x in new_groups] + list(g.get("proxies") or [])
            break

    return yaml.safe_dump(doc, allow_unicode=True, sort_keys=False, width=4096)
