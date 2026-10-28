/**
 * Cloudflare Worker — 订阅抓取（v2 APXS / v1 明文 / both 合并）
 *
 * v2（主线路）
 *   POST {API}/v2/auth/token              env.API_CERT（mTLS）
 *   GET  {SUB}/v2/feed/download           env.SUB_CERT（mTLS）
 *   → APXS，本地 AES-256-CTR 解密（WebCrypto）
 *
 * v1（遗留明文线路）
 *   POST {API}/api/v1/passport/auth/login env.API_CERT
 *   GET  {API}/api/v1/client/subscribe    env.API_CERT + apex UA
 *   → text/plain URI 列表，无需解密
 *
 * 端点：
 *   POST /decode                     body=APXS → YAML（无需账号）
 *   GET  /sub?token=xx&source=       v2|v1|both，KV 缓存
 *   GET  /health                     缓存状态
 *   cron                             定时刷新
 */

const K1_B64 = "fCA3jkvhXpLEpDVuqPstNUS/kXewk7yGL5o8Fbh3uSc=";
const TRAILER = 16 + 64;
const UA = "ua.net.fbclient.app.apex/7.2.5";
const DEFAULT_API = "https://fbaxapi.apiv2.a047.com";
const DEFAULT_SUB = "https://fbaxsub.web.ak005.com";

// ---------------------------------------------------------------- 工具

function b64ToBytes(s) {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function tryB64ToText(s) {
  try {
    const clean = s.trim().replace(/-/g, "+").replace(/_/g, "/");
    const pad = "=".repeat((4 - (clean.length % 4)) % 4);
    return atob(clean + pad);
  } catch {
    return "";
  }
}

function decodeComponent(s) {
  try {
    return decodeURIComponent(String(s).replace(/\+/g, " "));
  } catch {
    return String(s);
  }
}

// ---------------------------------------------------------------- APXS

async function decryptApxs(buf) {
  if (buf.length < 25 + TRAILER) throw new Error(`APXS 太短: ${buf.length}`);
  const magic = String.fromCharCode(buf[0], buf[1], buf[2], buf[3]);
  if (magic !== "APXS") throw new Error(`magic 不是 APXS: ${magic}`);
  if (buf[4] !== 0x02) throw new Error(`不支持的版本 0x${buf[4].toString(16)}`);
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const aesId = view.getUint32(5, false);
  const signId = view.getUint32(9, false);
  const nonce = buf.subarray(13, 25);
  const ct = buf.subarray(25, buf.length - TRAILER);

  const key = await crypto.subtle.importKey("raw", b64ToBytes(K1_B64), "AES-CTR", false, ["decrypt"]);
  const counter = new Uint8Array(16);
  counter.set(nonce, 0);
  counter[15] = 0x02;
  const plain = await crypto.subtle.decrypt({ name: "AES-CTR", counter, length: 32 }, key, ct);
  return { plain: new Uint8Array(plain), aesId, signId };
}

// ---------------------------------------------------------------- v1 解析

function parseV1(text) {
  const proxies = [];
  const meta = {};
  let skipped = 0;
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (!line) continue;
    if (line.startsWith("#")) {
      const m = line.match(/^#\s*([A-Za-z_]+)\s*:\s*(.+)$/);
      if (m) meta[m[1].toLowerCase()] = m[2].trim();
      continue;
    }
    if (!line.includes("://")) { skipped++; continue; }
    const scheme = line.split("://", 1)[0].toLowerCase();
    const hashIdx = line.indexOf("#");
    const body = hashIdx >= 0 ? line.slice(0, hashIdx) : line;
    const name = hashIdx >= 0 ? decodeComponent(line.slice(hashIdx + 1)) : "";

    try {
      if (scheme === "trojan") {
        const u = new URL(body);
        proxies.push({
          name: name || `trojan-${u.hostname}`,
          type: "trojan",
          server: u.hostname,
          port: Number(u.port) || 443,
          password: decodeComponent(u.username),
          sni: u.searchParams.get("sni") || u.hostname,
          "skip-cert-verify": ["1", "true"].includes((u.searchParams.get("allowInsecure") || "0").toLowerCase()),
          udp: true,
        });
      } else if (scheme === "ss") {
        const bare = body.slice(5);
        let method, password, host, port;
        if (bare.includes("@")) {
          const at = bare.lastIndexOf("@");
          const userinfo = decodeComponent(bare.slice(0, at));
          const hp = bare.slice(at + 1);
          const c = hp.lastIndexOf(":");
          host = hp.slice(0, c);
          port = Number(hp.slice(c + 1));
          const dec = userinfo.includes(":") ? userinfo : tryB64ToText(userinfo);
          [method, password] = dec.split(/:(.*)/s);
        } else {
          const dec = tryB64ToText(decodeComponent(bare));
          const m = dec.match(/^([^:]+):(.*)@([^:@\s]+):(\d+)$/);
          if (!m) { skipped++; continue; }
          method = m[1]; password = m[2]; host = m[3]; port = Number(m[4]);
          if (/^\d+$/.test(host)) { skipped++; continue; } // 「单端口承载」提示行
        }
        if (!host || !port || !method) { skipped++; continue; }
        proxies.push({
          name: name || `ss-${host}`,
          type: "ss",
          server: host,
          port,
          cipher: method,
          password,
          udp: true,
        });
      } else {
        skipped++;
      }
    } catch {
      skipped++;
    }
  }
  return { proxies, meta, skipped };
}

// ---------------------------------------------------------------- YAML 渲染

function q(v) {
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number") return String(v);
  const s = String(v);
  if (s === "" || /[:#[\]{}&*!|>'"%@`,]|^\s|\s$/.test(s)) return `'${s.replace(/'/g, "''")}'`;
  if (["true", "false", "yes", "no", "on", "off", "null", "~"].includes(s.toLowerCase())) return `'${s}'`;
  return s;
}

function inline(p) {
  return "{" + Object.entries(p).map(([k, v]) => {
    if (v && typeof v === "object" && !Array.isArray(v)) {
      return `${k}: {` + Object.entries(v).map(([kk, vv]) => `${q(kk)}: ${q(vv)}`).join(", ") + "}";
    }
    if (Array.isArray(v)) return `${k}: [${v.map(q).join(", ")}]`;
    return `${k}: ${q(v)}`;
  }).join(", ") + "}";
}

function buildConfig(proxies, meta, mixedPort = 7890) {
  const names = proxies.map((p) => p.name);
  const L = ["# 由 v1 明文线路生成（未使用 APXS）"];
  if (meta.remaining) L.push(`# remaining: ${meta.remaining}`);
  if (meta.expire_at) L.push(`# expire_at: ${meta.expire_at}`);
  L.push(`# nodes: ${proxies.length}`, "", `mixed-port: ${mixedPort}`,
    "allow-lan: false", "bind-address: 127.0.0.1", "mode: rule", "log-level: info",
    "external-controller: 127.0.0.1:9090", "", "proxies:");
  for (const p of proxies) L.push("  - " + inline(p));
  L.push("", "proxy-groups:", "  - name: PROXY", "    type: select", "    proxies:",
    "      - AUTO");
  for (const n of names) L.push(`      - ${q(n)}`);
  L.push("      - DIRECT", "  - name: AUTO", "    type: url-test",
    "    url: http://www.gstatic.com/generate_204", "    interval: 300", "    proxies:");
  for (const n of names) L.push(`      - ${q(n)}`);
  L.push("", "rules:", "  - GEOIP,LAN,DIRECT,no-resolve", "  - GEOIP,CN,DIRECT",
    "  - MATCH,PROXY", "");
  return L.join("\n");
}

/** 把 v1 节点文本插入 v2 配置（不引入 YAML 解析器，按结构定位） */
function mergeConfig(v2Text, proxies) {
  const lines = v2Text.split("\n");
  const pIdx = lines.findIndex((l) => /^proxies:\s*$/.test(l));
  if (pIdx < 0) throw new Error("v2 配置缺少 proxies: 段");

  // proxies 段结束位置：第一个非缩进、非空行
  let pEnd = lines.length;
  for (let i = pIdx + 1; i < lines.length; i++) {
    const l = lines[i];
    if (l.trim() === "") continue;
    if (!/^\s/.test(l)) { pEnd = i; break; }
  }
  const inserted = proxies.map((p) => "  - " + inline(p));

  // 分组
  const gIdx = lines.findIndex((l) => /^proxy-groups:\s*$/.test(l));
  const byType = {};
  for (const p of proxies) (byType[p.type] ||= []).push(p.name);
  const newGroups = Object.entries(byType).map(([t, names]) => ({
    name: `v1-${t}`, type: "url-test",
    url: "http://www.gstatic.com/generate_204", interval: 300, proxies: names,
  }));

  let out = [...lines.slice(0, pEnd), ...inserted, ...lines.slice(pEnd)];
  if (gIdx >= 0) {
    // 重新定位（插入后偏移）
    const gIdx2 = out.findIndex((l) => /^proxy-groups:\s*$/.test(l));
    let gEnd = out.length;
    for (let i = gIdx2 + 1; i < out.length; i++) {
      const l = out[i];
      if (l.trim() === "") continue;
      if (!/^\s/.test(l)) { gEnd = i; break; }
    }
    const gLines = [];
    for (const g of newGroups) {
      gLines.push(`  - name: ${q(g.name)}`, "    type: url-test",
        "    url: http://www.gstatic.com/generate_204", "    interval: 300", "    proxies:");
      for (const n of g.proxies) gLines.push(`      - ${q(n)}`);
    }
    out = [...out.slice(0, gEnd), ...gLines, ...out.slice(gEnd)];
  }
  return out.join("\n");
}

// ---------------------------------------------------------------- 网络

const json = (body, status = 200) => new Response(JSON.stringify(body, null, 2), {
  status,
  headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
});

async function v2Fetch(env) {
  const api = env.API_BASE || DEFAULT_API;
  const sub = env.SUB_BASE || DEFAULT_SUB;

  const r = await env.API_CERT.fetch(`${api}/v2/auth/token`, {
    method: "POST",
    headers: { "user-agent": UA, "content-type": "application/json; charset=utf-8", accept: "application/json" },
    body: JSON.stringify({ email: env.APEX_EMAIL, password: env.APEX_PASSWORD }),
  });
  if (!r.ok) throw new Error(`v2 登录失败 HTTP ${r.status}`);
  const data = (await r.json()).data || {};
  if (!data.token) throw new Error("v2 登录响应缺少 token");

  const d = await env.SUB_CERT.fetch(`${sub}/v2/feed/download?access_key=${encodeURIComponent(data.token)}`, {
    headers: { "user-agent": UA, accept: "*/*" },
  });
  if (!d.ok) throw new Error(`v2 下载失败 HTTP ${d.status}`);
  const { plain, aesId, signId } = await decryptApxs(new Uint8Array(await d.arrayBuffer()));
  const text = new TextDecoder().decode(plain);
  if (!/(^|\n)\s*proxies:/.test(text)) throw new Error("v2 解密结果不是订阅 YAML");
  const nodes = (text.match(/^\s*-\s*\{/gm) || []).length || (text.match(/^\s*-\s+name:/gm) || []).length;
  return { text, nodes, aesId, signId };
}

async function v1Fetch(env) {
  const api = env.API_BASE || DEFAULT_API;
  const r = await env.API_CERT.fetch(`${api}/api/v1/passport/auth/login`, {
    method: "POST",
    headers: { "user-agent": UA, "content-type": "application/json; charset=utf-8", accept: "application/json" },
    body: JSON.stringify({ email: env.APEX_EMAIL, password: env.APEX_PASSWORD }),
  });
  if (!r.ok) throw new Error(`v1 登录失败 HTTP ${r.status}`);
  const data = (await r.json()).data || {};
  if (!data.token) throw new Error("v1 登录响应缺少 token");

  const s = await env.API_CERT.fetch(`${api}/api/v1/client/subscribe?token=${encodeURIComponent(data.token)}`, {
    headers: { "user-agent": UA, accept: "*/*" },
  });
  if (!s.ok) throw new Error(`v1 订阅失败 HTTP ${s.status}`);
  const text = await s.text();
  const parsed = parseV1(text);
  return { raw: text, ...parsed, nodes: parsed.proxies.length };
}

async function build(env, source) {
  const t0 = Date.now();
  let body;
  let nodes;
  let info = { source };

  if (source === "v1") {
    const v1 = await v1Fetch(env);
    body = buildConfig(v1.proxies, v1.meta);
    nodes = v1.nodes;
    info = { ...info, v1: v1.nodes, remaining: v1.meta.remaining, expire_at: v1.meta.expire_at };
  } else if (source === "both") {
    const [v2, v1] = await Promise.all([
      v2Fetch(env).catch((e) => { info.v2_error = String(e.message || e); return null; }),
      v1Fetch(env).catch((e) => { info.v1_error = String(e.message || e); return null; }),
    ]);
    if (v2 && v1 && v1.proxies.length) {
      body = mergeConfig(v2.text, v1.proxies);
      nodes = v2.nodes + v1.nodes;
      info = { ...info, v2: v2.nodes, v1: v1.nodes };
    } else if (v2) {
      body = v2.text; nodes = v2.nodes; info.v2 = v2.nodes;
    } else if (v1) {
      body = buildConfig(v1.proxies, v1.meta); nodes = v1.nodes; info.v1 = v1.nodes;
    } else {
      throw new Error("两条线路都失败");
    }
  } else {
    const v2 = await v2Fetch(env);
    body = v2.text; nodes = v2.nodes;
    info = { ...info, v2: v2.nodes, aesId: v2.aesId, signId: v2.signId };
  }

  info.ms = Date.now() - t0;
  await env.SUBS.put("sub.yaml", body, { metadata: { updated: Date.now(), nodes, info } });
  return { body, nodes, info };
}

// ---------------------------------------------------------------- HTTP

function authorized(request, env) {
  if (!env.ACCESS_TOKEN) return false;
  const url = new URL(request.url);
  const q = url.searchParams.get("token");
  const h = request.headers.get("authorization") || "";
  const bearer = h.startsWith("Bearer ") ? h.slice(7) : h;
  return q === env.ACCESS_TOKEN || bearer === env.ACCESS_TOKEN;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";

    if (path === "/health") {
      const meta = await env.SUBS.getWithMetadata("sub.yaml");
      return json({ ok: true, cached: Boolean(meta.value), meta: meta.metadata || null, source: env.SOURCE || "v2" });
    }

    if (path === "/decode" && request.method === "POST") {
      try {
        const { plain, aesId, signId } = await decryptApxs(new Uint8Array(await request.arrayBuffer()));
        return new Response(plain, {
          headers: {
            "content-type": "text/yaml; charset=utf-8",
            "x-apex-aes-id": String(aesId), "x-apex-sign-id": String(signId),
            "cache-control": "no-store",
          },
        });
      } catch (e) {
        return json({ ok: false, error: String(e.message || e) }, 400);
      }
    }

    if (path === "/sub" || path === "/sub.yaml") {
      if (!authorized(request, env)) return json({ ok: false, error: "unauthorized" }, 401);

      const source = (url.searchParams.get("source") || env.SOURCE || "v2").toLowerCase();
      if (!["v2", "v1", "both"].includes(source)) {
        return json({ ok: false, error: "source 只能是 v2 / v1 / both" }, 400);
      }

      const kvKey = `sub-${source}.yaml`;
      const maxAge = Number(env.MAX_AGE_SECONDS || 21600);
      const cached = await env.SUBS.getWithMetadata(kvKey);
      const fresh = cached.value && cached.metadata && Date.now() - cached.metadata.updated < maxAge * 1000;

      if (fresh) {
        return new Response(cached.value, {
          headers: { "content-type": "text/yaml; charset=utf-8", "cache-control": "no-store",
            "x-apex-source": source, "x-apex-cached": "1" },
        });
      }
      try {
        const r = await build(env, source);
        return new Response(r.body, {
          headers: { "content-type": "text/yaml; charset=utf-8", "cache-control": "no-store",
            "x-apex-source": source, "x-apex-cached": "0", "x-apex-nodes": String(r.nodes) },
        });
      } catch (e) {
        if (cached.value) {
          return new Response(cached.value, {
            headers: { "content-type": "text/yaml; charset=utf-8", "cache-control": "no-store",
              "x-apex-source": source, "x-apex-cached": "stale",
              "x-apex-error": String(e.message || e).slice(0, 120) },
          });
        }
        return json({ ok: false, error: String(e.message || e) }, 502);
      }
    }

    return json({
      ok: true,
      endpoints: ["POST /decode", "GET /sub?token=***&source=v2|v1|both", "GET /health"],
    });
  },

  async scheduled(event, env, ctx) {
    const source = (env.SOURCE || "v2").toLowerCase();
    ctx.waitUntil(
      build(env, source)
        .then((r) => console.log(`refresh ${source} ok nodes=${r.nodes} ms=${r.info.ms}`))
        .catch((e) => console.error(`refresh failed: ${e.message || e}`)),
    );
  },
};
