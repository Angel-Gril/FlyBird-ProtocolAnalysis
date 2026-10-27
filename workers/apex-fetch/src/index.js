/**
 * Cloudflare Worker — 飞鸟订阅纯协议抓取
 *
 * 能力：
 *   POST /decode  body=APXS 原始字节  → 返回解密后的 YAML（无需账号）
 *   GET  /sub?token=xxx              → 返回订阅 YAML（KV 缓存，过期自动刷新）
 *   GET  /health                     → 健康检查
 *   cron                             → 定时刷新 KV
 *
 * 依赖绑定（见 wrangler.toml）：
 *   API_CERT / SUB_CERT  mTLS 证书绑定（env.X.fetch 自动带客户端证书）
 *   SUBS                 KV，缓存订阅内容
 *   APEX_EMAIL / APEX_PASSWORD / ACCESS_TOKEN   secrets
 */

const K1_B64 = "fCA3jkvhXpLEpDVuqPstNUS/kXewk7yGL5o8Fbh3uSc=";
const TRAILER = 16 + 64; // 尾部 16B 校验 + 64B 签名
const UA = "ua.net.fbclient.app.apex/7.2.4";
const DEFAULT_API = "https://fbaxapi.apiv2.a047.com";
const DEFAULT_SUB = "https://fbaxsub.web.ak005.com";
const KV_KEY = "sub.yaml";

function b64ToBytes(s) {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** APXS v2 → 明文（AES-256-CTR，计数器 = nonce || 0x00000002） */
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

async function login(env) {
  const api = env.API_BASE || DEFAULT_API;
  const res = await env.API_CERT.fetch(`${api}/v2/auth/token`, {
    method: "POST",
    headers: {
      "user-agent": UA,
      "content-type": "application/json; charset=utf-8",
      accept: "application/json",
    },
    body: JSON.stringify({ email: env.APEX_EMAIL, password: env.APEX_PASSWORD }),
  });
  if (!res.ok) throw new Error(`登录失败 HTTP ${res.status}`);
  const j = await res.json();
  const data = j.data || {};
  if (!data.token) throw new Error("登录响应缺少 token");
  return data;
}

async function fetchApxs(env, accessKey) {
  const sub = env.SUB_BASE || DEFAULT_SUB;
  const res = await env.SUB_CERT.fetch(
    `${sub}/v2/feed/download?access_key=${encodeURIComponent(accessKey)}`,
    { headers: { "user-agent": UA, accept: "*/*" } },
  );
  if (!res.ok) throw new Error(`下载失败 HTTP ${res.status}`);
  return new Uint8Array(await res.arrayBuffer());
}

async function refresh(env) {
  const started = Date.now();
  const data = await login(env);
  const apxs = await fetchApxs(env, data.token);
  const { plain, aesId, signId } = await decryptApxs(apxs);
  const text = new TextDecoder().decode(plain);
  if (!/(^|\n)\s*proxies:/.test(text)) throw new Error("解密结果不是订阅 YAML");
  const nodes = (text.match(/^\s*-\s+name:/gm) || []).length;
  await env.SUBS.put(KV_KEY, text, {
    metadata: { updated: Date.now(), bytes: text.length, aesId, signId, nodes },
  });
  return { bytes: text.length, nodes, aesId, signId, ms: Date.now() - started };
}

function json(body, status = 200, extra = {}) {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...extra },
  });
}

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
      const meta = await env.SUBS.getWithMetadata(KV_KEY);
      return json({
        ok: true,
        cached: Boolean(meta.value),
        meta: meta.metadata || null,
        ts: Date.now(),
      });
    }

    if (path === "/decode" && request.method === "POST") {
      try {
        const buf = new Uint8Array(await request.arrayBuffer());
        const { plain, aesId, signId } = await decryptApxs(buf);
        return new Response(plain, {
          headers: {
            "content-type": "text/yaml; charset=utf-8",
            "x-apex-aes-id": String(aesId),
            "x-apex-sign-id": String(signId),
            "cache-control": "no-store",
          },
        });
      } catch (e) {
        return json({ ok: false, error: String(e.message || e) }, 400);
      }
    }

    if (path === "/sub" || path === "/sub.yaml") {
      if (!authorized(request, env)) {
        return json({ ok: false, error: "unauthorized" }, 401);
      }
      const maxAge = Number(env.MAX_AGE_SECONDS || 21600);
      const cached = await env.SUBS.getWithMetadata(KV_KEY);
      const fresh =
        cached.value && cached.metadata && Date.now() - cached.metadata.updated < maxAge * 1000;
      if (fresh) {
        return new Response(cached.value, {
          headers: {
            "content-type": "text/yaml; charset=utf-8",
            "cache-control": "no-store",
            "x-apex-cached": "1",
          },
        });
      }
      try {
        const r = await refresh(env);
        const text = await env.SUBS.get(KV_KEY);
        return new Response(text, {
          headers: {
            "content-type": "text/yaml; charset=utf-8",
            "cache-control": "no-store",
            "x-apex-cached": "0",
            "x-apex-nodes": String(r.nodes),
          },
        });
      } catch (e) {
        if (cached.value) {
          return new Response(cached.value, {
            headers: {
              "content-type": "text/yaml; charset=utf-8",
              "cache-control": "no-store",
              "x-apex-cached": "stale",
              "x-apex-error": String(e.message || e).slice(0, 120),
            },
          });
        }
        return json({ ok: false, error: String(e.message || e) }, 502);
      }
    }

    return json({
      ok: true,
      endpoints: ["POST /decode", "GET /sub?token=***", "GET /health"],
    });
  },

  async scheduled(event, env, ctx) {
    ctx.waitUntil(
      refresh(env)
        .then((r) => console.log(`refresh ok nodes=${r.nodes} bytes=${r.bytes} ms=${r.ms}`))
        .catch((e) => console.error(`refresh failed: ${e.message || e}`)),
    );
  },
};
