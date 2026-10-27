# 08 · Serverless 部署（GitHub Actions / Cloudflare Workers）

> 纯协议实现只有两个外部依赖：**HTTPS + mTLS 证书** 和 **AES-CTR**。
> 这两件事在 serverless 平台上都能做到，所以不需要服务器也能跑。

---

## 8.1 两条路的定位

| 方案 | 形态 | 触发 | 产物去向 | 适合 |
|---|---|---|---|---|
| **GitHub Actions** | 定时任务 | cron / 手动 | artifact、私有仓库 | 备份归档、CI 集成 |
| **Cloudflare Worker** | 边缘常驻 | HTTP / cron | KV，按 token 提供 | 多设备共享、固定 URL |

---

## 8.2 GitHub Actions

工作流：[`.github/workflows/fetch.yml`](../.github/workflows/fetch.yml)

```
checkout → 还原证书 → 写配置 → python3 src/apex_fetch.py → 校验 → 清理凭据
```

### 需要的 Secrets

| Secret | 内容 |
|---|---|
| `APEX_EMAIL` / `APEX_PASSWORD` | 账号 |
| `APEX_API_CERT_B64` / `APEX_API_KEY_B64` | api 证书（base64） |
| `APEX_SUB_CERT_B64` / `APEX_SUB_KEY_B64` | subscription 证书（base64） |

生成 base64：

```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes('api.crt'))
```

```bash
base64 -w0 api.crt
```

### ⚠️ 公开仓库注意

**artifact 对任何有仓库读权限的人可见**。订阅 YAML 里有节点凭据，
所以在公开仓库里**不要**打开 `PUBLISH_ARTIFACT`。

推荐做法：

1. 把工作流放在**私有仓库**（fork 一份 private），或
2. 配 `PUBLISH_REPO` + `PUBLISH_TOKEN`，把结果推到**私有仓库**，或
3. 干脆不用 Actions，用 Worker / 自己的服务器。

工作流默认只打印节点数与大小到 Step Summary，不产出可下载文件。

---

## 8.3 Cloudflare Workers

目录：[`workers/apex-fetch/`](../workers/apex-fetch/)

### 可行性验证

两个关键能力都确认支持：

| 能力 | 结论 |
|---|---|
| 出站 mTLS | ✅ `mtls_certificates` 绑定，`env.CERT.fetch()` 自动带客户端证书 |
| AES-CTR | ✅ WebCrypto `{name:"AES-CTR", counter, length:32}` |

本仓库的 `tools/verify_webcrypto.mjs` 可直接验证解密正确性：

```bash
node tools/verify_webcrypto.mjs apxs.bin plain.bin
# aesId=1 signId=1 密文=26806 明文=26806
# 首行: mixed-port: 7890
# 与官方明文逐字节一致: true
```

### 端点设计

| 端点 | 需要凭据 | 说明 |
|---|---|---|
| `POST /decode` | 否 | 传 APXS，返回 YAML（k1 是公开常量） |
| `GET /sub?token=` | 是 | 返回订阅，KV 缓存 + 过期刷新 + 失败回退 |
| `GET /health` | 否 | 缓存状态 |
| cron | — | 每 6 小时刷新 KV |

### 关键代码

```js
// mTLS 绑定：自动带客户端证书
const res = await env.API_CERT.fetch(`${api}/v2/auth/token`, {...});
const apxs = await env.SUB_CERT.fetch(`${sub}/v2/feed/download?access_key=${key}`);

// AES-CTR：计数器 = nonce || 0x00000002
const counter = new Uint8Array(16);
counter.set(nonce, 0);
counter[15] = 0x02;
const plain = await crypto.subtle.decrypt(
  { name: "AES-CTR", counter, length: 32 }, key, ct);
```

### 免费额度

请求 100k/天、CPU 10ms/请求、KV 读 100k/天、写 1k/天 —— 本方案每 6 小时才写 1 次，
解密 26KB 约 1ms CPU，完全够用。

---

## 8.4 选型建议

```
只有一台服务器        → systemd（deploy/install.sh）
有 NAS / 群晖         → Docker（ghcr.io/angel-gril/apex-fetch）
想多设备共享一个 URL  → Cloudflare Worker（token 保护）
只想定期归档          → GitHub Actions（私有仓库）
```

---

## 8.5 安全提醒

无论哪种方式，产物都等价于**账号凭据**：

- 不要提交到公开仓库；
- 不要放在公开的 Pages / Gist / OSS；
- Worker 的 `/sub` 一定要设 `ACCESS_TOKEN`；
- Actions 的 artifact 在公开仓库等于公开。

仓库里的 CI 有一条 **敏感串扫描**，会拦截误提交的私钥与 JWT，
但它拦不住"把 YAML 放进 artifact"这种逻辑错误——这需要你自己判断。
