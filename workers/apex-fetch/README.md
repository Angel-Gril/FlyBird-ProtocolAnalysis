# Cloudflare Worker 部署

> 把纯协议抓取搬到 Cloudflare 边缘：**无需服务器、无需 root**，自带 KV 缓存与定时刷新。

## 为什么可行

两个关键前提都满足：

1. **Workers 支持出站 mTLS**：通过 `mtls_certificates` 绑定，
   `env.API_CERT.fetch(url)` 会自动携带客户端证书（详见 Cloudflare 文档）；
2. **WebCrypto 支持 AES-CTR**：`{ name: "AES-CTR", counter, length: 32 }`
   正好对应 GCM 的 `nonce || 0x00000002` 计数器，解密结果与官方客户端逐字节一致。

## 端点

| 方法 | 路径 | 说明 |
|---|---|---|
| `POST` | `/decode` | body = APXS 原始字节 → 返回 YAML（**不需要账号**，k1 是公开常量） |
| `GET` | `/sub?token=***` | 返回订阅 YAML；KV 缓存，超龄自动刷新，失败回退旧值 |
| `GET` | `/health` | 缓存状态与元数据 |

`/sub` 也支持 `Authorization: Bearer <token>`。

## 部署

### 1. 上传 mTLS 证书

```bash
npx wrangler login

# 注意：需要 API Token 具备 SSL and Certificates: Edit 权限
npx wrangler mtls-certificate upload --cert api.crt --key api.key --name apex-api
npx wrangler mtls-certificate upload --cert sub.crt --key sub.key --name apex-sub

# 记下输出的两个 certificate_id
npx wrangler mtls-certificate list
```

### 2. 创建 KV

```bash
npx wrangler kv namespace create SUBS
# 输出形如：id = "abcd1234..."
```

把两个 `certificate_id` 和 KV 的 `id` 填进 `wrangler.toml`。

### 3. 配置 secrets

```bash
npx wrangler secret put APEX_EMAIL
npx wrangler secret put APEX_PASSWORD
npx wrangler secret put ACCESS_TOKEN   # 自己生成：openssl rand -hex 24
```

### 4. 部署

```bash
npx wrangler deploy
```

### 5. 验证

```bash
# 健康检查
curl -s https://apex-fetch.<you>.workers.dev/health | jq

# 拉订阅（带 token）
curl -s "https://apex-fetch.<you>.workers.dev/sub?token=$ACCESS_TOKEN" -o sub.yaml
python3 -c "import yaml;print(len(yaml.safe_load(open('sub.yaml'))['proxies']))"

# 纯解密（不需要账号）
curl -s -X POST --data-binary @apxs.bin \
  https://apex-fetch.<you>.workers.dev/decode -o sub.yaml
```

## 定时刷新

`wrangler.toml` 里已配置：

```toml
[triggers]
crons = ["0 */6 * * *"]
```

Cron 触发时 Worker 会在后台调用 `refresh()` 更新 KV；
`/sub` 在缓存过期时会**同步刷新**，刷新失败则回退到旧值（响应头 `x-apex-cached: stale`）。

## 安全

| 措施 | 说明 |
|---|---|
| `/sub` 需 token | 未配置 `ACCESS_TOKEN` 时直接 401，不会泄露订阅 |
| 凭据放 secrets | 不写入 `wrangler.toml` |
| KV 私有 | 只有 Worker 能读，不暴露给公网 |
| 无日志泄露 | Worker 只打印节点数与耗时，不打印内容 |
| 缓存 TTL | `MAX_AGE_SECONDS`（默认 21600）控制刷新频率 |

## 免费额度够不够

| 资源 | 免费额度 | 本方案用量 |
|---|---|---|
| 请求 | 100k/天 | 你自己的客户端拉取次数 |
| CPU | 10ms/请求 | 解密 26KB ≈ 1ms |
| KV 读 | 100k/天 | 每次 `/sub` 1 次 |
| KV 写 | 1k/天 | 每 6 小时 1 次 |
| Cron | 支持 | 4 次/天 |

## 本地调试

```bash
npm install
npx wrangler dev
# 另开终端
curl -s -X POST --data-binary @apxs.bin http://127.0.0.1:8787/decode -o sub.yaml
```

本地模式下 mTLS 绑定不可用（无证书），`/decode` 与 `/health` 仍可测试。

## 与其它部署方式对比

| 方式 | 需要服务器 | 需要 root | 常驻 | 适合 |
|---|---|---|---|---|
| Cloudflare Worker | ❌ | ❌ | 边缘常驻 | 多设备共享、稳定 URL |
| GitHub Actions | ❌ | ❌ | 定时任务 | 备份归档、CI 集成 |
| systemd | ✅ | ✅ | ✅ | 自有服务器 |
| Docker | ✅ | ❌ | ✅ | 自有服务器 / NAS |
