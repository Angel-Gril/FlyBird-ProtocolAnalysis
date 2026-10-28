# 03 · API 测绘与 mTLS 证书体系

> 本文记录服务端接口的真实放行条件。**这是整个项目最反直觉的部分**：
> 大量请求返回 404 并不是"接口不存在"，而是"你不满足条件，我给你看个假的 404"。

---

## 3.1 域名拓扑

| 角色 | 主机 | 说明 |
|---|---|---|
| 官网 / 面板 | `web01.<domain>` | Laravel 面板，human_verify cookie 门禁 |
| 下载 CDN | `dl.<domain>` | 安装包 / OpenWrt 包，公开可下 |
| API（v2） | `fbaxapi.<edge-domain>` / `fbaxapi.web.<edge-domain>` | 登录、账户、access-token |
| 订阅（v2） | `fbaxsub.<edge-domain>` / `fbaxsub.web.<edge-domain>` | `/v2/feed/download` |
| OSS / 配置 | `oss-*.llguangli*` / `tcdn-ax.*` | 加密的远程配置（当前多返回 500） |

同一域名在不同地区解析到不同边缘（`axapi-overseas.*`），行为一致。

## 3.2 404 伪装机制

服务端用 nginx 对不满足条件的请求返回**统一的 153 字节 404 页**，让你以为接口不存在。
实测发现的三个必要条件：

| 条件 | 缺失时的表现 |
|---|---|
| 客户端证书（purpose 必须匹配 vhost） | 404 |
| `User-Agent: ua.net.fbclient.app.apex/<version>` | 404 |
| 正确的路径与 JWT | 404 / 403 |

**只满足其中两项仍然 404。** 这是本项目早期走了很久弯路的原因。

## 3.3 证书 purpose 分层（关键）

客户端安装目录里有三套证书：

```
profile5_api_client.{crt,key}.pem
profile5_subscription_client.{crt,key}.pem
profile5_oss_client.{crt,key}.pem
```

实测矩阵（✅=200 / ❌=404）：

| 证书 \ 目标 | `fbaxapi.*` | `fbaxsub.*` | OSS 主机 |
|---|---|---|---|
| api | ✅ | ❌ | ❌ |
| subscription | ❌ | ✅ | ❌ |
| oss | ❌ | ❌ | ❌（该主机当前 500） |
| 无证书 | ❌ | ❌ | ❌ |

结论：**证书按 purpose 严格绑定 vhost**，不能混用。
早期所有 `fbaxsub` 的 404 都是因为拿 api 证书去打它。

## 3.4 请求头矩阵

真实客户端的请求头（从 TLS 终止代理抓到的原文）：

```
User-Agent: ua.net.fbclient.app.apex/7.2.4
X-Client-Platform: openwrt
X-Client-Runtime-Abi: amd64
X-Client-Environment: unknown
Authorization: <JWT 原文>          ← 注意：没有 "Bearer " 前缀
```

差分测试结论：

- 只改 UA 版本号不影响路由（但 UA 必须存在且前缀正确）；
- `X-Client-*` 不是硬性门禁，但对某些路径有影响；
- **`Authorization` 是裸 JWT**，加 `Bearer ` 反而失败。

## 3.5 完整登录与订阅链路

```
POST {API}/v2/auth/token
     cert: api
     body: {"email":"…","password":"…"}
  →  {"data":{"auth_data":"<JWT>","token":"<access_key>", …}}

GET  {API}/v2/account/profile
     cert: api ; Authorization: <JWT>
  →  账户资料（余额、封禁状态、佣金…）

GET  {API}/v2/feed/access-token
     cert: api ; Authorization: <JWT>
  →  套餐、流量、到期时间（可能刷新 access_key）

GET  {SUB}/v2/feed/download?access_key=<access_key>
     cert: subscription ; UA: ua.net.fbclient.app.apex/7.2.4
  →  200  application/octet-stream  (APXS 信封)
```

JWT 结构（HS256）：

```json
{"uid":711447,"sub":"711447","exp":<exp+72h>,"iat":<iat>,"jti":"<随机>"}
```

TTL 72 小时；`jti` 每次登录都变；`access_key` 与账号绑定且**长期不变**。

## 3.6 其他被排除的路径

> ⚠️ **本节曾经写错过，已修正（2026-10-28）**
>
> 旧结论：「面板 v1 接口 `/api/v1/client/subscribe?token=` → 403 `{code:403102}`，Apex 分支关闭」
>
> **错在哪里**：当时测的是 `fbesa.*` 主机、且**没带客户端证书**。
> 实际上在 `fbaxapi.*` 主机 + **api 证书** + **apex UA** 上，v1 接口**返回明文**。
> 详见 [09-v1-legacy-endpoint.md](09-v1-legacy-endpoint.md)。

### v1 明文接口（可用）

```
POST {API}/api/v1/passport/auth/login     api 证书                  -> token
GET  {API}/api/v1/client/subscribe?token= api 证书 + apex UA        -> 明文 URI（18 KB）
```

放行矩阵：

| 证书 | UA | 主机 | 结果 |
|---|---|---|---|
| api | apex | `fbaxapi.*` | ✅ 200 明文 |
| subscription | apex | `fbaxapi.*` | ❌ 404 |
| api | 其他/无 | `fbaxapi.*` | ❌ 404 |
| 任意 | apex | `fbaxsub.*` | ❌ 404 |

`flag=clash/v2ray/ss/...` 均无效，只输出一种格式。

### 确实被排除的路径

| 目标 | 结论 |
|---|---|
| `/Apex.php` | 404 |
| 5 个 `fb_apexv2.json` 镜像 | 404 / 500 / 超时 |
| Malio 主题落地页 | 纯静态，无数据 |
| Cloudflare 验证站 | 无关 |

## 3.7 复现要点

```bash
# 最小可用组合（三条缺一不可）
curl --cert api.crt --key api.key \
     -H 'User-Agent: ua.net.fbclient.app.apex/7.2.4' \
     -H 'Content-Type: application/json' \
     -d '{"email":"…","password":"…"}' \
     https://<api-host>/v2/auth/token
```

对照实验（强烈建议自己跑一遍）：

```bash
# 去掉 --cert        -> 404
# 去掉 User-Agent    -> 404
# 两者都去掉         -> 404
```
