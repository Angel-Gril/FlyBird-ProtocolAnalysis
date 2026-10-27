# 突破：找到可用端点（非 404）+ 订阅 403 定性

> 授权沙箱内白盒审计（CWE-602）。凭据仅用于本次验证，未落盘到仓库；本文件不含 token 明文。

## 一、结论先行

| 判定 | 内容 |
|---|---|
| ✅ **找到可用端点** | `https://fbesa.apiv2.a047.com` 与 `https://fbesa.web.ak005.com` 是**存活的 v1 面板**（Laravel/V2Board） |
| ✅ 登录可用 | `POST /api/v1/passport/auth/login` → **200**，返回 `auth_data`(JWT) + `token` |
| ✅ 账号信息可用 | `GET /api/v1/user/getSubscribe`（Bearer）→ **200**，返回套餐/流量/到期/`subscribe_url` |
| ✅ 站点配置可用 | `GET /api/v1/guest/comm/config` → **200** JSON |
| ❌ 订阅下载不可用 | `GET /api/v1/client/subscribe?token=…` → **403 `403102` "授权凭证已失效，请重新获取"**（任何 token 都一样） |
| ❌ v2 网关不可用 | `fbesa.*` 上 `/v2/*` 全部 **404**（Laravel 原生 404），与 `fbaxapi.*` 的 nginx 404 不同源 |

## 二、怎么找到的（可复现）

1. 面板落地页（`w04.fbwebd07.cc`，Malio 主题）只链到 `fastlink.la`，无 API 线索。
2. **证书透明日志**（crt.sh）枚举 `ak005.com` / `a047.com`：
   - `ak005.com` 52 个子域，含 `fbesa.web.ak005.com`、`fbeo/fceo/fcesa/…esa.web.ak005.com`
   - `a047.com` 43 个子域，含 `fbesa.apiv2.a047.com` 等
3. 用**客户端真实 UA** `ua.net.fbclient.app.apex/v7.2.3` 扫描：
   - `fbesa.apiv2.a047.com/api/v1/guest/comm/config` → **200**（首例非 404）
   - 其余 `*esa` 主机 → nginx 403（WAF/未配置）
4. 用测试账号登录 → 200；`getSubscribe` → 200。

## 三、关键证据

```
GET  /api/v1/guest/comm/config            -> 200  299B  {"data":{"app_description":"Malio",
                                                          "app_url":"https://api.example.com", ...}}
POST /api/v1/passport/auth/login          -> 200  auth_data + token
GET  /api/v1/user/getSubscribe  (Bearer)  -> 200  balance/expired_at/plan/subscribe_url/uuid/token
GET  /api/v1/client/subscribe?token=<真>  -> 403  102B {"code":403102,"msg":"授权凭证已失效，请重新获取"}
GET  /api/v1/client/subscribe?token=deadbeef -> 403 同上（**真 token 与假 token 无差别**）
GET  /api/v1/user/getSubscribe  (无 Bearer) -> 401 "auth_data is missing"
GET  /api/v1/client/app/getVersion        -> 403 "token is null"（路由存在）
GET  /v2/site/settings                    -> 404  9B  "Not Found"（Laravel 原生）
GET  /api/v1/feed/access-token            -> 404  {"message":"Not Found","path":"/api/v1/feed/access-token"}
```

UA 差异（同一 URL）：

| UA | 结果 |
|---|---|
| `ua.net.fbclient.app.apex/v7.2.3` | 200 JSON / 403 JSON |
| `okhttp/4.12.0`、`curl/8.0`、`clash-verge/…` | 200 但返回 **12 KB HTML 挑战页**（诱饵） |
| `NetFlow/v3.0.3 …` | 403 nginx |

> 这条说明 `fbesa` 前面有 **Aliyun ESA**（响应头 `Server: ESA`、`via: ens-cache…`），按 UA 分流；只有 Apex 的 UA 能拿到 JSON。

## 四、403102 的定性

- **不是网络/指纹/IP 问题**：换 US 出口（mihomo global + 美国节点）结果完全一致；`fbesa.web.ak005.com` 与 `fbesa.apiv2.a047.com` 一致；Host 覆盖测试（`--resolve` 到 `api.example.com` / `fbaxsub.*`）分别为 CDN 403 / 530。
- **不是 token 值问题**：真 token、假 token、uuid、JWT 全部同一响应。
- **是服务端路由被替换/加固**：`client/subscribe` 已被自定义处理器接管，要求的是 **Apex 新体系的临时凭据（access_key）**，而非 v1 的长期 `token`。

旁证（Dart AOT 里的错误文案，原文）：

> "The server did not return a valid config.
> 1. Apex.php is not deployed on the server but the client used ?flag=apex
> 2. $encryptKey in Apex.php does not match the packing bot's XOR_KEY
> 3. Temporary panel failure"

即客户端在 v1 兼容路径上会追加 `?flag=apex`，服务端需要部署 `Apex.php`；当前 fbesa 上没有该文件（`/Apex.php` → 404），所以 v1 兼容路径必然失败。

## 五、对 headless 方案的影响

```
loginV2()  → ✅ 可换成 fbesa v1 登录（已实测 200）
getAccessCredential() → ❌ v2 /v2/feed/access-token 404；v1 subscribe 403102
downloadApxsSubscription() → ❌ 拿不到密文
```

也就是说：**账号本身是好的**（能登录、能读套餐/流量/到期），**卡在运营方下发了坏的订阅凭据**：

1. 面板 `app_url` 配成了占位符 `https://api.example.com` → 所有 `subscribe_url` 都是死链；
2. v2 网关（`fbaxapi.*` / `fbaxsub.*`）当前 404；
3. v1 兼容路径（`?flag=apex`）依赖的 `Apex.php` 未部署。

三条路径同时断，属于**服务端配置/部署问题**，客户端侧无法绕过（除非拿到 v2 的 `access_key`）。

## 六、下一步（按性价比排序）

1. **保留 `watch_v2.py` 常驻**：v2 网关一恢复，立刻能抓到 200 并对齐 APXS。
2. **用 fbesa 做"账号健康探针"**：`login + getSubscribe` 已可用，可每 10 分钟跑一次，判断"是账号问题还是网关问题"。
3. **向运营方反馈三件事**（有据可查）：
   - `app_url` 仍是 `https://api.example.com`；
   - `fbaxapi.*` / `fbaxsub.*` 返回 nginx 404；
   - `/api/v1/client/subscribe` 对合法 token 返回 `403102`，且 `Apex.php` 404。
4. 若拿到 v2 `access_key`（例如运营方修复后），直接进 `apxs_try.py` 对齐，无需改代码。

## 七、附：本轮新增工具

| 文件 | 用途 |
|---|---|
| `tools/ct_recon.py` | crt.sh 子域枚举 + 端点初筛（发现 fbesa 的关键） |
| `tools/fbesa_probe.py` | UA × 路径矩阵（区分 JSON / HTML 诱饵 / 403） |
| `tools/fbesa_login.py` | 登录 + getSubscribe + 订阅 URL 重建 |
| `tools/fbesa_subscribe.py` | 4 种订阅 URL 变体（v1/v1+flag/v2 access_key） |
| `tools/fbesa_matrix.py` | token 候选 × 参数名矩阵 |
| `tools/sub_ua_matrix.py` | UA × flag 组合（10×5） |
| `tools/esa_host_scan.py` | 全部 `*esa` 主机 × 4 端点 |
| `tools/v2_header_matrix.py` | Bearer / X-Auth-Token / X-Client-* × 6 主机 |
| `tools/pipe_api.py` | 通过命名管道访问 mihomo 控制器（出口切换用） |
| `tools/egress_matrix.py` | CN/US 出口对照（证明 403 与出口无关） |
| `tools/sub_via_exit.py` | 订阅端点在不同出口下复测 |
