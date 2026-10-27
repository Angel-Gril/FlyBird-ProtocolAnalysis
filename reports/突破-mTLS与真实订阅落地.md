# 结论反转：v2 不是 404，是缺 mTLS 客户端证书

> 授权沙箱。本文不含 token/密码明文；节点配置中的 servername/uuid 属测试账号数据，仅本地留存。

## 一、根因（一句话）

`fbaxapi.*` / `fbaxsub.*` 的 **nginx 对"没有客户端证书"的请求一律回 404**；带上内嵌的
`profile5_api_client.crt.pem/key.pem`（purpose=api）后，同一 URL 立刻恢复正常路由：

```
GET /v2/site/settings           无证书 → 404 (153B nginx)
GET /v2/site/settings           带证书 → 200 (299B JSON)
GET /v2/feed/access-token       无证书 → 404
GET /v2/feed/access-token       带证书 + Bearer → 200 (1641B)
GET /v2/feed/download?access_key=…  无证书 → 404
GET /v2/feed/download?access_key=…  带证书 → 200 (26.8KB APXS)
```

之前所有"v2 网关宕机 / 服务端没部署"的推断**全部作废**——包括"13:04–13:18 有窗口"的猜测，
实际是客户端一直带着证书，所以它一直能用。

## 二、现在可用的两条链路

### A. APXS v2（客户端同款）

```
1) POST https://fbaxapi.apiv2.a047.com/v2/auth/token   (mTLS, JSON email/password)
   → 200 {"data":{"auth_data": <JWT 72h>, "token": <订阅token>}}
2) GET  /v2/feed/access-token                          (mTLS + Authorization: Bearer <JWT>)
   → 200 用户信息（注意：不含密钥字段）
3) GET  /v2/feed/download?access_key=<订阅token>        (mTLS)
   → 200 application/octet-stream，`APXS\x02…`
```

APXS 信封结构（本次确认）：

```
"APXS" | 0x02 | u32be=1 | u32be=1 | nonce(12) | ciphertext | tag(16)
```

### B. 兼容层（SSPanel-Malio）

```
GET /api/v1/client/subscribe?token=<订阅token>   (mTLS)
→ 200 text/plain，149 条 URI（74 trojan + 75 ss）
   # remaining / # expire_at / 每行一条 trojan://… 或 ss://…
```

该接口在 fbesa（无 mTLS）上是 403102，在 fbaxapi（有 mTLS）上是 200——**403102 的真实含义是
"这个 vhost 不提供订阅，去带证书的那个"**。

兼容层节点域名 `*.6pzftj.com` 当前 **NXDOMAIN**（已死的旧节点），所以这条链路只能作参考。

## 三、APXS 明文：从客户端内存直接取到

密钥（AES-GCM）不是 token/uuid/profile_key 的简单派生（试了 448 种 KDF/编码组合，全部 GCM 认证失败），
但**明文不需要密钥也能拿到**：客户端解密后会把 YAML 留在堆里。

- `poc/extract_app_plaintext.py`：在 `Apex.exe` 内存里按 `proxies:\n  - {"name":"Hong Kong-01"` 定位，
  抠出完整明文（43KB）。
- `poc/extract_core_config.py`：在 `ApexCore.exe` 里抠 mihomo 运行时 JSON（74 条 proxies，含 server/port/uuid/servername）。

两者互相印证：**74 条 vless**，同一入口 `node.example.com`，端口 10301–10400，
`flow=xtls-rprx-vision`，每节点独立 `servername`。

## 四、交付物

| 文件 | 内容 | 校验 |
|---|---|---|
| `http/plain_from_app.yaml` | 从 APXS 明文重建的完整配置（74 节点 + AUTO/PROXY 组） | `health_check` → `ok:true`，node_count=74 |
| `http/last_good.yaml` | 从 mihomo 运行时 JSON 重建（含 DNS/规则） | node_count=74，TCP 可达 |
| `http/sub_plain.bin` | 兼容层原始响应（149 URI） | — |
| `http/v2_apxs2.bin` | 真实 APXS 密文（用于回归/日后破钥） | 26.8KB |

## 五、客户端这边同步确认的事

- 下载请求会带一整套 `X-Client-*` 设备指纹头（platform/model/board/serial/screen/…），
  但**没有签名头**；这些头不参与解密。
- `access-token` 请求只带 `authorization: <JWT>`（**没有 `Bearer ` 前缀**），服务端两种都接受。
- 订阅自动更新间隔由响应头 `profile-update-interval: 24` 决定；把 `shared_preferences.json` 里
  `profiles[].lastUpdateDate` 改旧再启动，即可**手动触发一次真实下载**（本次就是这么抓到的）。

## 六、仍未闭环

1. **APXS 的 AES 密钥**：未恢复。影响：无法在服务器上纯离线解密新抓的密文。
   现有替代：客户端刷新后从内存提取（`extract_app_plaintext.py`），或等兼容层节点恢复。
2. 兼容层 URI 的节点域名已 NXDOMAIN，短期不可用。
3. `fbesa`（无 mTLS）的 403102 与 `fbaxapi`（mTLS）的 200 说明：**同一套代码，不同 vhost 的入口策略不同**，
   运营方可能只给主域名挂了证书校验。

## 七、pipeline 变更

`poc/fb_pipeline.py` 新增：

```
--client-cert <pem> --client-key <pem>     # mTLS
```

行为：mTLS 登录 → access-token → download；解密失败时把密文存为
`apxs_undecrypted_<ts>.bin` 并 exit 2（保留 last-good），不会污染线上配置。

## 八、APXS 密钥攻坚记录（截至本轮，全部失败）

| 方向 | 规模 | 结果 |
|---|---|---|
| token/uuid/JWT/profile_key 的 raw/md5/sha1/sha256/hex/b64 | 560 组 | GCM 认证失败 |
| HMAC/HKDF/PBKDF2（常量盐 apex-sub-v2 等） | 448 组 | 失败 |
| 拼接/截断/补零/重复（token+const、const+token、T+U…） | 43 组 | 失败 |
| 每消息派生（salt=nonce/header） | 147 组 | 失败 |
| 证书派生（cert DER/pubkey DER/serial/fingerprint） | 18 组 | 失败 |
| 交叉 KDF（ikm/salt 在 token/uuid/PK/JWT 之间两两组合） | 327 组 | 失败 |
| Dart Uint8List 布局扫描（16/24/32/64 字节头 0x20/0x30/0x40/0x80） | 77 万候选 | 失败 |
| 明文区域 ±4MB 32 字节窗口扫描（已知首块 mixed-port: 7890） | 4 万候选 | 失败 |

结论：密钥**不是**公开字段的简单派生，也不是以普通 Uint8List 形式常驻堆中。
最可能是「二进制内硬编码的原始字节常量（非字符串）+ HKDF/PBKDF2」或「服务端与客户端共享的固定密钥」。
静态字符串检索找不到它（Dart AOT 里非字符串字节数组不走字符串表）。

下一步若继续攻坚，只剩两条路：
1. Frida + CModule（原生速度 AES 扫描 + 内存断点），或 hook crypto 库；
2. 让运营方给出 encrypt_key 的生成规则（服务端改动最快）。

## 九、不依赖密钥的可用方案（已实测）

1. **服务端直接分发** plain_from_app.yaml（74 条 vless，health_check ok）；
2. **刷新**：Windows 客户端点一次「更新订阅」（或把 profiles[].lastUpdateDate 改旧后重启），
   然后跑 poc/extract_app_plaintext.py 自动抠出新明文并重建 YAML；
3. **兼容层**：GET /api/v1/client/subscribe?token=…（mTLS）返回纯文本 149 条 URI——
   一旦运营方把 *.6pzftj.com 换回可用域名，这条路无需解密、可直接自动化。

## 十、密钥攻坚（第二轮，仍失败）

| 方向 | 规模 | 结果 |
|---|---|---|
| app.so / Apex.exe 全文件 32 字节窗口（4 字节对齐，含熵过滤） | 1,542,551 | 失败 |
| 同上扩到 16/24 字节密钥 | 5,056,171 | 失败 |
| nonce/tag 位置全排列 × 已知密钥族（96 组） | 96 | 失败 |
| 密码派生（PBKDF2/HKDF/HMAC，密码+邮箱，盐=token/uuid/PK） | 114 | 失败 |
| AES key-wrap 假设（PK 解前 16/32 字节得内层密钥） | 48 | 失败 |

判定：密钥既不是公开字段派生，也不是二进制里 4 字节对齐的原始 16/24/32 字节常量。
剩余可能：混淆存储（异或/分片拼接）、或服务端共享密钥。
静态与黑盒手段到此为止；继续需 Frida 原生扫描/hook，或运营方给出生成规则。

## 十一、不依赖密钥的落地方式（已自动化）

poc/refresh_config.py：从运行中的 Apex.exe 内存里提取解密后的明文 → 解析 74 条 proxies
→ 原子写入 YAML → 自动跑 health_check。

实测：解析到 74 个节点 → 已原子写入 → health OK。

日常流程：
1. 客户端点「更新订阅」（或把 profiles[].lastUpdateDate 改旧后重启）；
2. python poc/refresh_config.py --out /var/lib/fb/latest.yaml --min-nodes 10；
3. 分发。

全程不需要 APXS 密钥，也不需要再碰网络。

## 十二、全自动刷新（一条命令，实测 16 秒）

poc/auto_refresh.py 把「触发更新 + 抠明文 + 重建 + 体检」串成一步：

1. 停 Apex / ApexCore
2. 备份并改写 shared_preferences.json 的 profiles[].lastUpdateDate → 2000-01-01（强制过期）
3. 启动 Apex（客户端会自动走 mTLS 拉取并解密）
4. 每 6s 轮询内存，直到解析出 ≥ min-nodes 条 proxies
5. 原子写入 YAML + 自动 health_check

实测输出：

`
[*] 停止客户端
[*] lastUpdateDate 已改旧，启动客户端触发更新
[+] 第 16s 抓到 74 个节点
[+] 已原子写入 http/auto_live.yaml（74 节点）
[health] OK
`

三件套分工：

| 脚本 | 层级 | 用途 |
|---|---|---|
| xtract_app_plaintext.py | 取证 | 把内存窗口原样落盘（43KB，给人看） |
| 
efresh_config.py | 构建 | 从内存解析 proxies → 原子写 YAML → 体检（客户端已在跑时用） |
| uto_refresh.py | 编排 | 连客户端重启一起做（无人值守时用） |

## 十三、7.2.4 测绘（新版）

### 13.1 构建与证书

| 项 | 7.2.3 | 7.2.4 |
|---|---|---|
| pp.so 大小 | 18,072,464 | **18,088,848** |
| profile5_api_client.crt | 1574B | **1600B** |
| profile5_*_client.key | 2484B | **2524B** |
| 旧证书在服务端是否仍可用 | — | **是**（实测 200） |

新证书已提取到 certs_724/。

### 13.2 协议层：未变

`
GET /v2/site/settings        (mTLS, UA v7.2.4) -> 200 299B
POST /v2/auth/token          (mTLS)            -> 200 JWT
GET /v2/feed/download?access_key=… (mTLS)      -> 200 26,848B
   魔数仍为 "APXS" 0x02 + u32(1) + u32(1)
`

### 13.3 配置层：只换了文件名

`
旧: /apos/fb_apex.json
新: /apos/fb_apexv2.json     （5 个镜像，实测全部 404/500/超时）
`

新构建里仍保留 pex-config-v1、pi_path_mapping、nable_api_path_mapping、subscribe_domain
——**schema 与 v1 兼容**，变化集中在传输层（文件名、nonce）。

新增标识符：_apex_nonce、pex-file-content、x-apex-helper、configStream。

### 13.4 7.2.4 下的明文提取（已复测）

`
python poc/auto_refresh.py --out http/live_724.yaml --wait 120
[*] 第 11s 抓到 74 个节点
[+] 已原子写入（74 节点）
[health] OK
`

### 13.5 结论

- 协议客户端对 7.2.4 **无需改动**（换证书即可）；
- 配置镜像当前整体不可用，poc/watch_config.py 已在后台盯 b_apexv2.json；
- 密钥仍无新线索：新版没有引入任何新的密钥下发字段。
