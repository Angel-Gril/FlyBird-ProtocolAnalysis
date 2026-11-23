# 11 · 面板/订阅协议规格（Apex 1.x，客户端 7.2.3 – 7.3.1 实测）

> **本文是规范性文档**：按字节描述协议，配套参考实现 `src/apex_protocol.py`、
> 一致性向量 `tests/vectors.json`、校验用例 `tests/test_protocol_vectors.py`。
> 文中所有参数都在真实服务端信封上逐字节验通过（2026-11-23，客户端 7.3.1）。
>
> 范围：**面板与订阅链路**（登录 → 取凭据 → 下订阅 → 解包）。
> 不含节点侧传输（anytls / 私有 `transport/apex`）与节点 DNS 引导。

---

## 11.1 术语与分层

| 层 | 内容 | 本文覆盖 |
|---|---|---|
| 传输/门禁 | 主机、mTLS 证书 purpose、UA、404 伪装 | ✅ §11.3 |
| 账号链路 | `/v2/auth/token` → `/v2/feed/access-token` → `/v2/feed/download` | ✅ §11.4 |
| 订阅封装 | **APXS v2**（AES-256-GCM + Ed25519） | ✅ §11.5 |
| 远程配置 | **apex-config-v1**（base64 + XOR + Ed25519） | ✅ §11.6 |
| 节点面 | anytls 参数、私有 DoH、`transport/apex` | ❌ 见 `reports/11 §8` |

---

## 11.2 常量

| 名称 | 值 | 用途 |
|---|---|---|
| `k1` | `fCA3jkvhXpLEpDVuqPstNUS/kXewk7yGL5o8Fbh3uSc=` | APXS 数据键（AES-256） |
| `k2` | `lmzs43izW9GHIOOq+avbwhWh0TG/ldT3kipGkrQ4RiE=` | **订阅**签名公钥（Ed25519） |
| `k3` | `xZ//fP0AfP+8yW4OAZOrcKHe7dO78+Gpwu1ewno/fd8=` | **配置**签名公钥（Ed25519） |
| `AAD_PREFIX` | `"apex-sub-v2\x00"`（13 B） | GCM AAD 前缀 |
| `SIG_PREFIX` | `"apex-sub-sign-v2\x00"`（18 B） | 订阅签名前缀 |
| `CONFIG_PREFIX` | `"apex-config-v1\x00"`（15 B） | 配置签名前缀 |

> ⚠️ 三个前缀都**带结尾 NUL**。这是 7.2.x 阶段一直没验通签名的唯一原因。

---

## 11.3 传输与门禁

### 11.3.1 主机

| 角色 | 主机（7.3.1 配置下发） | 客户端证书 purpose |
|---|---|---|
| 面板 API | `fbaxapi.web.ak005.com` / `fbaxapi.apiv2.a047.com` | **api** |
| 订阅下载 | `fbaxsub.web.ak005.com` / `fbaxsub.apiv2.a047.com` | **subscription** |
| 配置 CDN | `apisa-ax.cnossfile.com` / `tcdn-ax.getxlx.com` / … | **oss** |
| 节点 DoH | 由订阅 `dns.proxy-server-nameserver` 下发 | **doh** |

配置里的 `domains` / `subscribe_domain` 是故障转移列表，按序尝试。

### 11.3.2 UA

```
User-Agent: ua.net.fbclient.app.apex/<version>      # 7.3.1 实测；版本号不参与校验
```

### 11.3.3 404 伪装

缺证书、UA 不对、路径不对 → 服务端返回 **153 字节 nginx 404 页**（`<html>…404 Not Found…`）。
**不要把它当作"接口不存在"**：三个条件缺一即伪装，满足后才是真实的 200/4xx。

### 11.3.4 错误语义

| 场景 | 返回 |
|---|---|
| 账号口令错 / 账号不存在 | `400 {"message":"Incorrect email or password"}`（不区分，无枚举） |
| access_key 无效 | `403 {"code":403103,…,"msg":"invalid token"}` |
| v1 订阅口 | `403 {"message":"token is error"}`（7.3.1 已下线） |

---

## 11.4 账号链路

### 11.4.1 登录

```http
POST https://{api}/v2/auth/token
Content-Type: application/json
User-Agent: ua.net.fbclient.app.apex/7.3.1

{"email":"…","password":"…"}
```

```json
{"data":{"auth_data":"<JWT>","token":"<access_key>","is_admin":false}, "status":"success"}
```

`auth_data` 为 HS256 JWT（`{uid,sub,exp,iat,jti}`，TTL 72h）。

### 11.4.2 取订阅凭据

```http
GET https://{api}/v2/feed/access-token
Authorization: <JWT 原文>          ← 裸 JWT，**不加** Bearer
```

返回账户/套餐/`token`（长效 access_key）。字段：`email plan_id u d transfer_enable expired_at token uuid subscribe_url`。

### 11.4.3 下载订阅

```http
GET https://{sub}/v2/feed/download?access_key=<access_key>
```

200 → `application/octet-stream`，正文为 **APXS v2 信封**（§11.5）。
`Authorization` 可带可不带；证书必须是 **subscription** purpose。

---

## 11.5 APXS v2 信封

### 11.5.1 布局

```
偏移          长度      内容
[0:4]         4        "APXS" (41 50 58 53)
[4]           1        版本 = 0x02
[5:9]         4        BE u32 aesKeyID   （实测恒为 1）
[9:13]        4        BE u32 signKeyID  （实测恒为 1）
[13:25]       12       nonce
[25:L-80]     n        密文
[L-80:L-64]   16       GCM tag
[L-64:L]      64       Ed25519 签名
```

长度约束：`105 ≤ L ≤ 16,777,321`。

### 11.5.2 数据段

与 CTR 等价：`AES-256-CTR(k1, 计数块 = nonce ‖ 0x00000002)`，计数器只递增低 32 位。

```python
keystream_block0 = AES-ECB(k1, nonce + b"\x00\x00\x00\x02")
```

### 11.5.3 AAD 与 tag

```
AAD = "apex-sub-v2\x00" ‖ body[0:25]        # 13 + 25 = 37 B
tag = GCM(k1, IV=nonce, CT=body[25:L-80], AAD)   # 标准 GHASH
```

即：**它是标准 AES-GCM**，数据段与 CTR 同流，尾部 16 B 是真正的 tag。

### 11.5.4 签名

```
sig = Ed25519(k2, "apex-sub-sign-v2\x00" ‖ body[0:L-64])     # 覆盖到 tag 结束
```

### 11.5.5 校验顺序（推荐）

1. 长度 → 2. magic/版本 → 3. `aesKeyID`/`signKeyID` → 4. tag → 5. 签名 → 6. 解密。

> 客户端实测顺序是：长度 → `isEnvelope`（magic/版本）→ keyID → 签名 → 解密；
> tag 由 GCM 解密内部校验。两者等价，但**先验签再解密**可以避免把未认证数据交给解析器。

---

## 11.6 远程配置 `apex-config-v1`

### 11.6.1 取数与层序

```
GET https://{cdn}/apos/fb_apexv2.json    （证书 purpose = oss）

body(text)  --base64decode-->  bin  --repeating-XOR(XOR_KEY)-->  JSON 信封
信封 = {"format":"apex-config-v1","payload":"<b64>","signature":"<b64 64B>"}
payload --base64decode--> 配置 JSON
```

镜像（7.3.1 字面量）：`apisa-ax.cnossfile.com` / `cdno01-ax.llguanglisf.com` /
`tcdn-ax.getxlx.com`（`/saos/apos/…`）/ `ocdn01-ax.llguangli25o.com:59991` / 一个 IPv4 与一个 IPv6 直连地址。

### 11.6.2 XOR_KEY

**每构建注入**，长度 32（7.3.1 实测 `CAQxDFqU0GFjI55caeVzZ9GdxzGQ8njL`）。
换版本时用已知明文反推（键长 < 已知明文长度才可验证）：

```
已知明文 = 'apex-config-v1\0' + 'payload":"eyJ'   （落在 stage1 的起始处）
```

### 11.6.3 验签

```
sig = Ed25519(k3, "apex-config-v1\x00" ‖ base64decode(payload))
```

验不过即视为配置不可信。**注意 payload 用的是解码后的字节，不是 base64 文本。**

### 11.6.4 配置字段

| 字段 | 说明 |
|---|---|
| `domains` / `subscribe_domain` | API / 订阅主机列表 |
| `subscribe_path` | v1→v2 路径改写表（32 条，7.3.1 与 7.2.3 逐条相同） |
| `features` | 功能开关（含 `ignore_banned`、`password_reset_official_only` 等） |
| `contact` / `update` | 官网、客服、三平台下载地址 |
| `panel_type` | `xboard` / `v2board` |

---

## 11.7 Conformance 向量

完整向量见 `tests/vectors.json`（测试私钥种子 `00..1f`，仅供一致性验证，与线上密钥无关）：

| 向量 | 值 |
|---|---|
| nonce | `000102030405060708090a0b` |
| 明文 | `mixed-port: 7890\nproxies: []\n`（29 B） |
| keystream 首块 | `50f336b0cc6cb2e0eb4ec61651529404` |
| AAD（37 B） | `617065782d7375622d763200` + `body[0:25]` |
| tag | `e84c1b71c22720192ed2d39bc9a93042` |
| 信封长度 | 134 |
| 配置 XOR 键 | `0123456789abcdef0123456789abcdef` |

自检：

```bash
python src/apex_protocol.py              # 构造→校验→解密→篡改拒绝
python tests/test_protocol_vectors.py    # 向量断言（CI 已接入）
```

---

## 11.8 参考实现映射

| 文档章节 | 实现 |
|---|---|
| §11.3 传输/门禁 | `apex_protocol.Transport` / `ApexClient` |
| §11.4 账号链路 | `ApexClient.login` / `.access_token` / `.download` / `.fetch` |
| §11.5 APXS | `parse` / `keystream_block` / `build_aad` / `gcm_tag` / `verify` / `decrypt` / `build` |
| §11.6 配置 | `decode_config` / `recover_config_key` / `verify_config` |
| 仅解密（不验签） | `decrypt(blob)` |

`src/apex_fetch.py`（CLI）与 `tools/windows/fetch_config.py`（配置拉取）是同一套逻辑的
命令行封装，默认**验签失败即拒绝**。

---

## 11.9 版本回归清单

升级客户端时只需重跑这几项（`python tools/windows/verify_build.py <安装目录>` 可自动核对）：

| 检查项 | 7.2.3 → 7.3.1 实测 |
|---|---|
| `k1/k2/k3` 是否变化 | 未变 |
| APXS 信封结构/AAD/前缀 | 未变 |
| mTLS 证书是否轮换（指纹） | 未轮换（RSA-3072） |
| 配置文件名/镜像 | `fb_apex.json` → **`fb_apexv2.json`**，新增 oss 证书门禁 |
| 配置信封 | 新增 `signature`（`k3`） |
| 配置 XOR_KEY | 随构建更换，需重推 |
| 节点类型 | `vless+vision` → **`anytls`**（导出模板需跟着改） |
| v1 明文线路 | **已下线**（403 `token is error`） |

---

## 11.10 集成清单与边界

**接入前自查**

- [ ] 三套证书按 purpose 分开放置（api / subscription / oss）；不要混用，混用即 404
- [ ] UA 固定为 `ua.net.fbclient.app.apex/<ver>`，缺了即 404
- [ ] `Authorization` 用裸 JWT
- [ ] 订阅落盘前跑 `verify()`（tag + 签名），失败即丢弃
- [ ] 配置先验签（`k3`）再用，未验签的配置不得下发到客户端
- [ ] 失败重试按镜像/域名轮转，不要固定单个 IP（CDN 边缘会变）

**边界（按 CWE-602 视角，供你们自建服务参考）**

- 订阅的所有解密材料都在客户端侧，服务端只按 `access_key` 发放密文——
  这是本协议族的固有属性，你们的服务若照抄，必须额外做**服务端权威判定**
  （绑定会话、限速、TTL、设备指纹），否则等于把授权判定交给客户端。
- 节点面（anytls / 私有 DoH）不在本规格内；`server` 字段在公网 DNS 上可能不可解析，
  属部署问题，不是解析问题。

---
