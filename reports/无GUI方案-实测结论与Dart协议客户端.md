# 无 GUI 协议客户端：可行性实测与落地方案（7.2.3）

> 你的目标：**不在 Linux 上跑臃肿的 Flutter 客户端**，而用脚本维持登录态、拉订阅、解密、分发。
> 本轮做了三个决定性实验，结论如下。

---

## 1. 决定性实验：客户端自己也拿不到 v2 响应（404）

### 1.1 客户端**没有证书固定**（可 MITM）

用 mitmproxy CA 签发的多 SAN 证书劫持 `fbaxapi.*`，客户端**正常完成 TLS 握手并发出请求** →
说明 `assets/cer/` 为空、pinning 实际未启用。

### 1.2 抓到的真实请求（原始字节）

```http
GET /v2/announcements/list HTTP/1.1
user-agent: ua.net.fbclient.app.apex/v7.2.3
accept: application/json
accept-encoding: gzip
host: fbaxapi.web.ak005.com
```

```http
GET /apos/fb_apex.json?t=1792946338340 HTTP/1.1
user-agent: ua.net.fbclient.app.apex/v7.2.3
pragma: no-cache
cache-control: no-cache, no-store, max-age=0
accept-encoding: gzip
host: cdno01-ax.llguanglisf.com
```

要点：
- 这两类请求**不带任何 `X-Client-*` 设备指纹头**（指纹头只在登录/订阅类路径上才会出现）；
- UA 固定为 `ua.net.fbclient.app.apex/v7.2.3`；
- 全部小写头名、无 ALPN（Dart/BoringSSL 特征）。

### 1.3 把客户端的**原样请求**转发给源站 → 仍然 404

我们的 MITM 代理把上面这条 `/v2/announcements/list` 原样转发到 `<edge-ip>:443`
（SNI/Host 一致），上游返回：

```
HTTP/1.1 404 Not Found
Server: nginx/1.30.6
Content-Length: 153
```

**结论：不是客户端做对了什么，而是这个域名/这台边缘当前确实没有 v2 路由。**
你在自己机器上看到的 74 节点，来自**之前已成功拉取并缓存/驻留内存的配置**，不是本次 404 后的新拉取。

> 旁证：同进程内存里仍有 `https://fbaxsub.web.ak005.com` + `/v2/feed/download` + `access_key` 字段，
> 但 6 个 `fb_apex.json` 镜像、4 个 API 域名（含 DoH 解析、mTLS、UA、指纹头、HTTP/2、Chrome/Safari/Firefox 指纹）
> 全部 404；`Dart SDK 3.13.7`（与客户端同源 TLS 栈）也是 404。

---

## 2. 你的方案的可行性判定

| 你的设想 | 判定 | 说明 |
|---|---|---|
| 脚本模拟登录（`/v2/auth/token`） | **可行**（协议层） | 标准表单 email/password；未观察到设备证明/签名；`X-Client-*` 若需要也是自报值 |
| 脚本换 `access_key`（`/v2/feed/access-token`） | **可行**（协议层） | Bearer 认证，返回 `access_key`（可能附 `encrypt_key/sign_key`） |
| 脚本拉订阅（`/v2/feed/download?access_key=`） | **协议正确，当前被 404 阻断** | 与 `apex-config-v1` 的路径映射一致 |
| Linux 跑完整客户端 | 不需要 | 见 §3，用 Dart CLI 即可，6.8 MB 单文件 |
| 长期免登录 | **取决于服务端** | 若 `access_key` 有效期 < 套餐周期且无静默续期接口，则仍需保存账号密码做自动重登 |

---

## 3. 最轻的服务器端方案：Dart CLI（已实现并验证可编译）

**为什么是 Dart**：官方客户端是 Dart/BoringSSL；实测 `Dart SDK 3.13.7` 的 ClientHello
与客户端**同构**（相同 cipher 顺序、相同扩展顺序、同为无 ALPN）：

```
ciphers: 1303 1301 1302 cca9 cca8 c02b c02f c02c c030 c009 c013 c00a c014 009c 009d 002f 0035
exts   : 0000 0017 ff01 000a 000b 0023 000d 0033 002d 002b
```

产物：`poc/fb_headless.dart`
- 只依赖 `dart:io`（零第三方包）；
- 流程：`loginV2 → getAccessCredential → download`，落盘 `raw_body.bin / credential.json / response_headers.json`；
- 支持三种模式：账号密码 / 只给 `xboard_token` / 只给 `access_key`；
- 支持 `--path-map` 覆盖（未来服务端改路径不用改代码）；
- `dart compile exe` 后 **6.8 MB 单文件**，Linux 上 `./fb_headless` 直接跑，**不需要 GTK/Xvfb/keyring/桌面**。

```bash
# 服务器上（一次性）
dart compile exe fb_headless.dart -o fb_headless

# 日常：只带 token（推荐，避免保存密码）
./fb_headless --base https://fbaxapi.<panel> --token "$XB_TOKEN" --out /var/lib/fb/latest

# 或首次用账号密码换 token
./fb_headless --base https://fbaxapi.<panel> --email a@b.c --password '***' --out /var/lib/fb/latest

# 解密（Python 侧，已支持 APXS v2 / legacy GCM / CBC / base64 / gzip）
python apex_crypto.py   # 或调用 apex_crypto.decrypt_subscription()
```

> 注意：`fb_headless.dart` 只做协议与落盘；**解密仍建议放在 Python**（`poc/apex_crypto.py`），
> 因为 APXS v2 的信封布局还需要一次真实响应来最终确认（见 §5）。

---

## 4. 登录态从哪来：两种取 token 的方式（都不需要 GUI 服务）

### 4.1 从已登录的 Windows 客户端离线取（推荐）

`flutter_secure_storage.dat` 是**单个 DPAPI blob**，整文件解密即得 JSON：

```powershell
python poc\unseal_secure_storage.py
# 本机实测输出：{"apex_profile_file_key_v3":"yypST7mGtpu9p/QEVQizrg=="}
# 登录后同一文件里会出现 xboard_token / xboard_saved_email 等
```

拿到 `xboard_token` 后即可在 Linux 上用 `fb_headless --token`，**Windows 端无需常驻同步**。
（只有在 token 过期且服务端无静默续期时，才需要重新登录一次。）

### 4.2 从运行态内存取（当 404 恢复后，可直接拿 access_key）

```powershell
python poc\live_scrape.py --process Apex.exe --loop 300 --interval 8 --out recovered_live
```

会 dump 出 `/v2/feed/download?access_key=...` 的完整 URL、`encrypt_key/sign_key`、运行 YAML。

---

## 5. 现在唯一缺的东西（按优先级）

1. **一次可达的 v2 响应**（任一端点：`/v2/site/settings` 或 `/v2/announcements/list`）。
   有了它，就能确定：登录响应字段、`access_key` 有效期、APXS v2 信封布局。
2. 若你的 Windows 客户端**还能刷新**（比如换了网络/代理），用 `live_scrape.py` 抓一次
   `access_key` + 响应体，我可以据此把 `apex_crypto.decrypt_apxs_v2()` 一次对齐。
3. 提供一个「探测脚本」，在部署前判断上游是否恢复：

```bash
python poc/probe_v2.py --hosts fbaxapi.web.ak005.com,fbaxapi.apiv2.a047.com \
                        --ua 'ua.net.fbclient.app.apex/v7.2.3'
# 期望：至少一个端点非 404（200/401/405 均可），再把 200 的路径写进 path-map
```

---

## 6. 结论（一句话）

**协议层可以完全脚本化，Dart 单文件二进制是最轻的服务器端形态（无 GUI/无 GTK）；**
**当前唯一的硬阻塞是上游 v2 源站对本网络返回 404 —— 这与客户端是否运行无关，
已用「客户端原样请求 → 上游 404」的 MITM 证据确认。** 在 404 消失前，任何脚本都无法完成登录/换 key；
建议先用 `xboard_token` + 既有 74 节点 YAML 维持分发，同时用探测脚本轮询上游恢复。
