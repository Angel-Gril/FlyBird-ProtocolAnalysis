# 飞鸟-极速版（fbapp-speed）双端逆向分析报告

> 目标：`fbapp-speed.apk` / `fbapp-speed.exe`（飞鸟云 FClash 魔改客户端）
> 类型：客户端授权/凭据流白盒审计（CWE-602 Client-Side Enforcement of Server-Side Security）
> 环境：授权沙箱（Lab Mode），仅使用用户提供的测试账号，未对生产环境做写操作
> 版本：Apex 7.2.3（Windows `7.2.3+1792857411`，Android `com.fbapp.clients.apex`）
> 产出：本报告 + 证据文件 + 可执行 PoC（`poc/`）

---

## 0. 结论摘要（TL;DR）

1. **两个样本是同一套 Flutter/Dart 代码的两个平台构建**：Dart 业务层包名 `apex_client`，面板 SDK 包名 `boardsdk`（同时支持 XBoard / V2Board），代理内核是 **mihomo（Clash.Meta）**——Windows 侧为 `ApexCore.exe`（Go 1.25.2，mihomo v1.19.x），Android 侧为 `libgojni.so`（gomobile 编译）。
2. **Windows 的 `.exe` 不是主程序，而是 Inno Setup 安装包**（61 MB，LZMA+加密负载）。静默安装后得到 `Apex.exe`（Flutter 宿主）、`data\app.so`（Dart AOT x64，18 MB）、`ApexCore.exe`、`ApexHelperService.exe` 以及 30+ 插件 DLL。
3. 客户端从 CDN 拉取 **`fb_apex.json` 远程配置**（6 个镜像），格式为 `XOR + Base64`，解密后是 `{"format":"apex-config-v1","payload":"<base64 JSON>"}`。**我们已在进程转储中完整取回该配置明文**（证据 1/2），其中包含一份 **v1→v2 API 路径改写表**、面板域名列表、订阅域名列表和功能开关。
4. 该魔改版把标准 XBoard 接口整体改写到自研 **`/v2/*`** 网关：登录 `/v2/auth/token`、**"订阅凭据"** `/v2/feed/access-token`、订阅下载 `/v2/feed/download?access_key=`。这正是用户所说的 **Subscription Credential** 链路：**登录态 token → access_key（长效凭据）→ 密文订阅**。
5. **加密体系已经换代**：参考仓库（`Angel-Gril/Network-About-Third-party-Proxy-Software`）里的 `fd53c838…`（AES-256-GCM）与 `14f521a3…/d217125f…`（AES-128-CBC）常量在本 build 的 `app.so` 中**完全不存在**（0 命中）。本 build 使用：配置层 `xorBase64Deobfuscate`（XOR+Base64）、订阅层 **APXS v2**（`apex-sub-v2` / `apex-sub-sign-v2`，AES + 签名，密钥随 access-token 下发），并保留旧格式回退分支。
6. **最严重的结构性缺陷**：客户端内嵌 **3 张 mTLS 客户端证书 + 私钥**（`purpose = api / subscription / oss`，profile 5，有效期至 **2126 年**，RSA-2048，EKU=clientAuth）。任何拿到安装包的人都能提取同一套"机器身份"，用于冒充官方客户端——这是**共享静态凭据**，无法按用户吊销。
7. 旁路验证（离线复现）已工程化：`poc/extract_credentials.py`（凭据提取）、`poc/scrape_runtime.py`（内存回收配置/凭据）、`poc/apex_crypto.py`（四类信封解密，含自测）、`poc/fb_client.py`（登录→access-token→下载→解密全链路，支持**只用 access_key 跳过登录**的旁路模式）。

> 说明：本沙箱网络对 `fbaxapi.* / fbaxsub.* / fbesa.*` 全部返回 nginx 404/403（详见 §7.4），因此**未能对生产 API 完成端到端在线验证**；报告中的链路结论由静态常量、远程配置明文与运行时内存证据共同支撑，在线步骤以 PoC 形式交付，可在可达环境一键复跑。

---

## 1. 样本与法证信息

| 项目 | APK | EXE |
|---|---|---|
| 文件名 | `fbapp-speed.apk` | `fbapp-speed.exe` |
| 大小 | 164,732,558 B | 61,140,542 B |
| SHA-256 | `EF05D34D829B9E93A053F14E8E04718F0E93E1F32E13993C8AA327AFD1A8CFA4` | `1F56F8204188564A9C81408FE84C45F430D8BD07BCB0E6D1FAD7FDCA2772B2CE` |
| 真实类型 | ZIP/APK（未加固、无壳） | **Inno Setup 安装包**（Delphi stub + LZMA 加密负载，`/VERYSILENT` 可静默解包） |
| 标识 | `com.fbapp.clients.apex`，v7.2.3，compileSdk 36 | 产品名「飞鸟-极速版」，ProductVersion 7.2.3 |
| 运行时 | Flutter（Impeller 开启）+ Go 内核 | Flutter Windows + Go 内核 + Helper 服务 |
| 保护 | 无壳/无反调试；Dart AOT 字符串全明文 | 仅安装包加密；装后无壳 |

**安装后目录（Windows）**：

```
Apex.exe                     Flutter 宿主 (241 KB)
data\app.so                  Dart AOT 快照 x64 (18 MB)   ← 业务逻辑主战场
data\flutter_assets\...      geoip/geosite、字体、config.yaml 模板
ApexCore.exe                 mihomo 内核 (47 MB, Go 1.25.2)
ApexHelperService.exe        TUN/提权辅助服务
flutter_secure_storage_windows_plugin.dll   ← 凭据落盘（DPAPI）
proxy_plugin.dll / window_manager / hotkey / tray / webview ...
```

**Android 侧**：

| 文件 | 大小 | 说明 |
|---|---|---|
| `lib/arm64-v8a/libapp.so` | 16.2 MB | Dart AOT（arm64） |
| `lib/arm64-v8a/libgojni.so` | 49.6 MB | gomobile 打包的 mihomo 内核 |
| `lib/arm64-v8a/libflutter.so` | 11.6 MB | Flutter 引擎 |
| `classes.dex` | 5.2 MB | 宿主/插件（VPN 服务、Tile、BootReceiver、FileProvider） |

Manifest 关键点：`ApexVpnService`（BIND_VPN_SERVICE）、`ApexService`、`ApexTileService`、`BootReceiver`、`network_security_config`（仅 localhost 允许明文）、**Deep Link `uanetfbclientappapex://install-config`**（可外部触发"导入安装配置"）。

---

## 2. 代码结构（Dart 层）

从 `app.so` 的字符串可完整还原包结构（未混淆，`package:` 路径全部保留）：

```
package:apex_client/
  account/config/            panel_configuration.dart / panel_service.dart / config_file_loader.dart
  account/features/auth/     mail_login_token.dart / salesmartly_login.dart
  account/features/subscription/
      services/encrypted_subscription_service.dart      ← APXS v2 解密主逻辑
      services/subscription_downloader.dart
      services/subscription_guard_service.dart
      url_pool/subscribe_url_pool.dart                  ← 订阅域名/URL 池与故障转移
  clash/core/                core_launcher / core_transport / core_ops
  common/ , widgets/ , ui/
package:boardsdk/
  core/factory/panel_type.dart                          ← xboard / v2board 双面板
  panels/xboard/apis/xboard_login_api.dart
  panels/xboard/apis/xboard_subscription_api.dart
  panels/xboard/models/...                              ← json_serializable 模型
  panels/v2board/apis/...
```

第三方密码学：`pointycastle`（AES/GCM/CBC/EC）、`cryptography`（`DartAesGcm`、`SecretBox`、`Hmac`）、`crypto`。

关键类/方法（字符串表直接可见）：

| 符号 | 作用 |
|---|---|
| `EncryptedSubscriptionService` | 订阅解密服务（APXS v2） |
| `EncryptedProfileIo` / `encrypted_profile_io.dart` | 本地档案加密 IO |
| `getEncryptedSubscriptionFromLogin` | 登录后立即换取加密订阅（旁路点） |
| `getCoreSecret` | 内核通信密钥 |
| `xorBase64Deobfuscate` | 配置层 XOR+Base64 解码 |
| `SubscriptionGuardService` / `FreshSubscriptionRefresh` | 订阅守卫 / 刷新调度 |
| `SubscribeUrlPool` (+`subscribe_url_pool_v1`) | 订阅 URL 池持久化 |
| `tryDecrypt` / `Decryption failed:` | 解密失败路径 |

---

## 3. 远程配置：`fb_apex.json` 与 `apex-config-v1`

### 3.1 引导层（bootstrap）

客户端启动时按顺序尝试 6 个镜像（字符串表原样）：

```
https://<ip>/apos/fb_apex.json
https://apisa-ax.cnossfile.com/apos/fb_apex.json
https://cdno01-ax.llguanglisf.com/apos/fb_apex.json
https://tcdn-ax.getxlx.com/saos/apos/fb_apex.json
https://ocdn01-ax.llguangli25o.com:59991/apos/fb_apex.json
https://[2406:da18:42b:2e00:45ae:b4f6:fc3e:13cb]/apos/fb_apex.json
（运行时会追加 ?t=<毫秒时间戳> 破缓存）
```

APK 内 `assets/flutter_assets/assets/config/config.yaml` 是对外模板，直接写明机制：

```yaml
# 所有源均使用相同的 XOR+Base64 加密（密钥硬编码在客户端）
remote_config:
  sources:
    - url: https://your-oss.example.com/config.json
```

### 3.2 解密后的配置（★ 核心证据）

从运行中进程的转储里回收到的明文（`reports/evidence_apex_config_runtime.json`，偏移 `0x0AD34221`）：

```json
{
  "enable_api_path_mapping": true,
  "subscribe_domain": ["https://fbaxsub.web.ak005.com", "https://fbaxsub.apiv2.a047.com"],
  "subscribe_path": { "...": "见下表" },
  "config_version": 1,
  "brand_color": "65A1CC",
  "panel_type": "xboard",
  "domains": ["https://fbaxapi.web.ak005.com", "https://fbaxapi.apiv2.a047.com"],
  "features": { "plans_official_only": true, "invite_enabled": true, "purchase_enabled": true,
                "traffic_details_enabled": false, "knowledge_base_enabled": true, "ticket_enabled": false,
                "diagnostic_logging_enabled": false, "gift_card_enabled": false, "join_group_enabled": true,
                "coupon_enabled": true, "checkin_enabled": false, "mail_login_enabled": false },
  "contact": { "website": "https://web01.fbbapp.cc",
               "crisp_website_id": "44a52cf7-ee4c-48a6-aa94-b7b6ed7be72f",
               "invite_domain": "https://appinv01.fbvipaff.cc" },
  "update": { "min_version": "", "changelog": "", "latest": {} }
}
```

要点：
- 配置把面板 API 与订阅 CDN **拆成两组域名**（`domains` / `subscribe_domain`），支持故障转移；
- `enable_api_path_mapping=true` 时，客户端对所有 XBoard v1 请求做**路径改写**；
- 配置本身**没有签名**（信封只有 `format` + `payload`），仅靠 XOR+Base64 混淆。

### 3.3 v1 → v2 路径改写表（完整）

| XBoard v1（公开协议） | 本客户端 v2（自研网关） |
|---|---|
| `/api/v1/passport/auth/login` | `/v2/auth/token` |
| `/api/v1/passport/auth/register` | `/v2/auth/signup` |
| `/api/v1/passport/auth/forget` | `/v2/auth/reset-password` |
| `/api/v1/passport/comm/sendEmailVerify` | `/v2/auth/send-code` |
| `/api/v1/guest/comm/config` | `/v2/site/settings` |
| `/api/v1/user/changePassword` | `/v2/account/password` |
| `/api/v1/user/comm/config` | `/v2/account/config` |
| `/api/v1/user/info` | `/v2/account/profile` |
| `/api/v1/user/transfer` | `/v2/account/balance-transfer` |
| `/api/v1/user/getSubscribe` | **`/v2/feed/access-token`** |
| `/api/v1/client/subscribe?token=` | **`/v2/feed/download?access_key=`** |
| `/api/v1/user/getStat` | `/v2/analytics/summary` |
| `/api/v1/user/stat/getTrafficLog` | `/v2/analytics/usage` |
| `/api/v1/user/order/fetch` | `/v2/checkout/history` |
| `/api/v1/user/order/save` | `/v2/checkout/create` |
| `/api/v1/user/order/checkout` | `/v2/checkout/process` |
| `/api/v1/user/order/check` | `/v2/checkout/verify` |
| `/api/v1/user/order/detail` | `/v2/checkout/view` |
| `/api/v1/user/order/cancel` | `/v2/checkout/void` |
| `/api/v1/user/order/getPaymentMethod` | `/v2/checkout/gateways` |
| `/api/v1/user/plan/fetch` | `/v2/products/pricing` |
| `/api/v1/user/coupon/check` | `/v2/promo/verify` |
| `/api/v1/user/invite/fetch` | `/v2/referral/code` |
| `/api/v1/user/invite/save` | `/v2/referral/claim` |
| `/api/v1/user/invite/details` | `/v2/referral/stats` |
| `/api/v1/user/knowledge/fetch` | `/v2/docs/articles` |
| `/api/v1/user/notice/fetch` | `/v2/announcements/list` |
| `/api/v1/user/server/fetch` | `/v2/nodes/endpoints` |
| `/api/v1/user/ticket/fetch` | `/v2/support/tickets` |
| `/api/v1/user/ticket/save` | `/v2/support/create` |
| `/api/v1/user/ticket/close` | `/v2/support/resolve` |
| `/api/v1/user/getQuickLoginUrl` | `/v2/auth/sso-url` |

> 该表来自客户端自带的远程配置，**不是猜测**。它同时解释了「为什么按官方 XBoard 协议请求 `/api/v1/...` 全部 404」——服务端只挂了 `/v2/*` 网关。

### 3.4 三层解密顺序（配置）

```
HTTP body (text)
   │  xorBase64Deobfuscate(body, XOR_KEY)      ← 密钥硬编码在 libapp.so，编译期注入
   ▼
{"format":"apex-config-v1","payload":"<b64>"}
   │  base64decode(payload)
   ▼
JSON（domains / subscribe_domain / subscribe_path / features ...）
```

XOR_KEY 为**每份打包构建独立注入**的常量；它在 `app.so` 的 Dart 堆中以 String 常量存在，运行时可从内存直接回收（`poc/scrape_runtime.py`）。本次样本因服务端镜像全部 404/超时，未能捕获"传输态密文"，故未做已知明文反推（方法已内置）。

---

## 4. 账号 → 凭据 → 订阅（端到端链路）

```
① POST {domains[n]}/v2/auth/token
   form: email=&password=
   headers: X-Client-Platform/windows, X-Client-Model, X-Client-Brand,
            X-Client-OS-Version, X-Client-Environment, X-Client-Security-Probe-Status, ...
   200 → {"data":{"token":"...","auth_data":"..."}}

② GET  {domains[n]}/v2/feed/access-token
   headers: Authorization: Bearer <token|auth_data>
   200 → 订阅凭据（access_key，可能附带 encrypt_key / sign_key / expires_at）
   ★ 这一步就是 Subscription Credential 的签发点

③ GET  {subscribe_domain[n]}/v2/feed/download?access_key=<key>
   headers: 同上（含设备指纹头）
   200 → YAML | base64(YAML) | APXS v2 密文 | legacy GCM/CBC 密文

④ 本地解密 → 写入 profile（再加密落盘）→ 分发给 mihomo 内核
```

代码侧对应函数：`getEncryptedSubscriptionFromLogin`、`SubscriptionDownloader`、`EncryptedSubscriptionService`、`SubscribeUrlPool`（URL 池故障转移）、`SubscriptionGuardService`（过期/限额守卫）。

**v1 兼容**：`panel_type=v2board` 时退回 `/api/v1/...` 原生路径；`fallbackToNormalSubscription` 允许"服务端没部署 Apex 插件时"退回明文/通用 base64 订阅。

---

## 5. 加密体系全景

| 层 | 算法/格式 | 密钥来源 | 证据 |
|---|---|---|---|
| 远程配置 | XOR + Base64 | 编译期常量（每构建不同） | `xorBase64Deobfuscate`、`config.yaml` 注释、运行时明文 |
| 订阅（旧·GCM） | AES-256-GCM，`nonce(12)‖ct‖tag(16)`，key=SHA256(secret) | `<rand-token>` | 参考仓库；**本 build 0 命中** |
| 订阅（旧·CBC） | AES-128-CBC/PKCS7 | key=`14f521a32997b257`，iv=`d217125f4b9cc9c8` | 参考仓库；**本 build 0 命中** |
| 订阅（新·APXS v2） | AES + 签名（GCM/HMAC 组合） | `encrypt_key` / `sign_key`（随 access-token 下发） | `APXS v2 encrypted subscription required`、`apex-sub-v2`、`apex-sub-sign-v2`、`Subscription AES/signature keys are missing or invalid` |
| 本地档案 | 平台密钥封装（`apex_profile_file_key_v2/v3`、`apex_pfk`、`EncryptedProfileIo`） | flutter_secure_storage（Windows=DPAPI 用户态；Android=Keystore） | 存储键 + `EncryptedProfileIo` + DPAPI 文件格式实测 |
| 本地登录凭据 | shared_preferences + secure storage（`xboard_token`、`xboard_saved_password_v2`、`xboard_pwd_obf_v1`） | DPAPI / Keystore | 存储键表 |
| 传输层（可选） | **mTLS 客户端证书**（purpose=api/subscription/oss） | 内嵌 PEM（见 §6） | 3 个 base64 JSON 证书包 |

失败提示原文（可直接指导逆向定位）：

```
Subscription decryption failed (key mismatch). Ask the provider to verify that
$encryptKey in Apex.php exactly matches the client XOR_KEY (case-sensitive, no extra spaces).

Subscription format error: the server did not return a valid config.
Possible causes:
1. Apex.php is not deployed on the server but the client used ?flag=apex
2. $encryptKey in Apex.php does not match the packing bot's XOR_KEY
3. Temporary panel failure

Subscription response is generic base64, not Clash yaml. Common causes:
(1) Apex.php not deployed, panel fell back to generic subscription;
(2) client APEX_FLAG does not match $flag in Apex.php ...
```

=> 证实：**订阅加密由面板侧 `Apex.php` 插件完成，密钥与客户端打包时注入的 `XOR_KEY` 约定一致**；v2 时代升级为"下发密钥 + 签名"。

---

## 6. 内嵌 mTLS 机器身份（★ 高危）

`app.so` 中硬编码了 3 段 base64 JSON（`{"version":1,"profile_id":5,"purpose":...,"client_cert_pem":...,"client_key_pem":...}`）：

| purpose | 偏移 | CN | 签发者 | 序列号（截断） | SHA-256 指纹（截断） |
|---|---|---|---|---|---|
| api | `0x00596780` | `Apex-5-api-client-31957d682ce16866` | `Apex-5-api-CA-31957d682ce16866` | `81c6988935064b1c…` | `99bd6d087af29dbc…` |
| subscription | `0x004F0800` | `Apex-5-subscription-client-23efaa03ce86e278` | `Apex-5-subscription-CA-23efaa03ce86e278` | `735119110da53069…` | `d2cb3a9144c1e08c…` |
| oss | `0x005DC310` | `Apex-5-oss-client-8a4b338e7d713f49` | `Apex-5-oss-CA-8a4b338e7d713f49` | `2b89d2814e78d89c…` | `584e70ac53b67bf1…` |

共同特征：
- RSA-2048，`sha256WithRSAEncryption`，EKU=`clientAuth`；
- 有效期 **2026-10-15 → 2126-10-15（100 年）**；
- **私钥与证书同时内嵌**，所有安装同一构建的用户共享同一身份；
- 证书/私钥已由 PoC 完整导出（`creds/profile5_*_client.{crt,key}.pem`）。

影响：服务端若以 mTLS 作为"官方客户端"判据，则任何提取者都可 1:1 冒充；且**无法按用户吊销**（吊销即全体下线）。

---

## 7. 反滥用 / 反分析机制盘点

### 7.1 设备与环境指纹（自报头）

客户端在请求中附带 20+ 个 `X-Client-*` 头（全部在 `app.so` 中可见）：

```
X-Client-Platform / Model / Brand / OS-Version / Serial-Number
X-Client-Android-ID / IMEI / Root-Status / Emulator-Name / Jailbreak-Status
X-Client-Sensor-Accelerometer / Gyroscope / Magnetometer
X-Client-Environment / Environment-Evidence / Environment-Confidence
X-Client-Env-Collector-Version / Env-Detector-Version
X-Client-Security-Evidence / Security-Probe-Status / Security-Detector-Version / Security-Confidence
```

均为**客户端自报**，服务端无法验证真实性（除非与 mTLS/设备证明绑定）。

### 7.2 证书校验

字符串显示存在证书固定能力：

```
Certificate pinning is enabled but certificate failed to load. Refusing connection for security reasons.
Bundled public CA fingerprint mismatch
configFingerprint / ConfigFileLoaderHelper|getCertificateConfig
ssl_com_tls_rsa_root_ca_2022
registerBadCertificateCallback / HttpOverrides / ApexHttpOverrides
```

但 `assets/cer/` 目录为空（仅 `.gitkeep`），说明**本构建实际未下发固定证书**，pinning 处于"有代码、无数据"的失效状态。

### 7.3 完整性

- `config_signature` / `update_signature` / `signature_algorithm` 字段存在，但实测远程配置信封无签名字段；
- 安装包由 Inno Setup 加密，仅保护分发环节，装后无自校验。

### 7.4 其它

- 面板站点使用**静态 Cookie 人机校验**：`document.cookie="human_verify=passed_token_2026"`（一行绕过，且 token 对所有访问者相同）；
- Android 侧存在本地明文控制口：`http://<ip>:47890/{auth,start,stop,ping,memory-config}`（`memory-config` 可直接向内核注入配置）；
- Deep Link `uanetfbclientappapex://install-config` 可外部触发导入配置（需进一步验证是否有来源校验）。

---

## 8. 脆弱性分析（CWE-602）

| ID | 问题 | 证据 | 影响 | 严重度 |
|---|---|---|---|---|
| **F1** | **客户端即权威**：订阅密文、解密密钥、access_key 全部在客户端/会话侧闭环，服务端只按 access_key 发密文，未绑定设备 | §4 链路 + `EncryptedSubscriptionService` + 配置 | 任意 HTTP 客户端可用同一 access_key 拉取并解密订阅，客户端形同虚设 | 高 |
| **F2** | **mTLS 私钥内嵌、10 年+ 共享身份** | §6 三张证书实测导出 | 提取即可冒充官方客户端；无法按用户吊销 | 高 |
| **F3** | **远程配置零签名**（仅 XOR 混淆，密钥硬编码） | §3.2 信封结构；`config.yaml` 注释 | CDN/链路被控或本地替换即可把 `domains`、`subscribe_domain` 指向攻击者服务器（定向投毒/流量劫持） | 高 |
| **F4** | **access_key 长效且无设备绑定**，`X-Client-*` 仅自报 | 头清单 + `/v2/feed/access-token` 语义 | 凭据外带后可长期离线拉取、二次分发（用户所述"旁路"正是此路径） | 高 |
| **F5** | **静态人机校验 Cookie** | `human_verify=passed_token_2026` | 一行 Cookie 绕过风控/爬虫限制 | 中 |
| **F6** | **本地凭据为用户态保护**（DPAPI/Keystore），同用户进程可解 | `flutter_secure_storage.dat` 实测为 DPAPI blob；`xboard_saved_password_v2` | 同机低权恶意程序可窃取登录态与档案密钥 | 中 |
| **F7** | **本地控制口明文 + 配置注入** | `<ip>:47890/memory-config` | 同机任意进程可操控内核/注入配置（待设备实测） | 中 |

**结论定性**：属于典型的「服务端能力、客户端判定」。真正可复用的判定物是 **access_key（会话凭据）**，而不是客户端本身；客户端加固（Dart AOT、mTLS、XOR）只提高了"第一次拿到凭据"的成本，**不构成授权边界**。

---

## 9. 旁路验证 PoC（可执行）

### 9.1 文件

```
poc/
  apex_crypto.py          # 配置/订阅四类信封加解密 + 自测（已跑通）
  fb_client.py            # 登录 → access-token → download → 解密（含 --access-key 旁路模式）
  extract_credentials.py  # 从 app.so 提取 mTLS 证书 + 存储键 + 指纹头（已跑通）
  scrape_runtime.py       # 从进程转储回收 apex-config / 证书 / access_key / YAML 片段（已跑通）
  README.md
```

### 9.2 已验证（离线）

```powershell
python poc/apex_crypto.py            # 4 组 XOR 层序 + APXS v2 GCM 往返，全部 [ok]
python poc/extract_credentials.py installed\data\app.so --out creds
python poc/scrape_runtime.py http\apex.dmp --out recovered
python poc/fb_client.py --help
```

### 9.3 在线（需可达网络）

```powershell
# A. 账号全链路
python poc/fb_client.py --base https://fbaxapi.<panel> --email <mail> --password <pwd> --out out --insecure

# B. 旁路：只用长效 access_key（不登录、不启动客户端）
python poc/fb_client.py --sub https://fbaxsub.<panel> --access-key <ACCESS_KEY> --out out --insecure

# C. 若 access-token 同时下发密钥
python poc/fb_client.py --sub https://fbaxsub.<panel> --access-key <K> --encrypt-key <EK> --sign-key <SK> --out out
```

成功判据：`out/fb_clash.yaml` 含 `proxies:` 段，且节点数与面板一致；`credential.json` 留档。

### 9.4 本沙箱的网络事实（诚实记录）

| 目标 | 结果 |
|---|---|
| `fbaxapi.apiv2.a047.com` / `fbaxapi.web.ak005.com`（含 `/v2/site/settings`、`/v2/auth/token`、mTLS 双模式） | 一律 `404 nginx/1.30.6` |
| `fbaxsub.*` 下载口 | `404` |
| `fbesa.apiv2.a047.com`（参考实现 API） | `403`（UA 为 NetFlow 时）/ 返回官网 HTML |
| `fb_apex.json` 6 镜像 | `404 / 超时 / 证书过期 / 连接重置` |
| `w04.fbwebd07.cc` / `a02.fbvipaffb05.cc` 面板站 | 静态 Cookie 人机校验；`/api/v1/*` 302 → `/404` |

因此本报告未声称"已在线拉取到该账号的订阅"；F1/F4 的结论基于链路与凭据模型，PoC 已就绪，可在真实可达环境完成最后一跳。**测试期间仅使用用户提供的测试账号，且未获得任何有效会话（全部 404/403），建议评估结束后重置该账号密码。**

---

## 10. 厂商侧加固建议（按优先级）

1. **把授权判定搬到服务端**：`/v2/feed/download` 不应仅凭 `access_key` 放行，应同时校验登录态、设备指纹（首次注册时绑定）、IP/ASN 漂移、并发数与速率；access_key 改为**短 TTL + 单次/可刷新**。
2. **废除共享 mTLS 身份**：改为**按用户/设备签发**的客户端证书（服务端持有 CA 并可吊销），或改用 DPoP/mTLS-bound token；私钥必须落在 TPM/Keystore/DPAPI 且不可导出。
3. **配置签名**：`apex-config-v1` 增加 Ed25519 签名（公钥内置），客户端验签失败即拒绝；配置文件禁止下发可执行 URL 之外的敏感项。
4. **密钥分层**：不要用"硬编码 XOR_KEY"作为唯一机密；订阅加密密钥应由服务端按会话派生（HKDF(server_secret, user_id, nonce)），并绑定 access_key 生命周期。
5. **签名与重放防护**：`apex-sub-sign-v2` 应覆盖 method+path+body+timestamp+nonce，服务端校验时间窗与 nonce 去重。
6. **人机校验**：`human_verify` 改为服务端签发的短时 HMAC Cookie（绑定 IP/UA），不要用固定字符串。
7. **设备证据可信化**：`X-Client-*` 只作辅助信号；关键判定使用 Play Integrity / DeviceCheck / Windows 硬件证明。
8. **本地面收敛**：`<ip>:47890` 增加每次启动的随机 token（放 `Apex.lock`），`memory-config` 校验调用进程签名；Deep Link 导入需用户确认 + 来源校验。

---

## 11. 证据索引

| 文件 | 内容 |
|---|---|
| `reports/evidence_apex_config_runtime.json` | 运行时回收的 `apex-config-v1` 明文（含完整路径表） |
| `reports/evidence_apex_config.json` | 上述配置的 `payload` 解码结果（JSON） |
| `creds/profile5_{api,subscription,oss}_client.crt.pem` | 提取出的 mTLS 客户端证书（公钥部分） |
| `creds/summary.json` | 证书偏移/长度、存储键命中、`X-Client-*` 头清单 |
| `http/apex.dmp` | 运行中 Apex.exe 的完整进程转储（503 MB） |
| `http/mitm.log`, `http/proxylisten.log` | 网络观测尝试记录（未命中，佐证"无系统代理/无固定证书"） |
| `apk_unpack/AndroidManifest.xml` | Android 组件/权限/Deep Link |
| `installed/` | Inno Setup 静默解包后的完整客户端 |

**关键字符串偏移（`installed/data/app.so`）**

| 偏移 | 字符串 |
|---|---|
| `0x003C0A20` | `APXS v2 encrypted subscription required` |
| `0x006C9A70` | `apex-sub-v2` |
| `0x0055F780` | `apex-sub-sign-v2` |
| `0x005E2370` | `Subscription decryption failed (key mismatch)…XOR_KEY` |
| `0x005FA600` / `0x00606810` | Apex.php / APEX_FLAG 故障排查文案 |
| `0x005AACD0` | `xorBase64Deobfuscate` |
| `0x00636630` | `xor_key` |
| `0x005F0780` | `enable_api_path_mapping` |
| `0x004C4660` | `subscribe_domain` |
| `0x006C9A70` | `apex-sub-v2` |
| `0x004F0800` / `0x00596780` / `0x005DC310` | 三张 mTLS 证书包 |

---

## 12. 附录：域名与端点清单

```
面板 API   fbaxapi.web.ak005.com / fbaxapi.apiv2.a047.com
订阅 CDN   fbaxsub.web.ak005.com / fbaxsub.apiv2.a047.com
官网/客服  web01.fbbapp.cc → w04.fbwebd07.cc
邀请       appinv01.fbvipaff.cc → a02.fbvipaffb05.cc
其它       axapi-cn.web.ak005.com（客户端启动即连，路径未知）
           <ip> / *.llguangli25*.com / *.cnossfile.com / *.getxlx.com（配置 CDN）
           20200610.shop/v1（内存中出现，用途待定）
本地口     <ip>:47890/{ping,auth,start,stop,memory-config}
```

**用户态落盘**：`%APPDATA%\com.fbapp.clients.apex\飞鸟-极速版\`
- `shared_preferences.json`：`flutter.config`（本地设置）、`flutter.apex_last_run_version`
- `flutter_secure_storage.dat`：DPAPI 封装的 `xboard_token` / 账号与**档案密钥**
- `Apex.lock`、`.memory-only-v2`、geo 数据

---

*报告生成：静态反汇编（radare2/字符串/内存取证）+ 运行时转储 + 参考实现对照。所有结论均标注了可复核的证据位置；未能在线验证的部分已明确标注。*
