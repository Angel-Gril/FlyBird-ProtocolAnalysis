# Changelog

本项目记录对目标客户端协议分析的完整过程。版本号对应**分析里程碑**，非软件版本。

## [未发布]

### 新增

- `scripts/local.sh`（Linux/macOS）与 `scripts/local.ps1`（Windows）一键脚本：
  环境自检 → 自动识别并导入证书（`api.crt` 或 `profile5_*_client.{crt,key}.pem`）
  → 写配置（600）→ 拉 v2/v1/both → 汇总。默认落在 `~/.apex-local/`（仓库之外）。
- `scripts/_check_env.py` / `scripts/_summary.py`：两个平台共用的自检与汇总。
- `apxs_decrypt.py` 重构：`argparse`（`-h` / `-f` / `--key`），AES 后端改为
  `cryptography → pycryptodome → openssl` 三级回退，不再硬依赖 pycryptodome。

### 文档

- `docs/03` 新增 §3.7 **证书与密钥的职责边界**：
  证书只管“取数”，k1 只管“解密”；不含证书的纯解密路径（`apxs_decrypt.py` / `POST /decode`）。
  附“按线路算需要几个证书”对照（v1=2 / v2=2 / both=4 / 仅解密=0）。
- `docs/08` 新增 §8.5 **证书在两种 Serverless 上怎么放**：
  Cloudflare `mtls-certificate upload` + `[[mtls_certificates]]` 绑定，
  GitHub Actions 六个 Secret 与临时文件清理；四张证书两种平台均支持。
- README 同步补上交叉引用。

## [1.6.0] - 2026-11-24

### 新增：把"协议输出"与"发布物"的分界写清楚

反复出现的"客户端连不上"里，有一部分不属于协议层。本次把边界与判据固化：

- `docs/11 §11.5.6`：**入口地址不在信封内**——`server` 是主机名，`ip-version` 只是拨号偏好；
  解析需要订阅里的私有 DoH + `purpose=doh` 身份，属客户端职责。第三方消费者必须自行解析并
  写入目标内核形式（Mihomo `hosts` / sing-box `server` 字面量）。
- `reports/12-协议输出与发布物之间的落差.md`：与维护中的服务仓库的分工、四类落差、
  四关验证判据（可加载 → 可解析 → 可连接 → 真实转发）、以及本仓库的收录边界。

### 说明

- 本仓库只记录**协议事实与验证方法**；服务部署、缓存、模板、门禁实现留在服务仓库。
- 不改变任何协议结论：APXS/配置的解密与验签实现不受影响。

## [1.5.3] - 2026-11-23

### 范围纠正：撤回运维排障内容

`1.5.1` / `1.5.2` 把"导出配置在第三方客户端连不上""节点域名解析不稳定"这类
**部署/网络排障**内容写进了协议仓库（`docs/11 §11.11` 与三个诊断脚本）。
它们不属于本项目的定位——本项目只负责**协议还原与实现**，节点可达性是运维问题。

本次撤回：

- 删除 `docs/11 §11.11`（导出配置失败面 / 三层分诊）；
- 删除 `tools/windows/diagnose_export.py`、`triage_export.py`、`node_dns_probe.py`；
- 相关结论只在 `reports/11 §8.4` 作为**分析过程记录**保留（记录"私有 DoH 存在且本网络不可达"），
  不再以工具或规范形式对外提供。

保留在仓库内的仍属协议层：

| 保留 | 理由 |
|---|---|
| `docs/11 §11.1–11.10` | 面板/订阅协议规格 |
| `src/apex_protocol.py` + `tests/vectors.json` | 参考实现与一致性向量 |
| `src/apxs_verify.py` / `src/apex_fetch.py` | 信封校验与抓取 |
| `tools/windows/fetch_config.py` | 配置获取与**验签**（协议 §11.6 的实现） |
| `tools/windows/verify_build.py` / `unpack_installer.ps1` | 版本回归（常量/证书/组件清单） |

## [1.5.2] - 2026-11-23

### 新增：导出配置的三层分诊（配置/规则 · DNS · IPv6）

- `tools/windows/triage_export.py`：
  - **A 配置/规则**：proxies 结构、旧字段混用、**规则 target 是否存在**（mihomo 遇到未知 target
    会拒绝加载整份配置）、`MATCH` 兜底、节点域名是否被规则误命中；
  - **B DNS**：多解析器对照 A/AAAA，检查私有 DoH 令牌；
  - **C IPv6/连通**：A 与 AAAA 各做 TCP 探活，结合 `ip-version` 与本机 IPv6 可用性；
  - `--emit-control` 产出**对照配置**（server→IP、去 `ipv6-prefer`、删私有 DoH 令牌，
    `--global` 再加 `mode: global`），用于在同一台失败机器上 A/B。
- `docs/11 §11.11.5`：三层分诊表与实测输出。

### 实测

```
[OK ] A 配置  proxies: 74 个 {'anytls': 74}
[OK ] A 配置  规则 target: 111 条规则，target 均存在
[OK ] A 配置  MATCH 兜底: 有
[OK ] B DNS   A=1 个 ['54.150.182.240'] / AAAA=0 个 []
[!! ] C 连通  IPv4 54.150.182.240:14301: TimeoutError
[!! ] C IPv6  ip-version: ['ipv6-prefer']；本机 IPv6 不可用
```

当天同一节点域名已观测到 4 个不同 A 记录（`18.138.78.126` / `47.131.14.168` /
`54.116.187.243` / `54.150.182.240`）——解析视角差异是"部分网络通、部分不通"的硬证据。

## [1.5.1] - 2026-11-23

### 新增：导出配置在第三方客户端的失败面（docs/11 §11.11）

针对"官方 App 能连、导出后 FlClash 连不上"，把四条已知失败面写进规格：

| # | 失败面 | 判定特征 |
|---|---|---|
| 1 | 私有 DoH 令牌过期 | `lookup <node>: no such host`；令牌每次 download 轮换 |
| 2 | 节点域名公共解析不稳定 | 同一域名不同解析器/不同时刻给出不同 IP |
| 3 | 内核不支持 `anytls` | `unsupported proxy type` |
| 4 | `ip-version: ipv6-prefer` | 纯 IPv4 网络下失败/极慢 |

**实测（2026-11-23）**：同一节点域名，系统 DNS `18.138.78.126`、alidns `54.116.187.243`
（另一次 `47.131.14.168`）、doh.pub `47.131.14.168`，AAAA 为 AWS IPv6 —— 三个解析器三个答案。

### 新增

- `tools/windows/diagnose_export.py`：吃一份导出的 YAML，逐项报 `OK/!!`
  （节点类型、字段新旧混用、多解析器对照、私有 DoH 令牌、ip-version），
  解析不一致时直接标出"N 个不同 IP"。

### 结论沉淀

- 这不是协议问题：APXS/配置解析都正常；问题在**解析视角**与**令牌时效**；
- 导出给第三方客户端的正确做法：`server` 写 IP + 保留 `sni`、移除私有 DoH 令牌、
  确认内核支持 anytls、按需去掉 `ipv6-prefer`。

## [1.5.0] - 2026-11-23

### 新增：面板/订阅协议的**规范性规格**与参考实现（层 ①）

把散在 README / docs/03 / docs/04 / reports 里的结论收敛成一份可按字节实现的规格：

- `docs/11-protocol-spec.md`：门禁矩阵、账号链路、APXS v2 布局与 AAD/签名、
  `apex-config-v1` 层序与验签、错误语义、**版本回归清单**、集成自查表与 CWE-602 边界说明；
- `src/apex_protocol.py`：单文件参考实现（`Transport` 可注入），
  覆盖 `login / access_token / download / fetch` 与 `parse / verify / decrypt / build`、
  `decode_config / verify_config`；默认验签，失败即抛；
- `tests/vectors.json` + `tests/test_protocol_vectors.py`：固定测试私钥（种子 `00..1f`）
  产生的**确定性向量**（keystream 首块、AAD、tag、签名、配置解码与验签），已进 CI。

### 说明

- 规格只覆盖**面板与订阅链路**；节点侧（anytls、私有 DoH、`transport/apex`）明确列为范围外，
  在 `reports/11 §8` 单独记录；
- 正文标注了每一条的验证状态："实测验通 / 推断 / 待运行时"。

## [1.4.5] - 2026-11-23

### 用官方 Windows 内核抓到私有 DoH 的真实请求形态

把 7.3.1 的 `ApexCore.exe` 用解出来的订阅启动（`log-level: debug`），经 external-controller
触发一次 delay 测试逼它解析节点，日志直接吐出请求：

```
[DNS] resolve axbtapp-….llguanglisf.com A from https://fbcg02.web.ak005.com:443/api-v2/<token>
Get "https://fbcg02.web.ak005.com:443/api-v2/<token>?dns=AAABAAABAAAAAAAAEWF4…AAAcAAE"
  → context deadline exceeded
```

解 base64url 得标准 DNS 查询：`id=0x0000`、`flags=0x0100`、`qname=节点域名`、
**`qtype=28（AAAA）`**、`qclass=1`；随后再查 A（与 `ip-version: ipv6-prefer` 一致）。

→ 形态是 **RFC8484 GET**（`?dns=<base64url(wireformat)>`）+ `purpose=doh` 的 mTLS，
不是 POST、也不是 `?name=&type=`。

### 改进

- `tools/windows/node_dns_probe.py` 改为**同款请求**（GET `?dns=` + AAAA/A 两轮 +
  `accept: application/dns-message`），HTTP/2 分支同步修正。
- 报告新增 §8.4.2：日志原文、解码结果、以及"**官方内核在本网络同样 `context deadline exceeded`**"
  ——把卡点从"我们的工具不行"钉成"到 `103.239.185.80:443` 的 TCP 不通"。

## [1.4.4] - 2026-11-23

### 定稿：节点侧私有 DoH 的入口、请求形态与可达性

**入口在配置里，不在二进制里。** 7.3.1 内核没有 `/api-v2/` 字面量；
`dns.apexDohTLS` 只加载 `purpose=doh` 证书，`dns.(*dnsOverHTTPS).createClient.apexDohRedirect`
把普通 DoH 客户端替换成带 mTLS 的实现，报文类型由字面量 `application/dns-message` 决定
→ **URL 完全由订阅的 `dns.proxy-server-nameserver` 下发，不存在隐藏端点**。

解析链（DoH 复核）：

```
fbcg02.web.ak005.com            CNAME  doh-aws.llguangli25n.com.
doh-aws.llguangli25n.com        CNAME  dsapi-sdcm02.llguanglisf.com.
dsapi-sdcm02.llguanglisf.com    A      103.239.185.80     （AAAA 为空）
```

CNAME 里直接写着 `doh-aws` —— DoH 专用域，不是随机子域。

**可达性穷举（本环境全部失败）**：

| 尝试 | 结果 |
|---|---|
| `103.239.185.80` TCP 80/443/8443/8080 | 全部超时 |
| HTTP/1.1 GET/POST × doh/sub/api/无证书 | 一次 404 伪装页，其余 TCP 超时 |
| **HTTP/2 + ALPN h2 + mTLS + POST** | **TCP 阶段即超时** |
| Cloudflare/Google/Quad9/NextDNS/AdGuard 查同一域名 | 全部不可达（拿不到非 CN 视角） |

→ 请求形态已明确并实现，**缺的只是网络可达性**；本版仍**不提供**"自动解决节点超时"的补丁。

### 改进

- `tools/windows/node_dns_probe.py` 增加 `--http2`：用 `h2` + ALPN + mTLS 发 RFC8484 POST，
  与 mihomo 的真实形态一致；TCP 不通时会明确报"未到 TLS 层"，避免误判为协议问题。

## [1.4.3] - 2026-11-23

### 更正（依据样本复核，两条都成立）

| 原表述 | 更正 |
|---|---|
| 「`purpose=doh` 是 7.3.x 新增」 | **7.2.4 就已存在**：`usr/bin/mihomo`（43,911,330 B）里有 `purpose=doh` 证书包（`@0x019A3BBF`）与 `apexDohMTLS`/`apexDohIdentityState`/`ExternalDohServer`。7.3.1 新增的是**引导层**（`apexBootstrapClient`/`apexBootstrapResult`，7.2.4 为 0） |
| 「7.3.1 的 OpenWrt 包还没拿到」 | **官方已提供**：`update.latest.openwrt = https://dl.pbbapi.rundingtai.com/apps/fb/fbapp-openwrt-speed.zip`（187,204,025 B，SHA-256 `C20BBB49…`，6 个 7.3.1 包）。已解包复核 |

### 新增：7.3.1 路由器端实测（§7.6）

`fnapp-openwrt-speed-24.10-7.3.1-…-armv7.ipk` → `usr/bin/apex_ua_net_fbcl_bfd4eda921e8`（56,883,770 B）：

| 符号 | 7.2.4 | 7.3.1 |
|---|---|---|
| `apexopenwrt` / `OpenAPXS` / `key32` / `RouterConfig` | 272 / 1 / 1 / 2 | **306 / 2 / 1 / 2** |
| `transport/apex` / `outbound.Apex` | 0 / 0 | **482 / 12** |
| `apexBootstrapClient` / `apexBootstrapResult` | 0 / 0 | **9 / 4** |
| `apexDohMTLS` / `apexDohIdentityState` | 1 / 4 | 1 / 4 |

→ **路由器端 APXS 解密器在 7.3.1 保留**，且自带引导层，是目前最好的离线 oracle。

### 新增：配置签名策略回归测试

`tests/test_config_sig.py`（已进 CI）覆盖审查里指出的绕过点：

```
正确签名 -> verified     全零签名 -> 拒绝        篡改 payload -> 拒绝
非 64 字节 -> 拒绝       旧格式(无签名) -> absent  错公钥 -> 拒绝
```

> 说明：审查提到的「全零签名仍被接受」发生在 `5c1d832`（首版无签名校验）。
> `3bd120d2` 起改为默认拒绝（退出码 3），`62577e82` 起用 k3 真验签，实测 `verified — builtin`。

### 新增：私有 DoH 探测工具（非生产）

`tools/windows/node_dns_probe.py`：从订阅 `dns.proxy-server-nameserver` 取私有 DoH，
按 GET(json) / POST(wireformat) × 证书组合探测解析。**明确标注为探测工具**——
截至本版，本网络对该端点不可达，仓库不提供"自动解决节点超时"的实现。

## [1.4.2] - 2026-11-23

### 定稿：APXS v2 参数完全对上（tag + 签名都验通）

之前 84 组签名、450 组 tag 全部失败，**不是算法不对，是两处字符串编码漏了**：

| 环节 | 正确参数 |
|---|---|
| 签名 | `Ed25519(k2, "apex-sub-sign-v2\0" ‖ body[0:L-64])` |
| 加密 | `AES-256-GCM(k1, nonce=body[13:25])`，数据段 = `CTR(nonce‖0x00000002)` |
| tag | `body[L-80:L-64] = GCM(k1, nonce, ct, AAD)` |
| **AAD** | **`"apex-sub-v2\0" ‖ body[0:25]`（37 B，不是空）** |

Dart 侧前缀是运行时拼接（`"apex-sub-sign-"` + `"v2"` + `"\0"`），那个 `\0` 被算进了消息与 AAD。
补上后，**两个真实信封**（nonce/tag/sig 全不同）的 tag 与签名逐字节验通。

### 新增

- `src/apxs_verify.py`：完整校验器（GCM tag + Ed25519 签名 + 解密），`--json` 可进 CI
- `tests/test_apxs_verify.py`：构造→校验→解密，外加篡改 tag / 篡改签名 / 过短信封三种拒绝用例
- `src/apex_fetch.py`：下载后**强制校验**，验不过拒绝发布（`APXS_VERIFY=0` 可关，不建议）
- `tools/windows/fetch_config.py`：配置签名改用 **k3** + `"apex-config-v1\0" + payload(解码后)`，
  默认严格，验不过退出码 3（实测 `verified — builtin`）

### 修正

- `docs/04 §4.8`「它不是 GCM」→ **它就是标准 AES-GCM**，数据段与 CTR 同流；
- README 协议速览补齐：GCM tag、AAD、签名前缀 NUL；
- `k3` 的用途由「OSS 模式密钥」更正为 **配置签名公钥**（Dart `ConfigSignature.verifyWithProvenance` 引用）；
- 新增 §9「验证链补测」，把否定结果与最终参数一并留档。

## [1.4.1] - 2026-11-23

### 修正：`fetch_config.py` 达到"可进自动服务"的标准

上一版把可用路径换坏了，也把不安全默认留在了脚本里。本次按三条硬约束重写：

| 约束 | 上一版 | 现在 |
|---|---|---|
| TLS | `check_hostname=False` + `CERT_NONE`（全局关校验） | **默认系统根 + 主机名校验**；仅 `--allow-expired`（只容忍错误码 10）或 `--insecure` 可继续，且记录叶子证书 SHA-256 |
| 配置签名 | 完全没验 | 出现 `signature` 时**默认拒绝产出**（退出码 3）；`--sign-pubkey` 可注入公钥，`--allow-unverified-signature` 才显式放行 |
| 解析 | 写死当时 DoH 解析出的 IP | **只写主机名**；系统 DNS → DoH 兜底；固定落点走 `--resolve HOST:IP`，代码里无地址常量 |

### 修正：配置镜像的 TLS 事实

| 镜像 | 叶子证书 | 有效期 | 严格校验 |
|---|---|---|---|
| `apisa-ax.cnossfile.com` | `*.cnossfile.com`（LE E7） | 2026-03-31 → **2026-06-29（已过期）** | ✗ code=10 |
| `tcdn-ax.getxlx.com` | `*.getxlx.com`（LE YR2） | 2026-10-27 → 2027-01-25 | ✓ 200 / 7244 B |

**并更正上一版的说法**：「系统 DNS 被污染、要用 DoH 换 IP」不成立——`tcdn-ax` 走系统 DNS
直接 200，用 DoH 换到另一个边缘反而 404。已从报告正文删除该结论。

### 新增：私有 DoH 入口定位

订阅的 `dns.proxy-server-nameserver` 里就是节点解析入口：

```yaml
- "https://fbcg02.web.ak005.com/api-v2/<per-fetch-token>"   # 每次 download 轮换
```

与内核 `dns.apexBootstrapClient` + `purpose=doh` 身份对应。本网络实测：一次 404 伪装页、
多次 TCP 超时（`103.239.185.80:443`），**入口已知但不可达**，只能作为已知项记录。

### 新增：验证链深度补测（§9）

- `aotopsy signal` 反汇编 39,215 个 Dart 函数（BLR 注释 97.4%），拿到 `BoardDecryptHelper.open`
  的完整调用链：`isEnvelope → getUint32 ×2 → base64Decode ×2 → Ed25519.verify → AesGcm.decrypt`；
- 用真实信封（35,173 B）证伪：签名 84 组、GCM tag 450 组、16 B 摘要 14 组**全部不匹配**，
  而 CTR 解密 + 官方内核校验通过；
- `docs/04 §4.8`「它不是 GCM」已加复核横幅，结论降级为"代码路径存在、参数待运行时确认"。

## [1.4.0] - 2026-11-23

### 客户端 7.3.1：协议未变，节点面换代

Windows 安装包（`fbapp-speed.exe`，65,009,528 B）解包后为 **7.3.1**（`Apex.exe 7.3.1+1794563169`），
Android APK 同步 7.3.1（versionCode `1794563093`，targetSdk 36）。逐项回归：

| 检查项 | 结果 |
|---|---|
| `k1 / k2 / k3` | **未变**（偏移随快照重排） |
| APXS v2 信封 | **未变**：线上 35,173 B → 明文 35,068 B，`aesID=1 signID=1` |
| mTLS 身份（api/subscription/oss） | **未轮换**，指纹与 7.2.3 一致（RSA **3072**） |
| 节点类型 | **vless+vision → anytls**（74 个，单域名 + 14301–14400 + 每节点随机 SNI） |
| 规则数 | 14 → **111** |
| 配置入口 | `/apos/fb_apex.json` → **`/apos/fb_apexv2.json`** |
| 配置门禁 | **必须 oss 用途证书**（api/subscription 一律 404） |
| 配置信封 | 新增 **`signature`**（64 B）字段 |
| 内核 | 61 MB / mihomo **v1.19.33**，新增私有 `transport/apex`（376 符号） |
| 组件完整性 | 新增 `apex-windows-components.json`（99 文件 sha256 + core/wintun 哈希） |
| 身份集 | 3 → **4**（Go 内核新增 `purpose=doh`） |

### 新增

- `tools/windows/unpack_installer.ps1`：Inno Setup 静默解包 → 文件清单 → 一键还原
- `tools/windows/verify_build.py`：常量 / 标记 / mTLS 证书 / APXS 往返 / 组件清单的机器可读回归
- `tools/windows/fetch_config.py`：oss 证书拉 `fb_apexv2.json`，用已知明文反推 XOR 键并解码
- `reports/11-7.3.1-更新差异与协议回归.md`：完整差异、门禁矩阵与线上实测
- CI 语法检查覆盖 `tools/windows/*.py`

### 修正

- **配置 CDN 需要 oss 证书**：旧记录「oss 主机 500，拿不到配置」实为缺证书
  （api/sub 证书一律 404，oss 证书才 200）
- **证书位长**：基线报告写 RSA-2048，实测三张均为 **RSA-3072**
- **v1 明文线路**：7.3.1 部署上登录 200，但订阅口 `403 token is error`、
  `subscribe_url` 指向占位域名 → 已下线（见 `docs/09`）
- `DEFAULT_UA` 升至 `ua.net.fbclient.app.apex/7.3.1`

### 实测

```
v2 登录 200 → access-token 200(1,690B) → download 200(35,173B, APXS)
解密  aesID=1 signID=1  明文 35,068B → 74 anytls / 3 分组 / 111 规则
官方内核  ApexCore.exe -t -f sub.yaml → test is successful (583ms)
```

## [1.3.0] - 2026-10-28

### 重要修正：v1 明文接口并未关闭

之前文档写着「v1 接口 → 403 `{code:403102}`，已关闭」——**错了**。
当时测的是 `fbesa.*` 主机且没带客户端证书。实测结果：

```
POST {API}/api/v1/passport/auth/login      api 证书                  → token
GET  {API}/api/v1/client/subscribe?token=  api 证书 + apex UA        → 明文 URI（18 KB）
```

放行条件：**api 证书 + apex UA + `fbaxapi.*` 主机**，缺一即 404 伪页。
`flag=clash/v2ray/...` 全部无效（只输出一种格式）。

### 两条线路对照

| | v2（主线路） | v1（遗留） |
|---|---|---|
| 证书 / 主机 | subscription / `fbaxsub.*` | **api** / `fbaxapi.*` |
| 响应 | APXS（需解密） | **明文 URI** |
| 节点 | 74 × vless + vision | 74 × trojan + 74 × ss |
| 域名 | `fbapp-*.llguanglisf.com` | `*.6pzftj.com` / `*.6pzfwf2511.com` |
| 端口 | 10301–10400 | 443 / 11011 |
| SNI | 固定 `aws.amazon.com` | 每节点随机子域 |

**节点集完全不重叠**（域名交集 0），是两批不同基础设施。v1 用 `aes-256-cfb` + 全局共享密码，
属上一代协议，更像为老客户端保留的兼容线路。

### 新增

- `src/v1_legacy.py`：v1 明文解析（trojan / ss，兼容 SIP002 与旧式 base64）、Clash 渲染、合并
- `apex_fetch.py --source v2|v1|both`（也支持配置项 `SOURCE=`）
- `tests/test_v1_parse.py`：离线单测（解析 / 渲染 / 合并 / 异常输入）
- `docs/09-v1-legacy-endpoint.md`：双线路深度对照
- Worker 同步支持 `?source=v2|v1|both`
- `deploy/` 与 `.env.example` 新增 `SOURCE` 配置

### 修正

- `docs/03-api-and-mtls.md`：更正 v1 接口的旧结论，补充放行矩阵
- README：新增双线路对照表与三条线路的用法

## [1.2.0] - 2026-10-27

### 新增

- **GitHub Actions 定时抓取**：`.github/workflows/fetch.yml`，cron 每 6 小时，
  凭据全部走 secrets，任务结束清理证书；默认不产出可下载产物（防公开仓库泄露）
- **Cloudflare Worker 边缘部署**：`workers/apex-fetch/`
  - `POST /decode`：传 APXS 直接返回 YAML（k1 为公开常量，不需账号）
  - `GET /sub?token=`：KV 缓存 + 过期刷新 + 失败回退
  - Cron 每 6 小时自动刷新
  - 依赖 Workers 的两项能力：**出站 mTLS**（`mtls_certificates`）与 **AES-CTR**（WebCrypto）
- **WebCrypto 验证脚本**：`tools/verify_webcrypto.mjs`，与官方明文逐字节比对
- **文档**：`docs/08-serverless.md`

### 验证

```
$ node tools/verify_webcrypto.mjs apxs.bin plain.bin
aesId=1 signId=1 密文=26806 明文=26806
首行: mixed-port: 7890
与官方明文逐字节一致: true
```

## [1.1.0] - 2026-10-27

### 新增

- **Docker 部署**：非 root 镜像（`python:3.12-slim`）、rootfs 只读、`cap_drop: ALL`、内置健康检查
- **GHCR 发布工作流**：打 tag 自动构建并推送 `ghcr.io/angel-gril/apex-fetch`，支持 amd64 + arm64
- **README 重构**：对齐社区风格，补齐徽章、目录导航、FAQ 与社区友链

### 验证：客户端 7.2.5 更新对本项目的影响

官方 7.2.5（2026-10-27 发布）更新日志：

1. 优化虚拟网卡安装及使用，解决 codex 等应用不能代理问题
2. 新增校园网模式，解决校园网不可使用问题
3. 优化节点选择页面
4. 优化代理类型说明

**结论：对协议无影响，无需调整。** 依据：

| 检查项 | 结果 |
|---|---|
| 服务端 APXS 信封 | `aesID=1`、`signID=1`，与之前一致 |
| 内置常量 k1 解密 | 成功，74 节点 / 3 分组 / 14 规则 |
| 新版 APK（7.2.5，当日构建） | `k1/k2/k3` 与 `apex-sub-sign-v2` 均存在且未变 |
| 新版 OpenWrt 包 | `fnapp-openwrt-speed-24.10-7.2.5-...ipk`，arm64 二进制体积与 7.2.4 完全一致（44,203,810 B） |
| 更新日志内容 | 全部为客户端侧（虚拟网卡 / 校园网 / UI） |

验证命令：

```bash
python3 src/apex_fetch.py --config /etc/apex-fetch/config --test
# 登录成功 → 下载 → 解密成功 aesID=1 → 74 节点
```

## [1.0.0] - 2026-10-27

### 完成

- **协议还原**：确认 APXS v2 信封结构（13B 头 + 12B nonce + 密文 + 16B 校验 + 64B 签名）
- **算法还原**：确认加密为 **AES-256-CTR**（GCM 计数器派生 `nonce||0x00000002`），
  尾 16 字节非标准 GCM tag；密钥为客户端内置常量
- **密钥捕获**：通过 Go pclntab 符号恢复 + gdb 断点，抓到 `key32` / `OpenAPXS` 真实入参与返回明文
- **纯协议实现**：`src/apex_fetch.py`，零第三方依赖，单次 8 秒
- **服务化**：systemd oneshot + timer + 原子发布 + 失败不覆盖
- **四路线文档**：Windows 内存 / Linux netns 内存 / gdb 断点 / 纯协议

### 推翻的结论（保留记录）

- ~~密钥由服务端按部署下发~~ → 客户端全流程无配置拉取仍可解密，密钥在二进制内
- ~~APXS 是标准 AES-GCM AEAD~~ → 只借用 GCM 计数器流，无 AAD
- ~~订阅接口对海外 IP 地域封锁~~ → 实为缺 UA / 缺证书导致的 404 伪装

### 事故与教训

- 在非 OpenWrt 宿主上直接运行该客户端会劫持宿主出站流量（nftables + ip rule），
  导致 SSH/nginx 失联 → 后续全部改为 netns 隔离
- `pkill -f` 会匹配到 SSH 自身命令行 → 使用 `[x]` 括号技巧

## [0.9.0] - 2026-10-26

- 首次完成 mTLS 证书 purpose 分层验证（api / subscription / oss）
- 拿到 200 APXS，确认客户端走解密链路（SNI 实证）
- 内存提取路线跑通，74 节点

## [0.5.0] - 2026-10-25

- Flutter AOT 反编译（Blutter），确认 Ed25519 验签与前缀 `apex-sub-sign-v2`
- 内置常量穷举（7 万+ 组合）失败，记录否证
- AES-NI 内存密钥扫描器（562MB × 6 布局，0 命中）

## [0.1.0] - 2026-10-24

- 样本定性：Windows(Inno Setup+Flutter+mihomo) / Android / Linux / OpenWrt(Go)
- 站点与 API 测绘，发现 404 伪装机制
