<div align="center">
  <img src="docs/images/logo.svg" width="96" alt="FlyBird-ProtocolAnalysis">

  <h1>FlyBird-ProtocolAnalysis</h1>

  <p>
    <strong>飞鸟 / Flutter 客户端协议分析与订阅提取</strong><br>
    APXS v2 信封逆向 · mTLS 证书体系测绘 · 四条提取路线 · 纯协议 8 秒复现
  </p>

  <p>
    <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-MIT-blue?style=flat-square"></a>
    <a href="NOTICE-LEGAL.md"><img alt="Usage" src="https://img.shields.io/badge/usage-authorized%20research-orange?style=flat-square"></a>
    <img alt="Platform" src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20Android%20%7C%20OpenWrt-334155?style=flat-square">
    <img alt="Client" src="https://img.shields.io/badge/client-7.2.3%20~%207.2.5-0b7285?style=flat-square">
    <img alt="Runtime" src="https://img.shields.io/badge/runtime-2026.10.27--r1-6b7280?style=flat-square">
    <a href="https://github.com/Angel-Gril/FlyBird-ProtocolAnalysis/actions/workflows/ci.yml"><img alt="CI" src="https://img.shields.io/github/actions/workflow/status/Angel-Gril/FlyBird-ProtocolAnalysis/ci.yml?style=flat-square&label=ci"></a>
  </p>

  <p>
    <a href="#快速开始"><strong>快速开始</strong></a> ·
    <a href="#功能特性">功能特性</a> ·
    <a href="#协议速览">协议速览</a> ·
    <a href="#四条路线">四条路线</a> ·
    <a href="#工作原理">工作原理</a> ·
    <a href="#工具链">工具链</a> ·
    <a href="#常见问题">常见问题</a> ·
    <a href="#社区交流">社区交流</a>
  </p>
</div>

---

> 仅用于**授权范围内的安全研究**与互通性研究。详见 [NOTICE-LEGAL.md](NOTICE-LEGAL.md)。

## 📖 简介

FlyBird-ProtocolAnalysis 是一套面向**多平台代理客户端**的协议逆向工程，用于回答一个问题：

> 当订阅解密完全发生在客户端本地时，防御的边界到底在哪里？

目标客户端把订阅以 **APXS v2** 信封下发，解密后才是标准 Clash/mihomo YAML。
官方只提供 GUI，没有公开格式与协议，文档明确写道：

> 账号密码、登录 Token 和节点**只在内存中使用**，不写入配置文件或缓存。

本项目完整还原了信封格式与加密算法，并给出**四条从"内存取证"到"纯协议"**的提取路线，
最终产物是一个 **8 秒、零依赖**的纯 Python 实现，以及配套的 systemd / Docker 部署方案。

## ✨ 功能特性

| 能力 | 说明 |
|---|---|
| 🔐 **APXS v2 解密** | 纯本地解密，`AES-256-CTR` + 内置常量，逐字节与官方输出一致 |
| 🧭 **四条提取路线** | Windows 内存 / Linux netns 内存 / gdb 断点 / 纯协议，全部可运行 |
| 🧩 **Go 符号恢复** | 自写 pclntab 解析器，剥符号的 Go 二进制也能定位函数地址 |
| 🎯 **gdb 断点取证** | 抓 `key32` / `OpenAPXS` 真实入参与明文返回值，可复现 |
| 🛰 **TLS 观察代理** | 自签 CA + DNAT + 转发，完整记录客户端真实请求序列 |
| 🧯 **netns 隔离** | 客户端自带 nftables 编排，隔离运行不污染宿主网络 |
| 🚀 **生产可用** | systemd oneshot + timer、Docker 非 root 镜像（GHCR 多架构）、原子发布、失败不覆盖 |
| 🧪 **CI 自检** | 语法检查 + CTR 往返 + APXS 构造→解密 + 敏感串扫描 + 镜像构建 |
| 📚 **完整文档** | 7 篇深度分析 + 20 篇过程报告（含失败记录与事故复盘） |

## 🧩 协议速览

```
偏移        长度   内容
[0:4]       4     "APXS"
[4]         1     版本 = 0x02
[5:9]       4     BE u32 aesKeyID     （实测恒为 1）
[9:13]      4     BE u32 signKeyID    （实测恒为 1）
[13:25]     12    nonce
[25:...]    n     AES-256-CTR 密文
尾部        16    校验块（不是标准 GCM tag）
            64    Ed25519 签名
```

```python
ctr = Counter.new(32, prefix=nonce, initial_value=2, little_endian=False)
plain = AES.new(k1, AES.MODE_CTR, counter=ctr).decrypt(ct)
```

内置常量（互通性研究所必需，已在 [docs/04](docs/04-apxs-v2-format.md) 完整说明还原过程）：

| 名称 | 值 | 用途 |
|---|---|---|
| `k1` | `fCA3jkvhXpLEpDVuqPstNUS/kXewk7yGL5o8Fbh3uSc=` | AES-256 密钥 |
| `k2` | `lmzs43izW9GHIOOq+avbwhWh0TG/ldT3kipGkrQ4RiE=` | Ed25519 公钥 |
| `k3` | `xZ//fP0AfP+8yW4OAZOrcKHe7dO78+Gpwu1ewno/fd8=` | OSS 模式密钥 |

**为什么值得记一笔**：按标准 GCM AEAD 去解，2500+ 种 AAD 全部验签失败；
真相是这个实现**只借用了 GCM 的计数器流**，尾部 16 字节根本不是 tag。

## 🚀 快速开始

三种方式，任选一种：

| 方式 | 适合 | 需要 root |
|---|---|---|
| **A. Docker** | 新机器、不想污染系统 | ❌ |
| **B. systemd** | 长期驻留的服务器 | ✅ |
| **C. 直接运行** | 临时验证 | ❌ |
| **D. Cloudflare Worker** | 多设备共享一个 URL | ❌ |
| **E. GitHub Actions** | 定期归档 / CI 集成 | ❌ |

> 三种方式都需要 **4 个证书文件**——它们是**本机设备身份**，从你自己已安装的客户端目录导出：
>
> ```
> profile5_api_client.{crt,key}.pem          → api.crt / api.key
> profile5_subscription_client.{crt,key}.pem → sub.crt / sub.key
> ```

### A. Docker（推荐）

```bash
# 直接用现成镜像（amd64 / arm64）
docker pull ghcr.io/angel-gril/apex-fetch:latest

# 或用仓库里的 compose 自行构建
cd deploy
mkdir -p certs output
cp api.crt api.key sub.crt sub.key certs/
cp .env.example .env && chmod 600 .env   # 填账号
docker compose up -d --build
cat output/sub.yaml
```

单次运行（cron / k8s Job）：

```bash
docker run --rm \
  -v $PWD/certs:/certs:ro -v $PWD/output:/output \
  -e APEX_EMAIL=... -e APEX_PASSWORD=... -e ONCE=1 \
  ghcr.io/angel-gril/apex-fetch:latest
```

### B. systemd

```bash
sudo ./deploy/install.sh /path/to/certs
sudo systemctl start apex-fetch.service
/opt/apex/apex-fetch.sh status
```

### C. 直接运行

```bash
cp samples/config.sample /etc/apex-fetch/config
chmod 600 /etc/apex-fetch/config
python3 src/apex_fetch.py --config /etc/apex-fetch/config --out sub.yaml
```

### D. Cloudflare Worker（无需服务器）

```bash
cd workers/apex-fetch
npx wrangler mtls-certificate upload --cert api.crt --key api.key --name apex-api
npx wrangler mtls-certificate upload --cert sub.crt --key sub.key --name apex-sub
npx wrangler kv namespace create SUBS   # 把 id 填进 wrangler.toml
npx wrangler secret put APEX_EMAIL
npx wrangler secret put APEX_PASSWORD
npx wrangler secret put ACCESS_TOKEN   # openssl rand -hex 24
npx wrangler deploy
```

然后：

```bash
curl -s "https://apex-fetch.<you>.workers.dev/sub?token=$ACCESS_TOKEN" -o sub.yaml
curl -s -X POST --data-binary @apxs.bin https://apex-fetch.<you>.workers.dev/decode
```

Workers 原生支持 **出站 mTLS**（`mtls_certificates` 绑定）与 **AES-CTR**（WebCrypto），
所以完整流程可以在边缘跑。详见 [workers/apex-fetch](workers/apex-fetch/README.md)。

### E. GitHub Actions（定时归档）

用 [`.github/workflows/fetch.yml`](.github/workflows/fetch.yml)：
填好 6 个 secret（账号 + 4 个证书 base64），每 6 小时跑一次。

> ⚠️ **公开仓库的 artifact 任何人可下载**，而订阅 YAML 含节点凭据。
> 请使用私有仓库，或配置 `PUBLISH_REPO` 推到私有仓库，
> 否则保持默认（不上传产物，只输出统计）。详见 [docs/08](docs/08-serverless.md)。

预期输出：

```
21:28:58 登录成功，access_key=***
21:29:00 账户：<account>  套餐=<plan>  已用=57.5GB  到期=***
21:29:02 下载成功：26853B
21:29:02 解密成功：aesID=1 signID=1 明文 26748B
21:29:02 校验通过：74 节点 / 3 分组 / 14 规则
21:29:02 已发布：sub.yaml（26748B）
```

### 卸载 / 回滚

```bash
systemctl disable --now apex-fetch.timer
rm -rf /opt/apex /etc/apex-fetch /var/lib/apex-fetch
```

## 🧭 四条路线

| 路线 | 原理 | 依赖 | 耗时 | 状态 |
|---|---|---|---|---|
| **A. Windows 内存** | 客户端解密后，读进程堆里的 YAML | Windows + 客户端 | ~10 s | ✅ 已验证 |
| **B. Linux netns** | 官方 OpenWrt 客户端跑在 netns 里，扫 `/proc/pid/mem` | Go 二进制 + netns | 25–45 s | ✅ 已验证 |
| **C. gdb 断点** | pclntab 定位函数，断点抓 key/nonce，dump 返回值 | 同上 + gdb | ~30 s | ✅ 已验证 |
| **D. 纯协议** | 复现 HTTPS 链路 + 本地 CTR 解密 | 仅 python3 | **~8 s** | ✅ 生产可用 |

路线的完整实现、失败尝试与教训见 [docs/05-approaches.md](docs/05-approaches.md)。

## ⚙️ 工作原理

```
① 登录          POST {API}/v2/auth/token            cert=api           → JWT + access_key
② 账户          GET  {API}/v2/feed/access-token     Authorization: <裸 JWT>
③ 下载          GET  {SUB}/v2/feed/download         cert=subscription  → APXS
④ 本地解密      AES-256-CTR(k1, nonce||0x00000002)
⑤ 校验发布      节点数/字段校验 → 原子替换 → 可选钩子
```

三个反直觉的门禁（缺一即 404 伪装页）：

| 条件 | 说明 |
|---|---|
| 客户端证书 **purpose 必须匹配** | api 证书只能打 `fbaxapi.*`，subscription 只能打 `fbaxsub.*` |
| `User-Agent` 必须正确 | `ua.net.fbclient.app.apex/<version>` |
| `Authorization` 是**裸 JWT** | 加 `Bearer ` 前缀反而失败 |

## 📊 关键发现

| # | 发现 |
|---|---|
| 1 | APXS v2 = **AES-256-CTR**，不是 GCM 的 AEAD 语义 |
| 2 | 密钥是**内置常量**，与账号无关 |
| 3 | **登录也要 mTLS**，不只是下载 |
| 4 | 证书按 purpose 绑定 vhost，混用一律 404 |
| 5 | UA 是第二道门禁，与证书缺一不可 |
| 6 | "明文不落盘"是唯一防线，但**防不住同机 root**（CWE-602） |
| 7 | 7.2.3 → 7.2.5 期间协议与常量**未变**（见 [CHANGELOG](CHANGELOG.md)） |

## 🗂 目录结构

```
.
├── docs/                     # 深度分析
│   ├── 01-overview.md            研究目标与方法论
│   ├── 02-client-architecture.md 四平台客户端形态
│   ├── 03-api-and-mtls.md        API 测绘与证书分层
│   ├── 04-apxs-v2-format.md      APXS 格式与算法还原全过程
│   ├── 05-approaches.md          四条路线
│   ├── 06-toolchain.md           Blutter/pclntab/gdb/netns/MITM
│   ├── 07-hardening-cwe602.md    厂商侧加固建议
│   └── 08-serverless.md          GitHub Actions / Cloudflare Worker 部署
├── reports/                  # 20 篇过程报告（已脱敏）
├── src/
│   ├── apex_fetch.py            纯协议抓取器（生产用）
│   ├── apxs_decrypt.py          APXS 解密库/CLI
│   ├── pclntab.py               Go 符号恢复
│   ├── extract_nodes.py         [备用] 内存提取节点
│   ├── hunt_yaml.py             [备用] 内存扫描明文
│   └── health_check.py          订阅健康检查
├── tools/
│   ├── mitm_observe.py          TLS 终止观察代理
│   ├── gdb/                     gdb 断点抓参与 dump 明文
│   ├── netns/                   隔离运行官方客户端
│   └── mem/aes_scan.c           [备用] AES-NI 密钥扫描内核
├── deploy/                   # systemd + Docker
├── workers/apex-fetch/       # Cloudflare Worker（边缘部署）
└── samples/                  # 脱敏样例
```

## 🛠 工具链

| 工具 | 用途 | 技巧 |
|---|---|---|
| **Blutter** | Flutter AOT 反编译 | 需匹配 Dart 引擎版本；Windows 编译不可行，用 Linux |
| **src/pclntab.py** | 剥符号 Go 二进制符号恢复 | 校验 magic + minLC + ptrSize，避免数据段误命中 |
| **gdb** | 断点抓入参/返回值 | Go ABI 寄存器传参；入口读返回地址下临时断点 |
| **netns** | 隔离运行自带防火墙编排的客户端 | 必须放行 FORWARD，否则 DNS 都出不去 |
| **mitm_observe.py** | 记录真实请求 | 自签 CA 只进测试进程的 mount namespace |
| **aes_scan.c** | 内存密钥扫描 | AES-NI key schedule 匹配，4.6M 窗口/秒 |

细节与踩坑见 [docs/06-toolchain.md](docs/06-toolchain.md)。

## ❓ 常见问题

<details>
<summary><b>为什么不直接改客户端二进制？</b></summary>

改二进制不可逆、抗升级差，而且一旦厂商换版本就要重做。
我们的路线是"让官方客户端自己解密，我们只读它的输出"，
或者更进一步——完全脱离客户端复现协议。
</details>

<details>
<summary><b>为什么不用中间人抓明文？</b></summary>

实测走不通：客户端有证书 pinning（内置 CA bundle），
且改 hosts 指向本地会形成环路（上游也解析到本地）。
最终改用"TLS 终止 + DNAT"观察，只用于记录请求，不用于提取明文。
</details>

<details>
<summary><b>7.2.5 更新了什么？会影响吗？</b></summary>

更新内容全部是客户端侧：虚拟网卡安装优化、校园网模式、节点选择 UI、代理类型说明。
服务端与协议未变——实测 `aesID=1`、k1 仍可解密、74 节点结构一致；
新版 APK 里 `k1/k2/k3` 与 `apex-sub-sign-v2` 均未变化。**不需要任何调整。**
</details>

<details>
<summary><b>证书过期了怎么办？</b></summary>

客户端升级会轮换证书。重新从客户端安装目录导出 4 个文件覆盖即可，
脚本与算法不需要改。若 `aesID` 不再是 1，则需按 [docs/04](docs/04-apxs-v2-format.md)
的流程重新抓一次常量。
</details>

<details>
<summary><b>可以在路由器上跑吗？</b></summary>

可以。官方 OpenWrt 包本身就是无界面的 mihomo，用 `tools/netns/run.sh` 的同一套
控制口协议即可；注意它要求 tmpfs 运行目录且必须关闭 swap。
</details>

## 💬 社区交流

本开源项目已链接并认可 [LINUX DO 社区](https://linux.do/)。

[![LINUX DO](docs/images/linuxdo.png)](https://linux.do/)

LINUX DO — 新的理想型社区。

欢迎 issue / PR：补充其他平台、改进解密实现、完善文档。
请**不要**提交任何真实凭据、节点信息或用于攻击的代码。

## 📄 许可

[MIT](LICENSE) · 使用前请阅读 [NOTICE-LEGAL.md](NOTICE-LEGAL.md)

---

<div align="center">
  <sub>Built for authorized security research · 仅用于授权范围内的安全研究</sub>
</div>
