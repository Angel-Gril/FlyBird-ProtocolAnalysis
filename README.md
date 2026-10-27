# FlyBird / 飞鸟 极速版 · 客户端协议分析与订阅提取

> 一个完整的、可复现的客户端逆向与协议复现工程。
> 覆盖 **Flutter/Dart AOT、Go、Inno Setup、OpenWrt 定制内核** 四种形态，
> 完整还原 **APXS v2 订阅信封的加密算法**，并给出 **四条提取路线** 与 **纯协议实现**。

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20Android%20%7C%20OpenWrt-blue)
![status](https://img.shields.io/badge/status-research-green)

---

## ⚠️ 免责声明

本项目**仅用于授权范围内的安全研究**：分析自己在合法订阅下的客户端、
验证客户端安全控制（CWE-602）是否有效、以及做互通性（interoperability）研究。

- 仓库内**不包含**任何真实账号密码、客户端私钥、订阅凭据或节点信息；
- 所有示例数据均为占位符；
- 请勿用于未授权访问他人服务、绕过付费或二次分发他人订阅。

详见 [NOTICE-LEGAL.md](NOTICE-LEGAL.md)。

---

## 一、这个项目解决了什么

客户端把订阅以 **APXS v2** 格式下发，内部是加密的 Clash/mihomo YAML。
官方只提供 GUI 客户端，没有公开格式与协议。本项目：

1. **完整测绘**了服务端 API 与 mTLS 证书体系（含 404 伪装机制）；
2. **完整还原**了 APXS v2 信封与加密算法（AES-256-CTR + 内置密钥）；
3. **实现了四条提取路线**，覆盖从"内存取证"到"纯协议"的全部层次；
4. 给出**可运维的服务化方案**（systemd + 定时刷新 + 原子发布）。

最终形态：**8 秒、零依赖、纯 Python 标准库**，从登录到拿到 74 节点的完整 YAML。

```
$ python3 src/apex_fetch.py --config /etc/apex-fetch/config --out sub.yaml
21:28:58 登录成功，access_key=***
21:29:00 账户：<account>  套餐=<plan>  已用=57.5GB  到期=***
21:29:02 下载成功：26853B
21:29:02 解密成功：aesID=1 signID=1 明文 26748B
21:29:02 校验通过：74 节点 / 3 分组 / 14 规则
21:29:02 已发布：sub.yaml（26748B）
```

---

## 二、核心发现（TL;DR）

| # | 发现 | 说明 |
|---|---|---|
| 1 | **APXS v2 = AES-256-CTR** | 不是 GCM 的 AEAD 语义，只借用其计数器流；尾部 16B 不是 GCM tag |
| 2 | **密钥是内置常量** | `k1` 作 AES key、`k2` 作 Ed25519 公钥、`k3` 给 OSS 模式 |
| 3 | **登录也要 mTLS** | `/v2/auth/token` 无客户端证书 → 404 伪装页 |
| 4 | **证书按 purpose 绑 vhost** | api 证书只能打 `fbaxapi.*`，subscription 证书只能打 `fbaxsub.*` |
| 5 | **UA 是第二道门禁** | 缺 `ua.net.fbclient.app.apex/vX` 一律 404，与证书缺一不可 |
| 6 | **JWT 是裸传的** | `Authorization: <jwt>`，**不带** `Bearer ` 前缀 |
| 7 | **"明文不落盘"是唯一防线** | 客户端不写 config.yaml，但明文在进程堆里，root 可读 |
| 8 | **每设备独立证书** | 客户端安装目录内自带 `profile5_{api,subscription,oss}_client.{crt,key}` |

---

## 三、APXS v2 信封

```
偏移        长度   内容
[0:4]       4     "APXS"
[4]         1     版本 = 0x02
[5:9]       4     BE u32 aesKeyID     （实测恒为 1）
[9:13]      4     BE u32 signKeyID    （实测恒为 1）
[13:25]     12    nonce
[25:...]    n     AES-256-CTR 密文
尾部        16    校验块（**不是** 标准 GCM tag）
            64    Ed25519 签名（覆盖 "apex-sub-sign-v2" + 头部+密文）
```

解密：

```python
ctr = Counter.new(32, prefix=nonce, initial_value=2, little_endian=False)
plain = AES.new(k1, AES.MODE_CTR, counter=ctr).decrypt(ct)
```

内置常量（来自客户端二进制，供互通性研究）：

| 名称 | 值 | 用途 |
|---|---|---|
| `k1` | `fCA3jkvhXpLEpDVuqPstNUS/kXewk7yGL5o8Fbh3uSc=` | APXS AES-256 密钥 |
| `k2` | `lmzs43izW9GHIOOq+avbwhWh0TG/ldT3kipGkrQ4RiE=` | Ed25519 公钥 |
| `k3` | `xZ//fP0AfP+8yW4OAZOrcKHe7dO78+Gpwu1ewno/fd8=` | OSS 模式密钥 |

> 还原过程见 [docs/04-apxs-v2-format.md](docs/04-apxs-v2-format.md)：
> 为什么 7 万种组合全部失败，最后靠 **pclntab + gdb + 已知明文反推** 一击命中。

---

## 四、四条提取路线

| 路线 | 原理 | 依赖 | 耗时 | 状态 |
|---|---|---|---|---|
| **A. Windows 内存** | 官方客户端解密后，读进程堆里的 YAML | Windows + 客户端 | ~10 s | ✅ 已验证 |
| **B. Linux 内存** | 官方 OpenWrt 客户端跑在 netns 里，扫 `/proc/pid/mem` | Go 二进制 + netns | 25–45 s | ✅ 已验证 |
| **C. gdb 断点** | pclntab 定位函数，断点抓 key/nonce，dump 返回值 | 同上 + gdb | ~30 s | ✅ 已验证 |
| **D. 纯协议** | 复现 HTTPS 链路 + 本地 CTR 解密 | 仅 python3 | **~8 s** | ✅ 生产可用 |

四条路线的完整实现、失败尝试与教训：[docs/05-approaches.md](docs/05-approaches.md)

---

## 五、快速开始（纯协议）

### 1. 准备证书

从**你自己**已安装的客户端目录取 4 个文件（这是本机设备身份）：

```
profile5_api_client.crt.pem           → api.crt
profile5_api_client.key.pem           → api.key
profile5_subscription_client.crt.pem  → sub.crt
profile5_subscription_client.key.pem  → sub.key
```

### 2. 配置

```bash
cp samples/config.sample /etc/apex-fetch/config
chmod 600 /etc/apex-fetch/config
$EDITOR /etc/apex-fetch/config     # 填账号密码与证书路径
```

### 3. 跑

```bash
python3 src/apex_fetch.py --config /etc/apex-fetch/config --out sub.yaml
```

### 4. 做成服务

```bash
sudo ./deploy/install.sh /path/to/certs
sudo systemctl start apex-fetch.service
/opt/apex/apex-fetch.sh status
```

---

## 六、目录结构

```
.
├── docs/                     # 深度分析文档
│   ├── 01-overview.md            研究目标与方法论
│   ├── 02-client-architecture.md 四平台客户端形态逆向
│   ├── 03-api-and-mtls.md        API 测绘、证书分层、404 伪装
│   ├── 04-apxs-v2-format.md      APXS 格式与算法还原全过程
│   ├── 05-approaches.md          四条路线对比与实现
│   ├── 06-toolchain.md           工具链：Blutter/capstone/pclntab/gdb/netns/MITM
│   └── 07-hardening-cwe602.md    厂商侧加固建议
├── reports/                  # 过程中的原始分析报告（已脱敏）
├── src/                      # 可运行代码
│   ├── apex_fetch.py             纯协议抓取器（生产用）
│   ├── apxs_decrypt.py           APXS 解密库/CLI
│   ├── pclntab.py                Go 符号恢复（剥符号二进制）
│   ├── extract_nodes.py          [备用] 内存提取节点
│   ├── hunt_yaml.py              [备用] 内存扫描明文 YAML
│   ├── health_check.py           订阅健康检查
│   └── cert_matrix.py            mTLS 证书 purpose 矩阵探测
├── tools/
│   ├── mitm_observe.py           TLS 终止观察代理（记录真实请求）
│   ├── gdb/                      gdb 断点抓参与 dump 明文
│   ├── netns/                    隔离运行官方 OpenWrt 客户端
│   └── mem/aes_scan.c            [备用] AES-NI 密钥扫描内核
├── deploy/                   # systemd 服务化
├── samples/                  # 脱敏样例配置
└── CHANGELOG.md
```

---

## 七、时间线（研究过程）

| 阶段 | 关键动作 | 结果 |
|---|---|---|
| 1 | 样本定性：Flutter AOT / Go / Inno Setup | 四平台客户端同源同协议 |
| 2 | 站点与 API 测绘 | 发现 404 伪装、UA 门禁 |
| 3 | 抓取局域网 TLS | 环路 + pinning，MITM 失败 |
| 4 | Blutter 反编译 Dart | 确认 APXS 信封与 Ed25519 验签 |
| 5 | 内置常量穷举 | 7 万+ 组合全败 |
| 6 | 内存密钥扫描（AES-NI） | 562MB × 6 布局，0 命中 |
| 7 | mTLS 证书分层 | 拿到 200 APXS，确认客户端走解密链路 |
| 8 | OpenWrt 客户端 + netns | 拿到明文 YAML（74 节点） |
| 9 | pclntab + gdb | 抓出真实 key/nonce，确认 AES-256-CTR |
| 10 | 纯协议实现 | 8 秒出配置，生产上线 |

---

## 八、贡献与联系

欢迎 issue / PR：补充其他平台、改进解密实现、完善文档。
请勿提交任何真实凭据、节点信息或用于攻击的代码。

---

## License

MIT，见 [LICENSE](LICENSE)。
