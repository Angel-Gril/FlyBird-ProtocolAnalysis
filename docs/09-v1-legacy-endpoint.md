# 09 · 遗留明文线路（v1）与双线路对照

> 这是本项目最重要的一次修正：我们最初认为 v1 接口已关闭（403 `{code:403102}`），
> 实际上**它在另一组主机上、用另一张证书、配同一个 UA 是通的**，并且**返回明文**。
>
> 本文把两条线路的放行条件、数据结构、节点集差异、以及安全含义一次说清。

---

## 9.1 两条线路并存

| | **v1（遗留）** | **v2（主线路）** |
|---|---|---|
| 登录 | `POST {API}/api/v1/passport/auth/login` | `POST {API}/v2/auth/token` |
| 取订阅 | `GET {API}/api/v1/client/subscribe?token=` | `GET {SUB}/v2/feed/download?access_key=` |
| 主机 | `fbaxapi.*` | `fbaxsub.*` |
| 客户端证书 | **api** | **subscription** |
| UA | `ua.net.fbclient.app.apex/<ver>` | 同左 |
| 响应 | `text/plain`，明文 URI | `application/octet-stream`，**APXS** |
| 加密 | **无** | AES-256-CTR + Ed25519 |
| 节点 | 74 trojan + 74 ss（+1 提示行） | 74 vless |

**同一个 access_key 对两条线路都有效**，只是证书与主机不同。

## 9.2 放行矩阵（实测）

### 证书维度（v1 订阅）

| 证书 | 结果 |
|---|---|
| api | ✅ 200，18,027 B 明文 |
| subscription | ❌ 404 伪页 |
| 无证书 | ❌ 404 伪页 |

### UA 维度（v1 订阅，带 api 证书）

| UA | 结果 |
|---|---|
| `ua.net.fbclient.app.apex/v7.2.5` | ✅ 200 |
| `v2rayN/6.31` | ❌ 404 |
| `clash-verge/v1.7.7` | ❌ 404 |
| `mihomo/1.19.0` | ❌ 404 |
| `ClashforWindows/0.20.39` | ❌ 404 |
| `curl/8.5.0` | ❌ 404 |
| 无 UA | ❌ 404 |

**只认自己的 UA**，不是"任意客户端都能拿"。

### 主机维度

| 主机 | v1 路径 | v2 路径 |
|---|---|---|
| `fbaxapi.*` | ✅ 200（api 证书） | ❌ 404 |
| `fbaxsub.*` | ❌ 404（两种证书都试过） | ✅ 200（sub 证书） |

### `flag` 参数

`flag=clash / v2ray / ss / surge / singbox` **全部无效**，返回内容完全一致（18,027 B 明文）。
说明该部署的 v1 分支只输出一种格式，不理会通用订阅参数。

## 9.3 v1 响应结构

```
# remaining: 105055509255
# expire_at: 2027-02-11T10:32:15Z
trojan://<uuid>@k8zq2nld9wfx3vyu7tmb-hk.6pzftj.com:443?sni=<sni>&allowInsecure=1#Hong+Kong-01
...
ss://<base64>

合计：153 行 = 2 行注释 + 74 条 trojan + 74 条 ss + 1 条「单端口承载」提示
```

关键特征：

| 项 | 值 |
|---|---|
| 响应头 | 只有 `Content-Type: text/plain; charset=utf-8`，**没有** `Subscription-Userinfo` / `Profile-Update-Interval` |
| 流量/到期 | 写在**注释行**里（`# remaining:` / `# expire_at:`） |
| trojan 端口 | 全部 **443**，同一主机靠 **SNI** 区分节点 |
| ss 编码 | **旧式 SIP002**：`base64(method:password@host:port)`，没有独立 `@host:port` |
| ss 加密 | `aes-256-cfb`（**非 AEAD 的旧流密码**） |
| ss 密码 | **全节点共用一个密码** |
| ss 端口 | 全部 **11011** |
| 额外行 | `Ss密码单端口承载`：`aes-256-cfb:<pw>@63111:11011`，提示可用单端口 63111 承载全部 SS 节点 |

## 9.4 节点集：完全不重叠

| | v1-trojan | v1-ss | v2-vless |
|---|---|---|---|
| 主机 | `k8zq2nld9wfx3vyu7tmb-<region>.6pzftj.com`（9 个） | `<随机>-fb-<region><NN>.6pzfwf2511.com`（74 个） | `fbapp-3roq8e1.llguanglisf.com`（1 个） |
| 端口 | 443 | 11011（或单端口 63111） | 10301–10400 |
| 协议 | trojan | ss (aes-256-cfb) | vless + xtls-rprx-vision |
| 数量 | 74 | 74 | 74 |

**三者的域名交集为 0**，是三套独立的接入点。

区域分布（两条线路一致）：

```
Hong Kong 20 / Japan 10 / Singapore 10 / Taiwan 10 / USA 10 / Malaysia 5 / UK 5 / Argentina 2 / Turkey 2
```

→ 节点**命名与区域一致**，但落地服务器是两套不同的基础设施。
这说明 v1 不是"同一批机器的另一种协议"，而是**另一批机器**。

## 9.5 时间线推测：v1 是给老客户端留的兼容线路

| 证据 | 含义 |
|---|---|
| v1 用 trojan/ss，v2 用 vless+vision | vless+vision 是新一代抗封锁协议 |
| v1 明文下发，v2 用 APXS 加密 | 加密是后加的，老客户端不支持 |
| v1 保留 `aes-256-cfb`（已被主流弃用） | 典型的"冻结不再维护" |
| v1 不支持 `flag=` 参数 | 简化实现，不追求通用性 |
| v1 与 v2 节点集不重叠 | 独立的一批老机器，可能逐步下线 |

## 9.6 SNI 策略的变化（观察）

| 版本 | v2 的 `servername` |
|---|---|
| 7.2.3 / 7.2.4（早期抓取） | 每节点随机串，如 `m5vedchzxgyudr96ny1kbaiz2yfz2bo9z6xo3nlvpdphoiq` |
| 7.2.5（本次） | **固定伪装域名 `aws.amazon.com`** |

v1 的 trojan 则是每节点独立 `sni=<随机子域>`。

含义：

- 随机 SNI 是"每节点一个伪装域名"，CDN/DPI 侧难以聚类；
- 固定 `aws.amazon.com` 更像"统一伪装"，实现简单但更容易被整体识别；
- 两者都配合 `skip-cert-verify: true`，即**不校验证书**——TLS 只提供加密，不提供身份认证。

## 9.7 安全含义（CWE-602 的又一实例）

> **同一个账号、同一套客户端证书，就能拿到明文订阅。**

加密（APXS）在这里只挡住了"纯抓包"，挡不住"用 curl 带证书直接请求"：

```
攻击面             APXS 是否有效
抓包（无证书）       ✅ 有效（TLS + mTLS）
拿到客户端证书       ❌ 无效（v1 直接给明文）
同机 root 读内存     ❌ 无效（v2 明文在堆里）
```

更严重的是：v1 的 SS 线路用 **`aes-256-cfb` + 全局共享密码**，
即便不谈抓包，这种配置本身就不满足现代加密要求（无认证、易被主动探测）。

## 9.8 对用量的影响

两条线路**共享同一个流量池**：

- v1 注释行 `# remaining: 105055509255`（约 97.8 GB）
- v2 账户接口 `used=59284476217`（约 55.2 GB）、`total=161061273600`（150 GB）

即 150 GB − 55.2 GB ≈ 94.8 GB，与 v1 的 remaining 基本一致（差值来自统计延迟）。

## 9.9 本项目的实现

```bash
# v2（默认，主线路，APXS 解密）
python3 src/apex_fetch.py --config ... --source v2

# v1（遗留明文线路，无需解密）
python3 src/apex_fetch.py --config ... --source v1

# 两条都取，合并成一份配置
python3 src/apex_fetch.py --config ... --source both
```

`--source both` 的效果：

- v2 的 74 个节点保持原名；
- v1 的节点加前缀（trojan 用原名，ss 用 `[SS] `），避免与 v2 重名；
- 自动生成 `v1-trojan` / `v1-ss` 两个 url-test 分组，并挂到第一个 `select` 分组最前面；
- 输出仍是标准 mihomo 配置，原有 `dns` / `rules` 不动。

代码：`src/v1_legacy.py`（解析 + 渲染 + 合并），单测 `tests/test_v1_parse.py`。

## 9.10 为什么仍以 v2 为主线

| 维度 | v1 | v2 |
|---|---|---|
| 协议代际 | 上一代（trojan/ss） | 当前（vless + xtls-rprx-vision） |
| 加密 | 无 | APXS |
| SS 加密强度 | `aes-256-cfb`（弱） | 无此项 |
| 可持续性 | 遗留，随时可能下线 | 主力，随客户端更新 |
| 线路冗余 | — | v1 可作为 v2 挂掉时的备份 |

**结论**：v1 是"低成本备份 + 历史线路"，v2 是主力。
`--source both` 让你们两边都拿到，但默认仍走 v2。
