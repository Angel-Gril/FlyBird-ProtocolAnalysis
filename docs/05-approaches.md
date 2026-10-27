# 05 · 四条提取路线：实现、对比与失败记录

> 同一个目标（拿到订阅明文），我们试了四条路。
> 每一条都保留实现，因为它们的适用场景不同（取证 vs 运维 vs 移植）。

---

## 路线总览

| 路线 | 依赖 | 耗时 | 可移植性 | 适用场景 |
|---|---|---|---|---|
| A. Windows 内存 | Windows + 官方客户端 | ~10 s | 低 | 取证、无源码环境 |
| B. Linux 内存（netns） | Go 二进制 + netns | 25–45 s | 中 | 无 Windows 时的过渡方案 |
| C. gdb 断点 | 同 B + gdb | ~30 s | 中 | 算法还原、取证留痕 |
| D. 纯协议 | 仅 python3 | **~8 s** | **高** | 生产运维 |

---

# 路线 A · Windows 客户端内存提取

## 原理

官方客户端解密后会把 YAML 交给 `ApexCore.exe`（mihomo），**全程不落盘**。
但明文一定在 Flutter 进程（`Apex.exe` / `app.so`）或内核进程的堆里。

## 实现

```python
# 1) 定位明文：扫 /proc/pid/mem 等价物（Windows 用 ReadProcessMemory）
#    标记：b"proxies:" / b"xtls-rprx-vision" / b"servername:"
# 2) 向后取 400 字节，字段级正则还原 11 个字段
# 3) 按 name 去重合并
```

参见 `src/extract_nodes.py`（跨平台，Linux 直接跑；Windows 需改用 `ReadProcessMemory`）。

## 结果

- 稳定拿到 74 节点；
- 但**重建的 YAML 缺少 `dns` / `nameserver-policy` 段**（内存里那些是解析后的结构体，不是原文）。

## 失败记录

- **AES-NI 内存密钥扫描**：自写扫描内核（`tools/mem/aes_scan.c`），
  单核 4.6M 窗口/秒，扫完 562 MB × 6 种布局 = 3950 万窗口，**0 命中**。
  原因后来才明白：密钥在二进制里，但**当时的布局假设错了**。
- **DPAPI 解密**：只能读出账号密码与订阅 URL，不含 APXS 密钥。

---

# 路线 B · Linux 跑官方 OpenWrt 客户端（曲线救国）

## 为什么可行

OpenWrt 构建是**唯一无 GUI 的官方版本**，用 Go 重写，行为与 GUI 版一致：
登录 → 拉订阅 → 解密 → 交给内核。区别只是没有界面，控制口是一个 Unix socket。

## 实现（`tools/netns/`）

```bash
# 1) 必须在独立 network namespace 里跑（见下方"事故"）
ip netns add apex
ip link add veth-ax0 type veth peer name veth-ax1
ip link set veth-ax1 netns apex
ip addr add 10.210.0.1/24 dev veth-ax0 && ip link set veth-ax0 up
ip netns exec apex ip addr add 10.210.0.2/24 dev veth-ax1
ip netns exec apex ip link set veth-ax1 up
ip netns exec apex ip route add default via 10.210.0.1
iptables -t nat -A POSTROUTING -s 10.210.0.0/24 -o eth0 -j MASQUERADE
iptables -I FORWARD 1 -s 10.210.0.0/24 -j ACCEPT
iptables -I FORWARD 1 -d 10.210.0.0/24 -j ACCEPT

# 2) 运行目录必须 tmpfs，swap 必须关闭
mount -t tmpfs -o size=256M,mode=700 tmpfs /tmp/apex-mihomo
swapoff -a

# 3) 启动 + 控制
ip netns exec apex ./mihomo -apex-openwrt -d /tmp/apex-mihomo &
curl --unix-socket /tmp/apex-mihomo/control.sock -X POST http://localhost/login \
     -d '{"email":"…","password":"…"}'
curl --unix-socket /tmp/apex-mihomo/control.sock -X POST http://localhost/start -d '{}'
```

## 结果

- 拿到**原始明文 YAML**（含 dns 段），74 节点；
- 但 `/start` 会返回"加载失败"——解密成功了，失败在"把配置下发给内核"阶段；
  明文在失败前已经生成，所以在 `/start` 之后立刻扫内存即可。

## ⚠️ 事故记录（必须看）

**第一次直接在宿主机上跑，把服务器网络搞挂了。**

原因：该二进制的 `transparent` 默认 `true`，`/start` 时会执行

```
nft table inet apex_mihomo
ip rule add pref 10999
ip route add local 0.0.0.0/0 dev lo table 2026
```

在非 OpenWrt 宿主上，这套规则会**劫持宿主机出站流量**，
表现为「TCP 能建连但应用层零数据」，SSH / nginx 全部失联，只能控制台强制重启。

**教训**：这类"自带防火墙编排"的二进制，必须放进独立 netns。
本仓库所有脚本都已改为 netns 隔离版本。

## 失败记录

- **MITM（改 hosts → 本地反代）**：形成环路（上游也解析到本地），且客户端内置
  CA bundle（`BundledPublicRoot`），大概率不认系统 CA。
- **`SSLKEYLOGFILE`**：客户端不写该文件（Go 需要显式设置 `KeyLogWriter`）。
- **`WSARecv` / IOCP hook**：只看到本地 mihomo API 与 65KB 分块，拿不到明文。

---

# 路线 C · gdb 断点抓真实密钥

## 原理

剥符号的 Go 二进制仍保留 pclntab → 可恢复函数地址 → 直接下断点抓入参。

## 实现（`tools/gdb/`）

```gdb
break *0x77e8a0          # key32
break *0x77e980          # OpenAPXS
```

关键技巧：在 `OpenAPXS` 入口读返回地址，下临时断点，在返回处 dump 返回值：

```gdb
set $retaddr = *(unsigned long*)$rsp
tbreak *$retaddr
commands
  silent
  dump binary memory plain.bin $rax ($rax + $rbx)
  continue
end
```

## 结果

- 抓到 `k1/k2/k3` 的真实使用方式；
- dump 出 26806 字节明文；
- **以此完成算法还原**（见 `04-apxs-v2-format.md`）。

## 注意

- gdb 的 Python 脚本用 `-x` 执行完后会 detach，必须用原生 `commands` + `continue` 保持附着；
- 断点命令里不要盲目 `x/8gx $r11`（小整数会触发 "Cannot access memory" 并中断整个命令文件）。

---

# 路线 D · 纯协议（最终方案）

## 原理

算法已知 + 常量已知 → 不需要任何客户端二进制，只要复现 HTTP 链路。

```
登录（api 证书）→ access-token（裸 JWT）→ 下载（subscription 证书 + UA）→ 本地 CTR 解密
```

## 实现

`src/apex_fetch.py`，零第三方依赖（stdlib + 可选 cryptography/openssl）。

```bash
python3 src/apex_fetch.py --config /etc/apex-fetch/config --out sub.yaml --test
```

## 结果

```
登录成功，access_key=***
账户：<account>  套餐=<plan>  已用=57.5GB  到期=***
下载成功：26853B
解密成功：aesID=1 signID=1 明文 26748B
校验通过：74 节点 / 3 分组 / 14 规则
已发布：sub.yaml（26748B）
```

单次 **8 秒**，无副作用，可 systemd 化（见 `deploy/`）。

---

# 四路线对比结论

| 判据 | A | B | C | D |
|---|---|---|---|---|
| 需要 Windows | ✅ | ❌ | ❌ | ❌ |
| 需要 48MB 客户端 | ❌ | ✅ | ✅ | ❌ |
| 会改动宿主网络 | ❌ | ⚠️（必须 netns） | ⚠️ | ❌ |
| 需要关 swap | ❌ | ✅ | ✅ | ❌ |
| 产物完整度 | 中（缺 dns） | 高 | 高 | 高 |
| 可自动化 | 中 | 中 | 低 | **高** |
| 推荐用途 | 取证 | 过渡 | 算法研究 | **生产** |

**最佳实践**：
用路线 C 做一次"算法取证"（留证、可复现），
然后用路线 D 做日常运维。路线 A/B 作为没有证书或算法再变时的兜底。
