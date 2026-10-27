# 06 · 工具链与关键技巧

本文汇总研究中真正用到的工具与"踩出来的技巧"，每条都对应仓库里的脚本。

---

## 6.1 Flutter / Dart AOT：Blutter

**用途**：反编译 `libapp.so` / `app.so`（Dart AOT 快照），恢复类名、字符串池与函数伪代码。

**做法**：

```bash
git clone https://github.com/worawit/blutter
cd blutter && python3 scripts/install_deps.py
python3 blutter.py <path-to-libapp.so> out/
```

产物：

- `pp.txt` — 对象池（所有字符串/类名，搜索常量从这里入手）
- `objs.txt` — 对象结构
- `asm/*.dart` — 函数级伪代码

**踩坑**：

- Blutter 需要**与目标 Dart 版本一致**的引擎源码；版本不匹配会直接崩。
- Windows 上编译 Blutter 不可行（依赖 MSVC 专有符号 `_ReturnAddress` / `__imp__sprintf_p`），
  建议在 Linux 上原生编译。
- Dart 的字符串常量常被拆成多段，搜索时要按片段匹配。

## 6.2 Go 二进制：pclntab 符号恢复

**问题**：`-s -w` 剥符号后，`go tool nm` / `objdump` 全部失效。

**方案**：自己解析 pclntab（`src/pclntab.py`）。

```bash
python3 src/pclntab.py ./mihomo apexopenwrt
# [+] pclntab @0x1ee4420 ptr=8 nfunc=52227 parsed=51917 textStart=0x401000
# === 'apexopenwrt': 169 ===
#   0x77e980  github.com/metacubex/mihomo/component/apexopenwrt.OpenAPXS
```

**常见坑**：

- magic `0xF1FFFFFF` 会在数据段里误命中 → 必须校验 `pad==0`、`minLC∈{1,2,4}`、`ptrSize∈{4,8}`，并检查 `nfunc` 落在合理区间；
- `funcoff` 是**相对 pclntab 基址**的偏移，不是相对 functab；
- 32/64 位要分别处理（ptrSize=4 时字段宽度不同）。

## 6.3 gdb 调试 Go 程序

**要点**：

1. **ABI**：Go 1.17+ 用寄存器传参，`RAX,RBX,RCX,RDI,RSI,R8,R9,R10,R11`；
   slice = 3 个 word（ptr,len,cap），string = 2 个 word（ptr,len）。
2. **断点脚本**：`gdb -p <pid> -x hook.gdb`，末尾必须有 `continue`，
   否则 gdb 读完脚本就 detach。
3. **不要盲目 dump 寄存器**：小整数当指针会触发 `Cannot access memory`，
   整个命令文件会中断。要么 `if` 判断，要么只 dump 已知是指针的寄存器。
4. **dump 返回值**：入口处 `set $ret = *(unsigned long*)$rsp` + `tbreak *$ret`。

参考 `tools/gdb/`。

## 6.4 网络隔离：network namespace

**为什么必须**：不少客户端二进制会自己编排 nftables/iptables（透明代理），
在宿主机上跑会劫持全局流量。

```bash
ip netns add apex
ip link add veth-ax0 type veth peer name veth-ax1
ip link set veth-ax1 netns apex
ip addr add 10.210.0.1/24 dev veth-ax0; ip link set veth-ax0 up
ip netns exec apex ip addr add 10.210.0.2/24 dev veth-ax1
ip netns exec apex ip link set veth-ax1 up
ip netns exec apex ip route add default via 10.210.0.1
sysctl -w net.ipv4.ip_forward=1
iptables -t nat -A POSTROUTING -s 10.210.0.0/24 -o eth0 -j MASQUERADE
iptables -I FORWARD 1 -s 10.210.0.0/24 -j ACCEPT
iptables -I FORWARD 1 -d 10.210.0.0/24 -j ACCEPT
```

**坑**：

- ufw 默认 `FORWARD DROP`，不加上面两条 FORWARD 规则，netns 里连 DNS 都出不去；
- `/etc/netns/<ns>/resolv.conf` 是 iproute2 的特殊挂载点，写这里才能给 netns 单独配 DNS；
- `pkill -f <模式>` 会**匹配到你自己的 SSH 命令**（命令行里含同样字符串），
  用 `pkill -f "/opt/apex/[m]ihomo"` 这种括号技巧避免自杀。

## 6.5 TLS 观察：终止代理 + DNAT

当客户端有证书绑定、又不接受系统 CA 时，最有效的手段是**让它以为在连真服务器**：

```
客户端 → hosts/DNS 指向 10.x.x.x → iptables DNAT 到 127.0.0.1:8443
       → 本地 TLS 服务器（自签 CA，预置进系统信任库）
       → 重建到真实服务器的连接（带客户端证书）→ 原样回传
```

这样能拿到**完整的请求头、路径、时序、响应体**，而且客户端行为完全真实。

参考 `tools/mitm_observe.py`。

**注意**：

- 自签 CA 只加进**测试进程的 mount namespace**（`unshare -m` + bind mount
  `/etc/ssl/certs/ca-certificates.crt`），不要污染宿主机；
- 端口 443 常被 nginx 占用 → 用 DNAT 转到 8443，而不是抢占 443。

## 6.6 内存取证

**Linux**：

```python
with open(f"/proc/{pid}/mem","rb",0) as mem, open(f"/proc/{pid}/maps") as maps:
    for line in maps:
        # 只扫匿名可写区（跳过文件映射）
        ...
```

要点：

- 找 `proxies:` / `xtls-rprx-vision` / `servername:` 等标记；
- 命中后**从已读入的 blob 截取**，不要再次 `seek` 重读（内存可能已变）；
- 明文可能是**多个独立小字符串**（不是一整块），因此要**逐节点块**解析再按 name 去重；
- `GOGC=off` 能显著延长明文驻留时间（Go 不回收，内容不被覆盖）。

**Windows**：`OpenProcess` + `ReadProcessMemory` + `VirtualQueryEx` 枚举区域。

## 6.7 密钥扫描器（AES-NI）

`tools/mem/aes_scan.c`：用 AES-NI 指令做 AES-256 key schedule，
在内存窗口里检测"这段 176/240 字节是否符合某个 key 的扩展密钥"。

实测性能：单核 **4.6M 窗口/秒**（562 MB × 6 布局 ≈ 28 秒）。

**这个工具最后没找到密钥**，但方法论有效：
后来证明密钥确实存在，只是**不在内存**（在二进制的字符串常量里）。
保留它是为了下次遇到"运行时派生密钥"的场景。

## 6.8 配置文件校验

`src/health_check.py`：对生成的 YAML 做三重检查

1. 结构：`proxies` 数量、必需字段（name/type/server/port）；
2. 语义：端口范围、server 域名合法性、uuid 格式；
3. 可用性：抽样节点做 TCP 连通性测试（可选）。

## 6.9 版本对照

| 客户端版本 | 变化 |
|---|---|
| 7.2.3 | 首次分析，证书 profile5 |
| 7.2.4 | 证书轮换，APXS 结构不变 |

**结论**：APXS 格式在 7.2.x 期间稳定；密钥常量未变。
若未来 `aesID != 1`，需要重新按 6.2/6.3 的流程抓一次。
