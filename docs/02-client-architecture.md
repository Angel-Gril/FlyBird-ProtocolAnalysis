# 02 · 客户端架构逆向（四平台）

四个平台的分发包形态完全不同，但**协议与加密实现同源**。
理解这一点是后续所有工作的前提：**搞定一份，等于搞定全部**。

---

## 2.1 Windows：Inno Setup + Flutter + 独立内核

安装包是 Inno Setup，解包后得到：

```
Apex.exe                  主程序（Flutter 壳）
data/app.so               Dart AOT 编译产物（业务逻辑 + 加密）
ApexCore.exe              mihomo 内核（独立进程）
ApexHelperService.exe     Windows 服务（提权/常驻）
certs/
  profile5_api_client.{crt,key}.pem
  profile5_subscription_client.{crt,key}.pem
  profile5_oss_client.{crt,key}.pem
```

要点：

- **Flutter 只做 UI 与网络**，真正的订阅解密在 `app.so` 里；
- `ApexCore.exe` 是**标准 mihomo**，通过本地 HTTP 控制器（`127.0.0.1:<port>`）接收配置；
- 三张证书按 **purpose** 分别用于 api / subscription / oss 三类请求；
- 客户端把解密后的 YAML 直接喂给 mihomo，**不落地**。

```
Flutter (app.so)                     ApexCore.exe (mihomo)
  ├─ 登录 / 拉 access_key               ▲
  ├─ mTLS 下载 APXS                     │ HTTP PUT /configs
  ├─ Ed25519 验签                       │ (纯内存，无文件)
  ├─ AES 解密 ────────────────────────►─┘
  └─ 节点列表 / 延迟 / 分组
```

## 2.2 Android：Flutter + Dart AOT

`libapp.so` 是 Dart AOT 快照，无法直接用 IDA/Ghidra 读。
用 **Blutter**（基于 Dart VM 的 `dart2native` 元数据）可以恢复出：

- 对象池（`pp.txt`）：所有字符串常量、类名；
- 反编译伪代码（`.dart` 文件）：函数级逻辑。

实测恢复了 `BoardDecryptHelper::open` / `decrypt` 的完整逻辑，确认了：

```
[0:4] "APXS" | [4] 0x02 | [5:9] BE u32 keyId | [9:13] BE u32 signKeyId
| [13:] 密文 | 尾 64B Ed25519 签名
```

以及验签消息 = `utf8("apex-sub-sign-v2") + bytes[0:len-64]`。

## 2.3 Linux：GTK 客户端

结构类似 Windows：Flutter/GTK 壳 + bundled mihomo。
行为一致，证书同样放在安装目录 `certs/`。

## 2.4 OpenWrt：Go 重写的 mihomo（关键突破口）

这是**唯一一个无 GUI 的官方构建**，也是整个研究的转折点。

```bash
# 解包 ipk
tar -xzf fnapp-openwrt-speed-24.10-*.ipk data.tar.gz
tar -xzf data.tar.gz ./usr/bin/mihomo
file mihomo
# ELF 64-bit LSB executable, statically linked, Go BuildID=..., stripped
```

启动方式：

```bash
mihomo -apex-openwrt -d /tmp/apex-mihomo
```

它会：

1. 检查运行目录必须是 **tmpfs**（`router runtime requires tmpfs`）；
2. 检查**磁盘 swap 必须关闭**（`secure memory policy unavailable`）；
3. 需要地理资源在 `/usr/share/apex-mihomo/geodata/{ASN.mmdb,geoip.metadb,GeoSite.dat}`；
4. 在内置 HTTP 服务上暴露 **Unix socket 控制口** `/tmp/apex-mihomo/control.sock`。

控制口协议（来自 LuCI 控制器源码）：

```
POST /login    {"email","password"}
POST /logout
POST /start    # 此时才下载并解密订阅
POST /stop
POST /refresh
POST /account  /state  /mode  /settings  /select  /delay  /diagnostics  /branding
```

**它把 APXS 的解密能力做成了一个可被本地调用的服务** —— 这就是"曲线救国"路线的入口。

## 2.5 四平台对照

| 维度 | Windows | Android | Linux | OpenWrt |
|---|---|---|---|---|
| UI | Flutter | Flutter | GTK/Flutter | LuCI (Lua) |
| 业务逻辑 | Dart AOT (`app.so`) | Dart AOT (`libapp.so`) | 同左 | **Go**（可符号恢复） |
| 内核 | mihomo 独立进程 | 内嵌 | 内嵌 | 同一二进制 |
| 证书位置 | `certs/*.pem` | assets/keystore | `certs/` | 内置/协商 |
| 可否无头运行 | 可（后台） | 需设备 | 可 | **原生无头** |
| 逆向难度 | 高 | 高（AOT） | 高 | **中（Go pclntab）** |

结论：**OpenWrt 构建是整个体系的阿喀琉斯之踵**。
一旦能在 Linux 上跑它，就等于拿到了官方的解密 oracle。
