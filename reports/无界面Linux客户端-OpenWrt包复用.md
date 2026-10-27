# 无界面 Linux 客户端：直接复用飞鸟官方 OpenWrt 包（2026-10-27 最终方案）

## 一、结论

飞鸟官网提供 **OpenWrt 版客户端**（`fnapp-openwrt-speed-7.2.4`），它就是一个
**无界面的 mihomo 定制守护进程**，用**本站账号密码登录**后拉取并解密订阅，
并提供 **Unix socket 控制接口**。

→ **不需要 Windows、不需要 Flutter、不需要 APXS 密钥**，任意 Linux 服务器都能跑。

## 二、下载地址

```
https://dl.pbbapi.rundingtai.com/apps/fb/fbapp-openwrt-speed.zip   156,670,522 B
  └─ fnapp-openwrt-speed-24.10-7.2.4-1793003123-arm64.ipk   → aarch64
  └─ fnapp-openwrt-speed-24.10-7.2.4-1793003123-armv7.ipk   → armv7
  └─ fnapp-openwrt-speed-24.10-7.2.4-1793003123.ipk         → x86_64（48 MB）
  └─ 对应的 25.12 apk 三个架构
```

（同目录还有 `flapp-openwrt-speed.zip`，是 Fastlink 品牌版，不要用。）

## 三、在 Linux 服务器上跑（3 步）

```bash
# 1) 取出二进制（ipk = 外层 ar/tar + data.tar.gz）
mkdir -p /opt/apex && cd /opt/apex
tar -xzf fnapp-openwrt-speed-24.10-7.2.4-1793003123-arm64.ipk data.tar.gz
tar -xzf data.tar.gz ./usr/bin/mihomo
chmod +x usr/bin/mihomo

# 2) 启动无界面守护（-d 指定工作目录，配置和节点都落在这里）
mkdir -p /tmp/apex-mihomo && chmod 700 /tmp/apex-mihomo
nohup ./usr/bin/mihomo -apex-openwrt -d /tmp/apex-mihomo > /tmp/apex-mihomo/daemon.log 2>&1 &

# 3) 通过 Unix socket 控制
S=/tmp/apex-mihomo/control.sock
curl -s --unix-socket $S -X POST http://localhost/login \
     -H 'Content-Type: application/json' \
     -d '{"email":"<账号>","password":"<密码>"}'

curl -s --unix-socket $S -X POST http://localhost/start -d '{}'   # 这一步才下载+解密订阅
curl -s --unix-socket $S -X POST http://localhost/account -d '{}' # 账户/流量
curl -s --unix-socket $S -X POST http://localhost/state -d '{}'   # 节点/分组状态
```

## 四、可用的控制动作（来自 LuCI 控制器源码）

```
login      {email, password}      登录
logout                            退出（清空内存会话）
start / stop                      开/关代理（start 时才下载订阅）
refresh                           更新订阅
account                           账户信息
state      {job}                  运行状态
mode       {mode}                 路由模式
settings   {allow_lan, transparent}
select     {id}                   切换节点
delay      {id}                   测延迟
diagnostics {enabled}             诊断开关
branding                          品牌信息
```

全部通过 `/tmp/apex-mihomo/control.sock` 的 HTTP/1.0 POST 调用，**不需要 LuCI**。

## 五、产物位置

- 解密后的 mihomo 配置：`/tmp/apex-mihomo/`（`-d` 目录，含 `config.yaml`）
- 守护日志：`/tmp/apex-mihomo/daemon.log`
- 也可通过 mihomo 自身 API（默认 9090）读 `/proxies`、`/configs`

## 六、与之前方案对比

| 方案 | 需要 Windows | 需要 APXS 密钥 | 状态 |
|---|---|---|---|
| 官方 Windows 客户端 + 内存提取 | ✅ 需要 | ❌ 不需要 | 已验证（7.5–22 s / 74 节点） |
| **OpenWrt 客户端（本方案）** | ❌ **不需要** | ❌ **不需要** | 待服务器实测 |
| 纯协议自研 | ❌ | ✅ 缺 | 卡在密钥 |

## 七、注意事项

1. **架构必须匹配**：`uname -m` → `aarch64` 用 arm64 包，`x86_64` 用无后缀包。
2. 它是 Go 静态二进制，OpenWrt 的 musl 环境编译，**普通 glibc Linux 一般可直接运行**；
   若报错先看 `daemon.log`。
3. 内核转发/nftables 透明代理只是可选功能；**只取配置时不需要** root 网络权限。
4. 会话只存在内存，进程重启后需要重新 login。
5. 该二进制内含完整 APXS 实现（`OpenAPXS` / `OpenOSS`），具备 Go 符号，
   后续若仍想要密钥，可在 Linux 上用 gdb 直接断在 `OpenAPXS` 上取值。
