# Linux 包评估 + 服务器侧验证方案（含 live_scrape 用法）

> 目标问题：能不能在 Linux 服务器上把客户端跑起来、自动提取 access_key？
> 结论：**能跑（需 Xvfb + GTK 桌面栈），但不建议把"自动提取"押在 Linux GUI 上**；
> 最短路径是「Windows 客户端（已能登录取到 74 节点）+ 运行时内存提取 → Linux 云端只做 HTTP 调用」。

---

## 1. `fbapp-linux-speed.zip` 只读勘察结果

| 项 | 值 |
|---|---|
| 路径 | `C:\Users\Admin\Downloads\fbapp-linux-speed.zip`（`D:\IDM Download\` 下不存在） |
| 大小 | 159,883,186 B |
| SHA-256 | `DA11439CF72BDBF864C4BDAA13277FAFDAE7D47368C3F056469A5576C5C9CDB4` |
| 内含 | `fnapp-linux-speed-7.2.3-1792853649-amd64.tar.gz`、同版本 `ubuntu22.04-amd64.tar.gz`、两个同名 `.deb`、`安装说明.txt` |

**未执行任何包内程序**，仅解压到 `workspace/fbapp/linux/` 做只读检查。

tar 内部结构（x86_64 / amd64）：

```
com.fbapp.clients.apex/
  apex                        24 KB      ELF 主程序（Flutter GTK 宿主）
  ApexCore                    47.9 MB    mihomo 内核（Linux）
  ApexHelperService            1.9 MB    TUN/提权辅助
  lib/libapp.so               18.0 MB    Dart AOT（与 Windows app.so 同一套代码）
  lib/libflutter_linux_gtk.so            Flutter GTK 引擎
  lib/libflutter_secure_storage_linux_plugin.so   ← libsecret/GNOME Keyring
  data/flutter_assets/assets/config/config.yaml   ← 仍是模板（your-oss.example.com）
  data/flutter_assets/version.json    {"app_name":"apex_client","version":"7.2.3","build_number":"1792853652"}
```

**静态对照结论**（`libapp.so` vs Windows `app.so`）：

| 常量 | Linux | Windows |
|---|---|---|
| `apex-sub-v2` / `apex-sub-sign-v2` / `APXS` | 命中 | 命中 |
| `xor_key` / `api_url` | 命中 | 命中 |
| `fbaxapi` / `fbaxsub` / `ak005` / `a047` | **0** | **0** |
| `example.com` | **0** | **0** |

=> 三端（Win/macOS/Linux）+ Android 共用同一套 Dart 逻辑；**真实域名同样不内嵌、配置同样只活在内存**。
因此"在 Linux 上跑"本身不会比 Windows 多拿到任何东西，只是换了个宿主。

---

## 2. 能不能在服务器上跑起来？

| 方案 | 可行性 | 说明 |
|---|---|---|
| **A. Linux 桌面 + Xvfb（无头）** | 可行但繁琐 | 需 `xvfb`、`libgtk-3-0`、`libsecret-1-0`、`libayatana-appindicator3-1` 等；`libsecret` 需要 gnome-keyring/session bus；首次要 **GUI 登录**（xdotool 模拟输入，脆弱） |
| **B. 直接跑 `ApexCore`** | 可行 | mihomo 内核，给 YAML 就能跑；但**不负责拉订阅**，拿不到 access_key |
| **C. 复用 Windows 客户端的运行态** | **推荐** | 客户端已登录、已拿到 74 节点 ⇒ access_key 就在内存里；用 `live_scrape.py` 直接捞 |
| **D. 用 A 的产物 + B 的运行时** | — | 抓到 key 后，云端只需要 curl/python，不需要任何 GUI |

一句话：**服务器只应该做"用 key 调 HTTP + 解密 + 分发"，不该承担"登录/取 key"**。

---

## 3. 立即可用：`poc/live_scrape.py`（新增）

从**正在运行**的进程直接读内存（Windows `ReadProcessMemory` / Linux `/proc/<pid>/mem`），不落大文件、不注入、不修改。

```powershell
# Windows：每 8s 扫一遍，持续 5 分钟（建议在客户端点"更新订阅"前后各跑一次）
python poc\live_scrape.py --process Apex.exe --loop 300 --interval 8 --out recovered_live
```

```bash
# Linux：同用户或 root
python3 live_scrape.py --pid $(pgrep -f 'com.fbapp.clients.apex/apex' | head -1) --loop 300 --interval 10 --out recovered_live
```

输出：

| 文件 | 内容 |
|---|---|
| `urls.txt` | 所有含 `fbaxapi/fbaxsub/ak005/a047 /v2/ /v2/feed/download?access_key= flag=apex subscribe` 的 URL |
| `secrets.txt` | `access_key` / `token` / `Bearer` / `encrypt_key` / `sign_key` / `apex-sub-sign-v2` 候选 |
| `profile*_{api,subscription,oss}_client.{crt,key}.pem` | 内嵌 mTLS 证书 |
| `yaml_*.txt` | 运行中的 Clash YAML（可打印化，便于直接比对 74 节点） |
| `report.json` | 去重汇总（本轮实测：单进程扫出 **228** 条 URL、3 张证书） |

本轮本机实测输出（节选）：

```
[mTLS] profile5_subscription / profile5_api / profile5_oss
[URL] https://fbaxapi.web.ak005.com/v2/announcements/list
[URL] https://fbaxapi.web.ak005.com/api/v1/user/notice/fetch
[URL] https://fbaxsub.web.ak005.com
[URL] https://fbaxsub.apiv2.a047.com
```

> 关键用途：**它会把客户端真正发出去的 URL（含 `?access_key=`）原样列出来**。
> 你现在的 404 只要和这里列出的 host/path 对不上，就说明云端用的不是客户端实际用的那条路。

---

## 4. 最短闭环（建议按此顺序）

1. **Windows 上**打开客户端 → 确认 74 节点 → 点一次"更新订阅"。
2. 同时跑 `live_scrape.py --process Apex.exe --loop 300`。
3. 在 `secrets.txt` / `urls.txt` 里取：
   - `.../v2/feed/download?access_key=XXXX`（或 `?token=`）
   - 若出现 `encrypt_key` / `sign_key`，一并记录（APXS v2 需要）。
4. 把 key + YAML 带回 Linux，用现成脚本验证：
   ```bash
   python3 fb_client.py --sub https://fbaxsub.web.ak005.com --access-key XXXX --out out --insecure
   ```
   或直接用 `apex_crypto.decrypt_subscription()` 解一段手上的密文做回归。
5. **只有当第 4 步在 Linux 上也 404 时**，才需要"服务器跑客户端"——那时说明是**出口 IP/区域**差异，
   再考虑把 Linux 出口挂到与 Windows 相同的网络路径。

---

## 5. 关于 404 的最后一次排查建议

已知：四个域名都 CNAME 到 `<edge-ip>`，DoH（doh.pub / alidns）解析结果一致，TLS 正常，
`Host:` 伪造返回 421（vhost 存在），但 `/`、`/v2/*`、`/api/v1/*` 全 404（含 mTLS + 指纹头）。

请用 `live_scrape.py` 抓到的**真实 URL 字符串**对照三件事：

1. **路径前缀**：客户端是否实际请求 `/{business}/v2/...`（配置里有 `api_business` 字段，默认值未知）；
2. **端口/协议**：是否走 `:8443`/HTTP、或 IPv6 直连；
3. **Host 与 SNI**：是否有第三个域名（不在我们抓到的 4 个里）。

这三点只要有一点不同，就能解释"客户端能用、curl 404"。

---

## 6. 附：Linux 无头跑法（仅在确实需要时）

```bash
sudo apt install -y xvfb libgtk-3-0 libsecret-1-0 libayatana-appindicator3-1 \
                    libjsoncpp25 libnotify4 xdotool python3-pip
tar -xzf fnapp-linux-speed-7.2.3-1792853649-amd64.tar.gz
cd com.fbapp.clients.apex

# 需要 session keyring，否则 flutter_secure_storage 初始化失败
eval $(dbus-launch --sh-syntax)
echo -n "" | gnome-keyring-daemon --unlock --components=secrets

xvfb-run -a -s "-screen 0 1280x800x24" ./apex &
sleep 25
python3 live_scrape.py --pid $(pgrep -f 'com.fbapp.clients.apex/apex' | head -1) --loop 300 --out recovered_linux
```

登录仍需 xdotool 模拟（示例）：

```bash
xdotool search --name "飞鸟" windowactivate --sync
xdotool type --delay 60 'you@example.com'; xdotool key Tab
xdotool type --delay 60 'password';            xdotool key Return
```

> 不建议把这条链路放进 CI：GTK/托盘/keyring 任一处漂移都会失败，维护成本高于收益。
