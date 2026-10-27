# 客户端是否真的解密 APXS？——运行时取证（2026-10-27 深夜）

## 一、今天的关键新证据

### 1. 客户端每次刷新都会拿到**新内容**

连续两次 `auto_refresh.py`：

```
第 10s → 74 节点 → ar1.yaml (23,364 B)
第 9s  → 74 节点 → ar2.yaml (23,466 B)
```

差异不在统计信息，而在**节点本身**：

```diff
-  servername: <rand-token>
+  servername: <rand-token>
```

→ 每次刷新都是**服务端实时生成的新配置**，不是本地缓存。

### 2. 刷新瞬间内存里**既没有 APXS，也没有 k1/k2 裸字节**

- `poc/apxs_watch.py`：重启客户端后 40 秒内每 0.1 s 全内存搜 `APXS\x02`
  → **0 命中**
- `poc/key_watch.py`：同样窗口每 0.2 s 搜 `base64decode("fCA3...")` / `base64decode("lmzs...")`
  → **0 命中**

而按反编译代码，只要走一次 APXS 解密，就必然：
1. 内存里出现 APXS 密文（`isEnvelope` 检查的就是它）；
2. `base64Decode` 出 32 字节 k1/k2。

两条都没有 → **客户端这次刷新根本没有执行 APXS 解密分支**。

### 3. v1 订阅接口返回的不是配置

```
GET /api/v1/client/subscribe?token=...&flag=apex   (带 mTLS)
→ 200, 18,025 B, 内容为：
  "最新地址请看官网\n本接口为SSPanel-Malio..."
```

是主题占位页，不是节点配置。

### 4. 配置镜像仍然全挂

`fb_apexv2.json`（5 个镜像）复测：404 / 500 / 连接超时，加了
`x-apex-helper` / `_apex_nonce` / `apex-file-content` 等 7.2.4 特征头也无变化。

### 5. v2 响应头没有密钥字段

`/v2/auth/token`、`/v2/feed/access-token`、`/v2/feed/download` 的响应头已全量打印，
只有 nginx / Cloudflare / 安全头，没有自定义 key 下发。

---

## 二、推论

> **客户端拿到的很可能是明文 YAML，不是 APXS。**
> `/v2/feed/download` 对我们返回 APXS，但对真实客户端可能返回明文
> （差别在请求头/参数），或者客户端用的是我们还没命中的另一条接口。

如果成立，那么：

- 之前所有“用 k1/k2 解 APXS 失败”就不是密钥问题，而是 **样本根本不是客户端用的那份**；
- 纯协议目标其实**不需要 APXS 密钥**，而是需要**客户端那套请求头**。

---

## 三、下一步（二选一）

### B1. 抓客户端的真实请求头（推荐）

`flutter_windows.dll` 里静态链接了 BoringSSL，没有导出符号，但可以：

1. 用特征码定位 `SSL_write`（或 `SSL_do_handshake`）；
2. hook 后在刷新时 dump 出**请求头全文**；
3. 照着拼一次 `/v2/feed/download`，看是否返回明文。

### B2. 端点模糊测试

以 `v2/feed/download` 为基线，穷举：
- query：`format`, `type`, `plain`, `raw`, `enc`, `mode`（我们测了 6 组，仍 APXS）
- header：`accept`（8 种）、`x-apex-*`、`apex-file-content`、`_apex_nonce`

目前 `/v2/feed/download` 对我们已开始返回
`403 {"User not found."}`（access_key 可能每次登录轮换），
需要每次重新走 `/v2/auth/token` 取新 key（`fb_pipeline.py` 已实现）。

---

## 四、脚本

```
poc/apxs_watch.py         刷新瞬间搜 APXS 密文（0 命中）
poc/key_watch.py          刷新瞬间搜 k1/k2 裸字节（0 命中）
poc/find_raw_keys.py      空闲态搜裸 key（0 命中）
tools/mirror_headers.py   镜像 + 自定义头复测（仍 404/500）
tools/v1_flag_apex.py     v1 + flag=apex（返回占位页）
tools/dump_v2_headers.py  v2 全量响应头（无 key 字段）
tools/v2_download_matrix.py  Accept/参数矩阵
tools/mihomo_conns.py     ApexCore 连接表（客户端不走代理）
```
