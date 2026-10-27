# 运行时抓 KEY 尝试记录（方案 A，2026-10-27）

> 目标：不依赖服务端，从运行中的 Windows 客户端直接取出 APXS 的 32 字节 AES key。
> 结论：**本轮未取到**，但把可行路径收敛到两条，并排除了三类做法。

---

## 一、已经打通的能力

### 1. 内存全量扫描（AES-NI 加速）

- `poc/aes_scan.c` + `poc/aes_scan.dll`：自实现 AES-256（AES-NI 内联汇编），
  单核 **4.6 M 窗口/s**；
- `poc/key_scan_fast2.py`：ctypes + 多进程，**562 MB 全内存 stride=1 扫描 28 秒**
  （6 种布局 161 秒）；
- 自测通过（把已知 key 塞进缓冲，能精确定位 offset 与 key）。

### 2. Frida 网络钩子

- `poc/frida_attach_hunt4.py`：`WSARecv` + IOCP `GetQueuedCompletionStatus`
  组合能拿到**明文 HTTP**（本地 mihomo API，`{"proxies":{...}}`）；
- 抓包 456 个缓冲、28.5 MB，落盘在 `http/client_recv/`。

### 3. 客户端刷新链路仍可用

`poc/auto_refresh.py` 复测：**22 秒 → 74 节点 → health OK**。

---

## 二、三条被排除的做法

| 做法 | 结果 |
|---|---|
| **hosts 劫持 + mitmproxy 反代** | ❌ 客户端仍走真实服务器（刷新时间戳正常更新），说明它不依赖系统 DNS 解析 |
| **把边缘 IP 挂到 Loopback 再反代** | ❌ 能挂上（`netsh ipv4 add address`），但 mitm 回源到同一 IP 会形成**环路**，无法完成握手 |
| **Frida hook socket 看 HTTP body** | ❌ 只看到 TLS 密文；能看到的明文全是 <ip> 的 mihomo API |

另外：**Ed25519 内存暴力验证**（找公钥）太慢（PyNaCl ~40µs/候选），
9 MB 区域跑 30 分钟未完成，已放弃这条路。

---

## 三、内存扫描结果

- 空闲态 562 MB × 6 种布局（nonce@0/13、12/16 字节、tag@-80/-64/-16/-128）→ **0 命中**
- 说明：key **不是**以裸 32 字节数组常驻在空闲堆里，
  或者在 decryption 前后**短暂存在**，或者存储形态不是连续 32 字节。

---

## 四、剩下两条真正可行的路

### A1. Hook BoringSSL 的 `SSL_read`（推荐先做，工作量小）

`flutter_windows.dll` 静态链接 BoringSSL，函数体没有导出符号，
但可以按**特征字节**定位 `SSL_read`（或在 DLL 里找 `SSL_do_handshake` 特征码）。

拿到之后：

1. 直接读出客户端收到的**真实 HTTP 响应体**；
2. 和我们的 APXS 对比 → **一次性回答"我们的样本是不是诱饵"**；
3. 如果是真样本，就能用这个真密文去测 k1/k2（现在的失败可能只是样本不对）。

### A2. Hook Dart 的 `BoardDecryptHelper::open`（拿到 key 本体）

思路：

1. 在内存里找 `"SecretBox has wrong message authentication code (MAC)"` 字符串对象；
2. 顺着它的对象池偏移，在 `app.so`（Windows x64）里找引用它的代码
   （x64 AOT 的池访问是 `mov rax, [r15+off]` / `lea`，可静态扫描）；
3. 反查到 `DartAesGcm::decrypt`，下断点读出 `SecretKeyData → SensitiveBytes → Uint8List`
   的 32 字节。

我们已经有**完整的对象图**（`SecretKeyData.field_7 → SensitiveBytes.field_b → Uint8List`，
数据指针 `+0x17` 压缩指针 + HEAP），只差定位地址。

### A3（兜底）. 向运营方确认密钥

错误文案本身写着要核对 `$encryptKey`,说明这是服务端**可配置**项。

---

## 五、脚本清单

```
poc/aes_scan.c / aes_scan.dll         AES-NI 扫描内核
poc/key_scan_fast2.py                 全内存多进程扫 key（28s/562MB）
poc/frida_attach_hunt4.py             WSARecv+IOCP 抓包（明文可见）
poc/ed_scan_mem.py                    Ed25519 公钥内存搜索（太慢，未完成）
poc/mitm_capture_client.py            hosts+mitmproxy 反代（无效，留作记录）
poc/auto_refresh.py                   客户端刷新 / 提明文（仍可用）
```

## 六、环境状态

- hosts：干净
- mitmproxy CA：已从 Root 移除
- <edge-ip> 保留地址：已删除
- 客户端与 ApexCore：运行中
