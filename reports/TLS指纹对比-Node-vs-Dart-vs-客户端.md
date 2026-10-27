# TLS 指纹对比：官方客户端 vs Dart SDK vs Node.js

实测方式：把 `fbaxapi.apiv2.a047.com` 指向本机 443，用 `tools/hello_dump.py` 解析各自的首个 ClientHello。

| 项 | 官方客户端 (Apex 7.2.3) | Dart SDK 3.13.7 | Node.js 24.21 (OpenSSL 3) |
|---|---|---|---|
| TLS 记录版本 | 0x0301 (legacy) | 0x0301 | 0x0301 |
| Cipher 数量 | **17** | **17（同序）** | **53** |
| Cipher 序列 | 1303 1301 1302 cca9 cca8 c02b c02f c02c c030 c009 c013 c00a c014 009c 009d 002f 0035 | **完全相同** | 1302 1303 1301 c02f c02b … c027 0067 … ccaa c0ad … 0035 002f |
| 扩展数量 | **10** | **10（同序）** | 11（顺序不同） |
| 扩展序列 | 0000 0017 ff01 000a 000b 0023 000d 0033 002d 002b | **完全相同** | ff01 0000 000b 000a 0023 0016 0017 000d 002b 002d 0033 |
| ALPN | **无** | **无** | 无（未设置时） |
| signature_algorithms | 9 个（0403 0804 0401 0503 0805 0501 0806 0601 0201） | **完全相同** | 26 个（含 0905/0906/0904…） |
| supported_groups | 1d 17 18（x25519, p256, p384） | 11ec 1d 17 18（多 ML-KEM 768） | 11ec 1d 17 1e 18 19 0100 0101 |
| key_share 大小 | 259 B 整包 | 1481 B（含 ML-KEM 大 share） | 1599 B |

**结论**

1. **Node（OpenSSL）与官方客户端差得很远**：cipher 集合是 3 倍、扩展顺序不同、sigalgs 26 vs 9。  
   若上游将来按 JA3/JA4 做白名单，Node 方案大概率被拒。
2. **Dart 与官方客户端同构**：cipher、扩展顺序、sigalgs 完全一致，唯一差别是 Dart 3.13 默认多带了
   X25519MLKEM768（`0x11ec`）的 key_share，导致 JA3 的 groups 段和包长略有不同。
   → 若真遇到指纹门禁，**Dart 是最接近的替代**；最稳妥仍是同版本 Dart 或直接复用客户端。
3. **当前没有证据表明存在指纹门禁**：客户端自己的请求原样转发给源站同样是 404，
   所以现阶段所有客户端（Node/Dart/curl/浏览器指纹）表现一致 —— 问题在源站路由，不在指纹。

## 建议

- 协议逻辑留一份实现即可（Node 版已满足）；把 **transport 抽象出来**，保留 `dartTransport` 开关；
- 上游恢复后做一次 A/B：Node 与 Dart 各打一次 `/v2/site/settings`，
  - 两者都 200 → 用 Node，零依赖；
  - 只有 Dart 200 → 切 Dart（`dart compile exe`，6.8 MB 单文件，无 GUI/GTK）；
  - 两者都 404 → 继续等上游，不要在指纹上做无用功。

## 附：官方客户端的真实请求（本轮 MITM 抓取）

```http
GET /v2/announcements/list HTTP/1.1
user-agent: ua.net.fbclient.app.apex/v7.2.3
accept: application/json
accept-encoding: gzip
host: fbaxapi.web.ak005.com
```

```http
GET /apos/fb_apex.json?t=1792946338340 HTTP/1.1
user-agent: ua.net.fbclient.app.apex/v7.2.3
pragma: no-cache
cache-control: no-cache, no-store, max-age=0
accept-encoding: gzip
host: cdno01-ax.llguanglisf.com
```

注意：这两类请求**不带 `X-Client-*`**；登录/订阅路径才可能带。
