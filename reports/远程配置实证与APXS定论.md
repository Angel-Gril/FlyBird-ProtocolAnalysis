# 远程配置实证 + APXS 定论（2026-10-27 收口）

## 一、从客户端内存里挖出的完整远程配置（BoardConfig）

地址区间 `0x24d80ac7000` 附近，字段与取值（已脱敏，无凭据）：

```
enable_api_path_mapping
subscribe_domain   = https://fbaxsub.apiv2.a047.com      ← 订阅专用 vhost
subscribe_path     = （由 subscribe_path 字段决定，映射见下）
config_version / brand_color = 65A1CC / product_dis ...
features: plans_official_only, password_reset_official_only, invite_enabled,
          purchase_enabled, traffic_details_enabled, knowledge_base_enabled,
          ticket_enabled, diagnostic_logging_enabled, gift_card_enabled,
          join_group_enabled, coupon_enabled, checkin_enabled, mail_login_enabled
update:   windows  → https://dl.pbbapi.rundingtai.com/apps/fb/fbapp-speed.exe
          android  → .../fbapp-speed.apk
          android-tv → .../fbapp-tv-speed.apk
domains:  https://fbaxapi.apiv2.a047.com
          https://fbaxapi.web.ak005.com
          https://web01.fbbapp.cc
          https://appinv01.fbvipaff.cc
```

**API 路径映射表（v1 → v2）**，共 30+ 条，关键几条：

```
/api/v1/guest/comm/config          → /v2/site/settings
/api/v1/passport/auth/login        → /v2/auth/token
/api/v1/user/getSubscribe          → /v2/feed/access-token
/api/v1/user/getStat               → /v2/analytics/summary
/api/v1/client/subscribe?token=    → /v2/feed/download?access_key=   ← 订阅
```

结论：客户端订阅请求 = `https://fbaxsub.apiv2.a047.com/v2/feed/download?access_key=<token>`。

## 二、把这条请求完整复现，结果仍然是 APXS

用 **subscription 证书** + 完整 `X-Client-*` 头 + `x-apex-helper` / `_apex_nonce` /
`apex-file-content` / `flag=apex` / `format=yaml` 共 **21 种组合**：

```
全部 200，26,795 – 26,902 B，全部以 "APXS\x02" 开头
```

即：**客户端拿到的就是 APXS，没有任何明文变体。**

## 三、密钥穷举的最终结果

| 尝试 | 规模 | 结果 |
|---|---|---|
| 内置常量 k1/k2 + 10 类派生 × 全布局 | ~70,000 | ❌ |
| 进程内 44 字符 base64（40 个）× 更宽布局（nonce 0–40，长度 8–24，tag 末尾 64/16） | 32,800 | ❌ |
| 早前：全内存 32 字节窗口 × GCM 布局 | 39,536,347 | ❌ |
| 早前：二进制窗口/子串搜索 | 5,056,171 + 775,322 | ❌ |

## 四、现在的确定结论

1. **客户端确实走 APXS 解密链路**（config 里 subscribe_domain 指向只提供 APXS 的 vhost，
   且用 subscription 证书才能 200）。
2. **密钥不是内置常量 k1/k2**（穷举失败）。
3. **密钥也没有出现在进程内存的可枚举形态里**（base64 字符串、裸 32 字节窗口都试过）。
4. 配置 JSON 里**没有**密钥字段（我们 dump 了字段名与取值，只有路径/域名/开关）。

→ 只剩下一种解释：**密钥在运行时由服务端随响应下发或以非枚举形态驻留**
（例如随 TLS 会话/首次握手协商、或存放在我们没覆盖的时间窗口里）。

## 五、可交付的成果

### 生产链路（已可用，不依赖密钥）
```
poc/auto_refresh.py   9–22 s → 74 节点 → health OK
poc/health_check.py   0/2/3 门禁
poc/fb_pipeline.py    fail-closed 原子发布
```

### 纯协议链路（已打通到下载，缺解密）
```
subscription 证书 + https://fbaxsub.apiv2.a047.com/v2/feed/download?access_key=<token>
  → 200 APXS（26.8 KB）
```

### 文档
```
reports/APXS-v2格式与密钥-反编译确认.md     信封格式 / 密钥选择逻辑（代码级）
reports/客户端是否解密APXS-运行时取证.md     刷新时序 / 内存取证
reports/证书用途分层与配置来源.md            mTLS 按用途分 vhost（本次突破）
reports/远程配置实证与APXS定论.md            本文件
```

## 六、运维提醒

- 本次排查中客户端曾由排查用的 PowerShell 会话启动，子进程会继承该会话的环境变量；
  **建议以干净环境重启客户端**，避免把无关环境变量带进被测进程。
- hosts / 保留 IP / mitmproxy CA 均已复原。
