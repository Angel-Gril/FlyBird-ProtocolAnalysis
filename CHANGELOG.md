# Changelog

本项目记录对目标客户端协议分析的完整过程。版本号对应**分析里程碑**，非软件版本。

## [1.1.0] - 2026-10-27

### 新增

- **Docker 部署**：非 root 镜像（`python:3.12-slim`）、rootfs 只读、`cap_drop: ALL`、内置健康检查
- **GHCR 发布工作流**：打 tag 自动构建并推送 `ghcr.io/angel-gril/apex-fetch`，支持 amd64 + arm64
- **README 重构**：对齐社区风格，补齐徽章、目录导航、FAQ 与社区友链

### 验证：客户端 7.2.5 更新对本项目的影响

官方 7.2.5（2026-10-27 发布）更新日志：

1. 优化虚拟网卡安装及使用，解决 codex 等应用不能代理问题
2. 新增校园网模式，解决校园网不可使用问题
3. 优化节点选择页面
4. 优化代理类型说明

**结论：对协议无影响，无需调整。** 依据：

| 检查项 | 结果 |
|---|---|
| 服务端 APXS 信封 | `aesID=1`、`signID=1`，与之前一致 |
| 内置常量 k1 解密 | 成功，74 节点 / 3 分组 / 14 规则 |
| 新版 APK（7.2.5，当日构建） | `k1/k2/k3` 与 `apex-sub-sign-v2` 均存在且未变 |
| 新版 OpenWrt 包 | `fnapp-openwrt-speed-24.10-7.2.5-...ipk`，arm64 二进制体积与 7.2.4 完全一致（44,203,810 B） |
| 更新日志内容 | 全部为客户端侧（虚拟网卡 / 校园网 / UI） |

验证命令：

```bash
python3 src/apex_fetch.py --config /etc/apex-fetch/config --test
# 登录成功 → 下载 → 解密成功 aesID=1 → 74 节点
```

## [1.0.0] - 2026-10-27

### 完成

- **协议还原**：确认 APXS v2 信封结构（13B 头 + 12B nonce + 密文 + 16B 校验 + 64B 签名）
- **算法还原**：确认加密为 **AES-256-CTR**（GCM 计数器派生 `nonce||0x00000002`），
  尾 16 字节非标准 GCM tag；密钥为客户端内置常量
- **密钥捕获**：通过 Go pclntab 符号恢复 + gdb 断点，抓到 `key32` / `OpenAPXS` 真实入参与返回明文
- **纯协议实现**：`src/apex_fetch.py`，零第三方依赖，单次 8 秒
- **服务化**：systemd oneshot + timer + 原子发布 + 失败不覆盖
- **四路线文档**：Windows 内存 / Linux netns 内存 / gdb 断点 / 纯协议

### 推翻的结论（保留记录）

- ~~密钥由服务端按部署下发~~ → 客户端全流程无配置拉取仍可解密，密钥在二进制内
- ~~APXS 是标准 AES-GCM AEAD~~ → 只借用 GCM 计数器流，无 AAD
- ~~订阅接口对海外 IP 地域封锁~~ → 实为缺 UA / 缺证书导致的 404 伪装

### 事故与教训

- 在非 OpenWrt 宿主上直接运行该客户端会劫持宿主出站流量（nftables + ip rule），
  导致 SSH/nginx 失联 → 后续全部改为 netns 隔离
- `pkill -f` 会匹配到 SSH 自身命令行 → 使用 `[x]` 括号技巧

## [0.9.0] - 2026-10-26

- 首次完成 mTLS 证书 purpose 分层验证（api / subscription / oss）
- 拿到 200 APXS，确认客户端走解密链路（SNI 实证）
- 内存提取路线跑通，74 节点

## [0.5.0] - 2026-10-25

- Flutter AOT 反编译（Blutter），确认 Ed25519 验签与前缀 `apex-sub-sign-v2`
- 内置常量穷举（7 万+ 组合）失败，记录否证
- AES-NI 内存密钥扫描器（562MB × 6 布局，0 命中）

## [0.1.0] - 2026-10-24

- 样本定性：Windows(Inno Setup+Flutter+mihomo) / Android / Linux / OpenWrt(Go)
- 站点与 API 测绘，发现 404 伪装机制
