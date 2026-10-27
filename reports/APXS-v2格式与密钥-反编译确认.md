# APXS v2 格式与密钥：反编译确认结论（2026-10-27）

> 证据来源：Blutter 反编译 `libapp_so`（Dart 3.12.2 / android arm64），
> 文件 `apex_client/account/core/utils/board_decrypt_helper.dart`，
> 以及本地 capstone 反汇编 xref 校验。

---

## 一、信封格式（已确认，代码级）

`BoardDecryptHelper::open`（addr 0x7c7694）：

| 偏移 | 长度 | 内容 | 校验代码 |
|---|---|---|---|
| 0 | 4 | `"APXS"` | `isEnvelope`：逐字节 == 'A','P','X','S' |
| 4 | 1 | `0x02` | `operator[](4) == 2` |
| 5 | 4 | BE u32，样例均为 `1` | 与 key id 参数比较 |
| 9 | 4 | BE u32，样例均为 `1` | 与 sign key id 参数比较 |
| 13 | N-77 | 加密体 | — |
| N-64 | 64 | **Ed25519 签名** | `sublist(len-64)` → `Signature()` |

整体长度约束：`105 <= len <= 16,777,321`。

### 签名

```
message = utf8("apex-sub-sign-v2") + body      # body = bytes[0 : len-64]
pubkey  = base64Decode(<sign key>)             # 32B，SimplePublicKey(ed25519)
DartEd25519::verify(message, Signature(sig, pubkey))
```

- 0x7c7904 `DartCryptography::ed25519()`
- 0x7c790c `"apex-sub-sign-v2"`
- 0x7c7938 `addAll(body)` → message
- 0x7c7954 `sublist(len-64)` → 签名
- 0x7c7960 `SimplePublicKey` ← `base64Decode(signKey)`
- 0x7c79b8 `DartEd25519::verify`

### 加密

```
aesKey  = base64Decode(<aes key>)   # 恰好 32B（代码用 cmp w1,#0x40 校验 = 32 字节）
aesGcm  = AesGcm._()
secretBox = SecretBox(cipherText, nonce, Mac(...))
DartAesGcm::decrypt(secretBox, secretKey=SecretKeyData(SensitiveBytes(aesKey)))
```

- 0x7c7890 / 0x7c789c：两个 base64 解码结果长度必须 **32 字节**
- 0x7c79e0 `AesGcm._()`，0x7c7a68 `SecretBox`，0x7c7a6c `Mac`
- 0x7c7ab8 `SecretKeyData`，0x7c7b34 `DartAesGcm::decrypt`
- 标准 GCM：`_nonceToBlock` / `_ghash` / `_calculateMacSync`，失败抛
  `"SecretBox has wrong message authentication code (MAC)"`

---

## 二、密钥从哪来（已确认）

`BoardDecryptHelper::decrypt`（addr 0x7c74c4）：

```
flags = LoadStaticField(0x10b4)          # 某个全局 int/bool
if (flags & 0x10):
    aesKeyStr  = "fCA3jkvhXpLEpDVuqPstNUS/kXewk7yGL5o8Fbh3uSc="
    signKeyStr = "lmzs43izW9GHIOOq+avbwhWh0TG/ldT3kipGkrQ4RiE="
    expectedId = 1
else:
    aesKeyStr  = ""
    signKeyStr = ""
    expectedId = 0
BoardDecryptHelper::open(body, aesKeyStr, expectedId, signKeyStr, expectedId)
```

- 0x7c7560 `LoadStaticField(0x10b4)` → 0x7c7568 `tbnz w0,#4` → 0x7c7574 内置 key 分支
- 0x7c75a8 `tst x0,#0x10` → 0x7c75ac `cset` → expectedId ∈ {0,1}
- 空串分支会在长度校验处抛 `"Subscription AES/signature keys are missing or invalid"`

两个内置常量在 Windows `app.so` 与 Android `libapp_so` 中**完全一致**（各出现 1 次）。

---

## 三、实测：内置密钥解不开现有样本

用上述格式，对 4 个真实样本做穷举验证：

| 样本 | 大小 | 结果 |
|---|---|---|
| `http/v2_apxs2.bin` | 26,765 | ❌ 验签失败 / GCM 失败 |
| `http/v724_apxs.bin` | 26,848 | ❌ |
| `Downloads/sub_web.bin` | 26,846 | ❌ |
| `Downloads/api_web.bin` | 26,851 | ❌ |

覆盖范围（`poc/` 下脚本）：

- `verify_ed25519.py` / `verify_ed2.py` / `ed_broad.py` / `ed_enc.py`：
  签名位置 0..40 与尾部、3 种前缀、base64/hex/原文编码、k1/k2 互换 —— 全部验签失败
- `apxs_gcm_final.py` / `apxs_gcm_wide.py` / `apxs_gcm_slide.py` / `apxs_gcm_keys.py`：
  nonce 位置 0..40、长度 1..40、tag 位置滑动（不在末尾也算）、AAD 变体、
  k1/k2/reversed/sha256/ASCII 共 10 种密钥派生 —— 全部 GCM 认证失败
- `mem_b64_keys.py`：运行中客户端内存里 158 个 44 字符 base64 串全部当 key 试 —— 无命中

**结论**：内置常量 `k1`/`k2` 不是当前服务端使用的密钥对。
服务端的签名公钥另有来源（配置下发），所以内置常量只作 fallback。

---

## 四、下一步三条路（按性价比排序）

### A. 运行时抓 key（最直接，不依赖服务端）

在运行中的客户端上 hook 到 `DartAesGcm::decrypt` 调用点，dump
`SecretKeyData → SensitiveBytes → Uint8List` 的 32 字节。

- 已确认对象图：`SecretKeyData.field_7` = `SensitiveBytes`，
  `SensitiveBytes.field_b` = `Uint8List`，`Uint8List` 数据指针在 `+0x17`（压缩指针 +HEAP）
- 需要先定位 Windows 版 `app.so` 里对应函数地址（arm64 与 x64 二进制不同，需重新找）

### B. 抓配置下发

客户端启动时会拉 `fb_apexv2.json`（5 个镜像当前全部 404/500）。
若配置里带 `keys[{id, aes, sign}]`，拿到即可解。
建议用 hosts 劫持 + 反向代理抓一次**成功**的配置响应（需要镜像复活或找到新域名）。

### C. 向运营方确认

错误文案本身写着要"核对 `$encryptKey`"，说明这是**可配置**的服务端密钥。
走运营方渠道索取 `$encryptKey` / key id 是最省事的合规路径。

---

## 五、生产兜底（不受影响）

密钥未知**不影响**当前的可用方案：

```
poc/auto_refresh.py  → 重启客户端触发刷新 → 内存提取明文 → 原子写 YAML（11–16s / 74 节点）
poc/health_check.py  → 0/2/3 门禁
poc/fb_pipeline.py   → fail-closed 原子发布
```

需要"纯协议解密"时才必须拿到 key。
