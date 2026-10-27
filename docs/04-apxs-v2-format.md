# 04 · APXS v2 格式与算法还原（全过程）

> 这一篇是项目的核心技术记录：从"完全不知道密钥"到"逐字节复现官方输出"。

---

## 4.1 信封格式

```
偏移        长度   内容
[0:4]       4     "APXS"（0x41 0x50 0x58 0x53）
[4]         1     版本 = 0x02
[5:9]       4     BE u32 aesKeyID
[9:13]      4     BE u32 signKeyID
[13:25]     12    nonce
[25:L-80]   n     AES-256-CTR 密文
[L-80:L-64] 16    校验块
[L-64:L]    64    Ed25519 签名
```

长度约束：`105 ≤ len ≤ 16,777,321`（1 + 4 + 4 + 12 + 16 + 64 = 101，加最小密文）。

**交叉验证**：一个 26911 字节的信封，解密后明文 26806 字节，
差值 `105 = 13 + 12 + 16 + 64`，与结构完全吻合。

## 4.2 第一次尝试：反编译 Dart（Android/Windows 的 app.so）

用 **Blutter** 恢复 Dart AOT 后，拿到 `board_decrypt_helper.dart`：

```dart
// 伪代码（Blutter 输出整理）
static Uint8List open(Uint8List body) {
  final magic = body.sublist(0, 4);            // "APXS"
  final ver   = body[4];                       // 0x02
  final aesId = beU32(body, 5);
  final signId= beU32(body, 9);
  final sig   = body.sublist(len - 64);        // Ed25519

  // 1) 验签：message = "apex-sub-sign-v2" + body[0 : len-64]
  final msg = utf8.encode("apex-sub-sign-v2") + body.sublist(0, len - 64);
  SimplePublicKey(pubkey, type: ed25519).verify(msg, Signature(sig));

  // 2) 解密：SecretBox(ct, nonce, Mac) -> DartAesGcm::decrypt
  ...
}
```

由此确认：

- 验签前缀是 `apex-sub-sign-v2`；
- 公钥来自 `base64decode(signKey)`；
- 客户端有一对内置常量（`k1` 作 aes、`k2` 作 sign），以及 `flags & 0x10` 决定的 expectedKeyId=1。

**但**：用这对常量去解真实 APXS，Ed25519 验签与 GCM 解密**全部失败**。

## 4.3 第二次尝试：穷举（7 万种组合，全败）

测试空间：

| 维度 | 取值 |
|---|---|
| 密钥 | k1 / k2 / k3 / 互换 |
| 签名位置 | 0..40 起始 × 3 长度 |
| 签名编码 | base64 / hex / 原文 |
| nonce 偏移 | 0..40 |
| tag 位置 | 滑动 1..40 |
| AAD | 空 / 头部 / nonce / 签名 / 各种拼接 |
| 派生 | 10 类（sha256、md5、HKDF…） |

结果：**0 命中**。同时用自写 AES-NI 扫描器扫了客户端 562MB 内存
（6 种布局、3950 万窗口、单核 4.6M 窗口/秒），也 0 命中。

结论（当时的错误推断）：*密钥由服务端下发，不在二进制里*。

## 4.4 第三次尝试：Go 二进制静态分析

OpenWrt 版的 Go 二进制暴露了大量类型元数据：

```
github.com/metacubex/mihomo/component/apexopenwrt.OpenAPXS
github.com/metacubex/mihomo/component/apexopenwrt.OpenOSS
github.com/metacubex/mihomo/component/apexopenwrt.key32
github.com/metacubex/mihomo/component/apexopenwrt.RouterConfig
```

结构体 tag 也完整可见：

```go
type Identity struct {
    AESID  int    `json:"aes_id"`
    SignID int    `json:"sign_id"`
    AES    string `json:"aes"`
    OSS    string `json:"oss"`
    OSSKey string `json:"oss_key"`
}
type Config struct {
    Identities      []Identity `json:"identities"`
    SubscribeDomain string     `json:"subscribe_domain"`
    SubscribePath   string     `json:"subscribe_path"`
    Domains         []string   `json:"domains"`
    ...
}
```

这坐实了"身份表"的存在，也解释了为什么内存里扫不到——**它可能压根没被加载**。

## 4.5 转折点：跑起官方 OpenWrt 客户端

在 Linux 上以 `-apex-openwrt` 启动后（详见 `05-approaches.md` 路线 B）：

- 登录成功；
- 通过 TLS 终止代理抓到**完整请求链**（只有 4 个请求，**没有任何配置拉取**）；
- 但 `/start` 报"加载失败"。

于是做内存扫描，结果在 Go 堆里扫到了**明文 YAML**：

```
proxies:
    - flow: xtls-rprx-vision
      name: Hong Kong-01
      network: tcp
      port: 10301
      server: <node-host>
      servername: <随机串>
      skip-cert-verify: true
      tls: true
      type: vless
      udp: true
      uuid: <uuid>
```

**这一下推翻了 4.3 的结论**：客户端没有拉配置却解密成功
→ 密钥一定在二进制里。

## 4.6 关键技术：Go pclntab 符号恢复

二进制被 `-s -w` 剥了符号（`go tool nm` 直接失败），但 **pclntab 一定还在**（Go 运行时靠它打栈回溯）。

自写解析器（`src/pclntab.py`）要点：

```
定位：扫描 magic 0xF1FFFFFF（go1.20+），并校验后随 2 字节为 0、
      minLC ∈ {1,2,4}、ptrSize ∈ {4,8}

头部（ptr 宽度）：
  nfunc, nfiles, textStart, funcnameOffset, cuOffset,
  filetabOffset, pctabOffset, pclnOffset

functab：每个 8 字节 (entryoff uint32, funcoff uint32)
_func：funcoff 处 +4 是 nameOff（相对 funcname 基址）

地址 = textStart + entryoff
```

x86_64 构建解析出 **51,917 个函数**，关键地址：

| 函数 | 地址 |
|---|---|
| `apexopenwrt.key32` | `0x77e8a0` |
| `apexopenwrt.OpenAPXS` | `0x77e980` |
| `apexopenwrt.OpenOSS` | `0x77efa0` |
| `apexopenwrt.RouterConfig` | `0x779240` |
| `apexopenwrt.OpenBuild` | `0x778b00` |

（arm64 构建：`0x329440 / 0x329530 / 0x3299e0 / 0x324f10`）

ELF `e_type = 2`（ET_EXEC，非 PIE）→ 地址就是绝对地址，可直接下断点。

## 4.7 gdb 断点：抓到真实入参

```gdb
break *0x77e8a0      # key32(s string) -> []byte
break *0x77e980      # OpenAPXS(body []byte, aes []byte, sign []byte, ids)
```

`key32` 的入参（Go 1.17+ 寄存器 ABI：RAX=ptr，RBX=len）：

```
### key32 entry rax=... rbx=44
xZ//fP0AfP+8yW4OAZOrcKHe7dO78+Gpwu1ewno/fd8=     ← k3（调用 2 次）
fCA3jkvhXpLEpDVuqPstNUS/kXewk7yGL5o8Fbh3uSc=     ← k1
lmzs43izW9GHIOOq+avbwhWh0TG/ldT3kipGkrQ4RiE=     ← k2
```

`OpenAPXS` 的入参：

```
body = 0xc0008e1000   len = 26780
aes  = 0xc0007a2b70   len = 32      ← 解码后 = k1
sign = 0xc0007a2ba0   len = 32      ← 解码后 = k2
ids  = 0x0000000100000001            ← aesID=1, signID=1
```

返回值（在返回地址处下临时断点 dump）：

```
### OpenAPXS return rax=0xc0008bca80 rbx=26806
```

**明文 26806 字节，直接 dump 出来了。**

## 4.8 为什么之前的 GCM 全失败：它不是 GCM

拿到 `(k1, nonce, ct, 明文)` 后做已知明文反推：

GCM 的计数器流：`J0 = nonce || 0x00000001`，首块数据用 `inc32(J0) = nonce || 0x00000002`。
于是只需验证：

```
AES-ECB(k1, nonce||0x00000002) XOR ct[0:16] == "mixed-port: 7890"
```

一次命中 → **密钥是 k1，密文从偏移 25 开始，算法是 CTR**。

进一步比较**整段**明文：

```python
ctr = Counter.new(32, prefix=nonce, initial_value=2, little_endian=False)
plain = AES.new(k1, AES.MODE_CTR, counter=ctr).decrypt(ct)
assert plain == gdb_dump          # True，26806 字节逐字节一致
```

再用 `AESGCM(k1)` 做 2500+ 种 AAD 的验签尝试：**全部失败**，
并且把标准 GCM tag 在信封里搜索也**找不到**。

结论：

> 实现只借用了 GCM 的**计数器流**做加密，
> 尾部 16 字节不是标准 GCM tag（不参与我们需要的解密），
> 完整性由末尾 64 字节 Ed25519 签名单独承担。

这就是为什么"按 GCM AEAD 去解"永远解不开——**AAD 根本不存在**。

## 4.9 三份样本交叉验证

| 样本来源 | 信封长 | 明文 | 节点 | 分组 | 规则 |
|---|---|---|---|---|---|
| gdb dump | 26911 | 26806 | 74 | 3 | 14 |
| TLS 代理抓取 | 26858 | 26753 | 74 | 3 | 14 |
| 早期抓取 | 26833 | 26728 | 74 | 3 | 14 |

三份的 `servername` 各不相同（每次下发轮换），其余结构一致。
明文包含完整的 `dns` / `fake-ip` / `nameserver-policy` / `proxy-groups` / `rules` 段。

## 4.10 参考实现

```python
import base64
from Crypto.Cipher import AES
from Crypto.Util import Counter

KEY_APXS = "fCA3jkvhXpLEpDVuqPstNUS/kXewk7yGL5o8Fbh3uSc="
TRAILER  = 16 + 64

def decrypt(blob: bytes) -> bytes:
    assert blob[:4] == b"APXS" and blob[4] == 0x02
    nonce = blob[13:25]
    ct    = blob[25:len(blob) - TRAILER]
    key   = base64.b64decode(KEY_APXS)
    ctr   = Counter.new(32, prefix=nonce, initial_value=2, little_endian=False)
    return AES.new(key, AES.MODE_CTR, counter=ctr).decrypt(ct)
```

没有 pycryptodome 时可用 openssl：

```bash
openssl enc -aes-256-ctr -K <key_hex> -iv <nonce_hex>00000002 -in ct.bin -out plain.yaml
```

（openssl 的 CTR IV 即初始计数器块，正好等于 `nonce||0x00000002`。）

## 4.11 经验教训

1. **"解不开"通常是参数错，不是密钥错**。我们把 k1 试了上千次，唯独没试"根本不用 AEAD"。
2. **已知明文是最强的攻击面**。拿到 16 字节明文就能反推密钥流。
3. **剥符号 ≠ 无法定位**。Go 的 pclntab 是逆向者的朋友。
4. **官方无头客户端是最好的 oracle**。它帮你完成所有校验，你只需要读它的输出。
