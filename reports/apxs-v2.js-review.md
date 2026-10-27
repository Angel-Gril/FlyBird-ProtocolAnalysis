# `apxs-v2.js` 代码评审 + 夹具回归结果

对象：`C:\Users\Admin\Downloads\apxs-v2.js`（9,710 B，WebCrypto 实现）
方法：10 个独立夹具（6 正例 + 2 边界 + 2 负例），参考实现 10/10 通过后，再跑被测模块。

---

## 一、回归结果

| 用例 | 覆盖点 | 结果 |
|---|---|---|
| 01 | nonce12+ct+tag16 / base64 / key=SHA256(utf8) / 签名对 ciphertext(hex) | ✅ |
| 02 | tag16+nonce12+ct / raw / 签名对 **plaintext**(base64) | ✅ |
| 03 | nonce12+tag16+ct / base64 / key=**base64decode** / 无签名 | ✅ |
| 04 | 明文 **gzip** / base64 / 签名对 ciphertext(base64) | ✅ |
| 05 | body 为 **hex** / key=**hexdecode** | ❌ 未支持 hex body |
| 06 | tag16+nonce12+ct / base64 | ✅ |
| 07 | 签名头带 **`sha256=` 前缀** | ✅（前缀剥离正确） |
| 08 | **JSON 信封** `{data,nonce,tag}` | ✅ |
| 90 | 篡改密文（必须失败） | ✅ 抛错 |
| 91 | 错误密钥（必须失败） | ✅ 抛错 |

**9/10 PASS**（参考实现 10/10，差异仅在 05）。

> 结论：**主路径、签名作用域、gzip、JSON 信封、前缀签名都已被证明正确**；
> 唯一缺口是 hex 编码的 body，属于"低成本补上更稳"的项，不是阻塞项。

---

## 二、按风险排序的改进项

### P1 建议修（低成本、防未来翻车）

**1. body 不支持 hex，且 `looksBase64` 会把 hex 误判为 base64**

hex 字符集是 base64 的子集，所以 `05` 用例里 `ascii(raw)` 被当成 base64 解码成垃圾。
建议在 `bodyVariants` 里先判 hex 再判 base64（或两个都推入）：

```js
function hexToBytes(text) {
  const out = new Uint8Array(text.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(text.slice(i * 2, i * 2 + 2), 16);
  return out;
}
// bodyVariants 内：
if (looksHex(text)) variants.push({ label: "hex", blob: hexToBytes(text) });
```

**2. 缺少两种"派生后取哈希"的密钥形态**

现在有 `raw / base64decode / hexdecode / sha256(utf8)`，缺：

```js
candidates.push({ name: `${name}:sha256(base64)`, value: await sha256(base64ToBytes(value)) });
candidates.push({ name: `${name}:sha256(hex)`,    value: await sha256(hexToBytes(value)) });
```

服务端如果对"解码后的密钥"再做 SHA256，现在会全盘解不开。多两行、只多两轮尝试。

**3. `verifyApxsV2Signature` 把"没有签名"和"签名错误"都返回 `false`**

`03` 这类无签名响应会让调用方误判失败。建议：

```js
if (!signature || !signKey) return null;   // N/A
```

调用方按服务端是否声明签名来决定是否强制。

**4. 签名比较不是常数时间**

`candidate === expected` 是字符串比较；HMAC 建议常量时间：

```js
function ctEqual(a, b) {            // a,b: Uint8Array
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
```
把 hex/base64 候选都解成字节后比较。

### P2 健壮性（可选）

**5. `bodyVariants` 的去重键把整个 body 展开成字符串**

```js
const key = `${variant.label}:${[...variant.blob].join(",")}`;
```

一个 1 MB 的密文体在这里会生成 ~2 MB 的中间字符串，且每次调用都做一遍。改成廉价指纹：

```js
const fp = (b) => `${b.length}:${b[0]},${b[1]},${b[b.length - 2]},${b[b.length - 1]}`;
```

**6. JSON 信封的 `data` 语义只支持一种**

现在"有 nonce/tag 时，`data` 必须是纯 ciphertext"。若某个面板把整段 `nonce‖ct‖tag` 放进 `data`
同时又回显 nonce/tag，就会失败。建议显式 nonce/tag 解不开时，回退 `layouts(blob)` 再试一轮。

**7. 明文解压只认 gzip**

补 zlib（首字节 `0x78`）：

```js
if (value[0] === 0x78) { /* DecompressionStream('deflate') 或 deflate-raw 兜底 */ }
```

**8. 错误信息缺诊断**

现在抛 `"unknown envelope, layout, or key"`，线上排查时不知道试了什么。建议：

```js
err.meta = { variants: variants.map(v => v.label), layouts: [...], keys: keys.map(k => k.name) };
```

**9. 性能：`importKey` 在三维循环里重复执行**

变体 × 布局 × 密钥 最多几十次导入。用一个 `Map<keyName, CryptoKey>` 缓存即可。

### P3 接口建议

**10. CLI 落 `apxs_meta.json` 时用 `decryptApxsV2Detailed`**

`decryptApxsV2()` 只回 YAML 字符串；`Detailed` 才有 `bodyEncoding/layout/key`——
你的 `apxs_meta.json` 应该记录这三个字段，方便与 `apxs_try.py` 的结论对账。

---

## 三、可以直接采用的补丁（P1 四项）

```js
// keyVariants 末尾追加
if (looksBase64(value)) candidates.push({ name: `${name}:sha256(base64)`, value: await sha256(base64ToBytes(value)) });
if (looksHex(value))    candidates.push({ name: `${name}:sha256(hex)`,    value: await sha256(hexToBytes(value)) });

// bodyVariants 追加（放在 base64 之前）
if (looksHex(text)) variants.push({ label: "hex", blob: hexToBytes(text) });

// verifyApxsV2Signature 开头
if (!signature || !signKey) return null;

// 比较处改为字节级常量时间比较
```

改完再跑一次：

```bash
node verify_apxs_fixtures.mjs --adapter ./apxs-v2.adapter.user.mjs
# 期望：10 passed, 0 failed
```

---

## 四、复现方式

```bash
# 夹具（已含 10 例，含负例）
python gen_apxs_fixtures.py
node verify_apxs_fixtures.mjs                              # 参考实现 10/10
node verify_apxs_fixtures.mjs --adapter ./apxs-v2.adapter.user.mjs   # 你的模块
```

文件：`poc/fixtures/apxs/*`、`poc/verify_apxs_fixtures.mjs`、`poc/apxs-v2.reference.mjs`、
`poc/apxs-v2.adapter.user.mjs`（已按你的导出名写好）。
