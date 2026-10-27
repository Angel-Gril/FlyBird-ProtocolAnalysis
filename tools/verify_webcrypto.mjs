// 验证 Worker 端 WebCrypto AES-CTR 解密与官方实现逐字节一致
// 用法：node tools/verify_webcrypto.mjs <apxs.bin> [plain.bin]
import { readFileSync } from "node:fs";

const K1 = "fCA3jkvhXpLEpDVuqPstNUS/kXewk7yGL5o8Fbh3uSc=";
const TRAILER = 16 + 64;

const b64 = (s) => Buffer.from(s, "base64");

async function decryptApxs(buf) {
  if (buf.length < 25 + TRAILER) throw new Error("too short");
  if (buf.subarray(0, 4).toString("latin1") !== "APXS") throw new Error("bad magic");
  if (buf[4] !== 0x02) throw new Error(`bad version 0x${buf[4].toString(16)}`);
  const aesId = buf.readUInt32BE(5);
  const signId = buf.readUInt32BE(9);
  const nonce = buf.subarray(13, 25);
  const ct = buf.subarray(25, buf.length - TRAILER);

  const key = await crypto.subtle.importKey("raw", b64(K1), "AES-CTR", false, ["decrypt"]);
  const counter = new Uint8Array(16);
  counter.set(nonce, 0);
  counter[15] = 0x02; // GCM 计数器：nonce || 0x00000002
  const plain = await crypto.subtle.decrypt({ name: "AES-CTR", counter, length: 32 }, key, ct);
  return { plain: Buffer.from(plain), aesId, signId };
}

const [apxsPath, plainPath] = process.argv.slice(2);
if (!apxsPath) {
  console.error("用法: node verify_webcrypto.mjs <apxs.bin> [plain.bin]");
  process.exit(2);
}
const buf = readFileSync(apxsPath);
const { plain, aesId, signId } = await decryptApxs(buf);
console.log(`aesId=${aesId} signId=${signId} 密文=${buf.length - 25 - TRAILER} 明文=${plain.length}`);
console.log("首行:", plain.subarray(0, 40).toString("utf8").split("\n")[0]);
if (plainPath) {
  const ref = readFileSync(plainPath);
  console.log("与官方明文逐字节一致:", Buffer.compare(plain, ref) === 0);
}
