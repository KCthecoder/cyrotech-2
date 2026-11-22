// Run: node --test tests/
const test = require("node:test");
const assert = require("node:assert/strict");
const C = require("../cipher.js");

const FAST = 1000; // low iteration count keeps tests quick

test("round trip: seal then open returns the message", async () => {
  const s = await C.seal("Hello, CyroTech 👋", "correct horse", { iterations: FAST });
  assert.equal(await C.open(s.base64, "correct horse", FAST), "Hello, CyroTech 👋");
});

test("wrong password is rejected", async () => {
  const s = await C.seal("secret", "right", { iterations: FAST });
  await assert.rejects(C.open(s.base64, "wrong", FAST));
});

test("flipping one bit anywhere in ciphertext or tag is detected", async () => {
  const s = await C.seal("tamper me", "pw", { iterations: FAST });
  for (const i of [C.SALT_LEN + C.IV_LEN, s.packed.length - 1]) {
    const bad = s.packed.slice();
    bad[i] ^= 1;
    await assert.rejects(C.open(C.toBase64(bad), "pw", FAST));
  }
});

test("ciphertext is the same length as the message, plus a 16-byte tag", async () => {
  const s = await C.seal("abcdef", "pw", { iterations: FAST });
  assert.equal(s.sealed.length, 6 + C.TAG_LEN);
  assert.equal(s.packed.length, C.SALT_LEN + C.IV_LEN + 6 + C.TAG_LEN);
});

test("UTF-8: ASCII is 1 byte, é is 2, emoji is 4", () => {
  const sizes = C.charBytes("aé👋").map((c) => c.bytes.length);
  assert.deepEqual(sizes, [1, 2, 4]);
});

test("same message twice gives different output (fresh salt and IV)", async () => {
  const a = await C.seal("same", "pw", { iterations: FAST });
  const b = await C.seal("same", "pw", { iterations: FAST });
  assert.notEqual(a.base64, b.base64);
});

test("reusing salt+IV: changing one character changes only that ciphertext byte (plus tag)", async () => {
  const salt = C.randomBytes(C.SALT_LEN);
  const iv = C.randomBytes(C.IV_LEN);
  const a = await C.seal("cat", "pw", { salt, iv, iterations: FAST });
  const b = await C.seal("car", "pw", { salt, iv, iterations: FAST });
  const ctA = a.sealed.slice(0, 3), ctB = b.sealed.slice(0, 3);
  assert.deepEqual([ctA[0] === ctB[0], ctA[1] === ctB[1], ctA[2] === ctB[2]], [true, true, false]);
});

test("pack/unpack and base64 are lossless", () => {
  const salt = C.randomBytes(16), iv = C.randomBytes(12), ct = C.randomBytes(40);
  const u = C.unpack(C.fromBase64(C.toBase64(C.pack(salt, iv, ct))));
  assert.deepEqual([u.salt, u.iv, u.ciphertextAndTag], [salt, iv, ct]);
});

test("segmentOf labels salt, iv, ciphertext and tag", () => {
  const n = 16 + 12 + 5 + 16;
  assert.deepEqual([0, 16, 28, n - 16].map((i) => C.segmentOf(i, n)), ["salt", "iv", "ct", "tag"]);
});
