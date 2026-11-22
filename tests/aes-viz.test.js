// Run: node --test tests/
const test = require("node:test");
const assert = require("node:assert/strict");
const A = require("../aes-viz.js");
const C = require("../cipher.js");

const hex = (s) => Uint8Array.from(s.match(/../g).map((h) => parseInt(h, 16)));
const toHex = (b) => Buffer.from(b).toString("hex");

test("S-box spot checks from FIPS-197", () => {
  assert.deepEqual([A.SBOX[0x00], A.SBOX[0x01], A.SBOX[0x53], A.SBOX[0xff]], [0x63, 0x7c, 0xed, 0x16]);
  assert.equal(new Set(A.SBOX).size, 256); // a permutation
});

test("FIPS-197 C.1: AES-128 known answer", () => {
  const out = A.encryptBlock(hex("000102030405060708090a0b0c0d0e0f"), hex("00112233445566778899aabbccddeeff"));
  assert.equal(toHex(out), "69c4e0d86a7b0430d8cdb78070b4c55a");
});

test("FIPS-197 C.3: AES-256 known answer", () => {
  const key = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
  const out = A.encryptBlock(key, hex("00112233445566778899aabbccddeeff"));
  assert.equal(toHex(out), "8ea2b7ca516745bfeafc49904b496089");
});

test("AES-256 trace has 14 rounds and 57 recorded states", () => {
  const { rounds, trace } = A.encryptBlockTrace(new Uint8Array(32), new Uint8Array(16));
  assert.equal(rounds, 14);
  assert.equal(trace.length, 57);
  assert.equal(trace.at(-1).op, "addRoundKey");
  assert.ok(!trace.some((t) => t.round === 14 && t.op === "mixColumns")); // last round skips MixColumns
});

test("matches Web Crypto on random keys and blocks (AES-CBC, zero IV, first block)", async () => {
  const subtle = globalThis.crypto.subtle;
  for (let n = 0; n < 20; n++) {
    const key = C.randomBytes(32), block = C.randomBytes(16);
    const k = await subtle.importKey("raw", key, "AES-CBC", false, ["encrypt"]);
    const ref = new Uint8Array(await subtle.encrypt({ name: "AES-CBC", iv: new Uint8Array(16) }, k, block)).slice(0, 16);
    assert.equal(toHex(A.encryptBlock(key, block)), toHex(ref));
  }
});

test("GCM: AES(IV + counter 2) XOR your first 16 bytes = the real ciphertext", async () => {
  const s = await C.seal("This message is longer than sixteen bytes", "pw", { iterations: 1000 });
  const ks = A.encryptBlock(s.keyBytes, A.gcmCounterBlock(s.iv, 2));
  const mine = s.plaintext.slice(0, 16).map((b, i) => b ^ ks[i]);
  assert.equal(toHex(mine), toHex(s.sealed.slice(0, 16)));
});

test("ShiftRows moves row r left by r", () => {
  const s = Uint8Array.from({ length: 16 }, (_, i) => i); // byte i = row i%4, col i/4
  const out = A.shiftRows(s);
  // row 1 (bytes 1,5,9,13) -> 5,9,13,1
  assert.deepEqual([out[1], out[5], out[9], out[13]], [5, 9, 13, 1]);
  // row 0 unchanged
  assert.deepEqual([out[0], out[4], out[8], out[12]], [0, 4, 8, 12]);
});
