// aes-viz.js — a small, readable AES block cipher that records every step,
// so the page can animate what Web Crypto does internally (Web Crypto never
// exposes AES's rounds). Teaching code only: the real encryption on the page
// still uses Web Crypto; tests check this matches it byte for byte.
//
// State layout follows FIPS-197: 16 bytes fill a 4x4 grid column by column,
// so byte i sits at row i % 4, column floor(i / 4).
(function (root) {
  "use strict";

  const SBOX = buildSbox();

  // S-box from its definition: multiplicative inverse in GF(2^8), then an
  // affine transform. Generated rather than typed in, so there are no typos.
  function buildSbox() {
    const sbox = new Uint8Array(256);
    const rotl = (x, s) => ((x << s) | (x >> (8 - s))) & 0xff;
    let p = 1, q = 1;
    do {
      p = (p ^ (p << 1) ^ (p & 0x80 ? 0x1b : 0)) & 0xff; // p * 3
      q ^= q << 1; q ^= q << 2; q ^= q << 4; q &= 0xff;  // q / 3
      if (q & 0x80) q ^= 0x09;
      sbox[p] = q ^ rotl(q, 1) ^ rotl(q, 2) ^ rotl(q, 3) ^ rotl(q, 4) ^ 0x63;
    } while (p !== 1);
    sbox[0] = 0x63;
    return sbox;
  }

  const xtime = (b) => ((b << 1) ^ (b & 0x80 ? 0x1b : 0)) & 0xff; // b * 2 in GF(2^8)

  function subBytes(s) {
    return s.map((b) => SBOX[b]);
  }

  // Row r moves left by r: new[r][c] = old[r][(c + r) % 4]
  function shiftRows(s) {
    const out = new Uint8Array(16);
    for (let r = 0; r < 4; r++)
      for (let c = 0; c < 4; c++) out[r + 4 * c] = s[r + 4 * ((c + r) % 4)];
    return out;
  }

  function mixColumns(s) {
    const out = new Uint8Array(16);
    for (let c = 0; c < 4; c++) {
      const [a0, a1, a2, a3] = s.slice(4 * c, 4 * c + 4);
      out[4 * c] = xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3;
      out[4 * c + 1] = a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3;
      out[4 * c + 2] = a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3);
      out[4 * c + 3] = (xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3);
    }
    return out;
  }

  function addRoundKey(s, k) {
    return s.map((b, i) => b ^ k[i]);
  }

  // Key schedule: 16/24/32-byte key -> (rounds + 1) round keys of 16 bytes.
  function expandKey(key) {
    const nk = key.length / 4;
    if (![4, 6, 8].includes(nk)) throw new Error("AES key must be 16, 24 or 32 bytes");
    const rounds = nk + 6;
    const words = [];
    for (let i = 0; i < nk; i++) words.push(key.slice(4 * i, 4 * i + 4));
    let rcon = 1;
    for (let i = nk; i < 4 * (rounds + 1); i++) {
      let t = Uint8Array.from(words[i - 1]);
      if (i % nk === 0) {
        t = Uint8Array.from([SBOX[t[1]] ^ rcon, SBOX[t[2]], SBOX[t[3]], SBOX[t[0]]]);
        rcon = xtime(rcon);
      } else if (nk > 6 && i % nk === 4) {
        t = t.map((b) => SBOX[b]);
      }
      words.push(words[i - nk].map((b, j) => b ^ t[j]));
    }
    const roundKeys = [];
    for (let r = 0; r <= rounds; r++) {
      const k = new Uint8Array(16);
      for (let w = 0; w < 4; w++) k.set(words[4 * r + w], 4 * w);
      roundKeys.push(k);
    }
    return { rounds, roundKeys };
  }

  // Encrypt one 16-byte block, recording the state after every operation.
  // Each entry: { round, op, before, state, roundKey? }
  function encryptBlockTrace(key, block) {
    if (block.length !== 16) throw new Error("AES works on 16-byte blocks");
    const { rounds, roundKeys } = expandKey(key);
    const trace = [];
    let s = Uint8Array.from(block);
    const push = (round, op, next, roundKey) => {
      trace.push({ round, op, before: s, state: next, roundKey });
      s = next;
    };
    trace.push({ round: 0, op: "input", before: s, state: s });
    push(0, "addRoundKey", addRoundKey(s, roundKeys[0]), roundKeys[0]);
    for (let r = 1; r <= rounds; r++) {
      push(r, "subBytes", subBytes(s));
      push(r, "shiftRows", shiftRows(s));
      if (r < rounds) push(r, "mixColumns", mixColumns(s));
      push(r, "addRoundKey", addRoundKey(s, roundKeys[r]), roundKeys[r]);
    }
    return { rounds, trace, output: s };
  }

  function encryptBlock(key, block) {
    return encryptBlockTrace(key, block).output;
  }

  // GCM encrypts counter blocks, not your text: block n is IV (12 bytes) +
  // a 4-byte big-endian counter. Counter 1 is reserved for the tag, so your
  // first 16 bytes use counter 2.
  function gcmCounterBlock(iv, counter) {
    if (iv.length !== 12) throw new Error("GCM counter blocks need a 12-byte IV");
    const b = new Uint8Array(16);
    b.set(iv, 0);
    b[12] = (counter >>> 24) & 0xff;
    b[13] = (counter >>> 16) & 0xff;
    b[14] = (counter >>> 8) & 0xff;
    b[15] = counter & 0xff;
    return b;
  }

  const api = {
    SBOX, subBytes, shiftRows, mixColumns, addRoundKey, expandKey,
    encryptBlockTrace, encryptBlock, gcmCounterBlock,
  };
  root.AesViz = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof globalThis !== "undefined" ? globalThis : this);
