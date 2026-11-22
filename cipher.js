// cipher.js — the real cryptography behind the explainer, kept free of UI code
// so it can be tested in Node (node --test) and loaded as a plain <script>.
//
// Scheme: PBKDF2-SHA256 turns password + salt into a 256-bit key, then
// AES-256-GCM encrypts the UTF-8 bytes with a random 12-byte IV.
// Package layout: salt (16) | iv (12) | ciphertext (n) | tag (16), base64.
(function (root) {
  "use strict";

  const subtle = root.crypto && root.crypto.subtle;
  const SALT_LEN = 16;
  const IV_LEN = 12;
  const TAG_LEN = 16;

  const enc = new TextEncoder();
  const dec = new TextDecoder("utf-8", { fatal: true });

  function randomBytes(n) {
    const b = new Uint8Array(n);
    root.crypto.getRandomValues(b);
    return b;
  }

  function utf8Encode(text) {
    return enc.encode(text);
  }

  function utf8Decode(bytes) {
    return dec.decode(bytes);
  }

  // One entry per user-visible character (code point) with its UTF-8 bytes,
  // so the page can show that "a" is 1 byte and an emoji is 4.
  function charBytes(text) {
    return Array.from(text).map((ch) => ({ char: ch, bytes: enc.encode(ch) }));
  }

  function toHex(bytes) {
    return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  }

  function toBase64(bytes) {
    let bin = "";
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return root.btoa(bin);
  }

  function fromBase64(text) {
    const bin = root.atob(String(text).replace(/\s+/g, ""));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  // Returns the raw key bytes so the page can display them. A real app would
  // derive a non-extractable CryptoKey instead and never look at the bytes.
  async function deriveKeyBytes(password, salt, iterations) {
    const base = await subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
    const bits = await subtle.deriveBits(
      { name: "PBKDF2", hash: "SHA-256", salt, iterations },
      base,
      256
    );
    return new Uint8Array(bits);
  }

  async function aesKey(keyBytes, usage) {
    return subtle.importKey("raw", keyBytes, "AES-GCM", false, [usage]);
  }

  // Returns ciphertext followed by the 16-byte authentication tag.
  async function encrypt(keyBytes, iv, plaintext) {
    const key = await aesKey(keyBytes, "encrypt");
    const out = await subtle.encrypt({ name: "AES-GCM", iv, tagLength: TAG_LEN * 8 }, key, plaintext);
    return new Uint8Array(out);
  }

  // Throws if the key is wrong or any byte was changed (tag check fails).
  async function decrypt(keyBytes, iv, ciphertextAndTag) {
    const key = await aesKey(keyBytes, "decrypt");
    const out = await subtle.decrypt({ name: "AES-GCM", iv, tagLength: TAG_LEN * 8 }, key, ciphertextAndTag);
    return new Uint8Array(out);
  }

  function pack(salt, iv, ciphertextAndTag) {
    const out = new Uint8Array(salt.length + iv.length + ciphertextAndTag.length);
    out.set(salt, 0);
    out.set(iv, salt.length);
    out.set(ciphertextAndTag, salt.length + iv.length);
    return out;
  }

  function unpack(bytes) {
    if (bytes.length < SALT_LEN + IV_LEN + TAG_LEN) throw new Error("Too short to be a CyroTech package");
    return {
      salt: bytes.slice(0, SALT_LEN),
      iv: bytes.slice(SALT_LEN, SALT_LEN + IV_LEN),
      ciphertextAndTag: bytes.slice(SALT_LEN + IV_LEN),
    };
  }

  // Which package segment each byte belongs to, for colouring.
  function segmentOf(index, totalLength) {
    if (index < SALT_LEN) return "salt";
    if (index < SALT_LEN + IV_LEN) return "iv";
    if (index < totalLength - TAG_LEN) return "ct";
    return "tag";
  }

  // Full pipeline: password + message -> base64 package (and every stage).
  async function seal(message, password, opts) {
    const o = opts || {};
    const salt = o.salt || randomBytes(SALT_LEN);
    const iv = o.iv || randomBytes(IV_LEN);
    const iterations = o.iterations || 600000;
    const plaintext = utf8Encode(message);
    const keyBytes = await deriveKeyBytes(password, salt, iterations);
    const sealed = await encrypt(keyBytes, iv, plaintext);
    const packed = pack(salt, iv, sealed);
    return { plaintext, salt, iv, iterations, keyBytes, sealed, packed, base64: toBase64(packed) };
  }

  async function open(base64, password, iterations) {
    const { salt, iv, ciphertextAndTag } = unpack(fromBase64(base64));
    const keyBytes = await deriveKeyBytes(password, salt, iterations || 600000);
    return utf8Decode(await decrypt(keyBytes, iv, ciphertextAndTag));
  }

  const api = {
    SALT_LEN, IV_LEN, TAG_LEN,
    randomBytes, utf8Encode, utf8Decode, charBytes, toHex, toBase64, fromBase64,
    deriveKeyBytes, encrypt, decrypt, pack, unpack, segmentOf, seal, open,
  };

  root.Cipher = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof globalThis !== "undefined" ? globalThis : this);
