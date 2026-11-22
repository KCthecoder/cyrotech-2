// Run: node --test tests/
const test = require("node:test");
const assert = require("node:assert/strict");
const K = require("../caesar.js");

test("encrypt shifts letters, keeps case, leaves other characters alone", () => {
  assert.equal(K.encrypt("Meet me at 6 👋, Zz!", 3), "Phhw ph dw 6 👋, Cc!");
});

test("decrypt undoes encrypt for every shift", () => {
  const msg = "The quick brown fox jumps over the lazy dog.";
  for (let s = 1; s < 26; s++) assert.equal(K.decrypt(K.encrypt(msg, s), s), msg);
});

test("brute force finds the shift for normal sentences", () => {
  for (const [msg, s] of [["Meet me at 6", 3], ["Attack at dawn", 13], ["Your package arrives tomorrow morning", 7], ["Hello, this is a secret message", 22]]) {
    const best = K.bruteForce(K.encrypt(msg, s))[0];
    assert.equal(best.shift, s, msg);
    assert.equal(best.text, msg);
  }
});

test("brute force always returns all 25 keys", () => {
  assert.equal(K.bruteForce("Khoor").length, 25);
});

test("repeated letters are grouped case-insensitively", () => {
  const g = K.repeatedLetters("Meet me");
  assert.deepEqual([...g.keys()], ["m", "e"]);
  assert.equal(K.repeatedLetters("abc").size, 0);
});
