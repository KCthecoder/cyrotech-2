// caesar.js — a Caesar cipher and its brute-force crack, used by step 8 to
// show why simple substitution leaks patterns that AES hides.
(function (root) {
  "use strict";

  const A = "A".charCodeAt(0), a = "a".charCodeAt(0);

  // Shift letters A–Z / a–z by `shift`, keeping case; everything else is unchanged.
  function shiftText(text, shift) {
    const k = ((shift % 26) + 26) % 26;
    let out = "";
    for (const ch of String(text)) {
      const c = ch.charCodeAt(0);
      if (c >= A && c < A + 26) out += String.fromCharCode(A + ((c - A + k) % 26));
      else if (c >= a && c < a + 26) out += String.fromCharCode(a + ((c - a + k) % 26));
      else out += ch;
    }
    return out;
  }

  const encrypt = (text, shift) => shiftText(text, shift);
  const decrypt = (text, shift) => shiftText(text, -shift);

  // English letter frequencies (%), A–Z.
  const FREQ = [8.2, 1.5, 2.8, 4.3, 12.7, 2.2, 2.0, 6.1, 7.0, 0.15, 0.77, 4.0, 2.4,
    6.7, 7.5, 1.9, 0.095, 6.0, 6.3, 9.1, 2.8, 0.98, 2.4, 0.15, 2.0, 0.074];

  const COMMON = new Set(("the be to of and a in that have i it for not on with he as you do at " +
    "this but his by from they we say her she or an will my one all would there their what so up " +
    "out if about who get which go me when make can like time no just him know take people into " +
    "year your good some could them see other than then now look only come its over think also " +
    "back after use two how our work first well way even new want because any these give day most " +
    "us is are was were has had am meet see hello hi secret message attack dawn tonight tomorrow " +
    "noon morning evening love yes ok").split(" "));

  // Lower is more English-like: chi-squared against letter frequencies,
  // minus a bonus for each common English word.
  function englishScore(text) {
    const counts = new Array(26).fill(0);
    let n = 0;
    for (const ch of text.toLowerCase()) {
      const c = ch.charCodeAt(0) - a;
      if (c >= 0 && c < 26) { counts[c]++; n++; }
    }
    if (n === 0) return Infinity;
    let chi = 0;
    for (let i = 0; i < 26; i++) {
      const expected = (FREQ[i] / 100) * n;
      chi += ((counts[i] - expected) ** 2) / expected;
    }
    const words = text.toLowerCase().match(/[a-z]+/g) || [];
    const hits = words.filter((w) => COMMON.has(w)).length;
    return chi / n - hits * 3;
  }

  // Try all 25 shifts; best guess first.
  function bruteForce(ciphertext) {
    const tries = [];
    for (let s = 1; s < 26; s++) {
      const plain = decrypt(ciphertext, s);
      tries.push({ shift: s, text: plain, score: englishScore(plain) });
    }
    return tries.sort((x, y) => x.score - y.score);
  }

  // Letters that occur more than once (case-insensitive) — the pattern a
  // Caesar cipher keeps and AES destroys. Map of letter -> group number.
  function repeatedLetters(text) {
    const seen = new Map();
    for (const ch of String(text).toLowerCase()) {
      if (/[a-z]/.test(ch)) seen.set(ch, (seen.get(ch) || 0) + 1);
    }
    const groups = new Map();
    let g = 0;
    for (const ch of String(text).toLowerCase()) {
      if (seen.get(ch) > 1 && !groups.has(ch)) groups.set(ch, g++);
    }
    return groups;
  }

  const api = { encrypt, decrypt, englishScore, bruteForce, repeatedLetters };
  root.Caesar = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof globalThis !== "undefined" ? globalThis : this);
