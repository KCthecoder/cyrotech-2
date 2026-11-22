# CyroTech 2 — See Encryption

An interactive, visual walk-through of real password-based encryption. Type a
message and a password and watch each stage happen live in the browser:

1. **Text → bytes.** UTF-8, one group of bytes per character (emoji take 4).
2. **Password → key.** PBKDF2-SHA256 with a random salt; adjustable rounds with live timing.
3. **IV.** 12 fresh random bytes per message.
4. **AES-256-GCM.** Ciphertext next to your bytes, with changes highlighted, plus the 16-byte tag.
   Edit the message without changing the IV to see why IVs must never be reused.
5. **Inside AES.** The real counter block (IV + counter 2) goes through all 14 rounds with your
   key: SubBytes, ShiftRows, MixColumns, AddRoundKey, animated step by step. The final keystream
   is checked against Web Crypto's ciphertext.
6. **Package.** salt | IV | ciphertext | tag, colour-coded, then base64.
7. **Try to break it.** Wrong password or a single flipped bit makes decryption refuse.
8. **Compare with Caesar.** Your message through a Caesar cipher next to AES: repeated letters stay
   visible in Caesar but not in AES, and "Crack it" tries all 25 shifts in about a millisecond.

All encryption uses the browser's built-in Web Crypto API. Step 5 re-runs one block in a small
JavaScript AES (`aes-viz.js`) only to show the rounds Web Crypto keeps hidden; it is tested against
the FIPS-197 vectors and against Web Crypto itself. Nothing leaves the
page, and there are no dependencies or build step.

This is a from-scratch rebuild of my 2021 university project; no code is reused.

**Live:** https://kcthecoder.github.io/cyrotech-2/

## Run it locally

```bash
git clone https://github.com/KCthecoder/cyrotech-2.git
cd cyrotech-2
python3 -m http.server 8000
# open http://localhost:8000
```

Opening `index.html` directly also works in Chromium and Firefox. Some browsers
only allow Web Crypto on `https://` or `localhost`.

## Test it

```bash
node --test tests/
```

21 tests cover the round trip, wrong-password and tamper rejection, UTF-8 sizes,
fresh output per message, IV-reuse behaviour, packing, the FIPS-197 AES-128 and AES-256
known answers, agreement with Web Crypto, the GCM keystream, and the Caesar cipher and its
brute-force crack.

## Files

| File | Purpose |
|---|---|
| `cipher.js` | All crypto (PBKDF2, AES-GCM, packing, base64). No UI code. |
| `app.js` | Drives the page and draws the byte grids. |
| `aes-viz.js` | Readable AES block cipher that records every round (teaching only). |
| `rounds.js` | Step 5: the round-by-round animation and the Web Crypto check. |
| `caesar.js` | Caesar cipher, English scoring and brute-force crack. |
| `caesar-ui.js` | Step 8: the Caesar vs AES comparison. |
| `index.html`, `style.css` | Page and styling (light and dark). |
| `tests/` | Node tests for `cipher.js`, `aes-viz.js` and `caesar.js`. |

## Status

Complete (2026-11-22). The GCM tag calculation (GHASH) was considered and left out of scope.
