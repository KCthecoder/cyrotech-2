# CyroTech 2 — See Encryption

An interactive, visual walk-through of real password-based encryption. Type a
message and a password and watch each stage happen live in the browser:

1. **Text → bytes.** UTF-8, one group of bytes per character (emoji take 4).
2. **Password → key.** PBKDF2-SHA256 with a random salt; adjustable rounds with live timing.
3. **IV.** 12 fresh random bytes per message.
4. **AES-256-GCM.** Ciphertext next to your bytes, with changes highlighted, plus the 16-byte tag.
   Edit the message without changing the IV to see why IVs must never be reused.
5. **Package.** salt | IV | ciphertext | tag, colour-coded, then base64.
6. **Try to break it.** Wrong password or a single flipped bit makes decryption refuse.

All cryptography uses the browser's built-in Web Crypto API. Nothing leaves the
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

Tests cover the round trip, wrong-password and tamper rejection, UTF-8 sizes,
fresh output per message, IV-reuse behaviour, and packing.

## Files

| File | Purpose |
|---|---|
| `cipher.js` | All crypto (PBKDF2, AES-GCM, packing, base64). No UI code. |
| `app.js` | Drives the page and draws the byte grids. |
| `index.html`, `style.css` | Page and styling (light and dark). |
| `tests/cipher.test.js` | Node tests for `cipher.js`. |

## Ideas for next steps

- Animate one AES round (SubBytes, ShiftRows, MixColumns, AddRoundKey) on a 4×4 grid.
- Compare with a weak scheme (e.g. a Caesar cipher) to show why patterns leak.
- Deploy to GitHub Pages.
