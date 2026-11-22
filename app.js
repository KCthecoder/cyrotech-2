// app.js — UI for the CyroTech explainer. All crypto lives in cipher.js.
(function () {
  "use strict";
  const C = window.Cipher;
  const $ = (id) => document.getElementById(id);

  if (!window.crypto || !window.crypto.subtle) {
    $("status").textContent =
      "This browser blocks Web Crypto here. Open the page through a local server (see README) or over https.";
    return;
  }

  const state = {
    salt: C.randomBytes(C.SALT_LEN),
    iv: C.randomBytes(C.IV_LEN),
    iterations: 600000,
    last: null,     // previous seal result + inputs, for "what changed" highlights
    run: 0,         // drops results from stale runs
    labDirty: false,
    flippedAt: -1,
  };

  const hex = (b) => b.toString(16).padStart(2, "0");
  const fmt = (n) => n.toLocaleString("en");
  const sameBytes = (a, b) => a && b && a.length === b.length && a.every((v, i) => v === b[i]);

  // Draw a row of byte cells. opts: cls (string or fn(i)), changed (fn(i) -> bool)
  function drawCells(el, bytes, opts) {
    const o = opts || {};
    const frag = document.createDocumentFragment();
    bytes.forEach((b, i) => {
      const d = document.createElement("span");
      const cls = typeof o.cls === "function" ? o.cls(i) : o.cls;
      d.className = "cell" + (cls ? " " + cls : "") + (o.changed && o.changed(i) ? " changed" : "");
      d.textContent = hex(b);
      d.title = `byte ${i} · ${b} · ${b.toString(2).padStart(8, "0")}`;
      frag.appendChild(d);
    });
    el.replaceChildren(frag);
  }

  function drawChars(message) {
    const wrap = $("chars");
    const frag = document.createDocumentFragment();
    let total = 0;
    for (const { char, bytes } of C.charBytes(message)) {
      total += bytes.length;
      const box = document.createElement("div");
      box.className = "char";
      const g = document.createElement("div");
      const visible = char.trim() !== "";
      g.className = "glyph" + (visible ? "" : " space");
      g.textContent = visible ? char : char === "\n" ? "⏎" : "space";
      const cells = document.createElement("div");
      cells.className = "cells";
      drawCells(cells, bytes);
      box.append(g, cells);
      frag.appendChild(box);
    }
    wrap.replaceChildren(frag);
    const chars = Array.from(message).length;
    $("bytes-meta").textContent = chars
      ? `${fmt(chars)} character${chars === 1 ? "" : "s"} → ${fmt(total)} byte${total === 1 ? "" : "s"}`
      : "Type a message above.";
  }

  // Colour each base64 character by the package segment its first bit came from.
  function drawBase64(b64, packed) {
    const el = $("b64");
    const frag = document.createDocumentFragment();
    let cur = null, buf = "";
    const flush = () => {
      if (!buf) return;
      const s = document.createElement("span");
      s.className = cur;
      s.textContent = buf;
      frag.appendChild(s);
      buf = "";
    };
    for (let i = 0; i < b64.length; i++) {
      const byte = Math.min(Math.floor((i * 6) / 8), packed.length - 1);
      const seg = b64[i] === "=" ? "tag" : C.segmentOf(byte, packed.length);
      if (seg !== cur) { flush(); cur = seg; }
      buf += b64[i];
    }
    flush();
    el.replaceChildren(frag);
  }

  async function pipeline() {
    const run = ++state.run;
    const message = $("message").value;
    const password = $("password").value;
    $("status").textContent = "Encrypting…";

    const t0 = performance.now();
    const keyBytes = await C.deriveKeyBytes(password, state.salt, state.iterations);
    const kdfMs = performance.now() - t0;
    const plaintext = C.utf8Encode(message);
    const sealed = await C.encrypt(keyBytes, state.iv, plaintext);
    if (run !== state.run) return; // a newer keystroke already started

    const packed = C.pack(state.salt, state.iv, sealed);
    const b64 = C.toBase64(packed);
    const prev = state.last;
    const ct = sealed.slice(0, sealed.length - C.TAG_LEN);
    const tag = sealed.slice(sealed.length - C.TAG_LEN);

    // Step 1
    drawChars(message);

    // Step 2
    drawCells($("salt"), state.salt, { cls: "salt" });
    const keyChanged = prev && !sameBytes(prev.keyBytes, keyBytes);
    drawCells($("key"), keyBytes, { cls: "key", changed: (i) => keyChanged && prev.keyBytes[i] !== keyBytes[i] });
    const perSec = kdfMs > 0 ? Math.round(1000 / kdfMs) : 0;
    $("kdf-time").textContent =
      `${fmt(state.iterations)} rounds took ${kdfMs.toFixed(0)} ms here, so about ${fmt(perSec)} guesses per second on this device. ` +
      `Attackers use much faster hardware, which is why more rounds help.`;
    const keyNote = $("key-note");
    if (prev && prev.password !== password && sameBytes(prev.salt, state.salt) && prev.iterations === state.iterations) {
      const diff = keyBytes.filter((b, i) => b !== prev.keyBytes[i]).length;
      keyNote.textContent = `You changed the password, and ${diff} of 32 key bytes changed (highlighted). Even a one-letter change gives a completely different key.`;
      keyNote.hidden = false;
    } else if (prev && !sameBytes(prev.salt, state.salt)) {
      keyNote.textContent = "New salt, same password, completely different key. That's why one precomputed table of password-to-key results can't crack everyone at once.";
      keyNote.hidden = false;
    } else {
      keyNote.hidden = true;
    }

    // Step 3
    drawCells($("iv"), state.iv, { cls: "iv" });

    // Step 4
    drawCells($("plain"), plaintext);
    const sameKeyIv = prev && sameBytes(prev.keyBytes, keyBytes) && sameBytes(prev.iv, state.iv);
    const ctChanged = (i) => prev && (i >= prev.ct.length || prev.ct[i] !== ct[i]);
    drawCells($("ct"), ct, { cls: "ct", changed: prev ? ctChanged : null });
    drawCells($("tag"), tag, { cls: "tag", changed: prev ? (i) => prev.tag[i] !== tag[i] : null });
    const changedCount = prev ? ct.filter((_, i) => ctChanged(i)).length : 0;
    $("ct-changed").textContent = prev ? `${changedCount} of ${ct.length} bytes changed (highlighted)` : `${ct.length} bytes`;
    const reuse = $("reuse-note");
    if (sameKeyIv && prev.message !== message) {
      reuse.innerHTML =
        "<b>Same key, same IV:</b> only the bytes you edited changed. An attacker comparing two messages can see exactly where they differ. " +
        "That's why a real app picks a <b>new IV for every message</b>. Press <i>New IV</i> to see the difference.";
      reuse.hidden = false;
    } else {
      reuse.hidden = true;
    }

    // Step 5
    drawCells($("packed"), packed, { cls: (i) => C.segmentOf(i, packed.length) });
    drawBase64(b64, packed);

    // Step 6 — keep the lab in sync until the user edits it
    if (!state.labDirty) {
      $("lab-input").value = b64;
      $("lab-password").value = password;
      clearResult();
    }

    state.last = { message, password, salt: state.salt, iv: state.iv, iterations: state.iterations, keyBytes, ct, tag, b64 };
    $("status").textContent = `Encrypted ${fmt(plaintext.length)} bytes into ${fmt(b64.length)} characters.`;
  }

  // ---------- step 6: decrypt lab ----------
  function clearResult() {
    const r = $("lab-result");
    r.className = "result";
    r.textContent = "Press Decrypt, or try to break it first.";
  }

  function showResult(ok, title, body) {
    const r = $("lab-result");
    r.className = "result " + (ok ? "ok" : "bad");
    const s = document.createElement("strong");
    s.textContent = title;
    const p = document.createElement("span");
    p.className = ok ? "msg" : "";
    p.textContent = body;
    r.replaceChildren(s, p);
  }

  async function labDecrypt() {
    try {
      const text = await C.open($("lab-input").value, $("lab-password").value, state.iterations);
      showResult(true, "Decrypted. The tag matched, so nothing was changed:", text);
    } catch (e) {
      const why = e && e.name === "OperationError"
        ? "The tag didn't match. Either the password is wrong or the text was changed. GCM refuses to return anything rather than returning garbage."
        : `That isn't valid CyroTech text (${e.message}).`;
      showResult(false, "Decryption refused.", why);
    }
  }

  function labFlip() {
    let bytes;
    try { bytes = C.fromBase64($("lab-input").value); } catch { return showResult(false, "Not valid base64.", "Press Reset to start again."); }
    const start = C.SALT_LEN + C.IV_LEN;
    if (bytes.length <= start) return;
    const i = start + Math.floor(Math.random() * (bytes.length - start));
    const bit = 1 << Math.floor(Math.random() * 8);
    bytes[i] ^= bit;
    state.labDirty = true;
    $("lab-input").value = C.toBase64(bytes);
    const seg = C.segmentOf(i, bytes.length) === "tag" ? "tag" : "ciphertext";
    showResult(false, `Flipped 1 bit in ${seg} byte ${i}.`, "Now press Decrypt.");
  }

  function labWrong() {
    state.labDirty = true;
    const p = $("lab-password");
    p.value = p.value ? p.value.slice(0, -1) + (p.value.endsWith("x") ? "y" : "x") : "x";
    showResult(false, "Changed the last letter of the password.", "Now press Decrypt.");
  }

  function labReset() {
    state.labDirty = false;
    if (state.last) {
      $("lab-input").value = state.last.b64;
      $("lab-password").value = state.last.password;
    }
    clearResult();
  }

  // ---------- wiring ----------
  let timer = 0;
  const schedule = (ms) => { clearTimeout(timer); timer = setTimeout(() => pipeline().catch(report), ms); };
  const report = (e) => { $("status").textContent = "Something went wrong: " + (e && e.message ? e.message : e); };

  $("message").addEventListener("input", () => schedule(200));
  $("password").addEventListener("input", () => schedule(250));
  $("iterations").addEventListener("change", (e) => { state.iterations = Number(e.target.value); schedule(0); });
  $("new-salt").addEventListener("click", () => { state.salt = C.randomBytes(C.SALT_LEN); schedule(0); });
  $("new-iv").addEventListener("click", () => { state.iv = C.randomBytes(C.IV_LEN); schedule(0); });
  $("copy").addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText($("b64").textContent);
      $("copy").textContent = "Copied";
      setTimeout(() => ($("copy").textContent = "Copy"), 1200);
    } catch { /* clipboard blocked; the text is still selectable */ }
  });
  $("lab-input").addEventListener("input", () => (state.labDirty = true));
  $("lab-password").addEventListener("input", () => (state.labDirty = true));
  $("lab-decrypt").addEventListener("click", labDecrypt);
  $("lab-flip").addEventListener("click", labFlip);
  $("lab-wrong").addEventListener("click", labWrong);
  $("lab-reset").addEventListener("click", labReset);

  schedule(0);
})();
