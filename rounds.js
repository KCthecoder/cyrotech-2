// rounds.js — step 5: animate one AES-256 block through all 14 rounds.
// Listens for "cyro:sealed" from app.js and uses AesViz (aes-viz.js).
(function () {
  "use strict";
  const A = window.AesViz;
  const $ = (id) => document.getElementById(id);
  if (!A || !$("step-rounds")) return;

  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const hex = (b) => b.toString(16).padStart(2, "0");
  const OP_LABEL = {
    input: "Counter block",
    subBytes: "SubBytes",
    shiftRows: "ShiftRows",
    mixColumns: "MixColumns",
    addRoundKey: "AddRoundKey",
  };

  const view = { trace: [], rounds: 14, index: 0, timer: 0, detail: null };

  function explain(step, isLast) {
    switch (step.op) {
      case "input":
        return "The 16 bytes going into AES: your 12-byte IV followed by the counter 00 00 00 02 (counter 1 is saved for the tag). AES arranges them in a 4×4 grid, column by column.";
      case "subBytes":
        return "Every byte is swapped for another using a fixed lookup table, the S-box. This is AES's only non-linear step, and it stops the cipher being solved like a set of simple equations. Hover a byte to see its lookup.";
      case "shiftRows":
        return "Row 1 stays put, row 2 slides left by 1, row 3 by 2, row 4 by 3. Bytes that shared a column are now spread across different columns.";
      case "mixColumns":
        return "Each column's 4 bytes are mixed together with byte-sized arithmetic (multiplication in GF(2⁸)). Change one byte and the whole column changes. ShiftRows followed by MixColumns spreads one byte's influence over the whole block within 2 rounds.";
      case "addRoundKey":
        if (step.round === 0) return "Mix in the key: XOR each byte with round key 0, which is the first 16 bytes of your 32-byte key.";
        return isLast
          ? "The final AddRoundKey. The last round skips MixColumns. This grid is the keystream block."
          : `XOR with round key ${step.round}. The key schedule stretches your 32-byte key into 15 round keys, so every round uses different key bytes.`;
    }
    return "";
  }

  function tooltip(step, i) {
    const r = i % 4, c = Math.floor(i / 4);
    const b = step.before[i], a = step.state[i];
    switch (step.op) {
      case "subBytes": return `S-box[${hex(b)}] = ${hex(a)}`;
      case "shiftRows": return `row ${r + 1}: came from column ${((c + r) % 4) + 1}`;
      case "mixColumns": return `column ${c + 1}: mix of ${Array.from(step.before.slice(4 * c, 4 * c + 4), hex).join(" ")}`;
      case "addRoundKey": return `${hex(b)} XOR ${hex(step.roundKey[i])} = ${hex(a)}`;
      default: return `row ${r + 1}, column ${c + 1}`;
    }
  }

  // Grid cells are laid out row by row on screen, but AES state is
  // column-major, so screen position (r, c) shows byte r + 4c.
  function drawGrid(el, bytes, opts) {
    const o = opts || {};
    const frag = document.createDocumentFragment();
    for (let r = 0; r < 4; r++) {
      for (let c = 0; c < 4; c++) {
        const i = r + 4 * c;
        const d = document.createElement("span");
        d.className = "g" + (o.cls ? " " + o.cls(i) : "") + (o.changed && o.changed(i) ? " changed" : "");
        d.textContent = hex(bytes[i]);
        if (o.title) d.title = o.title(i);
        d.dataset.r = r;
        d.dataset.c = c;
        frag.appendChild(d);
      }
    }
    el.replaceChildren(frag);
    return el.children;
  }

  function animate(cells, step) {
    if (reduceMotion) return;
    const list = Array.from(cells);
    if (step.op === "shiftRows") {
      // Start each byte where it came from, then let it slide into place.
      const pitch = list[1].getBoundingClientRect().left - list[0].getBoundingClientRect().left || 0;
      list.forEach((el) => {
        const r = +el.dataset.r, c = +el.dataset.c;
        // Row r moves left by r, so every byte starts r cells to its right
        // (wrapping bytes enter from beyond the right edge).
        const shift = r;
        el.style.transition = "none";
        el.style.transform = `translateX(${shift * pitch}px)`;
      });
      requestAnimationFrame(() => requestAnimationFrame(() => list.forEach((el) => {
        el.style.transition = "";
        el.style.transform = "";
      })));
      return;
    }
    const cls = { subBytes: "a-flip", mixColumns: "a-col", addRoundKey: "a-xor", input: "a-xor" }[step.op];
    list.forEach((el) => {
      el.classList.add(cls);
      if (step.op === "mixColumns") el.style.animationDelay = `${+el.dataset.c * 90}ms`;
    });
  }

  function drawProgress() {
    const wrap = $("aes-progress");
    if (wrap.childElementCount !== view.rounds + 1) {
      const frag = document.createDocumentFragment();
      for (let r = 0; r <= view.rounds; r++) {
        const s = document.createElement("span");
        s.textContent = r === 0 ? "start" : r;
        frag.appendChild(s);
      }
      wrap.replaceChildren(frag);
    }
    const cur = view.trace[view.index].round;
    Array.from(wrap.children).forEach((s, r) => {
      s.className = r < cur ? "done" : r === cur ? "now" : "";
    });
  }

  function render(withAnimation) {
    const step = view.trace[view.index];
    if (!step) return;
    const isLast = view.index === view.trace.length - 1;

    $("aes-slider").value = view.index;
    const roundText = step.round === 0 ? "Before round 1" : `Round ${step.round} of ${view.rounds}`;
    $("aes-where").textContent = `Step ${view.index + 1} of ${view.trace.length} · ${roundText} · ${OP_LABEL[step.op]}`;
    drawProgress();

    const inputCls = step.op === "input" ? (i) => (i < 12 ? "iv" : "ctr") : null;
    drawGrid($("aes-before"), step.before, { cls: inputCls });
    const changed = step.op === "input" ? null : (i) => step.before[i] !== step.state[i];
    const cells = drawGrid($("aes-after"), step.state, {
      cls: isLast ? () => "ks" : inputCls,
      changed,
      title: (i) => tooltip(step, i),
    });
    if (withAnimation) animate(cells, step);

    $("aes-op-name").textContent = step.op === "input" ? "→" : OP_LABEL[step.op];
    const keyGrid = $("aes-key");
    if (step.op === "addRoundKey") {
      drawGrid(keyGrid, step.roundKey, { cls: () => "rk" });
      keyGrid.hidden = false;
      $("aes-key-label").textContent = `⊕ round key ${step.round}`;
    } else {
      keyGrid.hidden = true;
      $("aes-key-label").textContent = "";
    }
    $("aes-explain").textContent = explain(step, isLast);
    renderCheck(isLast);
  }

  // Prove the animation is the real thing: keystream XOR your bytes must
  // equal the ciphertext Web Crypto produced in step 4.
  function renderCheck(isLast) {
    const el = $("aes-check");
    const d = view.detail;
    if (!d) return;
    const ks = view.trace[view.trace.length - 1].state;
    const n = Math.min(16, d.plaintext.length);
    if (n === 0) {
      el.textContent = "Type a message to see the keystream combined with your bytes.";
      return;
    }
    const mine = Array.from(d.plaintext.slice(0, n), (b, i) => b ^ ks[i]);
    const real = Array.from(d.sealed.slice(0, n));
    const ok = mine.every((b, i) => b === real[i]);
    const show = (arr) => arr.map(hex).join(" ");
    el.className = "callout " + (ok ? "check-ok" : "check-bad");
    el.innerHTML = "";
    const head = document.createElement("strong");
    head.textContent = ok
      ? (isLast ? "✓ Matches Web Crypto. " : "Where this ends up: ")
      : "✗ Mismatch with Web Crypto. ";
    const body = document.createElement("span");
    body.textContent = ok
      ? `keystream ⊕ your first ${n} bytes = ${show(mine)}, exactly the ciphertext in step 4.`
      : "The JavaScript AES and Web Crypto disagree; please report this.";
    el.append(head, body);
  }

  function go(i, withAnimation) {
    view.index = Math.max(0, Math.min(view.trace.length - 1, i));
    render(withAnimation);
  }

  function stop() {
    clearInterval(view.timer);
    view.timer = 0;
    $("aes-play").textContent = "▶ Play";
    $("aes-play").setAttribute("aria-label", "Play");
  }

  function play() {
    if (view.timer) return stop();
    if (view.index >= view.trace.length - 1) go(0, true);
    $("aes-play").textContent = "⏸ Pause";
    $("aes-play").setAttribute("aria-label", "Pause");
    view.timer = setInterval(() => {
      if (view.index >= view.trace.length - 1) return stop();
      go(view.index + 1, true);
    }, reduceMotion ? 1400 : 1100);
  }

  document.addEventListener("cyro:sealed", (e) => {
    const d = e.detail;
    const block = A.gcmCounterBlock(d.iv, 2);
    const { rounds, trace } = A.encryptBlockTrace(d.keyBytes, block);
    view.detail = d;
    view.rounds = rounds;
    view.trace = trace;
    $("aes-slider").max = trace.length - 1;
    go(view.index, false);
  });

  $("aes-first").addEventListener("click", () => { stop(); go(0, true); });
  $("aes-prev").addEventListener("click", () => { stop(); go(view.index - 1, true); });
  $("aes-next").addEventListener("click", () => { stop(); go(view.index + 1, true); });
  $("aes-last").addEventListener("click", () => { stop(); go(view.trace.length - 1, true); });
  $("aes-play").addEventListener("click", play);
  $("aes-slider").addEventListener("input", (e) => { stop(); go(+e.target.value, false); });
})();
