// caesar-ui.js — step 8: Caesar cipher next to AES, plus a brute-force crack.
// Listens for "cyro:sealed" (from app.js) for the message and AES output.
(function () {
  "use strict";
  const K = window.Caesar;
  const C = window.Cipher;
  const $ = (id) => document.getElementById(id);
  if (!K || !C || !$("step-caesar")) return;

  const GROUP_CLASSES = ["g-salt", "g-iv", "g-key", "g-tag", "g-ct"];
  const hex = (b) => b.toString(16).padStart(2, "0");
  const view = { message: "", aes: null, plainLen: 0, shift: 3 };

  function drawMap() {
    const letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const shifted = K.encrypt(letters, view.shift);
    $("caesar-map").textContent = Array.from(letters, (l, i) => `${l}→${shifted[i]}`).join("  ");
  }

  function drawGrid() {
    const grid = $("caesar-grid");
    const groups = K.repeatedLetters(view.message);
    const caesar = K.encrypt(view.message, view.shift);
    const caesarChars = Array.from(caesar);
    const frag = document.createDocumentFragment();
    let offset = 0;
    const examples = new Map(); // letter -> { caesar, aes: [] }

    C.charBytes(view.message).forEach(({ char, bytes }, i) => {
      const lower = char.toLowerCase();
      const group = groups.has(lower) ? GROUP_CLASSES[groups.get(lower) % GROUP_CLASSES.length] : "";
      const aesByte = view.aes && offset < view.aes.length ? view.aes[offset] : null;
      offset += bytes.length;

      const col = document.createElement("div");
      col.className = "ccol" + (group ? " " + group : "");
      const top = document.createElement("span");
      top.className = "c-plain" + (char.trim() ? "" : " space");
      top.textContent = char.trim() ? char : "·";
      const mid = document.createElement("span");
      mid.className = "c-caesar";
      mid.textContent = char.trim() ? caesarChars[i] : "·";
      const bot = document.createElement("span");
      bot.className = "c-aes";
      bot.textContent = aesByte === null ? "" : hex(aesByte);
      col.append(top, mid, bot);
      frag.appendChild(col);

      if (group && aesByte !== null) {
        if (!examples.has(lower)) examples.set(lower, { caesar: caesarChars[i].toLowerCase(), aes: [], count: 0 });
        const ex = examples.get(lower);
        ex.count++;
        if (ex.aes.length < 3) ex.aes.push(hex(aesByte));
      }
    });
    grid.replaceChildren(frag);
    drawLeak(examples);
  }

  function drawLeak(examples) {
    const el = $("caesar-leak");
    el.replaceChildren();
    if (!view.message.trim()) {
      el.textContent = "Type a message above to compare.";
      return;
    }
    if (examples.size === 0) {
      el.textContent = "Your message has no repeated letters. Try one like “Meet me at 6” to see the pattern a Caesar cipher leaks.";
      return;
    }
    // The most repeated letter makes the clearest example.
    const [letter, ex] = [...examples.entries()].sort((x, y) => y[1].count - x[1].count)[0];
    const b = document.createElement("strong");
    b.textContent = "The leak: ";
    const t = document.createElement("span");
    const aesList = ex.aes.join(", ");
    t.textContent =
      `“${letter}” appears ${ex.count} times and Caesar turns it into “${ex.caesar}” every time, so repeated letters stay visible (same colours). ` +
      `AES turned the same “${letter}” into ${aesList}: no pattern to follow.`;
    el.append(b, t);
  }

  function crack() {
    const out = $("caesar-result");
    out.replaceChildren();
    const ciphertext = K.encrypt(view.message, view.shift);
    if (!/[a-z]/i.test(ciphertext)) {
      out.textContent = "There are no letters to crack. Type a message with words in it.";
      return;
    }
    const t0 = performance.now();
    const tries = K.bruteForce(ciphertext);
    const ms = performance.now() - t0;
    const best = tries[0];

    const head = document.createElement("p");
    head.className = "callout check-ok";
    const s = document.createElement("strong");
    s.textContent = `Cracked in ${ms < 1 ? "under 1" : ms.toFixed(0)} ms. `;
    const span = document.createElement("span");
    span.textContent = `Best guess: shift ${best.shift} → “${best.text}”` +
      (best.shift === view.shift ? " (correct)." : ". Not right? The answer is still in the list below; a person spots it at a glance.");
    head.append(s, span);

    const list = document.createElement("ol");
    list.className = "tries";
    tries.slice().sort((x, y) => x.shift - y.shift).forEach((t) => {
      const li = document.createElement("li");
      li.className = t.shift === best.shift ? "best" : "";
      const k = document.createElement("span");
      k.className = "k";
      k.textContent = String(t.shift).padStart(2, " ");
      const v = document.createElement("span");
      v.textContent = t.text;
      li.append(k, v);
      list.appendChild(li);
    });

    const scale = document.createElement("p");
    scale.className = "callout";
    const s2 = document.createElement("strong");
    s2.textContent = "Why AES can't be cracked this way: ";
    const t2 = document.createElement("span");
    t2.textContent =
      "Caesar has 25 possible keys. AES-256 has 2²⁵⁶, about 1.2 × 10⁷⁷. Even at a billion billion guesses per second, " +
      "trying them all would take about 3.7 × 10⁵¹ years, far longer than the universe has existed (1.4 × 10¹⁰ years). " +
      "That's why attackers go after the password instead, and why step 2 makes every password guess slow.";
    scale.append(s2, t2);

    out.append(head, list, scale);
  }

  function update() {
    drawMap();
    drawGrid();
    $("caesar-result").replaceChildren();
  }

  document.addEventListener("cyro:sealed", (e) => {
    view.message = $("message").value;
    view.aes = e.detail.sealed.slice(0, e.detail.sealed.length - C.TAG_LEN);
    update();
  });

  $("caesar-shift").addEventListener("input", (e) => {
    view.shift = +e.target.value;
    $("caesar-shift-value").textContent = String(view.shift);
    update();
  });
  $("caesar-crack").addEventListener("click", crack);
})();
