# CTF Arsenal

A 75+ tool field console for Capture The Flag competitions — cryptography, web security, forensics, reverse engineering, binary exploitation, OSINT and competition housekeeping, all running **entirely in your browser**. No backend, no signup, no telemetry: open `index.html` (or the live GitHub Pages link) and everything works offline except the small set of libraries loaded from cdnjs on first visit.

**[Live demo →](https://0x0806.github.io/CTF-Arsenal/)**

## Why this rebuild

The previous version of this project listed 50+ tools, but roughly half of them were placeholder cards with no working logic behind them ("this tool is ready for implementation"). Every tool below is a real implementation — the kind of thing you'd actually reach for mid-competition — verified by opening all 75 tools and exercising their controls in a headless browser before every push.

Nothing here makes network requests on your behalf. Web-security tools generate payloads and parse text/headers you paste in; they never fire requests at a target. File-based tools (forensics, reverse engineering) read files with the browser's File/Canvas APIs only.

## Using it

- **⌘K / Ctrl+K** opens a command palette — type a few letters of any tool's name and hit enter.
- The search box on the dashboard does the same thing without the shortcut.
- Pick a category in the left rail to browse everything in it as cards.
- A session log on the dashboard tracks what you've opened this session (cleared when you close the tab — nothing is sent anywhere).
- Competition Utilities (challenge tracker, scratchpad notes) persist in `localStorage`, scoped to your browser only.

## What's inside

| Category | Tools | Examples |
|---|---|---|
| Cryptography (CRY) | 24 | Base64/Base32/Base58/Base85, classical ciphers + a real Vigenère cracker (chi-squared key recovery), hash generation/identification/cracking, a from-scratch RSA toy tool |
| Web Security (WEB) | 12 | SQLi/XSS/SSTI/command-injection payload sets, a full JWT decoder + HS256 secret cracker, security header analyzer, CSRF PoC generator, JS/CSS/HTML beautifier |
| Forensics (FOR) | 10 | Real PNG/JPEG chunk parsing, a byte-accurate hex viewer, ASCII/UTF-16 string extraction, pixel-level LSB steganography (extract + visualize), a real libpcap parser, file carving by signature |
| Reverse Engineering (REV) | 7 | A genuine ELF header + section table parser, a real x86-64 instruction decoder (REX/ModRM/SIB, RIP-relative addressing, jcc/setcc/cmov/movzx/movsx, syscall, endbr64), binary diffing, an entropy-per-chunk packer scanner |
| Binary Pwn (PWN) | 7 | A metasploit-compatible De Bruijn-style cyclic pattern generator + offset finder, a ret-gadget byte scanner, format-string payload builder, integer overflow calculator |
| OSINT & Misc (MSC) | 10 | QR/barcode generate & decode, Brainfuck and Whitespace interpreters, zero-width-character steganography, a layered "magic" auto-decoder, Unicode homoglyph inspector |
| Competition Utils (UTL) | 6 | Challenge tracker, scratchpad notes, countdown timer + stopwatch, writeup template generator, targeted wordlist generator, text diff |

## Running it locally

No build step — it's three static files.

```bash
git clone https://github.com/0x0806/CTF-Arsenal.git
cd CTF-Arsenal
python3 -m http.server 8000
# open http://localhost:8000
```

Or just open `index.html` directly in a browser; everything but the CDN-hosted libraries (crypto-js, jszip, node-forge, qrcode/jsQR, JsBarcode, js-beautify, Font Awesome) works fully offline.

## Design

Dark console UI built around a command palette as the primary way to move between tools (the way CTF players actually work: fast, keyboard-first, many tools in quick succession), a persistent session log, and a real catalog numbering scheme (`CRY-07`, `PWN-02`, …) so tools can be referenced precisely. Typeface pairing is IBM Plex Mono + IBM Plex Sans; a light console theme is available via the toggle in the rail.

## Responsible use

Everything here is for learning, authorized CTF competitions, and security testing you have explicit permission to perform. The RSA tool deliberately generates tiny, breakable keys for teaching the math — never use it for anything that needs to stay secret. Shellcode and payload references are standard CTF/pentest material; use them only against your own systems or systems you're authorized to test.

## License

MIT — see [LICENSE](LICENSE).

---

Built by [0x0806](https://github.com/0x0806).
