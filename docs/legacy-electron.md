# macvnc — a free VNC client for macOS Screen Sharing

A from-scratch VNC client that connects **from Windows (or Linux) to a Mac** running the built-in **Screen Sharing**, with no third-party account, no subscription, and no agent to install on the Mac. See your Mac's screen and control it with your mouse, keyboard, and clipboard.

Built because ordinary VNC clients **can't connect to a stock Mac** — and it turns out the reason is interesting.

---

## Why this exists

Turn on Screen Sharing on a Mac and point TightVNC / UltraVNC / RealVNC at it, and most of them fail to authenticate. That's not a bug in those clients — a stock Mac offers **only Apple's proprietary security types** over RFB. Standard VNC password auth (the DES challenge every classic client speaks) simply isn't on the menu unless you dig into a legacy checkbox.

So this client implements **Apple's authentication directly**: a Diffie-Hellman key exchange (RFC 2409 Oakley Group 2), an MD5-derived AES-128 key, and an encrypted credential blob — the same handshake Apple's own Screen Sharing.app uses. You log in with your **real macOS account**, no separate VNC password required.

Everything — the crypto, the RFB protocol, the image decoders — is written from scratch in plain JavaScript. The only runtime dependency is [pako](https://github.com/nodeca/pako) for DEFLATE.

## Inspiration

Remote desktop to a Mac usually means reaching for a paid tool — TeamViewer, AnyDesk, a subscription. But the Mac already has everything you need: Screen Sharing is built in and free. The only thing standing between you and it is Apple's undocumented authentication, which is exactly why the free VNC clients bounce off it.

So this project set out to prove a point: **with an AI coding agent, one person can reverse-engineer a proprietary protocol and build a real, working client from nothing — and give it away.** The Apple type-30 handshake here wasn't copied from a library (there isn't one for JavaScript); it was reconstructed byte by byte by probing a live Mac, verifying each field against the RFC and open-source implementations, and adversarially checking the findings before a line of code was written. Then the crypto, the RFB state machine, and the decoders were built and tested the same way.

The result is free remote access to your own Mac, owned entirely by you — no account, no cloud relay, no subscription, no telemetry. If it's useful to you, that's the whole point. Fork it, learn from it, make it better.

## Features

- 🔓 **Apple authentication** (RFB security type 30) — connects to a stock Mac with your macOS account
- 🖥️ **Live screen** — zlib / CopyRect / Raw decoding, RGB565 for low latency on a LAN
- 🖱️ **Full control** — mouse, scroll, keyboard, and two-way clipboard text
- ⌨️ **Correct key mapping** — Windows→macOS modifiers (Ctrl acts as ⌘ by default, or a Native profile)
- 💾 **Saved connections** — remember host/user, password encrypted at rest via the OS keychain, optional auto-connect
- 🖼️ **Fullscreen** — F11 (or Ctrl+Shift+F)
- 🧪 **114 unit tests**, protocol core runs headlessly with zero dependencies

## Requirements

- A **Windows, Linux or macOS** machine to run the client on
- A **Mac** with Screen Sharing enabled (see below)
- Both machines on the same network
- *Only if running from source:* **Node.js 20+** (developed on Node 24)

## Install

### Option 1 — download an installer (no tools needed)

Grab the file for your platform from the
**[latest release](https://github.com/ossbusinessmy/macvnc/releases/latest)**:

| Platform | File | Notes |
|---|---|---|
| **Windows** | `macvnc Setup <version>.exe` | Normal installer |
| **Windows** | `macvnc <version>.exe` | Portable — just run it, nothing installed |
| **Linux** | `macvnc-<version>.AppImage` | `chmod +x` then run |
| **macOS** | `macvnc-<version>.dmg` | Open and drag to Applications |

> ⚠️ **These builds are unsigned** — there's no paid code-signing certificate behind
> this project. Your OS will warn you:
> - **Windows:** "Windows protected your PC" → **More info** → **Run anyway**
> - **macOS:** right-click the app → **Open** (instead of double-clicking)
>
> That warning is expected for unsigned open-source software. Only bypass it because
> you trust this source — or build from source yourself (Option 2), which needs no
> such trust.

### Option 2 — run from source

Needs [Node.js](https://nodejs.org) 20+ and git.

```bash
git clone https://github.com/ossbusinessmy/macvnc.git
cd macvnc
npm install
npm start
```

To build your own installer: `npm run dist:win` (or `dist:linux` / `dist:mac`).
Output lands in `dist/`.

## Enable Screen Sharing on the Mac

1. **System Settings → General → Sharing → Screen Sharing → On**
2. Click the ⓘ next to Screen Sharing and make sure **your user account** is allowed.

That's all — you do **not** need "Remote Management," and you do **not** need to enable the legacy "VNC viewers may control screen with password" option.

## Connect

1. Enter the Mac's **IP address** (System Settings → Wi-Fi → Details shows it) and port **5900**.
2. Enter your **macOS account name and password** (the short name or full name both work).
3. Tick **Remember** to save the connection, **Auto-connect** to reconnect on launch.
4. Click **Connect**.

Your credentials are used only for the Apple handshake to your Mac. The password is never sent anywhere else, never written in plain text, and never logged.

## How it works

```
   Windows / Linux                                        Mac
┌─────────────────────────────────────────────┐      ┌──────────────────┐
│ Electron main process                        │      │  Screen Sharing  │
│   TCP socket ── RFB 3.889 protocol ──────────┼──────┤  (screensharingd)│
│   Apple DH + AES-128 auth                    │ 5900 │                  │
│        │ compressed rectangles (MessagePort) │      └──────────────────┘
│        ▼                                     │
│ Renderer worker: zlib / CopyRect / Raw decode│
│        │ finished frames (ImageBitmap)        │
│        ▼                                     │
│ Main thread: paints the <canvas>             │
└─────────────────────────────────────────────┘
```

The interesting parts:

- **`src/rfb/`** is a pure protocol core — no Electron, no Node networking, no `Buffer`. It runs identically in Node (for tests) and in a browser worker. A CI-style test greps the tree to keep it that way.
- **Decode happens in a worker**, and only *compressed* rectangles cross between processes — so bandwidth over the internal boundary equals bandwidth over the network, not the size of a decoded frame.
- **RGB565 pixels** (16-bit) are requested instead of 32-bit. On a LAN the Mac encodes and ships each frame in roughly half the time — the same trick Apple's own client uses at its "High" quality tier, reached here through the standard `SetPixelFormat` path.

For the full byte-level details — including the Apple type-30 auth handshake and a ranked list of the traps a from-scratch RFB client falls into — see [`docs/research/rfb-3889-protocol-brief.md`](research/rfb-3889-protocol-brief.md).

## Design decisions and optimizations

Each of these was chosen deliberately and, where it affects latency, measured against a live Mac:

| Decision | Why |
|---|---|
| **Portable protocol core** (`src/rfb/` uses no Node/Electron APIs) | Runs identically in Node (fast, headless unit tests) and in the browser worker. A test greps the tree to enforce it. |
| **Decode in a worker, ship compressed rectangles** | Only compressed bytes cross the process boundary, so internal bandwidth = network bandwidth, not the size of a decoded frame (~8 MB at 1440p). |
| **Frames returned as `ImageBitmap`, painted on the main thread** | A transferred `OffscreenCanvas` renders black from a worker on some Electron/GPU combos; handing back an `ImageBitmap` composites reliably and is a zero-copy transfer. |
| **zlib encoding preferred over ZRLE** | On a LAN the Mac encodes zlib far faster. Measured server response per frame dropped from **137–620 ms (ZRLE) to 9–76 ms (zlib)**. Bandwidth isn't the constraint on a LAN; the Mac's encode time is. |
| **16-bit RGB565 pixels instead of 32-bit** | Halves the bytes the Mac encodes and ships per frame — the same win Apple's own client gets from its `0x3ea` "High" encoding, reached here through the standard `SetPixelFormat` path. |
| **CopyRect kept high-priority** | Lets the Mac say "move this region" instead of re-encoding it — cheap window drags. |
| **One-outstanding-request pump, no render throttling** | Exactly one frame request in flight (never a timer); `backgroundThrottling: false` keeps decoding at full rate when the window isn't foreground. |

The net effect: on a LAN this is tuned about as far as **standard** Screen Sharing allows, and it's very usable for real work.

## Limitations, and a better approach

Be clear about the ceiling. Standard VNC is **demand-driven**: the client asks, the Mac sends one frame, repeat — one frame per network round trip. And the standard-RFB tricks that make clients like [TurboVNC](https://github.com/TurboVNC/turbovnc) fast (Tight + JPEG, adaptive quality) **don't help against a Mac** — Apple's `screensharingd` only sends Raw / CopyRect / zlib / ZRLE, never Tight. So a full-screen video or a fast drag of a large window will show the protocol's limits. That's structural, not a bug.

**The real path to commercial-tool smoothness is a different protocol.** Apple's own *High Performance* Screen Sharing doesn't send rectangles at all — it streams **HEVC (H.265) 4:4:4 video over UDP/SRTP**, hardware-decoded, with no per-frame round trip. That's why Apple's Screen Sharing.app and tools like TeamViewer feel smoother.

### High Performance (HEVC) mode — experimental, incomplete

An implementation lives in `src/rfb-hp/`. It is **developer-only**, gated behind the
`VNC_HP_PROBE` environment variable, and **does not render a correct picture yet**.
Be clear about what is and isn't proven, measured against a live Apple-Silicon Mac:

| Stage | Status |
|---|---|
| Reaching HP mode over the existing type-30 auth (no SRP needed) | ✅ proven |
| AES-128-CBC encrypted control channel (both directions) | ✅ proven |
| Virtual display + metadata (`0x451`/`0x453`/`0x455`/`0x456`) | ✅ decrypted |
| `0x1c` media negotiation — the Mac starts streaming | ✅ proven |
| SRTP decrypt | ✅ **7791/7791 packets, 0 HMAC failures** |
| HEVC decode via WebCodecs | ✅ real pixels decode |
| **Tile grouping + compositing** | ❌ **broken — the image is wrong** |

The failure is specific and understood: the depacketizer assumes four *equal
horizontal bands* grouped by matching RTP timestamp. Live traffic contradicts that —
the four tile SSRCs carry wildly uneven packet counts (e.g. `228 / 311 / 969 / 6283`),
only ~57 access units are assembled from ~7800 packets, and the composited output
repeats one strip four times instead of showing four distinct regions. **The tile
model is wrong**; fixing it means re-deriving how SSRCs map to screen regions rather
than inferring it.

So: the protocol, crypto and transport are demonstrably correct; the *rendering* is
not. Don't use HP mode expecting a working remote desktop. Contributions welcome —
see [`docs/hp-mode/`](hp-mode/) for byte-level blueprints of every component.

### Other known limitations

- **RFB traffic is unencrypted** on the wire (see [SECURITY.md](../SECURITY.md)). LAN or tunnel only.
- **No sandbox** on the renderer (`sandbox: false`) — a deliberate, documented trade-off.
- Standard-VNC mode is **view + control only**: no file transfer, no audio, no multi-monitor selection, no session recording.
- `Ctrl+Alt+Del` and `Win+L` cannot be forwarded — Windows reserves them.
- Tested against Apple Screen Sharing only. Other VNC servers (TightVNC, x11vnc, …) are **not** supported: the client requires Apple security type 30 and does not implement standard VNC password auth.
- Tested on Windows against one Apple-Silicon Mac (macOS Sonoma+). Linux and older/Intel Macs are unverified.

## Related projects and prior art

- **[iShareScreen](https://github.com/renegadelink/iShareScreen)** — cross-platform Python client for Apple's *High Performance* mode (HEVC over UDP/SRTP). The reference for the low-latency path described above.
- **[RoyalVNC](https://github.com/royalapplications/royalvnc)** — a modern, high-performance RFB implementation in Swift.
- **[vvncc](https://github.com/Eden-Sun/vvncc)** — iPad/iPhone VNC client for macOS Screen Sharing (Swift RFB core, Metal dirty-rect rendering).
- **[TigerVNC](https://github.com/TigerVNC/tigervnc)** / **[TurboVNC](https://github.com/TurboVNC/turbovnc)** — high-performance general-purpose VNC (Tight + JPEG); great references, though their speed tricks target non-Apple servers.
- **[noVNC](https://github.com/novnc/noVNC)** — the canonical JavaScript RFB client; invaluable for decoder and keysym reference.

## Development

```bash
npm test      # 114 unit tests, node:test, no network or Electron needed
npm start     # launch the app
```

The protocol core (`src/rfb/`) is tested against synthetic wire fixtures built from the verified byte layouts, including a "feed every fixture one byte at a time" test that catches TCP-segmentation bugs. See [`AGENTS.md`](../AGENTS.md) for the architecture and the rules that keep the core portable.

## Security

Full policy, threat model and scan results: **[SECURITY.md](../SECURITY.md)**. In short:

- **Your credentials go to your Mac and nowhere else.** No telemetry, no analytics, no cloud, no outbound requests. The password is encrypted at rest via Electron `safeStorage` (DPAPI/Keychain/libsecret) and is never logged.
- **RFB traffic is unencrypted on the wire** — only the auth handshake is protected. Use a trusted LAN or an SSH/VPN tunnel; never expose port 5900 to the internet.
- Every failed login is a **real** failed login on that Mac, so the client never auto-retries a rejected password.
- Hardened renderers: `contextIsolation` on, `nodeIntegration` off, strict CSP, no inline scripts, no remote code. **`sandbox: false` is a known, documented gap.**
- All wire-supplied lengths are bounds-capped before allocation; decoders clip to framebuffer bounds; SRTP rejects packets failing HMAC.
- **HP mode is reverse-engineered and unaudited.** Developer-only, off by default.

Latest scan (2026-09-05): `npm audit` **0 vulnerabilities** (runtime + dev), one runtime dependency (`pako`), no secrets in tracked files. Electron was upgraded 38.8.6 → 44.2.0 to clear a HIGH advisory.

Report vulnerabilities privately via [GitHub Security Advisories](https://github.com/ossbusinessmy/macvnc/security/advisories/new).

## License

[MIT](../LICENSE) — free to use, modify, and share.

## Credits

Built from scratch as an exploration of the RFB protocol and Apple's Screen Sharing authentication. Not affiliated with or endorsed by Apple. "VNC" is a trademark of its respective owner; this project is an independent, clean-room RFB client.
