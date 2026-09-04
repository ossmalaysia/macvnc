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
- 🧪 **88 unit tests**, protocol core runs headlessly with zero dependencies

## Requirements

- **Node.js 20+** on the client machine (developed on Node 24)
- A **Mac** with Screen Sharing enabled
- The two machines on the same network

## Quick start

```bash
git clone https://github.com/jazztong/macvnc.git
cd macvnc
npm install
npm start
```

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

For the full byte-level details — including the Apple type-30 auth handshake and a ranked list of the traps a from-scratch RFB client falls into — see [`docs/research/rfb-3889-protocol-brief.md`](docs/research/rfb-3889-protocol-brief.md).

## Performance and limitations

This is honest about its ceiling. Standard VNC is **demand-driven**: the client asks, the Mac sends one frame, repeat — one frame per network round trip. Commercial tools like TeamViewer feel smoother because they run their own agent on the Mac that captures and H.264-streams the screen continuously; they don't use Screen Sharing at all.

So: this is tuned about as far as the Screen Sharing protocol allows (zlib encoding, RGB565, no render throttling), and on a LAN it's very usable for real work — but a full-screen video or a fast drag of a large window will show the protocol's limits. That's structural, not a bug.

## Development

```bash
npm test      # 88 unit tests, node:test, no network or Electron needed
npm start     # launch the app
```

The protocol core (`src/rfb/`) is tested against synthetic wire fixtures built from the verified byte layouts, including a "feed every fixture one byte at a time" test that catches TCP-segmentation bugs. See [`CLAUDE.md`](CLAUDE.md) for the architecture and the rules that keep the core portable.

## Security notes

- The password is encrypted at rest with Electron's `safeStorage` (Windows DPAPI / macOS Keychain / libsecret), tied to your OS account. Only a base64 ciphertext is written to disk.
- Every failed login is a **real** failed login against your macOS account. The app never auto-retries a rejected password, to avoid tripping account lockout.
- RFB itself is unencrypted on the wire. Use this on a trusted local network, or tunnel it over SSH / a VPN, not across the open internet.

## License

[MIT](LICENSE) — free to use, modify, and share.

## Credits

Built from scratch as an exploration of the RFB protocol and Apple's Screen Sharing authentication. Not affiliated with or endorsed by Apple. "VNC" is a trademark of its respective owner; this project is an independent, clean-room RFB client.
