# VNC Client for macOS Screen Sharing — Design

**Date:** 2026-09-05
**Target:** Mac mini at `192.168.68.125:5900`, banner `RFB 003.889`
**Client platform:** Windows 11, Electron + Node 24

---

## 1. Problem

Off-the-shelf VNC clients cannot connect to a stock Mac. Live probing of the target
confirms it offers security types `30, 33, 36, 35` only — standard **VNC Auth (type 2)
is absent**, and the server pins its version to `RFB 003.889` regardless of what the
client announces. There is no fallback: Apple's Diffie-Hellman auth (type 30) must be
implemented or nothing connects.

This project builds a VNC client from scratch — protocol, auth, decoders, input — that
speaks Apple's dialect and gives full remote control of the Mac mini from Windows.

## 2. Goals / Non-goals

**Goals**

- Authenticate with a real macOS account via Apple security type 30.
- Render the Mac's screen at usable frame rates, including during video playback.
- Full input: mouse, scroll, keyboard with a correct Command-key mapping, clipboard.
- A protocol core that is unit-testable headlessly, with no Electron and no network.

**Non-goals (v1)**

- Security types 33/35/36 (SRP). No public byte-level spec exists; type 30 is proven working.
- Apple's proprietary high-performance encodings (`0x3e8`–`0x3f3`).
- File transfer, multi-monitor selection, session recording, SSH tunnelling.
- Reaching `Ctrl+Alt+Del` or `Win+L` on the Windows side — the OS reserves both.

## 3. Architecture

Chosen after weighing IPC cost: **decode in a renderer worker, ship compressed bytes
across IPC.** The alternative — decoding in Node and shipping RGBA — pushes 8.3 MB per
1080p frame through IPC and hits a measured ~26–34 ms/frame ceiling that collapses
under video or fast scrolling. Shipping compressed payloads makes IPC volume equal
network volume (~40 KB/frame with ZRLE).

```
  utilityProcess                MessagePort               renderer worker
┌────────────────────┐       (transferables,       ┌──────────────────────────┐
│ net.Socket         │        zero-copy)           │ inflate x2 (ZRLE, zlib6) │
│ RFB state machine  │ ──────────────────────────► │ decoders: Raw/CopyRect/  │
│ rectangle slicing  │   {meta:Int32Array,         │           zlib6/ZRLE     │
│ Apple type-30 auth │    payload:Uint8Array}      │ WebGL2 texSubImage2D     │
└────────────────────┘                             │ OffscreenCanvas          │
         ▲                                         └──────────────────────────┘
         │ input events (small)                              ▲
         └───────────────────────────────────────────────────┘

  main process: BrowserWindow (contextIsolation on, nodeIntegration off,
  sandbox on) + MessageChannelMain
```

**The load-bearing constraint:** `src/rfb/**` must run identically in Node and the
browser — no `require('electron')`, no `net`, no `Buffer`, no Node `zlib`. That forces
a vendored pure-JS incremental inflater, and it is what makes the core headlessly
testable. Enforced by an ESLint rule *and* a CI test that greps the tree, so violations
fail the build rather than surfacing at runtime.

### Module layout

| Path | Responsibility |
|---|---|
| `src/rfb/rfb-session.js` | Pure state machine: `feed(bytes)` returns events, `takeOutbound()` returns bytes. No sockets, promises or timers. |
| `src/rfb/io/reader.js` | Incremental big-endian reader; throws `NeedMoreBytes`, session rewinds and re-enters. |
| `src/rfb/io/writer.js` | Fixed-offset message builder; padding always zeroed. |
| `src/rfb/protocol/handshake.js` | Banner parse, version reply, security-list parse. |
| `src/rfb/protocol/security/apple-dh.js` | Type 30. Pure function returning the 256-byte payload. Never logs key material. |
| `src/rfb/protocol/pixel-format.js` | The 16-byte PixelFormat struct and derived tables. |
| `src/rfb/protocol/messages/client.js` | SetPixelFormat, SetEncodings, FramebufferUpdateRequest, KeyEvent, PointerEvent, ClientCutText, ClientInit. |
| `src/rfb/protocol/messages/server.js` | FramebufferUpdate, SetColourMapEntries, Bell, ServerCutText. |
| `src/rfb/framebuffer-update.js` | Resumable rectangle loop; LastRect break; untrusted rect count. |
| `src/rfb/decoders/raw.js` | Encoding 0. |
| `src/rfb/decoders/copyrect.js` | Encoding 1, overlap-safe. |
| `src/rfb/decoders/zlib6.js` | Encoding 6. |
| `src/rfb/decoders/zrle.js` | Encoding 16, 64x64 tiles, 8 subencoding families. |
| `src/rfb/inflate/inflate.js` | Vendored incremental inflater: `setInput`, `inflate(n)`, `reset`. |
| `src/rfb/keysym/` | DOM-key to keysym tables, Apple modifier profiles. |
| `src/service/vnc-service.js` | utilityProcess: owns socket, drives session, emits frame envelopes. |
| `src/main/index.js` | BrowserWindow, `utilityProcess.fork`, `MessageChannelMain`. |
| `src/preload/index.js` | ~15 lines: hand the MessagePort to the renderer. Never on the per-frame path. |
| `src/renderer/workers/vnc-worker.js` | OffscreenCanvas, WebGL2, decoders, rAF tick. |

## 4. Connection sequence

1. Read the 12-byte banner. Reply with the 12 bytes **`RFB 003.008\n`** (trailing
   newline included; the field is fixed-width) — measured: announcing 003.008
   yields the RFB 3.8 failure-reason string, while 003.889 gives a bare 4-byte result
   and a close. Same security list either way, so we take the diagnostics.
2. Read `U8 count` plus `U8[count]` types. **Scan** for type 30 by value, never by index.
3. Send `0x1E`.
4. Read `U16BE generator`, `U16BE keyLength`, `U8[L] prime`, `U8[L] serverPublic`.
   Observed: g=2, L=128, prime equal to RFC 2409 Oakley Group 2. **Read both from the
   wire and size every buffer from `keyLength`** — never hardcode.
5. Derive `A = g^x mod p` and `S = serverPub^x mod p`, both **left-zero-padded to exactly L**.
6. `K = MD5(S_padded)`, giving 16 bytes.
7. Build a 128-byte plaintext: fill with CSPRNG bytes, then username at bytes 0–63 and
   password at bytes 64–127, each UTF-8, NUL-terminated, capped at 63 bytes.
   Random slack, not zeros — under ECB, zero padding leaks credential lengths.
8. `C = AES-128-ECB(K, P)` with **auto-padding off**; assert exactly 128 bytes out.
9. Write ciphertext then public key — **ciphertext first**, 128 + L = 256 bytes total.
10. Read `U32BE` SecurityResult. On failure read the reason and **drain one extra
    trailing `0x00`** that Apple sends outside the declared length.
11. ClientInit, ServerInit, SetPixelFormat, SetEncodings, first update request.

## 5. Pixel format and encodings

SetPixelFormat: 32 bpp, **depth 24**, little-endian, true-colour, maxes 255,
shifts **red 0 / green 8 / blue 16**. This makes Raw, CPIXEL and TPIXEL all yield
R,G,B order — the alternative (16/8/0) produces two different byte orders inside one client.

Sent in a fixed order — SetPixelFormat, SetEncodings, *then* the first update request —
because changing format with a request outstanding makes the next update's format ambiguous.

Advertised set, in preference order:
`[16 ZRLE, 6 zlib, 1 CopyRect, 0 Raw, -239 Cursor, -223 DesktopSize, -224 LastRect]`

Apple supports Raw, CopyRect, zlib and ZRLE — **not** Tight, Hextile, RRE or TRLE.
We advertise only what is fully implemented, because an unrecognised encoding type has
no length field and cannot be skipped: it is an unrecoverable desync, not a warning.
We never advertise the VMware cursor pseudo-encodings — Apple responds by silently
sending no cursor updates at all.

ZRLE and zlib(6) each use **one inflate stream for the whole connection**, never reset,
decoded strictly in order.

## 6. Input

- **PointerEvent** carries scroll as button 4/5/6/7 press-and-release pairs.
- **Command key:** on Apple, `Meta_L` maps to *Option* and `Alt_L` / `Super_L` map to
  *Command* — the opposite of the intuitive reading. Gated on detecting the literal
  `RFB 003.889` banner, since OSXvnc-family servers differ.
- **Profile A (default):** `ControlLeft` becomes `Super_L` (Command), so Ctrl+C / Ctrl+V /
  Ctrl+Space become Cmd chords; `ControlRight` stays `Control_R`, keeping real Control
  reachable for Terminal's `^C`, `^A`, `^E`. `Alt` becomes `Meta` (Option).
- **Profile B (toggle):** label-faithful, for Apple keyboards or when keyboard-lock is armed.
- A pressed-key ledger keyed on `KeyboardEvent.code` stores the keysym **actually sent**
  and replays it on keyup, so Shift+2 producing `@` releases `@` rather than `2`.
  Release-all fires on blur, visibilitychange, window hide/minimize and disconnect; a
  modifier sweep runs on focus regain. A latched modifier makes the remote session
  unusable until someone physically intervenes at the Mac.
- Soft-key menu for chords Windows intercepts: Cmd-Tab, Cmd-Space, Cmd-Q.

## 7. Error handling

- Every `U32` length from the wire is capped before allocation (1 MiB clipboard,
  64 KiB name, 32 MiB zlib chunk); overflow aborts the connection.
- Encoding type is read as **signed** `getInt32` in exactly one place — unsigned reads
  turn `-224 LastRect` into 4294967072 and fail two layers from the cause.
- `Bell` is a **one-byte** message; the dispatcher reads one type byte then branches,
  never assuming a 4-byte header.
- Auth failure surfaces the server's reason verbatim, with a note that it cannot
  distinguish a wrong password from an account lacking Screen Sharing rights.
- "Connection refused" is reported distinctly from "auth failed", naming FileVault
  pre-boot as a cause — `screensharingd` is not running before the first local unlock.
- **Never auto-retry a rejected password.** Each attempt is a real failed login against
  a real macOS account and can trip lockout and MDM alerting.

## 8. Testing

- `node --test`, zero dependencies, no Electron, no network.
- **Fixture strategy.** Capturing real wire fixtures needs an authenticated connection,
  which is not available until the build is finished — so the whole client is developed
  against **synthetic fixtures hand-constructed from the verified byte layouts** in
  `docs/research/rfb-3889-protocol-brief.md`, whose auth and handshake sections were
  captured live and are byte-exact. Unauthenticated fixtures (the 12-byte banner, the
  5-byte security list, the 260-byte type-30 parameter block) can be re-captured from
  the Mac at any time without credentials, and are.
  Post-authentication fixtures — a FramebufferUpdate per encoding, a `ServerCutText`
  with non-ASCII text — are recorded during the single live test session and then kept
  as regression fixtures. This is the trade the "build everything, test once" choice
  implies: decoders are written against a spec rather than against observed bytes, so
  decoder bugs surface at first connection rather than incrementally.
- **Highest-value single test:** feed every fixture **one byte at a time** and assert the
  emitted event stream is identical to feeding it whole. This catches nearly every
  framing and `NeedMoreBytes` bug in one assertion.
- A unit test forces a leading-zero DH public key via a fixed private exponent and
  asserts the emitted field is exactly `keyLength` bytes.
- `test/harness/fake-server.js` replays fixtures for integration tests without the hardware.
- Manual acceptance: connect, see the desktop, click, type, copy-paste a string both
  ways, **and play video on the Mac** before declaring it done.

## 9. Credential handling

The app prompts for the macOS username and password in its own UI. Credentials are
never written to disk, never logged, never placed in a file the assistant reads, and
never echoed into the terminal. The DH shared secret, the MD5 key and the credential
blob are excluded from all logging paths, and parameter parsing is kept on a separate
call path from credential submission so handshake debugging can never submit them.

## 10. Reference

Full verified protocol brief, including byte-level layouts and 15 ranked implementation
risks: `docs/research/rfb-3889-protocol-brief.md`
