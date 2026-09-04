# CLAUDE.md — project guide for AI agents and contributors

A from-scratch VNC client (Electron) that connects from Windows/Linux to a Mac
running built-in Screen Sharing, using Apple's proprietary RFB authentication.

## Commands

- `npm start` — launch the Electron app
- `npm test` — run the unit tests (`node --test`, no network or Electron needed)
- `npm install` — install deps (Electron + pako)

## Architecture

```
src/rfb/            Pure protocol core. Runs in Node AND a browser worker.
  crypto/           Hand-rolled md5, aes-128-ecb, modpow/bigint (no node:crypto)
  io/               Incremental big-endian Reader (NeedMoreBytes) + Writer
  protocol/         handshake, Apple DH auth (security type 30), pixel format,
                    client/server message encode/decode
  decoders/         raw, copyrect, zlib6, zrle  (encoding registry)
  inflate/          long-lived zlib streams (pako), one per connection
  keysym/           DOM key -> X11 keysym, Apple modifier profiles
  rfb-session.js    the state machine: feed(bytes) -> events, takeOutbound()
src/main/           Electron main: TCP socket, drives the session, IPC, creds
src/preload/        contextBridge (CommonJS)
src/renderer/       connection UI, input capture; worker decodes + returns frames
test/rfb/           node:test suites over synthetic wire fixtures
docs/               design spec + the verified byte-level protocol brief
```

Data flow: the main process owns the socket and the RFB session (framing only,
no decode). It ships **compressed** rectangles over a MessagePort to a renderer
worker, which decodes them and hands finished `ImageBitmap` frames to the main
renderer thread, which paints the `<canvas>`.

## Hard rules

1. **`src/rfb/**` must stay portable.** No `require('electron')`, no `net`, no
   `fs`, no `node:crypto`, no Node `zlib`, no `Buffer`. Only `Uint8Array`,
   `DataView`, `BigInt`, `TextEncoder`/`TextDecoder`. This is what lets the core
   run in both Node (tests) and the browser worker. `test/rfb/no-electron-import`
   enforces it — do not weaken it.

2. **Read encoding types as signed** (`DataView.getInt32(off, false)`). RFB
   pseudo-encodings are negative (-224 LastRect, -223 DesktopSize, -239 Cursor);
   reading them unsigned silently breaks everything two layers away.

3. **Never log credentials.** Not the password, the DH shared secret, the MD5
   key, or the credential blob — not even behind a debug flag.

4. **One-outstanding-request pump.** Exactly one FramebufferUpdateRequest in
   flight, re-armed on `updateDone`, never on a timer. Two in flight desyncs it;
   zero stalls forever (the server may not send unsolicited updates).

5. **The two inflate streams live for the whole connection and are never reset.**
   Each rectangle after the first carries no zlib header.

## Gotchas worth knowing

- The Mac pins its version to `RFB 003.889` and offers only Apple security
  types (30, 33, 35, 36). We announce `RFB 003.008` anyway, because only 3.8
  yields a diagnostic reason string on auth failure.
- Apple's modifier mapping is inverted: `Meta_L` = Option, `Alt_L`/`Super_L` =
  Command. This is gated on the `RFB 003.889` banner.
- A transferred OffscreenCanvas does **not** composite from a worker on
  Electron/Windows (renders black) — that's why frames come back to the main
  thread as ImageBitmaps instead.
- We request 16bpp RGB565 pixels (half the bytes). ZRLE is not advertised
  because its decoder assumes 3-byte CPIXELs; zlib/CopyRect/Raw cover everything.

## Testing philosophy

The protocol core is tested against synthetic fixtures built from verified byte
layouts. The highest-value test feeds each fixture **one byte at a time** and
asserts the event stream matches feeding it whole — this catches TCP
segmentation / `NeedMoreBytes` bugs. When you touch framing or a decoder, add or
extend a fixture rather than mocking.

## Before publishing changes

- `npm test` must be green.
- Keep the default host field empty (don't commit a personal LAN IP).
- Don't commit screenshots that show a real desktop's contents.
