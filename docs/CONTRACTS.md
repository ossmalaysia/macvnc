# Module Contracts — implement to these exactly

Every module is **ESM** (`export` / `import`). `package.json` has `"type": "module"`.

## Hard rules for `src/rfb/**`

- **No** `require`, no `electron`, no `net`, no `Buffer`, no Node `zlib`, no `fs`, no timers.
- Only `Uint8Array`, `DataView`, `BigInt`, `Math`, `TextEncoder`/`TextDecoder`.
- Must run byte-identically in Node and in a browser worker.
- Crypto (MD5, AES) is hand-rolled in `src/rfb/crypto/` — **not** Node `crypto` — because
  this code also runs in the worker. Pure functions over `Uint8Array`.

## Architecture note (deviation from spec §3, deliberate)

The socket lives in the **Electron main process**, not a `utilityProcess`. Rationale:
ESM support in `utilityProcess` is unconfirmed, and the main process supports ESM in
Electron 28+. The load-bearing decision is unchanged — **compressed rectangle payloads
cross IPC and are decoded in a renderer worker**, so IPC volume equals network volume.

---

## `src/rfb/io/reader.js`

```js
export class NeedMoreBytes extends Error {}

export class Reader {
  push(chunk /* Uint8Array */)   // append to internal queue
  get remaining()                // bytes from cursor to end
  mark()                         // save cursor
  rewind()                       // restore to last mark
  commit()                       // discard everything before cursor (call after a full message)
  u8()                           // -> number,  throws NeedMoreBytes
  u16()                          // -> number, BIG-ENDIAN
  u32()                          // -> number, BIG-ENDIAN unsigned
  i32()                          // -> number, BIG-ENDIAN SIGNED  (encoding types!)
  bytes(n)                       // -> Uint8Array (copy), throws NeedMoreBytes
  skip(n)
}
```

Usage pattern in the session: `mark()`, parse, `commit()`; on `NeedMoreBytes` call
`rewind()` and wait for the next chunk. This is what makes partial TCP segments correct.

## `src/rfb/io/writer.js`

```js
export class Writer {
  constructor(length)        // allocates exactly `length` bytes, zero-filled
  u8(v) u16(v) u32(v) i32(v) // big-endian, advance cursor
  bytes(u8arr)
  skip(n)                    // leave zeroed padding
  get result()               // -> Uint8Array
}
```

## `src/rfb/crypto/md5.js`

```js
export function md5(data /* Uint8Array */)  // -> Uint8Array(16)
```

## `src/rfb/crypto/aes.js`

```js
export function aes128EcbEncrypt(key /* Uint8Array(16) */, plaintext /* Uint8Array, len%16===0 */)
// -> Uint8Array (same length as plaintext). NO padding added, ever.
```

## `src/rfb/crypto/dh.js`

```js
export function modPow(base /* BigInt */, exp /* BigInt */, mod /* BigInt */) // -> BigInt
export function bytesToBigInt(u8)            // big-endian
export function bigIntToBytes(v, byteLength) // big-endian, LEFT-ZERO-PADDED to byteLength exactly
```

## `src/rfb/protocol/security/apple-dh.js`

```js
// serverParams: { generator: number, keyLength: number, prime: Uint8Array, serverPublic: Uint8Array }
// Returns Uint8Array of exactly 128 + keyLength bytes: ciphertext(128) THEN clientPublic(keyLength).
export function buildAppleDhResponse(serverParams, username, password, randomBytes)
// randomBytes: (n) => Uint8Array  — injectable for tests
export function parseAppleDhParams(reader) // -> serverParams, throws NeedMoreBytes
```

Rules: pad client public key AND shared secret to exactly `keyLength` with
`bigIntToBytes`. `K = md5(paddedSecret)`. Plaintext = 128 bytes filled with
`randomBytes(128)`, then UTF-8 username at offset 0 (NUL-terminated, max 63 bytes),
UTF-8 password at offset 64 (NUL-terminated, max 63 bytes). Encrypt with
`aes128EcbEncrypt`. Never log key material.

## `src/rfb/protocol/pixel-format.js`

```js
export const CANVAS_PIXEL_FORMAT = {
  bitsPerPixel: 32, depth: 24, bigEndian: 0, trueColour: 1,
  redMax: 255, greenMax: 255, blueMax: 255,
  redShift: 0, greenShift: 8, blueShift: 16,
};
export function bytesPerPixel(pf)      // -> pf.bitsPerPixel / 8
export function writePixelFormat(writer, pf)  // writes exactly 16 bytes
export function readPixelFormat(reader)       // -> pf object, consumes 16 bytes
```

## `src/rfb/protocol/messages/client.js`

All return `Uint8Array`.

```js
export function clientInit(shared = 1)                       // 1 byte
export function setPixelFormat(pf)                           // 20 bytes
export function setEncodings(encodings /* number[] */)       // 4 + 4N
export function framebufferUpdateRequest(incremental, x, y, w, h)  // 10 bytes
export function keyEvent(down, keysym)                       // 8 bytes
export function pointerEvent(buttonMask, x, y)               // 6 bytes
export function clientCutText(text)                          // 8 + n, latin-1
```

## `src/rfb/decoders/*.js`

Every decoder has this exact signature and is **self-contained** (no Reader):

```js
// payload  : Uint8Array — exactly the rectangle's wire bytes
// rect     : { x, y, w, h }
// pf       : pixel format object
// fb       : Uint8ClampedArray — RGBA framebuffer, length fbW*fbH*4
// fbW, fbH : framebuffer dimensions
// ctx      : { inflate }  — per-connection state; see below
export function decode(payload, rect, pf, fb, fbW, fbH, ctx)
```

- `src/rfb/decoders/raw.js` — writes `[R,G,B]` from each 4-byte little-endian pixel, alpha 255.
- `src/rfb/decoders/copyrect.js` — payload is 4 bytes (`srcX` u16, `srcY` u16). Must be
  overlap-safe: copy row-by-row choosing direction from the sign of `dy`.
- `src/rfb/decoders/zlib6.js` — payload is `u32 length` + deflate bytes.
  Inflate via `ctx.inflate.zlib6`, then treat output exactly as a Raw rectangle.
- `src/rfb/decoders/zrle.js` — payload is `u32 length` + deflate bytes via
  `ctx.inflate.zrle`. 64x64 tiles, left-to-right then top-to-bottom.
  Subencoding byte per tile: `0` raw CPIXELs; `1` solid (one CPIXEL);
  `2..16` packed palette (paletteSize = subenc, bit-width 1/2/4, **each tile row
  padded to a whole byte**); `128` plain RLE; `130..255` palette RLE
  (paletteSize = subenc - 128). Values `17..127` and `129` are invalid → throw.
  CPIXEL here is **3 bytes** `[R,G,B]` (because depth 24 fits in the low 3 bytes and
  `bigEndian` is 0). RLE run length = sum of bytes while byte === 255, plus the final byte, plus 1.

`ctx.inflate` holds **two long-lived inflate streams**, created once per connection and
**never reset**:

```js
// src/rfb/inflate/streams.js
export function createInflateContext()  // -> { zrle: Inflator, zlib6: Inflator }
// Inflator: { push(bytes) -> Uint8Array }  // returns all bytes decompressed so far this call
```

Backed by pako's `Inflate` with `{ chunkSize }`, pushed with `Z_SYNC_FLUSH`.

## `src/rfb/rfb-session.js`

The pure state machine. **Computes each rectangle's payload length without decoding it**,
which is what lets the main process slice rectangles and ship them to the worker.

```js
export class RfbSession {
  constructor({ username, password, encodings, randomBytes })
  feed(chunk /* Uint8Array */)  // -> Event[]
  takeOutbound()                // -> Uint8Array | null   (drain and send over the socket)

  // input helpers — queue outbound bytes
  sendPointer(buttonMask, x, y)
  sendKey(down, keysym)
  sendCutText(text)
  requestUpdate(incremental)
}
```

Events emitted:

| Event | Shape |
|---|---|
| `serverInit` | `{ type, width, height, name }` |
| `rect` | `{ type, encoding, x, y, w, h, payload }` |
| `updateDone` | `{ type }` — all rectangles of one FramebufferUpdate consumed |
| `bell` | `{ type }` |
| `cutText` | `{ type, text }` |
| `desktopSize` | `{ type, width, height }` |
| `authFailed` | `{ type, reason }` |
| `error` | `{ type, message }` |

Payload length per encoding (no decoding required):

| Encoding | Payload bytes |
|---|---|
| `0` Raw | `w * h * bytesPerPixel` |
| `1` CopyRect | `4` |
| `6` zlib | `4 + u32 at offset 0` |
| `16` ZRLE | `4 + u32 at offset 0` |
| `-239` Cursor | `w*h*bpp + floor((w+7)/8)*h` |
| `-223` DesktopSize | `0` |
| `-224` LastRect | `0` — ends the rectangle loop immediately |

Sequence after `serverInit`: `setPixelFormat`, `setEncodings`, then the first
`framebufferUpdateRequest(0, ...)`. Then exactly one outstanding incremental request,
re-armed only on `updateDone`. Never on a timer.

Version reply is the 12 bytes `RFB 003.008\n`. Read encoding type with `i32()`.
`Bell` is **one byte** total. On `SecurityResult` failure, read `u32` reason length,
those bytes, then **drain one extra trailing `0x00`** if present.

## `src/rfb/keysym/index.js`

```js
export function keysymForDomKey(key /* KeyboardEvent.key */, code /* KeyboardEvent.code */, profile)
// -> number (X11 keysym) or null
export const PROFILE_CTRL_AS_CMD = 'ctrl-as-cmd';
export const PROFILE_NATIVE = 'native';
export const MODIFIER_KEYSYMS = [/* 0xffe1..0xffec */];
```

Apple mapping (banner-gated): `Meta_L 0xffe7` = **Option**, `Super_L 0xffeb` = **Command**,
`Control_L 0xffe3` = Control.

Profile `ctrl-as-cmd` (default): `ControlLeft` → `0xffeb` (Command);
`ControlRight` → `0xffe4` (real Control); `AltLeft/AltRight` → `0xffe7`/`0xffe8` (Option);
`MetaLeft/MetaRight` → `0xffe3` (Control).

Profile `native`: `ControlLeft/Right` → `0xffe3`/`0xffe4`;
`MetaLeft/Right` → `0xffeb`/`0xffec` (Command); `AltLeft/Right` → `0xffe7`/`0xffe8` (Option).

Printable characters: ASCII `0x20..0xff` → the codepoint itself; other Unicode →
`0x01000000 + codepoint`. Named keys (Enter, Tab, arrows, F1-F12, Home/End/PageUp/PageDown,
Escape, Backspace, Delete) → the standard X11 keysyms.

## IPC envelope (main → renderer worker)

`postMessage` with a transfer list, zero-copy:

```js
{ kind: 'rect', encoding, x, y, w, h, payload /* Uint8Array */ }
{ kind: 'init', width, height, name }
{ kind: 'updateDone' }
{ kind: 'resize', width, height }
{ kind: 'status', state, message }
```

Renderer worker → main:

```js
{ kind: 'input', ... }   // forwarded to the session
{ kind: 'ready' }
```
