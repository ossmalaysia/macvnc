# RFB 003.889 / Apple Screen Sharing — Verified Protocol Brief

> Generated from a 30-agent research workflow (3.0M tokens, 601 tool calls).
> Wire facts marked as observed were captured live against 192.168.68.125:5900.
> Adversarial verifiers refuted several initially-confident claims; corrections are inline.

## Apple Security Type 30 — Byte-Exact Auth Flow

APPLE SECURITY TYPE 30 ("ARD / Diffie-Hellman auth") — BYTE-EXACT, as empirically verified end-to-end against 192.168.68.125:5900 (RFB 003.889).

CONTRADICTION RESOLVED FIRST: one research thread claimed modern macOS sends generator=5 and keyLength=0x0200 (512 bytes / 4096-bit MODP Group 16, sourced from a RealVNC binary-patch repo). That is REFUTED for this target by four independent live captures: generator=2, keyLength=0x0080 (128 bytes / 1024-bit), prime byte-for-byte equal to RFC 2409 §6.2 Oakley Group 2 (== Node crypto.getDiffieHellman('modp2').getPrime(), Buffer.compare === 0). Both values MUST still be read from the wire and all buffers sized from keyLength; legacy ARD used 64, a future macOS could use 512. Assert-and-log if generator != 2 or keyLength != 128, do not reject.
SECOND CONTRADICTION RESOLVED: one adversarial pass asserted type 30 is "offered but not functional" on 003.889 and that type 36 (SRP) is the only working path. That is REFUTED by the live probe: the server consumed all 256 response bytes and returned a well-formed SecurityResult with status=1 plus the reason string "Authentication or authorization failure" — i.e. it parsed and evaluated the credential blob. Only the (deliberately wrong) password failed. Every framing/crypto step is proven. Type 30 is the primary path; 36 = SRP is future work with no public byte spec.

STEP 0 — VERSION HANDSHAKE
  S->C: exactly 12 bytes, no framing: 52 46 42 20 30 30 33 2E 38 38 39 0A  ("RFB 003.889\n")
  C->S: exactly 12 bytes: 52 46 42 20 30 30 33 2E 30 30 38 0A  ("RFB 003.008\n")
  RATIONALE (measured, both variants tried): announcing 003.008 vs 003.889 produces an IDENTICAL security list and IDENTICAL type-30 payload, but ONLY 003.008 yields the RFB 3.8 SecurityResult failure-reason string. Announcing 003.889 gives a bare 4-byte result and then a close — no diagnostics. Always announce 003.008.

STEP 1 — SECURITY TYPE LIST (RFB 3.7+ form, RFC 6143 §7.1.2)
  S->C: U8 count, then count x U8 type. Observed verbatim: 04 1E 21 24 23  => count=4, types=[30,33,36,35]. Exactly 5 bytes; server then blocks.
  If count == 0: next is U32BE reason-length + that many bytes of reason text. Abort with it.
  Select by SCANNING the list for the first type in your preference table [30]; never by index/position. Neither 0x01 (None) nor 0x02 (VNC Auth) is offered — the DES challenge path is dead code for this target.

STEP 2 — SELECT
  C->S: one unframed octet 0x1E (=30). No length prefix, no padding.

STEP 3 — DH PARAMETERS (server, 4 + 2*L bytes, all big-endian, no framing, no length prefixes)
  off 0        U16BE generator g          observed 00 02  => 2
  off 2        U16BE keyLength L (BYTES)  observed 00 80  => 128
  off 4        U8[L]  prime modulus p     big-endian, fixed width
  off 4+L      U8[L]  server public key   big-endian, LEFT-ZERO-PADDED to L by the server
  total        4 + 2*L = 260 on this target. Server then blocks until it has all 256 response bytes.
  Parse serverPub by FIXED OFFSET AND FIXED WIDTH [4+L, 4+2L). It is ephemeral per connection and is NOT always 128 significant bytes (one of two samples had bit-length 1023). Never scan for significant bytes, never trim.
  Observed prime (128 bytes, identical every connection):
  ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece65381ffffffffffffffff

STEP 4 — CLIENT DH
  x = cryptographically random private exponent (L random bytes is the reference choice; size is protocol-unconstrained).
  A = g^x mod p, serialized big-endian, LEFT-ZERO-PADDED to EXACTLY L bytes.
  S = serverPub^x mod p, serialized big-endian, LEFT-ZERO-PADDED to EXACTLY L bytes.
  NODE SPECIFICS (measured, Node v24.13.0):
    crypto.createDiffieHellman(primeBuf, genBuf) accepts the server prime verbatim (genBuf may be the raw 2-byte field; OpenSSL ignores the leading zero). verifyError == 0 on modp2.
    dh.computeSecret(serverPub) ALREADY zero-pads to prime length — 0 short results in 4000 trials. Pad anyway.
    dh.getPublicKey() STRIPS leading zeros — measured 11/4000 and 13/2000 returning L-1 bytes (~0.5%). THIS is the real bug source, not the secret. Pad unconditionally.
    setPrivateKey() does NOT derive the public key; you must call generateKeys() afterwards or getPublicKey() throws ERR_CRYPTO_INVALID_STATE ("No public key - did you forget to generate one?"). Only relevant for deterministic test vectors.
    Fallback: a plain BigInt square-and-multiply modPow is bit-identical and costs ~2.2 ms per 1024-bit exponentiation. Keep it behind a flag for FIPS builds / unusual primes.
  Write ONE leftPad(buf, L) helper and use it in BOTH places.

STEP 5 — KEY DERIVATION
  K = MD5(S_padded) over all L bytes => exactly 16 bytes. No salt, no label, no truncation, no additional data. Node: crypto.createHash('md5').update(S_padded).digest().
  Hashing a minimal/unpadded S is the classic ~1-in-256 intermittent auth failure.

STEP 6 — CREDENTIAL PLAINTEXT (exactly 128 bytes, FIXED, INDEPENDENT of L)
  1. Fill all 128 bytes with CSPRNG bytes (crypto.randomBytes(128)). Random, not zeros: under ECB, zero padding lets a passive observer read exact credential lengths off the ciphertext blocks.
  2. Encode username as UTF-8. Reject or truncate at 63 BYTES (validate the UTF-8 byte length, not the JS string length). memcpy to offset 0. Write 0x00 at offset usernameByteLen.
  3. Encode password as UTF-8, same 63-byte cap. memcpy to offset 64. Write 0x00 at offset 64 + passwordByteLen.
  Layout: username slot = [0,64), password slot = [64,128). Each slot is a NUL-terminated C string with random slack. The server parses each half as a C string and ignores bytes after the first NUL (nmap's NUL-padded variant also works, but use random).

STEP 7 — ENCRYPT
  C = AES-128-ECB(K, P). 128-byte plaintext = 8 independent 16-byte blocks => exactly 128 bytes out.
  Node: crypto.createCipheriv('aes-128-ecb', K, null); cipher.setAutoPadding(false); Buffer.concat([update(P), final()]).
  Leaving auto-padding ON silently emits 144 bytes and desynchronizes the stream. Mode is definitively ECB, not CBC: gtk-vnc has no ECB primitive and fakes it as CBC with a zeroed IV re-set before every 16-byte block.

STEP 8 — SUBMIT (one write, 128 + L = 256 bytes, no framing, no length prefix)
  bytes [0,128)      ciphertext C          ALWAYS 128, regardless of L
  bytes [128,128+L)  client public key A   LEFT-ZERO-PADDED to L
  ORDER IS CIPHERTEXT FIRST, THEN PUBLIC KEY. Reversing it fails. Confirmed in gtk-vnc, noVNC, Wireshark's dissector, the community rfbproto table, and live.

STEP 9 — SECURITYRESULT (RFC 6143 §7.1.3)
  S->C: U32BE status. 0 = OK, 1 = failed.
  On 0: proceed immediately to ClientInit (1 byte).
  On 1 with 003.008 announced: U32BE reason-length, then that many bytes of text. Observed verbatim, 48 bytes total:
      00 00 00 01 | 00 00 00 27 | 41 75 74 68 ... 65 ("Authentication or authorization failure", 39 bytes) | 00
  APPLE DEVIATION: there is ONE trailing 0x00 that is NOT counted in reason-length (4+4+39 = 47, 48 delivered). RFC 6143 says nothing follows the reason. Tolerate and discard it; do not assert EOF at 8+reasonLength and do not leave it buffered for a reconnect state machine. Server closes immediately after.
  Surface the reason string verbatim to the user — it is the ONLY diagnostic, and it is IDENTICAL for "wrong password" and "account not authorized for Screen Sharing".

CREDENTIAL SEMANTICS
  A real local macOS account short name (record name) + its password, evaluated against OpenDirectory. The account must be permitted under System Settings > General > Sharing > Screen Sharing (i) > Computer Settings, or Remote Management > Computer Settings, "Allow access for". Network/AD accounts are reported to work only via the Remote Management path (low confidence). With FileVault on, screensharingd is not running before first local unlock — port 5900 will not answer at all after a reboot.

SECURITY POSTURE (state this in the UI, do not oversell)
  The DH exchange is completely unauthenticated: the client cannot verify p, g, or the server public key, so type 30 is trivially MITM-able by anyone on the path to TCP/5900, and a MITM recovers the plaintext account password. It protects against passive eavesdropping only. All post-auth RFB traffic is plaintext regardless. Never log the blob, the shared secret, or the MD5 key.

TESTABILITY
  Structure as a pure function (serverParams, username, password, randomBytes, privateExponent) -> { payloadBytes, debugK } so it can be unit-tested against the captured 260-byte fixture with injected randomness. Keep credential submission on a separate call path from parameter exchange, so handshake debugging can never accidentally submit credentials (every wrong attempt is a real failed login against a real macOS account and can trip lockout / MDM alerting / unified-log noise). Never auto-retry a rejected password.

## Security Type Selection

30 (0x1E) — Apple Diffie-Hellman / ARD authentication. Offered set on this host is exactly {30, 33, 36, 35} in that wire order; 1 (None) and 2 (VNC Auth) are absent, so the DES-challenge path is unimplementable here and legacy-VNC-password fallback only becomes possible if the Mac's owner ticks "VNC viewers may control screen with password".

Why 30: it is the only Apple type with a published, reimplementable wire format and multiple independent reference implementations (gtk-vnc vnc_connection_co_auth_ard, noVNC _negotiateARDAuth, nmap vnc.lua, Wireshark's vnc.ard_auth_* dissector), and it was verified end-to-end against this exact server — the server consumed all 256 bytes and returned a parsed SecurityResult with a reason string.

Do NOT design around 33/35/36. 36 is Apple's SRP path (corroborated by 2026 screensharingd reverse-engineering and Apple's own EndpointSecurity authentication_type field), 35 has only a name ("Mac OS X security type", nmap), 33 is entirely unattributed. None has a public byte-level spec, none has an open-source implementation, and 36 additionally installs a ChaCha20-Poly1305 record layer after auth. Budget them as reverse-engineering, not as v1.

Registry precision: RFC 6143 §8 explicitly declines to create an IANA registry for security types; the de-facto registry is the community rfbproto document, which reserves 30–35 to Apple Inc. (30 is Apple's, not outside the block) and leaves 36 unregistered — Apple uses a number outside its own allocation. Nothing is "registered as Diffie-Hellman Authentication" by IANA; that is the community/Wireshark description.

Implementation shape: a pluggable table {typeNumber -> handler} with an explicit ordered preference list, currently [30]. On no match, fail with a message that lists the numeric types the server actually offered. This makes adding 36 later a table entry, not a refactor, and gives a clean diagnostic if a future macOS drops 30.

## RFB Message Layouts

All multi-byte integers are BIG-ENDIAN (RFC 6143 §7) EXCEPT pixel values, whose byte order is governed by PIXEL_FORMAT.big-endian-flag. Write all padding as zero; never validate padding on read. Build outbound messages with a fixed-size buffer and writeUInt*BE at fixed offsets. Build the inbound side as a RESUMABLE state machine over a growable receive buffer — every server message has a variable tail and TCP splits arbitrarily. The parser must be able to return NEED_MORE and re-enter at the same point.

=== SETUP ===
ClientInit (C->S), 1 byte total
  0   U8 shared-flag. Send 0x01 (shared) so you do not disconnect other viewers of the Mac.

ServerInit (S->C), 24 + nameLength bytes
  0..1    U16BE framebuffer-width
  2..3    U16BE framebuffer-height
  4..19   PIXEL_FORMAT (16 bytes)
  20..23  U32BE name-length
  24..    U8[name-length] name-string. Charset UNSPECIFIED by RFC 6143 (historically Latin-1, modern servers often UTF-8). Decode defensively; cap the length before allocating.

PIXEL_FORMAT (16 bytes, appears inside ServerInit and SetPixelFormat)
  0   U8  bits-per-pixel   (8, 16 or 32)
  1   U8  depth            (useful bits; <= bpp)
  2   U8  big-endian-flag
  3   U8  true-colour-flag
  4..5   U16BE red-max     (must be 2^N-1; these are message ints, always BE)
  6..7   U16BE green-max
  8..9   U16BE blue-max
  10  U8  red-shift
  11  U8  green-shift
  12  U8  blue-shift
  13..15  3 bytes padding
  Decode algorithm (§7.4): assemble the pixel per big-endian-flag, then value = (pixel >> chan-shift) & chan-max. With bpp=32 and big-endian-flag=0, wire byte index of a channel == shift/8; with flag=1 it is (bytesPerPixel-1 - shift/8).

=== CLIENT -> SERVER ===
SetPixelFormat (type 0), 20 bytes
  0   U8 = 0
  1..3   3 bytes padding
  4..19  PIXEL_FORMAT
  HARD ORDERING RULE (community rfbproto; omitted from RFC 6143): a client MUST NOT have an outstanding FramebufferUpdateRequest when it sends SetPixelFormat, or the format of the next FramebufferUpdate is ambiguous. Send SetPixelFormat, then SetEncodings, then the first FramebufferUpdateRequest. Never change format mid-stream.
  Also: if true-colour-flag is 0, the colour map becomes undefined immediately — discard any palette on every SetPixelFormat.

SetEncodings (type 2), 4 + 4*N bytes
  0   U8 = 2
  1   1 byte padding
  2..3   U16BE number-of-encodings N
  then N x S32BE encoding-type, most-preferred first. Pseudo-encodings go in the SAME list and are NEGATIVE — use writeInt32BE.
  The order is only a hint; the server may ignore the list entirely and "pixel data may always be sent in raw encoding even if not specified explicitly here". There is no reply and no way to query support.

FramebufferUpdateRequest (type 3), 10 bytes, no padding
  0   U8 = 3
  1   U8 incremental (0 = full/non-incremental, non-zero = incremental)
  2..3   U16BE x-position
  4..5   U16BE y-position
  6..7   U16BE width
  8..9   U16BE height
  Send incremental=0 only when your local framebuffer is invalid: once at session start; after any DesktopSize rect; after a pixel-format change; on an explicit user refresh. Everything else incremental=1. Always request the full 0,0,fbW,fbH.

KeyEvent (type 4), 8 bytes
  0   U8 = 4
  1   U8 down-flag (non-zero = pressed)
  2..3   2 bytes padding
  4..7   U32BE keysym (X11)
  Auto-repeat is generated client-side as repeated DOWN events with no intervening up.

PointerEvent (type 5), 6 bytes, no padding
  0   U8 = 5
  1   U8 button-mask
  2..3   U16BE x-position
  4..5   U16BE y-position

ClientCutText (type 6), 8 + n bytes
  0   U8 = 6
  1..3   3 bytes padding
  4..7   U32BE length
  8..    U8[length] text, ISO 8859-1 (Latin-1), LF (0x0a) line ends only, no CR, no trailing NUL.

=== SERVER -> CLIENT ===
FramebufferUpdate (type 0), 4-byte header + N rectangles
  0   U8 = 0
  1   1 byte padding
  2..3   U16BE number-of-rectangles
  Each rectangle header is EXACTLY 12 bytes:
    +0..1   U16BE x-position
    +2..3   U16BE y-position
    +4..5   U16BE width
    +6..7   U16BE height
    +8..11  S32BE encoding-type   <-- SIGNED. readInt32BE. Reading it unsigned silently breaks every pseudo-encoding and is the single most common from-scratch RFB bug.
  followed immediately by that rectangle's payload, whose length is IMPLICIT IN THE ENCODING and is NOT transmitted. Consequences:
   - number-of-rectangles is an UNTRUSTED UPPER BOUND. Never preallocate from it (0xFFFF x 12 is the trivial abuse). Never require it to reach 0 to complete an update.
   - 0 rectangles is legal and means an empty update that must complete immediately — a do/while(--n) loop hangs here.
   - Stop unconditionally on encoding-type == -224 (LastRect), regardless of the header count. Servers that do not know the count up front advertise 0xFFFF and terminate early with LastRect. Do NOT gate the -224 branch on count == 0xFFFF.
   - An unrecognised encoding-type is UNRECOVERABLE — there is no length to skip. Treat it as a fatal protocol error, log the numeric value, and disconnect. Only ever advertise encodings you have fully implemented.
  Loop shape (mirrors noVNC _framebufferUpdate): keep FBU state {rects, encoding, x, y, w, h} ACROSS socket reads. While rects > 0: if encoding == null require >= 12 buffered bytes else NEED_MORE; parse the 12-byte header; call the decoder, which itself may return NEED_MORE; on success rects-- and encoding = null. Present the frame only when the loop completes.

SetColourMapEntries (type 1), 6 + 6*N bytes
  0   U8 = 1 | 1 padding | 2..3 U16BE first-colour | 4..5 U16BE number-of-colours
  then N x { U16BE red, U16BE green, U16BE blue } (0..65535 each)
  You will never legitimately receive this with true-colour requested, but you MUST parse its full length to stay in sync if it arrives.

Bell (type 2), 1 BYTE TOTAL
  0   U8 = 2. No padding, no body. Any receive loop assuming a minimum 4-byte server header desyncs permanently the first time the Mac beeps.

ServerCutText (type 3), 8 + n bytes
  0   U8 = 3 | 1..3 padding | 4..7 length | 8.. text (Latin-1, LF only)
  Read the length as S32BE: with the Extended Clipboard pseudo-encoding (0xC0A1E5CE) negative means extended format. We do not request it, so treat negative as a protocol error rather than allocating ~4 GiB. Cap positive length (e.g. 1 MiB) before allocating.

=== ENCODING PAYLOADS ===
Raw (0): exactly width*height*bytesPerPixel bytes, left-to-right, top-to-bottom scanlines, no header. bytesPerPixel = bpp/8 = 4 with the recommended format. A 1920x1080 rect is 8,294,400 bytes — must be a streaming/partial-read state machine.

CopyRect (1): exactly 4 bytes — U16BE src-x-position, U16BE src-y-position. Copies a w x h block within the SAME framebuffer. SOURCE MAY OVERLAP DESTINATION (window drag / scroll is the normal case): either copy via a temp buffer, or choose iteration direction (rows bottom-up when dstY > srcY; within a row right-to-left when dstX > srcX). On canvas, ctx.drawImage(sameCanvas, sx,sy,w,h, dx,dy,w,h) is defined as if the source were snapshotted first and sidesteps this. Also: the source region must not include pixels updated by earlier rectangles in the same update.

zlib (6) — NOT in RFC 6143, community encoding:
  U32BE length, then length bytes appended to ONE per-connection inflate stream dedicated to encoding 6. Inflated output is EXACTLY a Raw rectangle (w*h*bytesPerPixel). The zlib header (78 9C) appears only once, on the first zlib rect of the connection; every later rect starts mid-DEFLATE and back-references the earlier sliding window. Rectangles must be decoded strictly in order. Never reset this stream.

ZRLE (16) — RFC 6143 §7.7.6:
  U32BE length, then length bytes appended to ONE per-connection inflate stream dedicated to ZRLE (SEPARATE from the encoding-6 stream). "A single zlib stream object is used for a given RFB connection, so that ZRLE rectangles must be encoded and decoded strictly in order." The server flushes to a byte boundary at the END of each rectangle but NOT between tiles, so tile data is not byte-aligned and the decompressed size is not known in advance — parse until tilesX*tilesY tiles are consumed.
  Tiles: 64x64, left-to-right/top-to-bottom. tilesX = ceil(w/64), tilesY = ceil(h/64). For tile i: col = i % tilesX, row = floor(i / tilesX), tx = rect.x + col*64, ty = rect.y + row*64, tw = min(64, rect.x+rect.w - tx), th = min(64, rect.y+rect.h - ty). Every inner size formula uses tw/th, never 64.
  Per tile: U8 subencoding. Top bit = RLE, low 7 bits = palette size.
    0        Raw: tw*th CPIXELs
    1        Solid: one CPIXEL, fill tile
    2..16    Packed palette: paletteSize CPIXELs, then packed indices, MSB-first within each byte, EACH ROW padded to a byte boundary. Bits/pixel: 1 for size 2; 2 for 3-4; 4 for 5-16. Bytes = floor((tw+7)/8)*th, floor((tw+3)/4)*th, floor((tw+1)/2)*th respectively.
    17..127  ILLEGAL in ZRLE (127 and 129 are TRLE palette-reuse; ZRLE never reuses palettes)
    128      Plain RLE: repeated (CPIXEL, runLength) until tw*th pixels covered; runs may cross row boundaries
    129      ILLEGAL
    130..255 Palette RLE: paletteSize = subencoding-128 CPIXELs, then a stream where a byte < 128 is a run of length 1 with that palette index, and a byte >= 128 means index = byte-128 followed by a run-length sequence
  runLength = 1 + sum of all length bytes; every 0xFF byte continues, the first non-0xFF terminates. (1=[0], 255=[254], 256=[255,0], 257=[255,1], 510=[255,254], 511=[255,255,0].)
  CPIXEL = PIXEL, except when true-colour-flag != 0 AND bpp == 32 AND depth <= 24 AND all R/G/B bits fit in either the 3 least- or 3 most-significant bytes — then it is 3 bytes carrying those bytes in the PIXEL's own byte order. With the recommended format (LE, shifts 0/8/16) CPIXEL is 3 bytes = [R,G,B]. bytesPerCPixel applies to EVERY CPIXEL in the tile stream: raw pixels, solid colour, palette entries and RLE pixel values.
  SANITY CHECK: after feeding exactly `length` compressed bytes, the inflater must have produced exactly the bytes the tile parser accounted for. Mismatch => drop the connection; a mis-parsed tile does not throw, it silently consumes the wrong byte count and every subsequent rectangle in the connection decodes to garbage with no possible resynchronisation.

=== PSEUDO-ENCODINGS (arrive as ordinary 12-byte rect headers) ===
Cursor (-239): payload = width*height*bytesPerPixel cursor-pixels, then floor((width+7)/8)*height bitmask bytes. Bitmask scanlines top-to-bottom, each padded to a whole byte, MSB = leftmost pixel, 1 = pixel valid/opaque. The rect's x/y are the HOTSPOT, not a screen position. width or height == 0 means hide the cursor — guard before allocating. NEVER blit this into the framebuffer; render it as a CSS/local cursor. With 32bpp the 4th pixel byte is padding, not alpha — the 1bpp mask is the only transparency channel. Advertising -239 tells the server to stop drawing the pointer into the framebuffer, so you MUST composite locally or the pointer disappears.
DesktopSize (-223): ZERO payload. x/y ignored; width/height are the NEW framebuffer size. Sent as the last rectangle in an update. The server then assumes you no longer have the previous contents, so resize the canvas/texture and issue a NON-incremental full request at the new dimensions.
LastRect (-224): ZERO payload. Terminate the rectangle loop immediately.

## Pixel Format

SEND EXACTLY THIS 20-byte SetPixelFormat, before SetEncodings and before the first FramebufferUpdateRequest:

  00 00 00 00 | 20 18 00 01 | 00 FF 00 FF 00 FF | 00 08 10 | 00 00 00

  00           message-type = 0
  00 00 00     padding
  20           bits-per-pixel = 32
  18           depth = 24            <-- MUST be 24, not 32
  00           big-endian-flag = 0   (little-endian pixels)
  01           true-colour-flag = 1
  00 FF        red-max   = 255       (U16 BIG-ENDIAN even though big-endian-flag = 0)
  00 FF        green-max = 255
  00 FF        blue-max  = 255
  00           red-shift   = 0
  08           green-shift = 8
  10           blue-shift  = 16
  00 00 00     padding

CONTRADICTION RESOLVED: one research thread recommended shifts 16/8/0 ("matches the Mac's native BGRA, matches every reference decoder's fast path"). That is REFUTED. noVNC — the canonical canvas decoder — emits shifts 0/8/16 (RFB.messages.pixelFormat: bits = floor(depth/3) = 8, then bits*0, bits*1, bits*2, little-endian byte 0), and its raw/zrle/tight decoders copy buf[j], buf[j+1], buf[j+2] straight into ImageData R,G,B with zero swizzling. 16/8/0 would render red/blue swapped in those decoders and, worse, would give you TWO different byte orders inside one client (see below).

WHY 0/8/16 IS THE RIGHT ANSWER — the three consumers agree:
  Raw:    4 bytes/pixel little-endian => wire bytes [R, G, B, X]. Byte-identical to canvas ImageData except the alpha slot.
  CPIXEL: maxPixel = 0x00FFFFFF < 1<<24 => fitsInLS3Bytes, little-endian => the 3-byte low CPIXEL form => [R, G, B].
  TPIXEL: spec-fixed as [R, G, B] regardless of shifts.
  So every path yields R,G,B in that order. With 16/8/0 you would get Raw=[B,G,R,X], CPIXEL=[B,G,R], TPIXEL=[R,G,B] — inconsistent, and requiring a per-pixel swap for canvas.

DERIVATION (RFC 6143 §7.4): big-endian-flag=0 means wire bytes b0..b3 assemble as pixel = b0 | b1<<8 | b2<<16 | b3<<24. red = (pixel>>0)&255 = b0; green = (pixel>>8)&255 = b1; blue = (pixel>>16)&255 = b2; b3 is unused padding (depth 24 of 32 bpp). Flipping big-endian-flag to 1 with the same shifts reverses the byte order to [X,B,G,R] — the flag and the shifts are not independent knobs.

WHY depth MUST BE 24, NOT 32: RFC 6143 §7.7.5 makes CPIXEL 3 bytes only when depth <= 24. depth=32 silently disables the compact form and costs 33% more bandwidth on every ZRLE tile, with no error. It also breaks a decoder that hard-codes bytesPerCPixel = 3.

ALPHA IS NOT FREE: RFB has no alpha field; byte 3 is undefined padding and the RFC says recipients must not assume padding has any particular value. Every decoder must force A=255. This is a strided write-only pass (or one `u32[i] |= 0xFF000000` pass), not a full read-shuffle-write, but it is not zero. Do not claim "no swizzle".

ZRLE/TIGHT EXPANSION IS UNAVOIDABLE: requesting bpp=32/depth=24/8-8-8 is exactly the condition that makes the server send 3-byte CPIXELs, so ZRLE tiles need a 3->4 byte expand + alpha fill in the putImageData path. On the WebGL2 path this pass genuinely vanishes: upload 3-byte tile rows with gl.pixelStorei(gl.UNPACK_ALIGNMENT, 1) and gl.texSubImage2D(..., gl.RGB, gl.UNSIGNED_BYTE, tileBuf), no alpha byte, no expansion.

BRING-UP SEQUENCING: for the very first pixels, parameterise the decoder by the ACTIVE PixelFormat object rather than hard-coding, log ServerInit's PIXEL_FORMAT verbatim, and assert the format observed in the first Raw rectangle. Whether Apple's screensharingd honours an arbitrary SetPixelFormat is UNVERIFIED — likely yes (noVNC and libvnclient both request their own format unconditionally and are routinely pointed at macOS with no reported universal red/blue swap), but the symptom of failure is "renders perfectly with red and blue swapped", which is easy to mistake for a decoder bug. A parameterised decoder makes the same code correct either way.

## Encoding Plan

ADVERTISE ONLY WHAT IS FULLY IMPLEMENTED. An unrecognised encoding-type has no length field and cannot be skipped — it is an unrecoverable desync, not a warning. "Gracefully ignore unknown encodings" is impossible in RFB.

=== WHAT APPLE'S screensharingd ACTUALLY SUPPORTS (high confidence) ===
Supported: Raw(0), CopyRect(1), zlib(6), ZRLE(16), plus Apple-proprietary encodings.
NOT supported: Hextile(5), Tight(7), TightPNG(-260), RRE(2), CoRRE(4), zlibhex(8), TRLE(15).
Evidence, strongest first:
 1. noVNC issue #1095 (macOS 10.13.5, banner "RFB 003.889" confirmed in the attached log): instrumented rfb.js logged "FBU encoding:0" (Raw) while that revision advertised CopyRect(1), Tight(7), Hextile(5), RRE(2), Raw(0) and TightPNG(-260). The server fell through to Raw => it honoured none of Tight/TightPNG/Hextile/RRE. This is a direct per-rectangle observation, not inference.
 2. Chapoly1305's 2026 reverse-engineered "Apple VNC High-Performance Extension" spec (packet captures + static analysis of screensharingd/ScreenSharing.framework) §8.9.2 lists what Apple's OWN client advertises per quality tier: Full = zlib, copyrect; Low = 0x3e8, zlib, zrle; Medium = 0x3e9, zlib, zrle; High = 0x3f3, 0x3ea, zlib, zrle. The string "hextile" appears zero times in ~99 KB. This also PROMOTES CopyRect(1) from "assumed" to confirmed.
 3. noVNC #673 (patrakov): "the native MAC VNC server supports only ZLIB, ZRLE, RAW, and proprietary encodings. Not even Hextile." Weakest of the three — it opens "I believe this has to do with..." and its TigerVNC corroboration ran over ngrok — cite it last.
Freshness caveat: the Hextile/Tight-negative measurements are 2016/2018 (Sierra / High Sierra); the 2026 spec is silent on Hextile rather than affirmatively denying it. No public per-rectangle log from a third-party client on macOS 14/15/26 was found.

FALSE LEAD to ignore: searches surface "copyrect tight hextile zlib corre rre raw". That is the default -encodings preference list from the classic TightVNC/RealVNC unix vncviewer man page — a CLIENT default, nothing to do with macOS capability.

=== SHIP IT IN THREE PHASES ===
Phase 1 (first light — get pixels on screen):
  SetEncodings = [ 1 CopyRect, 0 Raw, -239 Cursor, -223 DesktopSize, -224 LastRect ]
  Raw is the only encoding a client is REQUIRED to implement and the only one a server is guaranteed to be able to send. CopyRect is a 4-byte payload and is what makes window drags and scrolling usable. Full-screen Raw at 1080p is 8.29 MB/frame — slow but correct, and it is the fixture you unit-test everything else against.
Phase 2 (bandwidth, ~20 lines):
  add 6 zlib, at the front: [ 6, 1, 0, -239, -223, -224 ]
  zlib(6) is literally Raw inside a second persistent inflate stream. It is the second encoding Apple is reported to support and it is nearly free once you have Raw.
Phase 3 (the real win, ~250 lines):
  final list, in preference order: [ 16 ZRLE, 6 zlib, 1 CopyRect, 0 Raw, -239 Cursor, -223 DesktopSize, -224 LastRect ]
  ZRLE is ~10-50x better than Raw on desktop content and is the highest-value target for macOS.

=== NEVER ADVERTISE (each is an active hazard, not a free option) ===
 - 0x574d5664 VMwareCursor / 0x574d5666 VMwareCursorPosition: Apple STOPS SENDING ALL CURSOR UPDATES if the client advertises the VMware cursor extension (Pierre Ossman, TigerVNC maintainer, reproduced first-hand on noVNC #1430). This is exactly why noVNC shows no cursor against macOS while Remmina/libvncclient does. It also disproves the comfortable assumption that unsupported pseudo-encodings are silently ignored — Apple demonstrably violates that for this one. Advertise the MINIMUM set and add anything new one at a time, observing.
 - 7 Tight / -260 TightPNG: 4 stateful zlib streams with per-rectangle reset bits (which must be honoured even for Fill and JPEG rects), 3 filters, compact lengths, and a "<12 bytes after filtering is sent raw with NO length prefix" special case. Apple will most likely never send one. Also, Tight-JPEG requires an async image decode, which breaks a synchronous raw-pixel-only decoder.
 - 5 Hextile: the fiddliest decoder relative to payoff (background/foreground carry-over between tiles) and reportedly unsupported by Apple.
 - 2 RRE / 4 CoRRE / 15 TRLE: obsolete or never observed.
 - -308 ExtendedDesktopSize, -312 Fence, -313 ContinuousUpdates: TigerVNC-originated; advertising is a PROMISE to handle the resulting messages. ContinuousUpdates additionally collides on message number 150 in both directions and would change the whole update model. Stick to the classic one-outstanding-request pump.
 - -316 ExtendedMouseButtons: overloads button-mask bit 7 into an "extended event" flag. Keep bit 7 meaning plain "Back".
 - -32..-23 JPEG quality levels: NOT advertising one legally forbids the server from ever sending a JpegCompression rectangle. Free insurance.
 - 0xC0A1E5CE Extended Clipboard: TigerVNC extension, no evidence of Apple support, and it turns the ServerCutText length field signed.
 - Apple-registered ranges 1000-1002, 1011, 1100-1105 (and the unregistered 1010, 1107, 1109, 1110): undocumented, undecodable, unskippable.
 - -250 DesiredCompressionLevel: optional and probably harmless, but given the VMwareCursor precedent, defer it to phase 3 and add it as a single isolated change.

=== APPLE PROPRIETARY ENCODINGS (context, not a target) ===
1000/0x3e8 Low Quality (4-bit, 16 colours per 8px block, deflate 9); 1001/0x3e9 Medium (8-bit YCoCg dither, deflate 6); 1002/0x3ea High (RGB565, deflate 1); 1011/0x3f3 Multi-Variant Scaled (per-tile YCbCr/DCT); 1103/0x44f EncodeEncryptionInfo (rekey to an AES-128-CBC record layer); 1104/0x450 CursorImage; 1105/0x451 AppleDisplayLayout. These are how Apple's own Screen Sharing.app gets its low-latency feel; a standard-RFB client is structurally capped below it. Useful fact: 0x3e8/0x3e9/0x3ea and 0x06 all share ONE zlib pipeline and differ only in pixel pre-processing and deflate level, so implementing zlib(6) puts you most of the way to 0x3ea if you ever want it.

=== MANDATORY FIRST-SESSION INSTRUMENTATION ===
Log the S32 encoding-type of EVERY rectangle received in the first real session. A server never advertises its encodings (RFC 6143 §7.5.2), so this single log line is the only way to convert every medium-confidence claim above into fact, and it must gate any decision to invest in Hextile or Tight. Also log ServerInit's PIXEL_FORMAT and the format observed in the first Raw rectangle.

## Input, Keysyms and the Command Key

=== WIRE (repeated for precision) ===
KeyEvent:     U8 4 | U8 down-flag | 2 bytes padding | U32BE keysym            (8 bytes)
PointerEvent: U8 5 | U8 button-mask | U16BE x | U16BE y                        (6 bytes, no padding)
ClientCutText:U8 6 | 3 bytes padding | U32BE length | Latin-1 text             (8+n bytes)
RFB has no keycode/scancode channel and no scroll message. Keysyms are the ONLY lever.

=== THE COMMAND KEY ANSWER ===
On Apple screensharingd (verified against RFB 003.889):
  Control_L/R  0xffe3 / 0xffe4  ->  Control
  Meta_L/R     0xffe7 / 0xffe8  ->  OPTION      <-- counterintuitive, but this is the real mapping
  Alt_L/R      0xffe9 / 0xffea  ->  COMMAND
  Super_L/R    0xffeb / 0xffec  ->  COMMAND
  Shift_L/R    0xffe1 / 0xffe2  ->  Shift
Evidence: AVNC issue #163 — reporter verified key identity in the macOS Keyboard Viewer; the maintainer shipped the fix in v2.2.2 gated on detecting the literal banner string "RFB 003.889". Independently corroborated by Remmina's shipped "Map Meta Keys" preset {Super_L=Meta_L, Meta_L=Super_L}, documented as "exactly what we need for MacOS". So BOTH Alt_L and Super_L reach Command, and Option is reachable only via Meta_L/Meta_R.
GATE THIS ON THE BANNER. It is Apple-specific: OSXvnc/Vine Server (OSXvnc-server/kbdptr.h and VNCServer.m) maps XK_Super_L to Option and has no case for Super_L in its modifier set at all, so on that server Super_L yields Option, not Command. Detect "RFB 003.889" (as AVNC does) before enabling the Apple table; fall back to Alt_L-for-Command on OSXvnc-family servers.
UNVERIFIED: whether Apple distinguishes left vs right Command/Option internally. Assume no handedness until probed.

=== WINDOWS-SIDE CONSTRAINT AND THE TWO PROFILES ===
Corrected fact: you do NOT need a native WH_KEYBOARD_LL addon to capture the Win key. Chromium already contains that hook and exposes it as navigator.keyboard.lock(); Electron ships it (electron PR #40365 patches its fullscreen interaction). Contract: secure context, top-level browsing context, argument is uievents-code strings (["MetaLeft","MetaRight","AltLeft","AltRight","Tab","Escape"]), and CAPTURE IS ACTIVE ONLY WHILE THE FOCUSED CONTEXT HAS A NON-NULL HTML FULLSCREEN ELEMENT — Electron's win.setFullScreen() / kiosk mode alone does NOT arm it. Chrome >= 130 gates it behind a permission prompt (route via session.setPermissionRequestHandler). Escape is special-cased: you get keydown, but a ~2s hold still exits fullscreen. Ctrl+Alt+Del remains unreachable (winlogon registers the SAS first) and Win+L is probably unblockable — document both.

PROFILE A — "Ctrl acts as Command" (DEFAULT, windowed, no keyboard lock):
  ControlLeft   -> Super_L 0xffeb  (Command)
  ControlRight  -> Control_R 0xffe4 (LEFT AS CONTROL — this is the escape hatch; Jump Desktop's actual solution)
  AltLeft/Right -> Meta_L 0xffe7 / Meta_R 0xffe8  (Option)
  MetaLeft/Right(Win) -> Control_L 0xffe3 (bonus path only, unreliable)
  ShiftLeft/Right -> Shift_L / Shift_R
  Rationale: Ctrl+C / Ctrl+V / Ctrl+Space become Cmd-C / Cmd-V / Cmd-Space. Routing Command onto Alt would make Cmd-Tab permanently unreachable (Alt+Tab is consumed by the shell); routing it onto Win pops the Start menu. Splitting left/right Control is what keeps the Mac's Control reachable for ^C, ^A/^E/^D/^R in Terminal, ^Left/^Right, ^F2.
  NOTE: MSRD-for-Mac is NOT a precedent for this — its documented default is label-faithful (Control->Ctrl, Option->Alt, Command->Windows key). Jump Desktop's Windows client is the real precedent.
PROFILE B — "label-faithful / native" (offer as a toggle; correct when keyboard lock is armed in fullscreen, or for users on Apple keyboards):
  ControlLeft/Right -> Control_L / Control_R
  MetaLeft/Right    -> Super_L / Super_R  (Command)
  AltLeft/Right     -> Meta_L / Meta_R    (Option)
  (A third, genuinely POSITIONAL profile — Ctrl->Control, Win->Meta_L(Option), Alt->Super_L(Command) — preserves physical left-to-right order PC Ctrl|Win|Alt vs Mac Control|Option|Command. Optional.)
Pick Super_L over Alt_L for Command so Alt_L stays free as an OSXvnc-family compatibility fallback.
Provide soft keys / a menu for chords the OS eats: Cmd-Tab, Cmd-Space, Cmd-Q, Cmd-W, Cmd-`, Ctrl-Up (Mission Control), Cmd-Shift-3/4, Escape, and Ctrl-Alt-Del. Each is: modifiers down in order, key down, key up, modifiers up in reverse.

=== KEYSYM RESOLUTION (do NOT drive from a scancode table) ===
Order: (1) look up KeyboardEvent.key in a named-key table indexed by KeyboardEvent.location (0 standard, 1 left, 2 right, 3 numpad) — Enter -> [Return, Return, Return, KP_Enter]; ArrowDown -> [Down,Down,Down,KP_Down]; ' ' -> [space,space,space,KP_Space]. (2) if key.length is 1 (use codePointAt, and skip the low surrogate — noVNC's charCodeAt mangles astral chars): cp in 0x20..0xff -> keysym = cp; else consult a legacy keysym table; else 0x01000000 | cp. RFC 6143 explicitly prefers the legacy encoding when a key has both. (3) 'Dead' / 'Process' / 'Unidentified' -> no keysym; fall through to the composition path below.
Case is significant: send 'A' (0x41), not Shift+'a'. Shift state is only a hint; the server resolves it.
Constants you need: BackSpace 0xff08, Tab 0xff09, Return 0xff0d, Escape 0xff1b, Insert 0xff63, Delete 0xffff, Home 0xff50, Left 0xff51, Up 0xff52, Right 0xff53, Down 0xff54, Prior 0xff55, Next 0xff56, End 0xff57, F1..F12 = 0xffbe..0xffc9, Caps_Lock 0xffe5, Num_Lock 0xff7f, ISO_Level3_Shift 0xfe03, KP_Enter 0xff8d, KP_0..KP_9 0xffb0..0xffb9. macOS note: Backspace = XK_BackSpace 0xff08 (Mac's "Delete"), and XK_Delete 0xffff is Forward Delete (fn+Delete) — the naive mapping is already right.
LAYOUT CAVEAT (corrected): Apple's server maps the keysym through a FIXED US-layout table to a CGKeyCode and posts a CGEvent; the Mac's active input source is applied downstream by the receiving app. So interpretation is POSITIONAL, and a non-US Mac mangles LETTERS too (a<->q on AZERTY, y<->z on QWERTZ), not just punctuation. Since macOS 10.15 there is reportedly a Unicode-character path (Screens 5 "prioritizes Unicode characters over key codes... eliminates the need to match the keyboard language and layout"), which would be the in-protocol fix — but the exact keysym encoding Apple honours is UNVERIFIED. Probe it: set the Mac to QWERTZ, focus TextEdit, and send 0x007A vs 0x0100007A and 0x00E9 vs 0x010000E9. Ship a "legacy keyboard mapping" toggle. Also note injected CGEvents bypass System Settings modifier remapping and Karabiner, so remote-side fixes are not available.
QEMU Extended Key Event (-258) would sidestep all of this but Apple does not implement it, and the server must opt in by sending an empty pseudo-rectangle with encoding -258 before a client may use it.

=== STATE HYGIENE (this is where clients actually break) ===
 - Key the pressed ledger on KeyboardEvent.code and STORE THE KEYSYM YOU ACTUALLY SENT. On keyup, replay that stored keysym; never recompute. Otherwise: Shift down, '2' down (sends '@' 0x40), Shift up, '2' up recomputes 0x32 and leaves 0x40 latched down on the Mac forever.
 - Ignore any keyup for a code not in the ledger.
 - preventDefault every keydown/keyup while the canvas has focus, so Chromium's own Ctrl+C/W/R never fire. EXCEPTION: do NOT preventDefault a composition keydown (see below).
 - Release-all on: renderer 'blur', document 'visibilitychange' when hidden, main-process BrowserWindow 'blur'/'hide'/'minimize'/'leave-full-screen', 'fullscreenchange', and RFB disconnect. A renderer blur is NOT always delivered when Windows steals focus (UAC prompt, lock screen). Mirror this for the pointer: send one PointerEvent with button-mask 0 at the last coordinates on blur/pointerleave so a held button is not left down mid-drag.
 - On focus regain, after emptying the ledger, send unconditional key-UP for 0xffe1, 0xffe2, 0xffe3, 0xffe4, 0xffe7, 0xffe8, 0xffe9, 0xffea, 0xffeb, 0xffec. Releasing a key the server does not think is held is a no-op on every mainstream server. Never send matching downs. (Convention, not Apple-documented — verify once that a spurious release toggles nothing.)
 - AltGr: Windows delivers AltGr as a synthetic ControlLeft-down immediately followed by AltRight-down. Under Profile A that becomes Super_L + Meta_R = a spurious Cmd+Option. Implement noVNC's rule: buffer a ControlLeft keydown, arm a flag with a timestamp; if AltRight arrives within 50 ms, discard the buffered Control_L and emit the AltGr keysym; otherwise flush the buffered Control_L. Run this coalescing BEFORE the modifier remap. On macOS the AltGr role belongs to Option, so emit Meta_L rather than ISO_Level3_Shift.
 - IME / dead keys: detect with `evt.isComposing || evt.keyCode === 229` (isComposing primary, 229 legacy fallback; key === 'Dead'/'Process' is a secondary heuristic). PASS SUCH KEYDOWNS THROUGH WITHOUT preventDefault or you break the composition you are trying to capture. Capture the result on a FOCUSABLE off-screen input (opacity:0 with non-zero size; display:none cannot receive focus) via `input` guarded by !e.isComposing, plus `compositionend`, and TEAR DOWN the `input` listener on the first `compositionstart` so text is never sent twice. Do not use `beforeinput` — its insertCompositionText variant fires per intermediate candidate. Diff the field value and emit XK_BackSpace 0xff08 for candidate corrections. Before each synthetic char pair, emit explicit KeyEvent(down=0) for every modifier your ledger says is held (RFC 6143 §7.5.4 requires this: on a German keyboard Ctrl-Alt-Q makes '@', and Ctrl-Alt-@ means something else entirely), then send char down + up, then re-press anything still physically held.

=== POINTER ===
button-mask bits: 0 Left(0x01), 1 Middle(0x02), 2 Right(0x04), 3 ScrollUp(0x08), 4 ScrollDown(0x10), 5 ScrollLeft(0x20), 6 ScrollRight(0x40), 7 Back(0x80).
DOM MouseEvent.buttons uses a DIFFERENT bit order — middle and right are swapped. Map {0:1<<0, 1:1<<2, 2:1<<1, 3:1<<7}. Drop DOM bit 4 (Forward); it only exists under ExtendedMouseButtons, which we never request.
Wheel: no scroll message exists. Per notch emit TWO PointerEvents at the SAME (x,y): current held-button mask OR the wheel bit, then the current mask again (bit cleared). Back-to-back, no delay.
Accumulate browser deltas or you flood: if ev.deltaMode !== 0 multiply dX/dY by 19 (WHEEL_LINE_HEIGHT); accumulate; while |accum| >= 50 (WHEEL_STEP) emit one press/release pair and RESET the accumulator to 0 (noVNC deliberately drops the remainder). Sign: deltaY<0 = up (bit 3), deltaY>0 = down (bit 4), deltaX<0 = left (bit 5), deltaX>0 = right (bit 6). Ship an "invert scroll direction" toggle — macOS applies its own natural-scrolling preference downstream to injected wheel events.
Coordinates: framebuffer pixel space from ServerInit (on a Retina Mac this is the LOGICAL resolution, not the panel resolution); re-read on DesktopSize. Map with clientX/clientY minus getBoundingClientRect(), scaled by fbWidth/rect.width — both operands are CSS pixels so devicePixelRatio cancels exactly. If you find yourself multiplying by devicePixelRatio here, it is a bug. Clamp to [0, fbW-1] / [0, fbH-1] before packing (a U16 write silently wraps). Avoid offsetX/offsetY. Call setPointerCapture(ev.pointerId) on pointerdown so drags leaving the canvas keep delivering clamped events; release on pointerup/pointercancel.

=== CLIPBOARD ===
Base protocol is Latin-1 ONLY. Outbound: normalise CRLF -> LF, strip CR, substitute any codepoint > 0xff with '?' (0x3f) yourself BEFORE Buffer.from(text,'latin1') — latin1 encoding silently truncates the low byte otherwise. No trailing NUL. Inbound: read length as S32BE, treat negative as a protocol error (we never request Extended Clipboard), cap at ~1 MiB, decode with toString('latin1').
Apple's ServerCutText behaviour is the LEAST-verified thing in this brief: it may be UTF-8 in practice, may only fire after a UI action (Screen Sharing.app exposes clipboard as an explicit Edit > Get/Send Clipboard), or may not fire on remote clipboard change at all. Probe: copy 'é' and '→' on the Mac and hexdump the ServerCutText body — Latin-1 0xE9, UTF-8 0xC3 0xA9, or '?'. Do not build a bidirectional clipboard UX before measuring actual bytes.

## Electron Architecture

=== THE LOAD-BEARING FACT ===
ELECTRON HAS NO ZERO-COPY PATH FOR PIXELS FROM A NODE PROCESS TO A RENDERER. Every documented channel copies. ipcRenderer.postMessage, webContents.postMessage and MessagePortMain.postMessage all use the Structured Clone Algorithm and their transfer lists accept ONLY port objects (MessagePort[] / MessagePortMain[]) — never ArrayBuffer. webContents.send / ipcRenderer.send have no transfer list at all. contextBridge is no better even though preload and the main world share one process AND one V8 isolate: electron_api_context_bridge.cc's IsPlainObject() explicitly excludes ArrayBuffer/ArrayBufferView/DataView/SharedArrayBuffer, so typed arrays fall through to `blink::CloneableMessage` + gin::ConvertFromV8 — a full ValueSerializer round trip. There is no GetBackingStore/memcpy fast path. Values crossing contextBridge are also copied AND FROZEN, which is useless for a mutating framebuffer. MessagePort and SharedArrayBuffer are absent from contextBridge's supported-type table entirely.
SharedArrayBuffer cannot cross the Node<->renderer boundary either: main/utilityProcess and the renderer are distinct OS processes in distinct agent clusters. SAB is only useful WITHIN the renderer (main thread <-> its workers) or within Node (worker_threads), and in the renderer it additionally requires cross-origin isolation (COOP: same-origin + COEP: require-corp injected via session.webRequest.onHeadersReceived or a custom protocol handler) before self.crossOriginIsolated is true.

MEASURED COST OF THE COPY (Node v24.13.0, this machine + published electron-bench on Electron 43.2.0):
  memcpy 8.29 MB (Uint8Array.set)   0.243 ms      [flagged as optimistic: implies ~34 GB/s; treat 1-3 ms as realistic on a cold buffer]
  v8.serialize 8.29 MB Uint8Array   1.303 ms, serialized size 8,294,408 B (8-byte envelope, no compression)
  MessagePort end-to-end, 1 MB ArrayBuffer copied 4.1 ms p50 / transferred 3.2 ms p50 / as JSON 21.5 ms p50
  => 8.29 MB extrapolates to ~26-34 ms one-way, i.e. a ~30 fps ceiling for full frames on one core. (Extrapolation is LINEAR and may be wrong — mojo may switch to a shared-memory attachment above some threshold. Measure on your Electron version before treating it as a hard ceiling.)
  Never send pixels as JSON: 6.5x worse than a typed array.
PER-MESSAGE FLOOR (measured v8.serialize by size): 0 B = 2.72 us, 1 KB = 3.20, 16 KB = 9.91, 64 KB = 27.44, 8.29 MB = 1552. A 64x64 BGRA rect (16,384 B) costs 9.91 us to serialize of which only ~0.5 us is the memcpy — ~95% fixed overhead. 500 such rects as 500 messages = ~3.9 ms of serialization plus 500 mojo dispatches (electron-bench measures 0.5 ms p50 round trip). Small-rect traffic dies on MESSAGE COUNT, not bandwidth.

=== THE ANSWER: DON'T OPTIMISE THE COPY, MOVE THE BOUNDARY ===
utilityProcess: TCP socket, RFB handshake + type 30, message framing, slicing each rectangle's payload out of the stream. It does NOT inflate and does NOT expand pixels.
Renderer worker: zlib inflate + pixel expansion + WebGL2 upload, directly into the surface it draws from.
IPC volume then EQUALS NETWORK VOLUME, which is provably minimal. A 5%-dirty 1080p frame is 414,720 raw bytes (0.40 MiB, 124 us to serialize) before compression, versus 8.29 MB / ~1.5 ms serialize / ~26-34 ms transit for decode-in-Node.
Second-order win: with decode AND render in the SAME worker, you need no SharedArrayBuffer at all — the decoder writes a plain ArrayBuffer and uploads from it in place — which also removes the COOP/COEP requirement entirely. Introduce SAB only if you later fan ZRLE tile decode across multiple workers.

=== PROCESS PLACEMENT ===
Socket goes in a utilityProcess. This is unusually the security-correct AND performance-correct answer at once. Full Node (net, crypto, zlib), its own OS process and JS thread, Chromium-managed lifecycle. electron-bench, main-process CPU over 10,000 messages: ipcRenderer.send 1062 ms, ipcRenderer.invoke 1672 ms, renderer<->renderer over MessagePort 375 ms, renderer<->utilityProcess over MessagePort 140 ms — the lowest of all eight routes, 7.6x less main-process CPU than send. Putting the socket in the main process would jank window drag/resize with every blocking inflate or 8 MB serialize.
REJECT nodeIntegration: true. It is genuinely the performance ceiling (net.Socket -> decode -> SAB -> OffscreenCanvas, zero process hops, zero copies) but it forces contextIsolation: false, and a VNC client BY DESIGN ingests attacker-influenced data (ServerCutText, the remote framebuffer, the server name string). Any injected script then gets require('child_process') and full RCE. Renderer config: contextIsolation: true, nodeIntegration: false, sandbox: true, webSecurity: true.

=== TRANSPORT WIRING (one-time, at startup) ===
1. Main creates a MessageChannelMain.
2. port1 -> utilityProcess via child.postMessage(msg, [port1]).
3. port2 -> renderer via webContents.postMessage('vnc-port', null, [port2]).
4. Preload's ONLY job, the officially documented pattern: ipcRenderer.on('vnc-port', async (e) => { await windowLoaded; window.postMessage('vnc-port', '*', e.ports); }). MessagePort IS a genuine transferable across isolated worlds (same process, same agent), so this hop is a real handle transfer, not a copy.
5. Renderer main world transfers the port on to the worker together with the OffscreenCanvas: worker.postMessage({canvas: off, port}, [off, port]).
After startup, per-frame traffic touches neither preload, nor contextBridge, nor the main process's JS thread.

=== FRAME ENVELOPE (one message per frame, exactly two typed arrays) ===
Measured: {meta: Int32Array, payload: Uint8Array} serializes in 1206.6 us for 500 x 64x64 rects, versus 3683.3 us for an array of 500 per-rect objects (3.05x worse) and 3924.8 us as 500 separate messages. An array of 500 objects in ONE message does NOT help — the win comes specifically from flattening to a single contiguous byte range, and it collapses 500 mojo dispatches into 1.
  meta : Int32Array, 4-int32 header + 6 int32 per rect (native LE; host verified LE)
    header[0] magic 0x52464231 ('RFB1'), header[1] rectCount, header[2] fbWidth, header[3] fbHeight
    rect i at meta[4 + i*6 + k]: k=0 x, 1 y, 2 w, 3 h, 4 rfbEncodingNumber, 5 byteOffset into payload
  payload : Uint8Array, concatenated (still-compressed) rect bytes, EACH RECT PADDED TO A 4-BYTE BOUNDARY.
The 4-byte alignment is mandatory, not cosmetic: `new Uint32Array(buf, 2, 4)` throws RangeError ("start offset of Uint32Array should be a multiple of 4").

=== RENDER PATH ===
One renderer worker owns the canvas via canvas.transferControlToOffscreen(), with a WebGL2 context, one RGBA8 texture the size of the remote framebuffer, and a full-screen quad.
REQUIRE WebGL2. Verified: gl.UNPACK_ROW_LENGTH is undefined on a WebGL1 context but 3314 on WebGL2 (UNPACK_SKIP_ROWS 3315, UNPACK_SKIP_PIXELS 3316). Those three let you upload a sub-rect straight out of the full-frame buffer with no repacking:
  gl.pixelStorei(gl.UNPACK_ROW_LENGTH, fbWidth); UNPACK_SKIP_PIXELS = rect.x; UNPACK_SKIP_ROWS = rect.y;
  gl.texSubImage2D(TEXTURE_2D, 0, rect.x, rect.y, rect.w, rect.h, RGBA, UNSIGNED_BYTE, fullFrameU8)
WebGL1 forces a per-rect row-by-row memcpy. Also set UNPACK_ALIGNMENT = 1 and upload 3-byte ZRLE tile rows as gl.RGB/UNSIGNED_BYTE to skip the 3->4 expand entirely. Any channel reordering is free in the fragment shader; the CPU equivalent costs 3.73 ms/frame scalar or 1.80 ms/frame with a Uint32 twiddle. Filtering: gl.NEAREST when upscaling, gl.LINEAR when downscaling.
2D FALLBACK: build ONE ImageData wrapping the full-frame Uint8ClampedArray once, then per rect call the 7-arg putImageData(img, 0, 0, rect.x, rect.y, rect.w, rect.h) — allocation-free and copy-free, and it ignores transform/clip/globalAlpha so there is no canvas state cost. Downside: Chromium may de-accelerate the canvas under writeback pressure. Do NOT set willReadFrequently: true (it explicitly disables acceleration and we write, we never read).
noVNC's proven shape, worth copying either way: decode into an offscreen backbuffer, accumulate a single damage bounding box, and present it with ONE drawImage per frame — never per rect. CopyRect must be a same-surface blit (drawImage from the backbuffer to itself), not a round-trip through your pixel buffer.

=== BATCHING RULE (the "40% of bbox area" heuristic is REFUTED) ===
Measured (1920x1080 RGBA8, WebGL2, medians of 41 interleaved reps): 200 x 64x64 at coverage 0.395 => N-small 3.2 ms vs bbox 4.4 ms (N-small wins), while 800 x 32x32 at IDENTICAL coverage 0.395 => 3.2 vs 2.1 (bbox wins). Same coverage, opposite answers — any pure-coverage threshold is invalid, and at the claimed 40% knee the rule fires backwards. 2000 x 16x16 at coverage 0.247 has bbox winning 2.6x, i.e. below the gate where the rule would refuse.
CORRECT RULE: cost_N = N*F + sumArea*bpp/T; cost_bbox = F + bboxArea*bpp/T. Merge to the bbox iff (bboxArea - sumRectArea) < K*(N-1), where K = F*T/bpp. Measured F = 4.2 us per texSubImage2D call, T = 1.1-4 GB/s => K ~= 4000 px, which predicted all six measured rows correctly. CALIBRATE K at startup (time one full-frame upload and one batch of 2x2 uploads) rather than hard-coding.
Caveat the heuristic hides: RFB rects are disjoint, so the union bbox contains gap pixels the server never sent, and WebGL has no glGetTexImage. Merging therefore REQUIRES a full-resolution CPU shadow framebuffer (8.3 MB at 1080p, 33 MB at 4K). Budget it explicitly.

=== rAF / PACING ===
self.requestAnimationFrame IS available in DedicatedWorkerGlobalScope in Chromium (measured 12 callbacks at 16.65 ms avg) and fires even with no canvas transferred, with the canvas detached, and under display:none. Coalesce all drawing to one rAF tick.
BUT: the pending-rect list MUST be bounded. KasmVNC ships exactly this guard ("if the secondary display is not in focus, the browser may not call requestAnimationFrame, thus we need to limit our buffer" — queue capped at 5000 with a droppedRects counter). Electron makes it worse: webPreferences.backgroundThrottling defaults to true. Add a hard cap with an explicit drop / coalesce-to-full-frame policy, a setTimeout fallback tick, and a dropped-rect counter.
Also correct the pacing model: RFB is DEMAND-DRIVEN. RFC 6143 §3: "The server must not send unsolicited updates. An update must only be sent in response to a request from the client." So the real lever is FramebufferUpdateRequest cadence, not draw coalescing — coalescing alone just grows a decode backlog. Use a strict ONE-OUTSTANDING-REQUEST pump: one non-incremental full request after SetPixelFormat+SetEncodings, then exactly one incremental full request re-armed only after the last rectangle of each update is fully decoded. It cannot stall (there is always one request in flight) and cannot flood (the rate self-throttles to your decode rate). NEVER use setInterval. Instrument the in-flight request count — both "forgot to re-arm" (permanent stall, no error, server forbidden from pushing) and "timer flood" (unbounded backlog) look identical to the user: a frozen screen.

=== IRREVERSIBLE / SILENT-FAILURE API FACTS (verified in Chromium 152) ===
 - transferControlToOffscreen() twice throws InvalidStateError. After transfer, main-thread getContext('2d'|'webgl'|'webgl2'|'bitmaprenderer') THROWS InvalidStateError — it does not return null. Any status overlay, scaling indicator or cursor must be a SEPARATE stacked DOM element, planned up front.
 - After transfer, canvas.width = N THROWS, but canvas.setAttribute('height','300') does NOT throw and silently diverges from the worker's OffscreenCanvas size. Do backing-store resize IN THE WORKER and forward resize as a message. CSS width/height remain settable on the main thread.
 - canvas.toDataURL() no longer reflects worker content — screenshot via OffscreenCanvas.convertToBlob() in the worker.
 - OffscreenCanvas.prototype.commit is undefined (removed); frames auto-propagate at end of task.

=== SCALING / DPI ===
Canvas BACKING STORE stays exactly fbWidth x fbHeight, always. Never scale it — that resamples once in your code and again in the compositor.
Fit by computing the box in DEVICE pixels and rounding, then converting back to CSS px: scale = min(boxW/fbW, boxH/fbH); devW = round(fbW*scale*dpr); style.width = (devW/dpr)+'px'. Better: read entry.devicePixelContentBoxSize from a ResizeObserver for the exact integer device-pixel box.
image-rendering: pixelated (nearest) when scale >= 1 so remote text stays crisp; auto (linear) when scale < 1 to avoid shimmer while scrolling. Switch dynamically. On WebGL this is TEXTURE_MIN/MAG_FILTER instead.
devicePixelRatio changes with no event when the window moves between monitors: watch matchMedia(`(resolution: ${devicePixelRatio}dppx)`) and RE-REGISTER the listener each time it fires (the query string is stale after a change).
Set canvas { display:block; border:0; padding:0; } — the inline-element baseline gap and any border shift the box and break coordinate mapping.

=== THE ONE OPEN ARCHITECTURAL DEPENDENCY: BROWSER-SIDE INFLATE ===
Corrected risk direction: the BROWSER side is the solved one. noVNC ships core/inflator.js — a pure-JS pako-based inflater with exactly the pull API RFB needs: setInput(u8), inflate(expectedBytes) -> Uint8Array (throwing "Incomplete zlib block" if it cannot produce exactly that many), reset(). NODE is the awkward side: there is no synchronous incremental inflate in the public API — flush(Z_SYNC_FLUSH, cb) fires asynchronously, and the old inflate._processChunk(buf, Z_SYNC_FLUSH) trick used by several existing Node VNC libraries works EXACTLY ONCE on modern Node (verified v24.13.0: it returns correct data, nulls _handle, and the second call throws "Cannot read properties of null (reading 'writeSync')"). zlib.inflateSync is wrong for all three stateful encodings (verified: rect1 throws Z_BUF_ERROR without finishFlush: Z_SYNC_FLUSH, and rect2 throws Z_DATA_ERROR "incorrect header check" because it carries no zlib header). The correct Node API is one long-lived zlib.createInflate({flush: Z_SYNC_FLUSH}) per RFB stream, written to in order, with output collected from 'data' — asynchronous, and its errors arrive on the 'error' event decoupled from the write that caused them (an unhandled one crashes the process).
CONCLUSION: vendor ONE pure-JS incremental inflater (not a native addon, so it satisfies the constraint) and import it directly in both runtimes. It removes the seam, keeps the decoder synchronous, and is the only option that meets ZRLE's byte-exact pull requirement — DecompressionStream('deflate') exists in both Node and the browser but cannot request exactly N bytes, which ZRLE needs (1-byte subencoding, then palette, then runs). Do NOT design the decoder around an injected createInflate; injection buys only Node zlib, which cannot meet the contract. Keep the constructor parameter for testability/fault-injection, not as a portability mechanism.
NOTE: Z_SYNC_FLUSH is a DEFLATE-side action the server performs (it emits 00 00 FF FF, observed live); the client's flush argument is irrelevant — noVNC passes 0 with the comment "Flush argument not used."
Tight would need reset() on 4 streams; ZRLE and zlib(6) streams must NEVER be reset.

## Open Questions

- Which encodings does screensharingd ACTUALLY emit on macOS 14/15/26? The Hextile/Tight-negative evidence is from Sierra (2016) and High Sierra 10.13.5 (2018); the 2026 reverse-engineered Apple spec is silent on Hextile rather than affirmatively denying it. GATE any investment in Hextile or Tight on one log line: the S32 encoding-type of every rectangle in the first real session. A server never advertises its encodings, so this is the only way to know.
- Does Apple honour an arbitrary SetPixelFormat? LIKELY YES (noVNC and libvncclient both request their own RGBX 32/24 unconditionally, hard-assume it in every decoder, and are routinely pointed at macOS without a universal red/blue-swap symptom being reported) but never positively confirmed. The failure mode is 'renders perfectly with red and blue swapped', easy to misattribute. Probe by logging ServerInit's PIXEL_FORMAT and the format observed in the first Raw rectangle. Keep decoders parameterised either way — the CPIXEL width depends on it.
- Does Apple's ServerInit report depth == bits-per-pixel (32/32)? Some servers do 'for historical reasons', and depth > 24 disables the 3-byte CPIXEL form. Only matters if you ever decode without sending your own SetPixelFormat.
- Is Meta_L -> Option still true on Sonoma/Sequoia/Tahoe? The mapping is well-corroborated (AVNC #163 verified with the Keyboard Viewer and gated on the literal 'RFB 003.889' banner; Remmina's shipped Map-Meta-Keys preset) but no client except AVNC ever emits 0xffe7, so it is a low-traffic code path in Apple's server — low regression pressure to break it, low guarantee it still works. Cheap post-auth probe: focus TextEdit on a US layout and send [modifier down] + keysym 0x0033 ('3') + [modifier up] per candidate. '3' = modifier dropped, '#' = Shift, 'GBP' = Option, no character = Command, nothing at all = Control. Requires being attached to the CONSOLE session (defaults write /Library/Preferences/com.apple.RemoteManagement VNCAlwaysStartOnConsole -bool true) or a Keyboard-Viewer oracle sees nothing. Karabiner EventViewer is NOT a valid oracle — screensharingd injects at the CGEvent layer, above Karabiner's virtual-HID driver.
- Does Apple distinguish left vs right Command / Option (Super_L vs Super_R, Meta_L vs Meta_R)? AVNC only established key identity, not handedness; OSXvnc collapses both sides to one keycode. Assume no handedness until probed.
- Does the post-Catalina Unicode-keysym path exist on the wire, and in what encoding? Screens 5 documents that 'since macOS 10.15 Catalina, Apple has changed how the Screen Sharing service processes keyboard input... Screens 5 now prioritizes Unicode characters over key codes,' which would fix the positional-layout problem entirely. The exact encoding Apple honours (0x01000000|cp vs plain Latin-1 keysym vs an ARD-private message) is NOT confirmed by any source. Probe: set the Mac to QWERTZ/AZERTY, focus TextEdit, and send 0x007A, 0x0100007A, 0x00E9, 0x010000E9 as separate trials.
- What does Apple actually do with ServerCutText? Is it Latin-1 or UTF-8 in practice, does it fire on remote clipboard change or only after a UI action (Screen Sharing.app exposes clipboard as an explicit Edit > Get/Send Clipboard), and does it fire at all? Probe by copying 'e-acute' and a right-arrow on the Mac and hexdumping the body: Latin-1 0xE9, UTF-8 0xC3 0xA9, or '?'. Do not build a bidirectional clipboard UX before measuring bytes.
- Does screensharingd honour -223 DesktopSize and -224 LastRect for a plain third-party client, or does it substitute its proprietary 0x451 AppleDisplayLayout and 0x450 CursorImage? Log it in the same first-session experiment.
- Are 33 and 35 anything we can use? 36 is corroborated as Apple SRP (2026 screensharingd reverse-engineering; Apple's EndpointSecurity screensharing_attach event reports authentication_type 'RSA-SRP'), with a ChaCha20-Poly1305 record layer installed post-auth and a 4-byte big-endian frame-length field, but no public byte-level spec. 35 has only a name ('Mac OS X security type', nmap). 33 is entirely unattributed. Treat all three as reverse-engineering projects, not fallbacks.
- Is the ~26-34 ms extrapolation for an 8.29 MB IPC transfer real, or does mojo switch to a shared-memory attachment above some payload threshold? The figure is a LINEAR extrapolation from published 1 MB measurements on Electron 43.2.0. Measure on your actual Electron version before treating ~30 fps as a hard ceiling. Also note the local v8.deserialize figure of 0.002 ms for 8.29 MB is an in-process aliasing artifact (V8 took ownership of the backing store) and must NOT be read as 'the receive side is free' — across an OS process boundary there is a genuine copy.
- Is worker requestAnimationFrame suspended or merely throttled in a minimized / occluded Electron BrowserWindow? webPreferences.backgroundThrottling defaults to true and KasmVNC ships a defensive queue cap for exactly this, but the distinction was not confirmed under test. Assume suspension and ship the setTimeout fallback tick.
- Does utilityProcess support an ESM entry point on your target Electron version? Electron main supports ESM from v28 with .mjs, but utilityProcess may differ. Use CommonJS for src/service/** until confirmed.
- What is the exact Electron permission string for the Chrome >= 130 keyboard-lock permission gate, to be handled in session.setPermissionRequestHandler? Not confirmed in Electron's docs; probe it.
- Can navigator.keyboard.lock() actually suppress Win+L? No authoritative statement either way was found. Ctrl+Alt+Del is definitively unreachable (winlogon registers the SAS before any other process). Treat Win+L as unblockable, document it, and do not design around capturing it.
- Will crypto.createDiffieHellman reject a future non-Oakley-Group-2 prime under a stricter OpenSSL safe-prime check, and is MD5 available in your Node build? MD5 is unavailable on a FIPS-enabled OpenSSL. Keep a BigInt modPow fallback (measured ~2.2 ms per 1024-bit exponentiation, bit-identical to OpenSSL) and a JS MD5 behind a flag.

## Module Breakdown

- src/rfb/** — HARD RULE: zero `require('electron')`, zero I/O, zero timers, zero Buffer, zero canvas. Runs identically in Node and the browser. Enforce with an ESLint no-restricted-imports rule AND a CI test that greps the tree, so it fails in CI rather than at runtime.
- src/rfb/rfb-session.js — the pure state machine and the single most important design decision. API: feed(Uint8Array) -> Event[]; takeOutbound() -> Uint8Array; no sockets, no promises, no timers inside it. Tests become synchronous byte-in/byte-out assertions: fast and non-flaky.
- src/rfb/io/reader.js — incremental BIG-ENDIAN reader over a chunk queue. Throws a sentinel NeedMoreBytes; the session rolls its cursor back and re-enters at the same point on the next chunk. This is what makes partial TCP segments correct by construction rather than by luck. Explicit DataView.getUint16(off,false)/getUint32(off,false) — never rely on typed-array views, which are native little-endian. Encoding-type MUST use getInt32(off,false).
- src/rfb/io/writer.js — fixed-offset message builder. Every outbound message is allocated at its exact length and written with writeUInt*BE; padding always zeroed.
- src/rfb/protocol/handshake.js — 12-byte banner parse (major/minor from the fixed ASCII layout, clamp minor>8 to 3.8 semantics), 12-byte 'RFB 003.008\n' reply, security-list parse (U8 count + U8[n], count==0 => U32BE reason).
- src/rfb/protocol/security/index.js — pluggable registry {typeNumber -> handler} with an explicit ordered preference list, currently [30]. Scans the offered list for a match; on failure raises an error listing the offered numbers verbatim.
- src/rfb/protocol/security/apple-dh.js — security type 30. Pure function (serverParams, username, password, rng, privateExponent) -> {payload256, debugOnlyKeyMaterial}. Contains the one shared leftPad(buf, keyLength) helper used for BOTH the client public key and the shared secret. Never logs the blob, the secret or the MD5 key. Kept on a separate call path from parameter parsing so handshake debugging can never submit credentials.
- src/rfb/protocol/pixel-format.js — the 16-byte PIXEL_FORMAT struct, plus derived bytesPerPixel / bytesPerCPixel / channel-byte-index tables. Every decoder takes a PixelFormat object; nothing hard-codes 3 or 4.
- src/rfb/protocol/messages/client.js — SetPixelFormat(20), SetEncodings(4+4N), FramebufferUpdateRequest(10), KeyEvent(8), PointerEvent(6), ClientCutText(8+n), ClientInit(1).
- src/rfb/protocol/messages/server.js — dispatcher for FramebufferUpdate(0), SetColourMapEntries(1), Bell(2, ONE byte, no body), ServerCutText(3). Must not assume a minimum 4-byte server header.
- src/rfb/framebuffer-update.js — the resumable rectangle loop. Holds FBU state {rects, encoding, x, y, w, h} across socket reads; unconditional break on encoding-type -224; treats number-of-rectangles as an untrusted upper bound; handles 0 rectangles as an immediately-complete empty update; treats an unadvertised encoding-type as fatal with the numeric value logged.
- src/rfb/decoders/index.js — registry keyed by encoding number so the advertised set is config-driven. decode(reader, rect, pixelFormat, framebufferU8, fbStride) -> true | NEED_MORE. Note the signature carries stride AND pixel format; rect alone cannot give you the destination offset.
- src/rfb/decoders/raw.js — phase 1. w*h*bytesPerPixel, plus the alpha fill.
- src/rfb/decoders/copyrect.js — phase 1. 4-byte payload; overlap-safe (temp buffer or direction-aware iteration, or same-surface drawImage on the canvas path).
- src/rfb/decoders/zlib6.js — phase 2. U32BE length + bytes into the encoding-6 stream; output is exactly a Raw rectangle.
- src/rfb/decoders/zrle.js — phase 3. 64x64 tiles, the 8 subencoding families, packed-palette row byte alignment, base-255 run-length varint, CPIXEL width from PixelFormat. Asserts decompressed-bytes-consumed == tile-parser-accounted and drops the connection on mismatch. AVOID the known bugs in filipecbmoc/vnc-rfb-client: its 2-bit palette path uses (byte & 196) >> 6 where the correct mask is 0xC0 = 192, and its row handling only implements per-row alignment by accident. That package also ships an empty 24-line Tight stub — a useful signal for Tight's real cost.
- src/rfb/pseudo/cursor.js — -239: pixels + floor((w+7)/8)*h mask, hotspot from rect x/y, 0-size means hide. Emits a cursor event; never writes the framebuffer.
- src/rfb/pseudo/desktop-size.js — -223: zero payload, resize + force a non-incremental full request.
- src/rfb/inflate/inflate.js — ONE vendored pure-JS incremental inflater with a byte-exact pull API: setInput(u8), inflate(expectedBytes), reset(). Imported directly by Node and the browser. Two instances per connection (ZRLE, zlib6), never reset.
- src/rfb/keysym/ — domkeytable.js (DOM key -> keysym, 4-element arrays indexed by KeyboardEvent.location), keysymdef.js (codepoint -> keysym: 0x20..0xff direct, legacy table, then 0x01000000|cp), apple-modifiers.js (the banner-gated Apple table + the Profile A / Profile B remaps).
- src/rfb/transport.js — INTERFACE ONLY: {write(u8), onData(cb), close()}. Nothing in src/rfb implements it.
- src/service/node-transport.js — the net.Socket implementation. Node-only. Lives OUTSIDE src/rfb.
- src/service/vnc-service.js — runs inside utilityProcess: owns the socket, drives rfb-session, slices rectangle payloads and emits the {meta:Int32Array, payload:Uint8Array} frame envelope down the MessagePort. Does NOT inflate, does NOT expand pixels. Use CommonJS here until ESM support in utilityProcess is confirmed on your Electron version.
- src/main/index.js — BrowserWindow (contextIsolation true, nodeIntegration false, sandbox true), utilityProcess.fork, MessageChannelMain creation and the port1/port2 split, optional COOP/COEP header injection (only if you ever need SAB), keyboard-lock permission handler.
- src/preload/index.js — roughly 15 lines. ipcRenderer.on('vnc-port') -> await windowLoaded -> window.postMessage('vnc-port','*',e.ports). Nothing else. Never on the per-frame path.
- src/renderer/app.js — DOM, input capture (pointer/keyboard/wheel/clipboard), the pressed-key ledger, focus/blur release-all, ResizeObserver + devicePixelRatio watcher, transferControlToOffscreen, and forwarding the port + canvas to the worker. Overlays are SEPARATE stacked DOM elements, since the canvas can never be drawn to from the main thread again.
- src/renderer/workers/vnc-worker.js — owns the OffscreenCanvas + WebGL2 context + the framebuffer texture + the CPU shadow buffer; runs the decoders; implements the calibrated (bboxArea - sumArea) < K*(N-1) merge rule; bounded pending-rect queue with a drop counter; rAF tick with a setTimeout fallback; handles resize messages by setting the OffscreenCanvas dimensions itself.
- test/rfb/*.test.js — node --test (built in; zero dependencies). No Electron, no network, fully synchronous.
- test/rfb/fixtures/*.bin — REAL captured bytes from 192.168.68.125:5900 in BOTH directions. Capture these FIRST, while you have the Mac mini: the 12-byte banner, the 5-byte security list, the 260-byte type-30 parameter block, a full FramebufferUpdate of each encoding you see, a ServerCutText after copying 'é' and '→'. These are perishable; you cannot unit-test the 003.889 handshake without them.
- test/harness/fake-server.js — net.createServer replaying a fixture, for integration tests without the hardware.
- test/rfb/split-feed.test.js — THE HIGHEST-VALUE SINGLE TEST: feed every fixture ONE BYTE AT A TIME and assert the emitted event stream is byte-identical to feeding it whole. This catches nearly every framing and NeedMoreBytes bug in one assertion.
- test/rfb/no-electron-import.test.js — greps src/rfb/** for 'electron', 'require(\'net\')', 'Buffer', 'zlib' and fails the build on a hit.

## Top Risks

### R1. FIRST-CONNECTION KILLER: forgetting to left-zero-pad the DH client public key. Measured on Node v24.13.0, dh.getPublicKey() STRIPS leading zeros — 11 of 4000 and 13 of 2000 trials returned keyLength-1 bytes (~0.5%). The client public key is a fixed keyLength-wide wire field, so a short one makes the server misparse the 256-byte submission. This is an intermittent ~1-in-150-to-256 failure that is non-reproducible and extremely expensive to diagnose after the fact. (Note the mirror-image belief is wrong: computeSecret() ALREADY pads — 0 short in 4000 trials — so the widely-cited 'pad the secret' advice targets the wrong end.)

**Mitigation:** Write ONE leftPad(buf, keyLength) helper and call it on BOTH the client public key and the shared secret, unconditionally, regardless of Node's behaviour. Add a unit test that forces a leading-zero public key via a fixed private exponent and asserts the emitted field is exactly keyLength bytes.

### R2. Leaving PKCS#7 auto-padding on for the AES-128-ECB step. The 128-byte plaintext is already a multiple of 16, so autopadding silently emits 144 bytes, the server reads 16 bytes of ciphertext as the start of the client public key, and the whole submission desynchronizes. Fails 100% of the time but the error surfaces only as a generic auth failure.

**Mitigation:** cipher.setAutoPadding(false) immediately after createCipheriv, and assert the ciphertext length === 128 before writing. Assert the total write === 128 + keyLength.

### R3. Hardcoding keyLength = 128 or generator = 2. One research thread confidently reported generator=5 and keyLength=512 (4096-bit MODP Group 16) for modern macOS from a RealVNC binary-patch project; the live probe of THIS target shows 2 and 128. Legacy ARD used 64. Stock RealVNC 7.15.1 fails against some Macs with exactly 'Protocol error: key length too large' then 'Unsupported DH generator 5' for this reason.

**Mitigation:** Read generator and keyLength from the wire on every connection and size every buffer, slice and pad width from the field. Never validate generator against a whitelist. Log loudly (do not reject) if generator != 2 or keyLength != 128, and if the prime is not RFC 2409 Oakley Group 2.

### R4. Reading the rectangle encoding-type with readUInt32BE instead of readInt32BE. This silently breaks EVERY pseudo-encoding (-223 DesktopSize, -224 LastRect, -239 Cursor) — -224 reads as 4294967072 — and manifests as the unrecoverable 'unknown encoding, fatal' failure two layers away from the cause. It is the single most common bug in from-scratch RFB clients; noVNC has to force signedness explicitly with `this._FBU.encoding >>= 0`.

**Mitigation:** Use DataView.getInt32(off, false) in exactly one place, in io/reader.js. Unit-test that -224 round-trips. Never compare against unsigned constants.

### R5. Unknown or unimplemented encoding-type is UNRECOVERABLE. RFB carries no per-rectangle length, so you cannot skip a payload you cannot decode, and there is no resynchronisation short of reconnecting. Advertising an encoding you have only half-implemented, or an Apple-proprietary number, kills the session mid-frame.

**Mitigation:** Advertise ONLY fully-implemented encodings, always include Raw(0), phase the list (Raw+CopyRect -> +zlib6 -> +ZRLE), and treat any unadvertised encoding-type as a hard disconnect with the numeric value logged. Never request 1000-1002, 1011, 1100-1105.

### R6. Advertising VMwareCursor (0x574d5664) — or, more generally, assuming unsupported pseudo-encodings are silently ignored. Apple STOPS SENDING ALL CURSOR UPDATES to a client that advertises the VMware cursor extension (reproduced first-hand by TigerVNC's maintainer on noVNC #1430). This is exactly why noVNC shows no cursor against macOS while libvncclient-based clients do. Symptom: no pointer at all, no error.

**Mitigation:** Never advertise 0x574d5664 or 0x574d5666. Advertise the minimum pseudo-encoding set (-239, -223, -224) and add anything further one at a time while observing. Ship a local-arrow / dot-cursor fallback, because Apple's cursor updates are also known to go stale (TigerVNC #826).

### R7. Bell is a ONE-BYTE message with no padding and no body. Any receive loop that assumes a minimum 4-byte server-message header desyncs permanently the first time the Mac beeps — which will happen during normal use, long after you have declared the client working.

**Mitigation:** Dispatch server messages by reading exactly one type byte first, then branching to a per-type reader. Unit-test a fixture containing Bell sandwiched between two FramebufferUpdates.

### R8. Creating a fresh inflater per rectangle, or using zlib.inflateSync, or copying the inflate._processChunk pattern from older Node VNC libraries. Verified on Node v24.13.0: inflateSync(rect1) throws Z_BUF_ERROR without finishFlush:Z_SYNC_FLUSH and inflateSync(rect2) throws Z_DATA_ERROR 'incorrect header check' because rectangle 2 carries no zlib header; _processChunk works exactly ONCE then nulls the internal handle and the next call throws a TypeError. ZRLE and zlib(6) each use ONE stream for the entire connection that must never be reset and must be decoded strictly in order.

**Mitigation:** Vendor one pure-JS incremental inflater with a byte-exact pull API (setInput / inflate(expectedBytes) / reset) and use it in both runtimes. Create exactly two instances at connect time. Never call reset() on either. After each ZRLE rectangle, assert decompressed-bytes-consumed equals what the tile parser accounted for, and drop the connection on mismatch — a mis-parsed tile does not throw, it silently poisons every later rectangle.

### R9. Sending SetPixelFormat while a FramebufferUpdateRequest is outstanding. The community rfbproto states a client MUST NOT do this because the format of the next FramebufferUpdate becomes ambiguous. The symptom — wrong colours or garbage — is indistinguishable from 'Apple ignored my SetPixelFormat', which will corrupt the very probe you use to decide the decoder's pixel handling.

**Mitigation:** Fixed order after ServerInit: SetPixelFormat, then SetEncodings, then the FIRST FramebufferUpdateRequest. Never change format mid-session. Parameterise all decoders by the active PixelFormat object and log both ServerInit's format and the format observed in the first Raw rectangle.

### R10. The update pump. A setInterval-driven FramebufferUpdateRequest loop floods the server and builds an unbounded decode backlog (RFC 6143 permits one update to satisfy several outstanding requests but does not bound how many may be in flight). Conversely, forgetting to re-arm the incremental request after a fully-decoded update stalls the session FOREVER with no error, because the server is forbidden from sending unsolicited updates. Both look identical to the user: a frozen screen.

**Mitigation:** Strict one-outstanding-request pump: one incremental=0 full-screen request after SetPixelFormat+SetEncodings, then exactly one incremental=1 full-screen request re-armed only when the rectangle loop reports all rectangles consumed. Never a timer. Instrument and expose the in-flight request count.

### R11. U32 length fields are attacker/bug-controlled up to ~4 GiB: ServerCutText length, ServerInit name-length, and ZRLE's zlibData length. Allocating on the announced size OOMs the process. ServerCutText's length additionally becomes SIGNED under Extended Clipboard.

**Mitigation:** Cap every one before allocating (e.g. 1 MiB clipboard, 256 B..64 KiB name, 32 MiB zlib chunk) and abort the connection on overflow. Read ServerCutText length as S32BE and treat negative as a protocol error, since we never request 0xC0A1E5CE.

### R12. Apple's undocumented trailing 0x00 after the SecurityResult failure reason (48 bytes delivered where 4+4+39 = 47). A strict RFC 6143 reader that asserts EOF at 8+reasonLength, or that leaves the byte buffered for the next state, produces a spurious protocol error or corrupts reconnect logic.

**Mitigation:** Read status, then reasonLength, then reasonLength bytes; drain and discard anything remaining; treat the connection as closed. Unit-test against the captured 48-byte fixture.

### R13. Environmental failures that look like protocol bugs. With FileVault enabled, screensharingd is not running before the first local unlock — after a reboot port 5900 does not answer at all. A valid password for an account NOT in the Screen Sharing / Remote Management allow-list produces the IDENTICAL opaque 'Authentication or authorization failure' as a wrong password. And every failed attempt is a real failed login against a real macOS account, so retry loops can trip account lockout, MDM alerting and unified-log noise.

**Mitigation:** Distinguish 'connection refused / no listener' from 'auth failed' in the UI and name FileVault pre-boot as a cause. Surface the server's reason string verbatim and state that it cannot distinguish bad password from insufficient rights. Rate-limit retries and NEVER auto-retry a rejected password.

### R14. Modifier keys latching permanently on the Mac. Recomputing the keysym at keyup instead of replaying the one you sent (Shift down, '2' down sends '@' 0x40, Shift up, '2' up sends 0x32) leaves 0x40 held forever. Renderer 'blur' is also not always delivered when Windows steals focus (UAC prompt, lock screen, Alt+Tab), so a modifier down-event can have no matching up. Once a modifier latches, the remote session is unusable until someone physically intervenes at the Mac.

**Mitigation:** Key the pressed ledger on KeyboardEvent.code and store the keysym actually sent; replay it on keyup; ignore keyups for codes not in the ledger. Release-all on renderer blur, document visibilitychange, main-process BrowserWindow blur/hide/minimize/leave-full-screen, fullscreenchange, and RFB disconnect. Add an unconditional modifier-release sweep (0xffe1-0xffec) on focus regain.

### R15. Assuming dirty rects stay small. Full-screen video, fast scrolling, or a Mission Control animation turns every frame into a near-full-frame update, which is precisely the case that collapses a design tuned on 'someone typing in Terminal'. On the decode-in-Node design this hits the measured ~26-34 ms/frame IPC ceiling.

**Mitigation:** Ship compressed-payload-over-IPC (decode in the renderer worker) so IPC volume equals network volume, and TEST with video playing on the Mac before declaring the client done. Bound the pending-rect queue with an explicit drop-to-full-frame policy and expose a dropped-rect counter.
