// Wire-level tests for the RFB protocol layer: message builders, PIXEL_FORMAT,
// Apple type-30 auth (cross-checked against node:crypto), and the RfbSession
// state machine driven by synthetic server bytes -- whole, then one byte at a time.

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createCipheriv,
  createDiffieHellman,
  createHash,
  getDiffieHellman,
} from 'node:crypto';

import { Writer } from '../../src/rfb/io/writer.js';
import {
  CANVAS_PIXEL_FORMAT,
  bytesPerPixel,
  writePixelFormat,
  readPixelFormat,
} from '../../src/rfb/protocol/pixel-format.js';
import {
  clientInit,
  setPixelFormat,
  setEncodings,
  framebufferUpdateRequest,
  keyEvent,
  pointerEvent,
  clientCutText,
} from '../../src/rfb/protocol/messages/client.js';
import { Reader } from '../../src/rfb/io/reader.js';
import {
  buildAppleDhResponse,
  parseAppleDhParams,
} from '../../src/rfb/protocol/security/apple-dh.js';
import { bytesToBigInt, bigIntToBytes, modPow } from '../../src/rfb/crypto/dh.js';
import { RfbSession, State } from '../../src/rfb/rfb-session.js';

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

const cat = (...parts) => {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
};

const u8 = (v) => new Uint8Array([v & 0xff]);
const u16be = (v) => new Uint8Array([(v >>> 8) & 0xff, v & 0xff]);
const u32be = (v) => {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, v >>> 0, false);
  return b;
};
const i32be = (v) => {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setInt32(0, v | 0, false);
  return b;
};
const ascii = (s) => new Uint8Array(Array.from(s, (c) => c.charCodeAt(0) & 0xff));
const hex = (u) => Array.from(u, (b) => b.toString(16).padStart(2, '0')).join('');
const leftPad = (bytes, n) => {
  const out = new Uint8Array(n);
  out.set(bytes, n - bytes.length);
  return out;
};

/** The session logs banner/DH info; keep the test report readable. */
function quiet(fn) {
  const saved = { info: console.info, warn: console.warn, log: console.log };
  console.info = () => {};
  console.warn = () => {};
  console.log = () => {};
  try {
    return fn();
  } finally {
    Object.assign(console, saved);
  }
}

/**
 * xorshift32 PRNG. Same seed => same bytes, so the whole-chunk run and the
 * byte-at-a-time run produce a byte-identical DH response.
 * The high bit of byte 0 is cleared so the private exponent is always < p.
 */
function deterministicRandom(seed = 0x1a2b3c4d) {
  let s = seed >>> 0;
  const calls = [];
  const fn = (n) => {
    const out = new Uint8Array(n);
    for (let i = 0; i < n; i++) {
      s ^= (s << 13) >>> 0;
      s >>>= 0;
      s ^= s >>> 17;
      s ^= (s << 5) >>> 0;
      s >>>= 0;
      out[i] = s & 0xff;
    }
    if (n > 0) out[0] &= 0x7f;
    calls.push(out.slice());
    return out;
  };
  fn.calls = calls;
  return fn;
}

// ---------------------------------------------------------------------------
// message builders
// ---------------------------------------------------------------------------

test('writePixelFormat emits the exact 16 bytes for CANVAS_PIXEL_FORMAT', () => {
  const w = new Writer(16);
  writePixelFormat(w, CANVAS_PIXEL_FORMAT);
  const b = w.result;

  assert.equal(b.length, 16);
  assert.deepEqual(
    Array.from(b),
    [
      16, // bits-per-pixel = 16 (RGB565)
      16, // depth
      0, // bigEndian
      1, // trueColour
      0, 31, // redMax   u16 BE (5 bits)
      0, 63, // greenMax        (6 bits)
      0, 31, // blueMax         (5 bits)
      11, // redShift
      5, // greenShift
      0, // blueShift
      0, 0, 0, // padding
    ],
  );
  assert.equal(CANVAS_PIXEL_FORMAT.depth, 16);
  assert.equal(CANVAS_PIXEL_FORMAT.redShift, 11);
  assert.equal(CANVAS_PIXEL_FORMAT.greenShift, 5);
  assert.equal(CANVAS_PIXEL_FORMAT.blueShift, 0);
  assert.equal(bytesPerPixel(CANVAS_PIXEL_FORMAT), 2);
});

test('readPixelFormat round-trips writePixelFormat', () => {
  const w = new Writer(16);
  writePixelFormat(w, CANVAS_PIXEL_FORMAT);
  const r = new Reader();
  r.push(w.result);
  assert.deepEqual(readPixelFormat(r), CANVAS_PIXEL_FORMAT);
  assert.equal(r.remaining, 0);
});

test('clientInit is one byte', () => {
  assert.deepEqual(Array.from(clientInit(1)), [1]);
  assert.deepEqual(Array.from(clientInit(0)), [0]);
  assert.equal(clientInit().length, 1);
});

test('setPixelFormat is exactly 20 bytes: type, 3 pad, 16 format', () => {
  const b = setPixelFormat(CANVAS_PIXEL_FORMAT);
  assert.equal(b.length, 20);
  assert.deepEqual(
    Array.from(b),
    [0, 0, 0, 0, 16, 16, 0, 1, 0, 31, 0, 63, 0, 31, 11, 5, 0, 0, 0, 0],
  );
  assert.deepEqual(Array.from(setPixelFormat()), Array.from(b), 'defaults to CANVAS_PIXEL_FORMAT');
});

test('framebufferUpdateRequest is exactly 10 bytes', () => {
  assert.deepEqual(
    Array.from(framebufferUpdateRequest(0, 0, 0, 1024, 768)),
    [3, 0, 0, 0, 0, 0, 0x04, 0x00, 0x03, 0x00],
  );
  const inc = framebufferUpdateRequest(1, 0x0102, 0x0304, 0x0506, 0x0708);
  assert.equal(inc.length, 10);
  assert.deepEqual(Array.from(inc), [3, 1, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
});

test('keyEvent is exactly 8 bytes with a big-endian u32 keysym', () => {
  const down = keyEvent(true, 0xff0d); // Return
  assert.equal(down.length, 8);
  assert.deepEqual(Array.from(down), [4, 1, 0, 0, 0x00, 0x00, 0xff, 0x0d]);

  const up = keyEvent(false, 0x0100263a); // unicode keysym, high bit region
  assert.equal(up.length, 8);
  assert.deepEqual(Array.from(up), [4, 0, 0, 0, 0x01, 0x00, 0x26, 0x3a]);
});

test('pointerEvent is exactly 6 bytes', () => {
  const p = pointerEvent(0x01, 300, 700);
  assert.equal(p.length, 6);
  assert.deepEqual(Array.from(p), [5, 1, 0x01, 0x2c, 0x02, 0xbc]);
  assert.deepEqual(Array.from(pointerEvent(0, 0, 0)), [5, 0, 0, 0, 0, 0]);
});

test('setEncodings is 4 + 4N and negative pseudo-encodings survive as signed i32', () => {
  const encodings = [16, 6, 1, 0, -239, -223, -224];
  const b = setEncodings(encodings);

  assert.equal(b.length, 4 + 4 * encodings.length, '4 + 4N');
  assert.equal(b.length, 32);
  assert.deepEqual(Array.from(b.subarray(0, 4)), [2, 0, 0x00, 0x07], 'type, pad, u16 count');

  const view = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const readBack = encodings.map((_, i) => view.getInt32(4 + i * 4, false));
  assert.deepEqual(readBack, encodings);

  // The exact two's-complement bytes, spelled out.
  assert.equal(hex(b.subarray(4 + 4 * 4, 4 + 5 * 4)), 'ffffff11', '-239 Cursor');
  assert.equal(hex(b.subarray(4 + 5 * 4, 4 + 6 * 4)), 'ffffff21', '-223 DesktopSize');
  assert.equal(hex(b.subarray(4 + 6 * 4, 4 + 7 * 4)), 'ffffff20', '-224 LastRect');

  assert.equal(setEncodings([]).length, 4);
  assert.deepEqual(Array.from(setEncodings([])), [2, 0, 0, 0]);
});

test('clientCutText is 8 + n latin-1 bytes', () => {
  const b = clientCutText('AB');
  assert.equal(b.length, 10);
  assert.deepEqual(Array.from(b), [6, 0, 0, 0, 0, 0, 0, 2, 0x41, 0x42]);
});

// ---------------------------------------------------------------------------
// Apple Diffie-Hellman (security type 30)
// ---------------------------------------------------------------------------

const MODP2_PRIME = new Uint8Array(getDiffieHellman('modp2').getPrime());
const GENERATOR = 2;
const KEY_LENGTH = 128;

/** A real server keypair from node:crypto, left-padded to keyLength like the wire. */
function makeServerKeypair() {
  const dh = createDiffieHellman(Buffer.from(MODP2_PRIME), Buffer.from([GENERATOR]));
  dh.generateKeys();
  return {
    dh,
    publicKey: leftPad(new Uint8Array(dh.getPublicKey()), KEY_LENGTH),
  };
}

const SERVER = makeServerKeypair();

test('MODP2 prime and server public key are both exactly 128 bytes', () => {
  assert.equal(MODP2_PRIME.length, KEY_LENGTH);
  assert.equal(SERVER.publicKey.length, KEY_LENGTH);
});

test('parseAppleDhParams reads generator, keyLength, prime, serverPublic', () => {
  const r = new Reader();
  r.push(cat(u16be(GENERATOR), u16be(KEY_LENGTH), MODP2_PRIME, SERVER.publicKey));
  const p = parseAppleDhParams(r);
  assert.equal(p.generator, 2);
  assert.equal(p.keyLength, 128);
  assert.deepEqual(p.prime, MODP2_PRIME);
  assert.deepEqual(p.serverPublic, SERVER.publicKey);
  assert.equal(r.remaining, 0, 'consumed exactly 4 + 2L bytes');
});

test('buildAppleDhResponse: 128 + keyLength bytes, ciphertext half then public half', () => {
  const rand = deterministicRandom();
  const params = {
    generator: GENERATOR,
    keyLength: KEY_LENGTH,
    prime: MODP2_PRIME,
    serverPublic: SERVER.publicKey,
  };
  const out = buildAppleDhResponse(params, 'alice', 'hunter2', rand);

  assert.equal(out.length, 128 + KEY_LENGTH, 'total is 128 + keyLength');
  assert.equal(out.length, 256);

  const ciphertext = out.subarray(0, 128);
  const clientPublic = out.subarray(128);
  assert.equal(ciphertext.length, 128, 'ciphertext half is exactly 128 bytes');
  assert.equal(clientPublic.length, KEY_LENGTH, 'client public half is exactly keyLength bytes');

  // --- cross-check every value against node:crypto -------------------------
  assert.equal(rand.calls.length, 2, 'randomBytes called for the exponent and the plaintext');
  const privateExponent = rand.calls[0];
  const plaintextFill = rand.calls[1];
  assert.equal(privateExponent.length, KEY_LENGTH);
  assert.equal(plaintextFill.length, 128);

  const clientDh = createDiffieHellman(Buffer.from(MODP2_PRIME), Buffer.from([GENERATOR]));
  clientDh.setPrivateKey(Buffer.from(privateExponent));
  clientDh.generateKeys(); // OpenSSL reuses an already-set private key
  const nodeClientPublic = leftPad(new Uint8Array(clientDh.getPublicKey()), KEY_LENGTH);
  assert.deepEqual(
    new Uint8Array(clientPublic),
    nodeClientPublic,
    'client public key matches node DiffieHellman',
  );

  const nodeSecret = leftPad(
    new Uint8Array(clientDh.computeSecret(Buffer.from(SERVER.publicKey))),
    KEY_LENGTH,
  );
  const serverSideSecret = leftPad(
    new Uint8Array(SERVER.dh.computeSecret(Buffer.from(nodeClientPublic))),
    KEY_LENGTH,
  );
  assert.deepEqual(nodeSecret, serverSideSecret, 'both DH sides agree');

  const ourSecret = bigIntToBytes(
    modPow(
      bytesToBigInt(SERVER.publicKey),
      bytesToBigInt(privateExponent),
      bytesToBigInt(MODP2_PRIME),
    ),
    KEY_LENGTH,
  );
  assert.deepEqual(ourSecret, nodeSecret, 'shared secret matches node DiffieHellman');
  assert.equal(ourSecret.length, KEY_LENGTH, 'secret is left-zero-padded to keyLength');

  // Rebuild the credential blob independently with node's MD5 + AES-128-ECB.
  const expectedPlaintext = Uint8Array.from(plaintextFill);
  const user = new TextEncoder().encode('alice');
  const pass = new TextEncoder().encode('hunter2');
  expectedPlaintext.set(user, 0);
  expectedPlaintext[user.length] = 0;
  expectedPlaintext.set(pass, 64);
  expectedPlaintext[64 + pass.length] = 0;

  const key = createHash('md5').update(Buffer.from(ourSecret)).digest();
  const cipher = createCipheriv('aes-128-ecb', key, null);
  cipher.setAutoPadding(false);
  const expectedCiphertext = Buffer.concat([
    cipher.update(Buffer.from(expectedPlaintext)),
    cipher.final(),
  ]);
  assert.equal(expectedCiphertext.length, 128, 'no padding block added');
  assert.deepEqual(
    new Uint8Array(ciphertext),
    new Uint8Array(expectedCiphertext),
    'ciphertext matches node md5 + aes-128-ecb over the same plaintext',
  );
});

test('buildAppleDhResponse rejects a username longer than 63 bytes', () => {
  const params = {
    generator: GENERATOR,
    keyLength: KEY_LENGTH,
    prime: MODP2_PRIME,
    serverPublic: SERVER.publicKey,
  };
  const ok = 'u'.repeat(63);
  const tooLong = 'u'.repeat(64);

  assert.equal(buildAppleDhResponse(params, ok, 'p', deterministicRandom()).length, 256);
  assert.throws(
    () => buildAppleDhResponse(params, tooLong, 'p', deterministicRandom()),
    /username is 64 bytes UTF-8/,
  );
  // Multi-byte UTF-8 counts in bytes, not characters.
  assert.throws(
    () => buildAppleDhResponse(params, 'é'.repeat(32), 'p', deterministicRandom()),
    /username is 64 bytes UTF-8/,
  );
  assert.throws(
    () => buildAppleDhResponse(params, 'u', 'p'.repeat(64), deterministicRandom()),
    /password is 64 bytes UTF-8/,
  );
});

// ---------------------------------------------------------------------------
// RfbSession -- synthetic server stream
// ---------------------------------------------------------------------------

const SESSION_ENCODINGS = [16, 6, 1, 0, -239, -223, -224];
const FB_W = 1024;
const FB_H = 768;
const DESKTOP_NAME = 'Test Mac';
const RAND_SEED = 0x1a2b3c4d;

const sessionOpts = () => ({
  username: 'alice',
  password: 'hunter2',
  encodings: SESSION_ENCODINGS,
  randomBytes: deterministicRandom(RAND_SEED),
});

const F = {
  banner: ascii('RFB 003.889\n'),
  securityList: new Uint8Array([0x04, 0x1e, 0x21, 0x24, 0x23]),
  dhParams: cat(u16be(GENERATOR), u16be(KEY_LENGTH), MODP2_PRIME, SERVER.publicKey),
  securityResultOk: u32be(0),
  serverInit: cat(
    u16be(FB_W),
    u16be(FB_H),
    // Server-side PIXEL_FORMAT: 32bpp depth 24, BGR shifts (typical screensharingd).
    new Uint8Array([32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0]),
    u32be(DESKTOP_NAME.length),
    ascii(DESKTOP_NAME),
  ),
};

const EXPECTED_VERSION_REPLY = ascii('RFB 003.008\n');

/** The DH blob the session must send, computed from an independent identical stub. */
const EXPECTED_DH_RESPONSE = buildAppleDhResponse(
  { generator: GENERATOR, keyLength: KEY_LENGTH, prime: MODP2_PRIME, serverPublic: SERVER.publicKey },
  'alice',
  'hunter2',
  deterministicRandom(RAND_SEED),
);

const rawRect = (x, y, w, h, fill) => {
  // Raw payload length follows the requested pixel format (now 16bpp = 2 bytes).
  const pixels = new Uint8Array(w * h * bytesPerPixel(CANVAS_PIXEL_FORMAT));
  pixels.fill(fill);
  return cat(u16be(x), u16be(y), u16be(w), u16be(h), i32be(0), pixels);
};

const zlibRect = (x, y, w, h, deflateBytes) =>
  cat(u16be(x), u16be(y), u16be(w), u16be(h), i32be(6), u32be(deflateBytes.length), deflateBytes);

const fbu = (...rects) => cat(u8(0), u8(0), u16be(rects.length), ...rects);

const BELL = u8(0x02);
const ZLIB_BLOB = Uint8Array.from({ length: 24 }, (_, i) => (i * 37 + 11) & 0xff);

/** Feed the chunks as given, draining outbound after each. */
function runWhole(chunks, opts = sessionOpts()) {
  return quiet(() => {
    const session = new RfbSession(opts);
    const steps = chunks.map((chunk) => ({
      events: session.feed(chunk),
      out: session.takeOutbound() ?? new Uint8Array(0),
    }));
    return { session, steps };
  });
}

/** Feed the exact same bytes one at a time; collect everything. */
function runByteWise(chunks, opts = sessionOpts()) {
  return quiet(() => {
    const session = new RfbSession(opts);
    const events = [];
    const outs = [];
    for (const chunk of chunks) {
      for (let i = 0; i < chunk.length; i++) {
        events.push(...session.feed(chunk.subarray(i, i + 1)));
        const o = session.takeOutbound();
        if (o) outs.push(o);
      }
    }
    return { session, events, out: cat(...outs) };
  });
}

/** Whole-stream and byte-at-a-time must agree on events and on every sent byte. */
function assertIdenticalBothWays(chunks, opts = sessionOpts) {
  const whole = runWhole(chunks, opts());
  const byteWise = runByteWise(chunks, opts());
  const wholeEvents = whole.steps.flatMap((s) => s.events);
  const wholeOut = cat(...whole.steps.map((s) => s.out));

  assert.deepEqual(byteWise.events, wholeEvents, 'same events one byte at a time');
  assert.deepEqual(byteWise.out, wholeOut, 'same outbound bytes one byte at a time');
  assert.equal(byteWise.session.state, whole.session.state, 'same final state');
  return { whole, byteWise, wholeEvents, wholeOut };
}

const HANDSHAKE = [
  F.banner,
  F.securityList,
  F.dhParams,
  F.securityResultOk,
  F.serverInit,
];

test('RfbSession handshake: event sequence and client bytes at every step', () => {
  const { session, steps } = runWhole(HANDSHAKE);

  // 1. version banner -> reply RFB 003.008, no events
  assert.deepEqual(steps[0].events, []);
  assert.deepEqual(steps[0].out, EXPECTED_VERSION_REPLY);
  assert.equal(steps[0].out.length, 12);

  // 2. security list 04 1e 21 24 23 -> pick type 30 by value
  assert.deepEqual(steps[1].events, []);
  assert.deepEqual(Array.from(steps[1].out), [30]);

  // 3. type-30 parameter block -> 256-byte credential blob
  assert.deepEqual(steps[2].events, []);
  assert.equal(steps[2].out.length, 256);
  assert.deepEqual(steps[2].out, EXPECTED_DH_RESPONSE);

  // 4. SecurityResult 0 -> ClientInit(shared)
  assert.deepEqual(steps[3].events, []);
  assert.deepEqual(Array.from(steps[3].out), [1]);

  // 5. ServerInit -> serverInit event, then SetPixelFormat, SetEncodings, full FBUR
  assert.deepEqual(steps[4].events, [
    { type: 'serverInit', width: FB_W, height: FB_H, name: DESKTOP_NAME },
  ]);
  assert.deepEqual(
    steps[4].out,
    cat(
      setPixelFormat(CANVAS_PIXEL_FORMAT),
      setEncodings(SESSION_ENCODINGS),
      framebufferUpdateRequest(0, 0, 0, FB_W, FB_H),
    ),
  );
  assert.equal(steps[4].out.length, 20 + 32 + 10);

  assert.equal(session.state, State.RUNNING);
  assert.equal(session.width, FB_W);
  assert.equal(session.height, FB_H);
  assert.equal(session.name, DESKTOP_NAME);
  assert.deepEqual(session.serverPixelFormat.redShift, 16, 'server format parsed, not overwritten');
  assert.equal(session.takeOutbound(), null, 'outbound fully drained');
});

test('RfbSession handshake is identical fed one byte at a time', () => {
  const { wholeEvents, wholeOut } = assertIdenticalBothWays(HANDSHAKE);
  assert.deepEqual(wholeEvents, [
    { type: 'serverInit', width: FB_W, height: FB_H, name: DESKTOP_NAME },
  ]);
  assert.equal(
    wholeOut.length,
    12 + 1 + 256 + 1 + 20 + 32 + 10,
    'exact total bytes sent through the handshake',
  );
});

test('a Bell between two FramebufferUpdates does not desync the stream', () => {
  const chunks = [
    ...HANDSHAKE,
    cat(
      fbu(rawRect(0, 0, 2, 2, 0xab)),
      BELL, // ONE byte, no padding, no body
      fbu(zlibRect(4, 8, 16, 16, ZLIB_BLOB)),
    ),
  ];
  const { whole } = assertIdenticalBothWays(chunks);
  const events = whole.steps[5].events;

  assert.deepEqual(
    events.map((e) => e.type),
    ['rect', 'updateDone', 'bell', 'rect', 'updateDone'],
  );

  const raw = events[0];
  assert.equal(raw.encoding, 0);
  assert.deepEqual([raw.x, raw.y, raw.w, raw.h], [0, 0, 2, 2]);
  assert.equal(raw.payload.length, 2 * 2 * bytesPerPixel(CANVAS_PIXEL_FORMAT), 'w * h * bytesPerPixel');
  assert.ok(raw.payload.every((b) => b === 0xab));

  const zl = events[3];
  assert.equal(zl.encoding, 6);
  assert.deepEqual([zl.x, zl.y, zl.w, zl.h], [4, 8, 16, 16]);
  assert.equal(zl.payload.length, 4 + ZLIB_BLOB.length, 'u32 length prefix is part of the payload');
  assert.deepEqual(zl.payload, cat(u32be(ZLIB_BLOB.length), ZLIB_BLOB));

  // One re-armed incremental request per completed update, never on a timer.
  assert.deepEqual(
    whole.steps[5].out,
    cat(
      framebufferUpdateRequest(1, 0, 0, FB_W, FB_H),
      framebufferUpdateRequest(1, 0, 0, FB_W, FB_H),
    ),
  );
  assert.equal(whole.session.state, State.RUNNING);
  assert.equal(whole.session.fbuActive, false);
});

test('a Bell split across the FBU boundary in tiny chunks still lands in order', () => {
  const stream = cat(
    fbu(rawRect(0, 0, 2, 2, 0x11)),
    BELL,
    fbu(rawRect(2, 2, 1, 1, 0x22)),
  );
  // Chop at deliberately awkward offsets, including mid-rect-header.
  const chunks = [...HANDSHAKE];
  for (let i = 0; i < stream.length; i += 3) chunks.push(stream.subarray(i, i + 3));

  const { whole } = assertIdenticalBothWays(chunks);
  const running = whole.steps.slice(5).flatMap((s) => s.events);
  assert.deepEqual(
    running.map((e) => e.type),
    ['rect', 'updateDone', 'bell', 'rect', 'updateDone'],
  );
});

test('LastRect, DesktopSize and cutText are handled inside one update', () => {
  const lastRect = cat(u16be(0), u16be(0), u16be(0), u16be(0), i32be(-224));
  const desktopSize = cat(u16be(0), u16be(0), u16be(800), u16be(600), i32be(-223));
  const cutText = cat(u8(3), new Uint8Array(3), u32be(2), ascii('hi'));

  const chunks = [
    ...HANDSHAKE,
    // numRects says 3; DesktopSize consumes one, LastRect ends the loop early.
    cat(u8(0), u8(0), u16be(3), desktopSize, rawRect(0, 0, 1, 1, 0x7f), lastRect),
    cutText,
  ];
  const { whole } = assertIdenticalBothWays(chunks);
  const events = whole.steps.slice(5).flatMap((s) => s.events);

  assert.deepEqual(
    events.map((e) => e.type),
    ['desktopSize', 'rect', 'updateDone', 'cutText'],
  );
  assert.deepEqual(events[0], { type: 'desktopSize', width: 800, height: 600 });
  assert.deepEqual(events[3], { type: 'cutText', text: 'hi' });
  assert.equal(whole.session.width, 800);
  assert.equal(whole.session.height, 600);
  // DesktopSize sets pendingFullUpdate, so the re-armed request is non-incremental.
  assert.deepEqual(whole.steps[5].out, framebufferUpdateRequest(0, 0, 0, 800, 600));
});

test("auth failure parses Apple's uncounted trailing 0x00 and surfaces the reason", () => {
  const reason = 'Authentication failed';
  const failure = cat(
    u32be(1), // SecurityResult: failed
    u32be(reason.length),
    ascii(reason),
    u8(0x00), // NOT counted in the length above
  );
  const chunks = [F.banner, F.securityList, F.dhParams, failure];

  const { whole, byteWise } = assertIdenticalBothWays(chunks);
  assert.deepEqual(whole.steps[3].events, [{ type: 'authFailed', reason }]);
  assert.equal(whole.session.state, State.FAILED);
  assert.equal(byteWise.session.state, State.FAILED);
  assert.deepEqual(whole.steps[3].out, new Uint8Array(0), 'nothing sent after a failed auth');

  // Same reason when the server omits the trailing NUL.
  const noNul = runWhole([F.banner, F.securityList, F.dhParams, failure.subarray(0, -1)]);
  assert.deepEqual(noNul.steps[3].events, [{ type: 'authFailed', reason }]);
});

test('an unsupported security list produces an error event', () => {
  const { steps, session } = runWhole([F.banner, new Uint8Array([0x02, 0x01, 0x02])]);
  assert.equal(steps[1].events.length, 1);
  assert.equal(steps[1].events[0].type, 'error');
  assert.match(steps[1].events[0].message, /no supported security type/);
  assert.equal(session.state, State.FAILED);
});

test('input helpers queue bytes only while RUNNING', () => {
  const early = new RfbSession(sessionOpts());
  early.sendKey(true, 0xff0d);
  early.sendPointer(1, 5, 5);
  assert.equal(early.takeOutbound(), null, 'no input before the session is up');

  const { session } = runWhole(HANDSHAKE);
  session.sendPointer(1, 10, 20);
  session.sendKey(true, 0x0061);
  session.sendCutText('AB');
  assert.deepEqual(
    session.takeOutbound(),
    cat(pointerEvent(1, 10, 20), keyEvent(true, 0x0061), clientCutText('AB')),
  );

  // A full refresh while a request is outstanding is deferred, not duplicated.
  session.requestUpdate(0);
  assert.equal(session.takeOutbound(), null);
  quiet(() => session.feed(fbu(rawRect(0, 0, 1, 1, 0))));
  assert.deepEqual(session.takeOutbound(), framebufferUpdateRequest(0, 0, 0, FB_W, FB_H));
});
