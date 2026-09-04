// Tests for src/rfb/io/reader.js and src/rfb/io/writer.js.
//
// The load-bearing property is that a Reader-driven parser is indifferent to
// how the TCP stream was segmented: parsing a byte string one byte at a time
// must produce byte-identical results to parsing it in a single push.

import test from 'node:test';
import assert from 'node:assert/strict';

import { Reader, NeedMoreBytes } from '../../src/rfb/io/reader.js';
import { Writer } from '../../src/rfb/io/writer.js';

function u8a(...bytes) {
  return new Uint8Array(bytes);
}

function makeRng(seed) {
  let s = seed >>> 0;
  if (s === 0) s = 0x9e3779b9;
  return function next() {
    s ^= s << 13;
    s >>>= 0;
    s ^= s >>> 17;
    s ^= s << 5;
    s >>>= 0;
    return s;
  };
}

// ---------------------------------------------------------------------------
// Reader: primitives
// ---------------------------------------------------------------------------

test('Reader: u8 reads bytes in order and advances', () => {
  const r = new Reader();
  r.push(u8a(0x00, 0x7f, 0x80, 0xff));
  assert.equal(r.remaining, 4);
  assert.equal(r.u8(), 0x00);
  assert.equal(r.u8(), 0x7f);
  assert.equal(r.u8(), 0x80);
  assert.equal(r.u8(), 0xff);
  assert.equal(r.remaining, 0);
});

test('Reader: u16 is big-endian and unsigned', () => {
  const r = new Reader();
  r.push(u8a(0x01, 0x02, 0xff, 0xff, 0x80, 0x00, 0x00, 0x01));
  assert.equal(r.u16(), 0x0102);
  assert.equal(r.u16(), 65535);
  assert.equal(r.u16(), 32768);
  assert.equal(r.u16(), 1);
});

test('Reader: u32 is big-endian and unsigned', () => {
  const r = new Reader();
  r.push(u8a(0x12, 0x34, 0x56, 0x78, 0xff, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00));
  assert.equal(r.u32(), 0x12345678);
  assert.equal(r.u32(), 4294967295);
  assert.equal(r.u32(), 2147483648);
});

test('Reader: i32 is big-endian SIGNED - ff ff ff 20 must be -224 (LastRect)', () => {
  const r = new Reader();
  r.push(u8a(0xff, 0xff, 0xff, 0x20));
  assert.equal(r.i32(), -224);
});

test('Reader: i32 covers the RFB pseudo-encoding range', () => {
  const r = new Reader();
  r.push(
    u8a(
      0xff, 0xff, 0xff, 0x11, // -239 Cursor
      0xff, 0xff, 0xff, 0x21, // -223 DesktopSize
      0x00, 0x00, 0x00, 0x00, // 0 Raw
      0x00, 0x00, 0x00, 0x10, // 16 ZRLE
      0x80, 0x00, 0x00, 0x00, // INT32_MIN
      0x7f, 0xff, 0xff, 0xff, // INT32_MAX
    ),
  );
  assert.equal(r.i32(), -239);
  assert.equal(r.i32(), -223);
  assert.equal(r.i32(), 0);
  assert.equal(r.i32(), 16);
  assert.equal(r.i32(), -2147483648);
  assert.equal(r.i32(), 2147483647);
});

test('Reader: i32 and u32 disagree on the same bytes, as they must', () => {
  const bytes = u8a(0xff, 0xff, 0xff, 0x20);
  const a = new Reader();
  a.push(bytes);
  const b = new Reader();
  b.push(bytes);
  assert.equal(a.i32(), -224);
  assert.equal(b.u32(), 4294967072);
});

test('Reader: bytes(n) returns a copy that survives commit()', () => {
  const r = new Reader();
  r.push(u8a(1, 2, 3, 4, 5, 6));
  const first = r.bytes(3);
  assert.deepEqual(first, u8a(1, 2, 3));
  r.commit();
  r.push(u8a(9, 9, 9, 9, 9, 9, 9, 9));
  assert.deepEqual(first, u8a(1, 2, 3), 'copy must not alias the reader buffer');
  assert.deepEqual(r.bytes(3), u8a(4, 5, 6));
});

test('Reader: bytes(0) is legal and returns an empty array', () => {
  const r = new Reader();
  r.push(u8a(1, 2));
  const empty = r.bytes(0);
  assert.equal(empty.length, 0);
  assert.equal(r.remaining, 2);
});

test('Reader: skip advances without returning', () => {
  const r = new Reader();
  r.push(u8a(1, 2, 3, 4, 5));
  r.skip(2);
  assert.equal(r.remaining, 3);
  assert.equal(r.u8(), 3);
  r.skip(0);
  assert.equal(r.u8(), 4);
});

// ---------------------------------------------------------------------------
// Reader: NeedMoreBytes must never consume
// ---------------------------------------------------------------------------

test('Reader: u32 on 3 bytes throws NeedMoreBytes and consumes nothing', () => {
  const r = new Reader();
  r.push(u8a(0xde, 0xad, 0xbe));
  assert.throws(() => r.u32(), NeedMoreBytes);
  assert.equal(r.remaining, 3, 'cursor must not have moved');
  r.push(u8a(0xef));
  assert.equal(r.u32(), 0xdeadbeef, 'the same 4 bytes must still be readable');
});

test('Reader: every accessor is non-consuming when short', () => {
  const cases = [
    ['u8', (r) => r.u8(), 0],
    ['u16', (r) => r.u16(), 1],
    ['u32', (r) => r.u32(), 3],
    ['i32', (r) => r.i32(), 3],
    ['bytes', (r) => r.bytes(10), 9],
    ['skip', (r) => r.skip(10), 9],
  ];
  for (const [name, fn, have] of cases) {
    const r = new Reader();
    if (have > 0) r.push(new Uint8Array(have).fill(0xab));
    assert.throws(() => fn(r), NeedMoreBytes, name + ' should throw');
    assert.equal(r.remaining, have, name + ' must not consume on failure');
  }
});

test('Reader: NeedMoreBytes carries needed/available and is an Error', () => {
  const r = new Reader();
  r.push(u8a(1, 2, 3));
  try {
    r.u32();
    assert.fail('should have thrown');
  } catch (e) {
    assert.ok(e instanceof NeedMoreBytes);
    assert.ok(e instanceof Error);
    assert.equal(e.needed, 4);
    assert.equal(e.available, 3);
  }
});

test('Reader: repeated failed reads stay idempotent', () => {
  const r = new Reader();
  r.push(u8a(0x00, 0x01));
  for (let i = 0; i < 5; i++) {
    assert.throws(() => r.u32(), NeedMoreBytes);
  }
  assert.equal(r.remaining, 2);
  assert.equal(r.u16(), 1);
});

// ---------------------------------------------------------------------------
// Reader: mark / rewind / commit
// ---------------------------------------------------------------------------

test('Reader: rewind restores the cursor to the last mark', () => {
  const r = new Reader();
  r.push(u8a(1, 2, 3, 4, 5, 6, 7, 8));
  r.u8();
  r.mark();
  assert.equal(r.u16(), 0x0203);
  assert.equal(r.u8(), 4);
  r.rewind();
  assert.equal(r.remaining, 7);
  assert.equal(r.u16(), 0x0203, 'same bytes re-read after rewind');
});

test('Reader: rewind after a partial parse replays the whole message', () => {
  const r = new Reader();
  r.mark();
  r.push(u8a(0x00, 0x00, 0x00, 0x02)); // header of a 6-byte message
  assert.equal(r.u16(), 0);
  assert.throws(() => r.u32(), NeedMoreBytes);
  r.rewind();
  assert.equal(r.remaining, 4);
  r.push(u8a(0xaa, 0xbb));
  r.mark();
  assert.equal(r.u16(), 0);
  assert.equal(r.u32(), 0x0002aabb);
});

test('Reader: commit discards consumed bytes and resets the mark', () => {
  const r = new Reader();
  r.push(u8a(1, 2, 3, 4, 5, 6));
  r.mark();
  r.skip(4);
  r.commit();
  assert.equal(r.remaining, 2);
  r.rewind();
  assert.equal(r.remaining, 2, 'rewind after commit must not resurrect committed bytes');
  assert.deepEqual(r.bytes(2), u8a(5, 6));
});

test('Reader: commit with nothing consumed is a no-op', () => {
  const r = new Reader();
  r.push(u8a(7, 8, 9));
  r.commit();
  assert.equal(r.remaining, 3);
  assert.deepEqual(r.bytes(3), u8a(7, 8, 9));
});

test('Reader: mark/rewind survives a push that reallocates the buffer', () => {
  const r = new Reader();
  r.push(u8a(0xaa, 0xbb, 0xcc, 0xdd));
  r.mark();
  assert.equal(r.u16(), 0xaabb);
  // Force growth well past the 8 KiB initial capacity.
  r.push(new Uint8Array(40000).fill(0x5a));
  r.rewind();
  assert.equal(r.u32(), 0xaabbccdd, 'DataView must track the reallocated buffer');
  assert.equal(r.u8(), 0x5a);
  assert.equal(r.remaining, 39999);
});

test('Reader: interleaved push/commit over many cycles keeps data intact', () => {
  const r = new Reader();
  let expected = 0;
  for (let i = 0; i < 5000; i++) {
    r.push(u8a((i >> 8) & 0xff, i & 0xff));
    r.mark();
    assert.equal(r.u16(), i & 0xffff);
    r.commit();
    expected = i;
  }
  assert.equal(r.remaining, 0);
  assert.equal(expected, 4999);
});

// ---------------------------------------------------------------------------
// THE HIGH-VALUE TEST: segmentation independence
// ---------------------------------------------------------------------------

// A miniature RFB server-message parser built on the documented usage pattern:
// mark(), parse, commit(); on NeedMoreBytes rewind() and wait for more bytes.
function drainMessages(r, out) {
  for (;;) {
    r.mark();
    try {
      out.push(parseMessage(r));
      r.commit();
    } catch (e) {
      if (e instanceof NeedMoreBytes) {
        r.rewind();
        return;
      }
      throw e;
    }
  }
}

function parseMessage(r) {
  const type = r.u8();
  switch (type) {
    case 0: {
      // FramebufferUpdate
      r.skip(1);
      const n = r.u16();
      const rects = [];
      for (let i = 0; i < n; i++) {
        const rect = {
          x: r.u16(),
          y: r.u16(),
          w: r.u16(),
          h: r.u16(),
          encoding: r.i32(),
        };
        if (rect.encoding === -224) {
          rect.payload = new Uint8Array(0);
          rects.push(rect);
          break; // LastRect ends the loop immediately
        }
        rect.payload = r.bytes(payloadLength(rect));
        rects.push(rect);
      }
      return { type: 'framebufferUpdate', rects };
    }
    case 2:
      return { type: 'bell' }; // one byte total
    case 3: {
      r.skip(3);
      const len = r.u32();
      const raw = r.bytes(len);
      let text = '';
      for (let i = 0; i < raw.length; i++) text += String.fromCharCode(raw[i]);
      return { type: 'cutText', text };
    }
    default:
      throw new Error('unexpected message type ' + type);
  }
}

function payloadLength(rect) {
  switch (rect.encoding) {
    case 0:
      return rect.w * rect.h * 4;
    case 1:
      return 4;
    case -223:
      return 0;
    default:
      throw new Error('unsupported encoding ' + rect.encoding);
  }
}

function buildStream() {
  const next = makeRng(0x1337beef);
  const b = [];
  const push8 = (v) => b.push(v & 0xff);
  const push16 = (v) => {
    b.push((v >>> 8) & 0xff, v & 0xff);
  };
  const push32 = (v) => {
    b.push((v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff);
  };

  // FramebufferUpdate: raw rect, copyrect, desktopsize, lastrect.
  push8(0);
  push8(0);
  push16(4);

  push16(3); push16(5); push16(7); push16(2); push32(0); // Raw 7x2
  for (let i = 0; i < 7 * 2 * 4; i++) push8(next());

  push16(10); push16(11); push16(12); push16(13); push32(1); // CopyRect
  push16(1); push16(2);

  push16(0); push16(0); push16(1024); push16(768); push32(0xffffff21); // -223
  push16(0); push16(0); push16(0); push16(0); push32(0xffffff20); // -224 LastRect

  // Bell (one byte).
  push8(2);

  // ServerCutText.
  const text = 'clipboard éÿ payload';
  push8(3);
  push8(0); push8(0); push8(0);
  push32(text.length);
  for (let i = 0; i < text.length; i++) push8(text.charCodeAt(i));

  // Two bells back to back - adjacent one-byte messages are a classic
  // off-by-one trap for a commit()-based loop.
  push8(2);
  push8(2);

  // A larger FramebufferUpdate whose payload straddles many segments.
  push8(0);
  push8(0);
  push16(2);
  push16(0); push16(0); push16(64); push16(48); push32(0); // Raw 64x48 = 12288 bytes
  for (let i = 0; i < 64 * 48 * 4; i++) push8(next());
  push16(1); push16(1); push16(2); push16(2); push32(1); // CopyRect
  push16(9); push16(8);

  // Empty update (zero rects) and a zero-length cut text.
  push8(0); push8(0); push16(0);
  push8(3); push8(0); push8(0); push8(0); push32(0);

  return new Uint8Array(b);
}

// FBU(4 rects), bell, cutText, bell, bell, FBU(2 rects), FBU(0 rects), cutText('')
const MESSAGE_COUNT = 8;

function canonical(events) {
  return JSON.stringify(events, (key, value) =>
    value instanceof Uint8Array ? Array.from(value) : value,
  );
}

test('Reader: one byte at a time parses identically to one big push', () => {
  const stream = buildStream();

  const whole = [];
  const rWhole = new Reader();
  rWhole.push(stream);
  drainMessages(rWhole, whole);
  assert.equal(rWhole.remaining, 0, 'whole-stream parse must consume everything');

  const dripped = [];
  const rDrip = new Reader();
  for (let i = 0; i < stream.length; i++) {
    rDrip.push(stream.subarray(i, i + 1));
    drainMessages(rDrip, dripped);
  }
  assert.equal(rDrip.remaining, 0, 'byte-at-a-time parse must consume everything');

  assert.equal(dripped.length, whole.length, 'same number of messages');
  assert.equal(canonical(dripped), canonical(whole));

  // Sanity: the fixture actually exercised what it claims to.
  assert.equal(whole.length, MESSAGE_COUNT);
  assert.equal(whole[0].type, 'framebufferUpdate');
  assert.equal(whole[0].rects.length, 4);
  assert.equal(whole[0].rects[0].payload.length, 7 * 2 * 4);
  assert.equal(whole[0].rects[3].encoding, -224);
  assert.equal(whole[1].type, 'bell');
  assert.equal(whole[2].type, 'cutText');
  assert.equal(whole[3].type, 'bell');
  assert.equal(whole[4].type, 'bell');
  assert.equal(whole[5].rects[0].payload.length, 64 * 48 * 4);
  assert.equal(whole[6].rects.length, 0);
  assert.equal(whole[7].text, '');
});

test('Reader: arbitrary random segmentations all agree with the whole-push parse', () => {
  const stream = buildStream();
  const reference = [];
  const rRef = new Reader();
  rRef.push(stream);
  drainMessages(rRef, reference);
  const expected = canonical(reference);

  const next = makeRng(0x2468ace0);
  for (let trial = 0; trial < 40; trial++) {
    const got = [];
    const r = new Reader();
    let off = 0;
    while (off < stream.length) {
      const n = Math.min(stream.length - off, 1 + (next() % 1500));
      r.push(stream.subarray(off, off + n));
      off += n;
      drainMessages(r, got);
    }
    assert.equal(r.remaining, 0, 'trial ' + trial + ' left bytes unconsumed');
    assert.equal(canonical(got), expected, 'trial ' + trial + ' diverged');
  }
});

test('Reader: a truncated stream leaves the partial message intact for later', () => {
  const stream = buildStream();
  const cut = stream.length - 3;

  const got = [];
  const r = new Reader();
  r.push(stream.subarray(0, cut));
  drainMessages(r, got);
  const partialCount = got.length;
  assert.ok(partialCount < MESSAGE_COUNT, 'the tail message must still be pending');

  r.push(stream.subarray(cut));
  drainMessages(r, got);
  assert.equal(got.length, MESSAGE_COUNT);
  assert.equal(r.remaining, 0);

  const reference = [];
  const rRef = new Reader();
  rRef.push(stream);
  drainMessages(rRef, reference);
  assert.equal(canonical(got), canonical(reference));
});

// ---------------------------------------------------------------------------
// Writer
// ---------------------------------------------------------------------------

test('Writer: allocates exactly the requested length, zero-filled', () => {
  for (const n of [0, 1, 6, 8, 10, 16, 20, 4096]) {
    const w = new Writer(n);
    assert.equal(w.result.length, n, 'length ' + n);
    assert.ok(w.result instanceof Uint8Array);
    assert.deepEqual(w.result, new Uint8Array(n), 'must start all-zero');
  }
  assert.throws(() => new Writer(-1), RangeError);
});

test('Writer: primitives are big-endian', () => {
  const w = new Writer(14);
  w.u8(0xab);
  w.u16(0x1234);
  w.u32(0xdeadbeef);
  w.i32(-224);
  w.u8(0xff);
  assert.deepEqual(
    w.result,
    u8a(0xab, 0x12, 0x34, 0xde, 0xad, 0xbe, 0xef, 0xff, 0xff, 0xff, 0x20, 0xff, 0x00, 0x00),
  );
});

test('Writer: i32 round-trips through Reader.i32', () => {
  const values = [0, 1, -1, -224, -239, -223, 16, 2147483647, -2147483648];
  const w = new Writer(values.length * 4);
  for (const v of values) w.i32(v);
  const r = new Reader();
  r.push(w.result);
  for (const v of values) assert.equal(r.i32(), v);
});

test('Writer: skip leaves zeroed padding, not garbage', () => {
  const w = new Writer(20);
  w.u8(0); // SetPixelFormat message type
  w.skip(3); // 3 bytes of padding
  w.u8(32).u8(24).u8(0).u8(1);
  w.u16(255).u16(255).u16(255);
  w.u8(0).u8(8).u8(16);
  w.skip(3); // trailing padding
  const out = w.result;
  assert.equal(out.length, 20);
  assert.equal(out[1], 0);
  assert.equal(out[2], 0);
  assert.equal(out[3], 0);
  assert.equal(out[17], 0);
  assert.equal(out[18], 0);
  assert.equal(out[19], 0);
  assert.equal(w.position, 20, 'every byte accounted for');
});

test('Writer: skipped padding stays zero even between written values', () => {
  const w = new Writer(8);
  w.u8(0xff);
  w.skip(6);
  w.u8(0xff);
  assert.deepEqual(w.result, u8a(0xff, 0, 0, 0, 0, 0, 0, 0xff));
});

test('Writer: bytes() copies in at the cursor', () => {
  const w = new Writer(10);
  w.u16(0x0102);
  w.bytes(u8a(9, 8, 7));
  w.u8(0x55);
  assert.deepEqual(w.result, u8a(0x01, 0x02, 9, 8, 7, 0x55, 0, 0, 0, 0));
  assert.equal(w.position, 6);
});

test('Writer: values are masked, not allowed to bleed into neighbours', () => {
  const w = new Writer(7);
  w.u8(0x1ff);
  w.u16(0x1ffff);
  w.u32(0xffffffff);
  assert.deepEqual(w.result, u8a(0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff));
});

test('Writer: overflow throws rather than silently truncating', () => {
  assert.throws(() => new Writer(3).u32(1), RangeError);
  assert.throws(() => new Writer(1).u16(1), RangeError);
  assert.throws(() => new Writer(2).bytes(u8a(1, 2, 3)), RangeError);
  assert.throws(() => new Writer(2).skip(3), RangeError);
  assert.throws(() => new Writer(4).skip(-1), RangeError);

  const w = new Writer(4);
  w.u32(0x11223344);
  assert.throws(() => w.u8(1), RangeError, 'writing past a full buffer');
  assert.deepEqual(w.result, u8a(0x11, 0x22, 0x33, 0x44), 'buffer unchanged by the failure');
});

test('Writer: exact wire lengths for the fixed-size RFB client messages', () => {
  // KeyEvent: type, down, 2 pad, u32 keysym = 8 bytes.
  const key = new Writer(8);
  key.u8(4).u8(1).skip(2).u32(0xff0d);
  assert.equal(key.position, 8);
  assert.deepEqual(key.result, u8a(4, 1, 0, 0, 0x00, 0x00, 0xff, 0x0d));

  // PointerEvent: type, buttonMask, u16 x, u16 y = 6 bytes.
  const ptr = new Writer(6);
  ptr.u8(5).u8(0x01).u16(300).u16(200);
  assert.equal(ptr.position, 6);
  assert.deepEqual(ptr.result, u8a(5, 1, 0x01, 0x2c, 0x00, 0xc8));

  // FramebufferUpdateRequest: type, incremental, 4x u16 = 10 bytes.
  const fbur = new Writer(10);
  fbur.u8(3).u8(1).u16(0).u16(0).u16(1440).u16(900);
  assert.equal(fbur.position, 10);
  assert.deepEqual(fbur.result, u8a(3, 1, 0, 0, 0, 0, 0x05, 0xa0, 0x03, 0x84));

  // SetEncodings: type, pad, u16 count, then N x i32 = 4 + 4N.
  const encodings = [16, 6, 1, 0, -223, -224];
  const se = new Writer(4 + 4 * encodings.length);
  se.u8(2).skip(1).u16(encodings.length);
  for (const e of encodings) se.i32(e);
  assert.equal(se.result.length, 28);
  assert.equal(se.position, 28);
  assert.equal(se.result[1], 0, 'pad byte zeroed');
});

test('Writer: result is stable across repeated reads', () => {
  const w = new Writer(4);
  w.u32(0xcafebabe);
  const a = w.result;
  const b = w.result;
  assert.equal(a, b, 'same underlying array');
  assert.deepEqual(a, u8a(0xca, 0xfe, 0xba, 0xbe));
});

test('Writer output feeds Reader byte-for-byte', () => {
  const next = makeRng(0x0f0f0f0f);
  for (let trial = 0; trial < 100; trial++) {
    const w = new Writer(11);
    const a = next() & 0xff;
    const b = next() & 0xffff;
    const c = next() >>> 0;
    w.u8(a).u16(b).u32(c).skip(4);
    const r = new Reader();
    r.push(w.result);
    assert.equal(r.u8(), a);
    assert.equal(r.u16(), b);
    assert.equal(r.u32(), c);
    assert.equal(r.u32(), 0, 'skipped bytes read back as zero');
  }
});
