import test from 'node:test';
import assert from 'node:assert/strict';
import zlib from 'node:zlib';

import { decode as decodeRaw } from '../../src/rfb/decoders/raw.js';
import { decode as decodeCopyRect } from '../../src/rfb/decoders/copyrect.js';
import { decode as decodeZlib6 } from '../../src/rfb/decoders/zlib6.js';
import { decode as decodeZrle } from '../../src/rfb/decoders/zrle.js';
import { createInflateContext } from '../../src/rfb/inflate/streams.js';
import { CANVAS_PIXEL_FORMAT as PF } from '../../src/rfb/protocol/pixel-format.js';

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

const SENTINEL = [0x11, 0x22, 0x33, 0x44]; // deliberately alpha != 255

function makeFb(w, h, fill = SENTINEL) {
  const fb = new Uint8ClampedArray(w * h * 4);
  for (let i = 0; i < w * h; i++) fb.set(fill, i * 4);
  return fb;
}

function px(fb, fbW, x, y) {
  const o = (y * fbW + x) * 4;
  return [fb[o], fb[o + 1], fb[o + 2], fb[o + 3]];
}

function concat(...parts) {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/** Raw wire bytes for CANVAS_PIXEL_FORMAT: 32bpp LE, shifts 0/8/16 => [R,G,B,pad]. */
function rawPayload(w, h, colourAt) {
  const out = new Uint8Array(w * h * 4);
  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) {
      const [r, g, b] = colourAt(x, y);
      const o = (y * w + x) * 4;
      out[o] = r;
      out[o + 1] = g;
      out[o + 2] = b;
      out[o + 3] = 0x7f; // pad byte: must be ignored, alpha is forced to 255
    }
  }
  return out;
}

/** u32 big-endian length header + the compressed bytes — the zlib/ZRLE envelope. */
function wrap(compressed) {
  const out = new Uint8Array(4 + compressed.length);
  new DataView(out.buffer).setUint32(0, compressed.length, false);
  out.set(compressed, 4);
  return out;
}

/**
 * A single zlib deflate stream flushed with Z_SYNC_FLUSH per rectangle — this
 * is exactly what an RFB server does, and the reason the inflate side must
 * never be reset between rectangles.
 */
function makeDeflater() {
  const def = zlib.createDeflate();
  const chunks = [];
  def.on('data', (c) => chunks.push(c));
  return {
    push(bytes) {
      return new Promise((resolve, reject) => {
        def.write(Buffer.from(bytes), (err) => {
          if (err) return reject(err);
          def.flush(zlib.constants.Z_SYNC_FLUSH, () => {
            setImmediate(() => {
              const out = Buffer.concat(chunks);
              chunks.length = 0;
              resolve(new Uint8Array(out));
            });
          });
        });
      });
    },
  };
}

/** Packs palette indices MSB-first, restarting on a byte boundary EVERY ROW. */
function packIndices(rows, bits) {
  const tw = rows[0].length;
  const rowBytes = (tw * bits + 7) >> 3;
  const out = new Uint8Array(rowBytes * rows.length);
  for (let j = 0; j < rows.length; j++) {
    let bitPos = 0;
    for (let i = 0; i < tw; i++, bitPos += bits) {
      const o = j * rowBytes + (bitPos >> 3);
      out[o] |= (rows[j][i] & ((1 << bits) - 1)) << (8 - bits - (bitPos & 7));
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// raw
// ---------------------------------------------------------------------------

test('raw: 2x2 rectangle lands at the right offset with alpha 255', () => {
  const fbW = 6;
  const fbH = 5;
  const fb = makeFb(fbW, fbH);

  const colours = [
    [10, 20, 30],
    [40, 50, 60],
    [70, 80, 90],
    [100, 110, 120],
  ];
  const rect = { x: 2, y: 1, w: 2, h: 2 };
  const payload = rawPayload(2, 2, (x, y) => colours[y * 2 + x]);

  decodeRaw(payload, rect, PF, fb, fbW, fbH);

  assert.deepEqual(px(fb, fbW, 2, 1), [10, 20, 30, 255]);
  assert.deepEqual(px(fb, fbW, 3, 1), [40, 50, 60, 255]);
  assert.deepEqual(px(fb, fbW, 2, 2), [70, 80, 90, 255]);
  assert.deepEqual(px(fb, fbW, 3, 2), [100, 110, 120, 255]);

  // Every other pixel — including the immediate neighbours — is untouched.
  for (let y = 0; y < fbH; y++) {
    for (let x = 0; x < fbW; x++) {
      const inside = x >= 2 && x < 4 && y >= 1 && y < 3;
      if (inside) continue;
      assert.deepEqual(px(fb, fbW, x, y), SENTINEL, `pixel ${x},${y} disturbed`);
    }
  }
});

// ---------------------------------------------------------------------------
// copyrect
// ---------------------------------------------------------------------------

const FB8 = 8;

function patternFb() {
  const fb = new Uint8ClampedArray(FB8 * FB8 * 4);
  for (let y = 0; y < FB8; y++) {
    for (let x = 0; x < FB8; x++) {
      const o = (y * FB8 + x) * 4;
      fb[o] = x * 16 + 1;
      fb[o + 1] = y * 16 + 2;
      fb[o + 2] = x * 8 + y + 3;
      fb[o + 3] = 255;
    }
  }
  return fb;
}

function copyRectPayload(srcX, srcY) {
  return new Uint8Array([srcX >> 8, srcX & 0xff, srcY >> 8, srcY & 0xff]);
}

test('copyrect: overlapping DOWNWARD copy does not smear rows', () => {
  const fb = patternFb();
  const before = patternFb();

  // src (0,0) 8x6 -> dst (0,2): the regions overlap by 4 rows.
  decodeCopyRect(copyRectPayload(0, 0), { x: 0, y: 2, w: 8, h: 6 }, PF, fb, FB8, FB8);

  for (let y = 0; y < FB8; y++) {
    for (let x = 0; x < FB8; x++) {
      const expected = y >= 2 ? px(before, FB8, x, y - 2) : px(before, FB8, x, y);
      assert.deepEqual(px(fb, FB8, x, y), expected, `pixel ${x},${y}`);
    }
  }
});

test('copyrect: overlapping UPWARD copy does not smear rows', () => {
  const fb = patternFb();
  const before = patternFb();

  // src (0,2) 8x6 -> dst (0,0).
  decodeCopyRect(copyRectPayload(0, 2), { x: 0, y: 0, w: 8, h: 6 }, PF, fb, FB8, FB8);

  for (let y = 0; y < FB8; y++) {
    for (let x = 0; x < FB8; x++) {
      const expected = y < 6 ? px(before, FB8, x, y + 2) : px(before, FB8, x, y);
      assert.deepEqual(px(fb, FB8, x, y), expected, `pixel ${x},${y}`);
    }
  }
});

test('copyrect: overlapping HORIZONTAL copy on the same rows', () => {
  const fb = patternFb();
  const before = patternFb();

  // src (0,0) 6x8 -> dst (2,0): same rows, columns overlap.
  decodeCopyRect(copyRectPayload(0, 0), { x: 2, y: 0, w: 6, h: 8 }, PF, fb, FB8, FB8);

  for (let y = 0; y < FB8; y++) {
    for (let x = 0; x < FB8; x++) {
      const expected = x >= 2 ? px(before, FB8, x - 2, y) : px(before, FB8, x, y);
      assert.deepEqual(px(fb, FB8, x, y), expected, `pixel ${x},${y}`);
    }
  }
});

// ---------------------------------------------------------------------------
// zlib (encoding 6)
// ---------------------------------------------------------------------------

test('zlib6: decodes identically to raw, and the inflate stream is never reset', async () => {
  const fbW = 8;
  const fbH = 8;
  const zfb = makeFb(fbW, fbH);
  const rfb = makeFb(fbW, fbH);

  const ctx = { inflate: createInflateContext() };
  const deflater = makeDeflater();

  // --- rectangle 1 ---------------------------------------------------------
  const rect1 = { x: 1, y: 1, w: 4, h: 3 };
  const raw1 = rawPayload(4, 3, (x, y) => [x * 30 + 5, y * 40 + 6, x + y * 7]);

  const payload1 = wrap(await deflater.push(raw1));
  decodeZlib6(payload1, rect1, PF, zfb, fbW, fbH, ctx);
  decodeRaw(raw1, rect1, PF, rfb, fbW, fbH);
  assert.deepEqual(zfb, rfb, 'first zlib rectangle differs from raw');

  // --- rectangle 2, same deflate stream, same inflate context ---------------
  // The second chunk carries no zlib header and back-references the first
  // rectangle's sliding window: it only inflates if the stream was kept alive.
  const rect2 = { x: 0, y: 5, w: 6, h: 2 };
  const raw2 = rawPayload(6, 2, (x, y) => [x * 30 + 5, y * 40 + 6, 200 - x]);

  const compressed2 = await deflater.push(raw2);
  assert.ok(compressed2.length > 0, 'second rectangle produced no deflate output');

  decodeZlib6(wrap(compressed2), rect2, PF, zfb, fbW, fbH, ctx);
  decodeRaw(raw2, rect2, PF, rfb, fbW, fbH);
  assert.deepEqual(zfb, rfb, 'second zlib rectangle differs from raw');

  // A fresh inflate context must NOT be able to read the second chunk alone.
  const fresh = { inflate: createInflateContext() };
  assert.throws(
    () => decodeZlib6(wrap(compressed2), rect2, PF, makeFb(fbW, fbH), fbW, fbH, fresh),
    /zlib|inflate/i,
    'headerless continuation decoded on a fresh stream — state is not being kept',
  );
});

// ---------------------------------------------------------------------------
// ZRLE (encoding 16)
// ---------------------------------------------------------------------------

/** Compresses one tile stream and returns the u32-length-prefixed payload. */
async function zrlePayload(deflater, tileBytes) {
  return wrap(await deflater.push(tileBytes));
}

function freshZrle() {
  return { ctx: { inflate: createInflateContext() }, deflater: makeDeflater() };
}

test('zrle: subencoding 1 (solid) fills the tile with one colour', async () => {
  const fbW = 8;
  const fbH = 8;
  const fb = makeFb(fbW, fbH);
  const { ctx, deflater } = freshZrle();

  const tile = new Uint8Array([1, 200, 100, 50]);
  const rect = { x: 1, y: 1, w: 4, h: 4 };
  decodeZrle(await zrlePayload(deflater, tile), rect, PF, fb, fbW, fbH, ctx);

  for (let y = 0; y < fbH; y++) {
    for (let x = 0; x < fbW; x++) {
      const inside = x >= 1 && x < 5 && y >= 1 && y < 5;
      assert.deepEqual(
        px(fb, fbW, x, y),
        inside ? [200, 100, 50, 255] : SENTINEL,
        `pixel ${x},${y}`,
      );
    }
  }
});

test('zrle: subencoding 0 (raw CPIXELs) is 3 bytes per pixel', async () => {
  const fbW = 8;
  const fbH = 8;
  const fb = makeFb(fbW, fbH);
  const { ctx, deflater } = freshZrle();

  const w = 3;
  const h = 2;
  const colour = (x, y) => [x * 20 + 1, y * 60 + 2, x * 5 + y * 9 + 3];
  const cpixels = new Uint8Array(w * h * 3);
  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) cpixels.set(colour(x, y), (y * w + x) * 3);
  }

  const rect = { x: 2, y: 3, w, h };
  decodeZrle(
    await zrlePayload(deflater, concat(new Uint8Array([0]), cpixels)),
    rect, PF, fb, fbW, fbH, ctx,
  );

  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) {
      assert.deepEqual(px(fb, fbW, 2 + x, 3 + y), [...colour(x, y), 255], `pixel ${x},${y}`);
    }
  }
  assert.deepEqual(px(fb, fbW, 1, 3), SENTINEL);
  assert.deepEqual(px(fb, fbW, 5, 3), SENTINEL);
});

test('zrle: packed palette, 2 colours (1 bit), rows padded to whole bytes', async () => {
  const fbW = 12;
  const fbH = 6;
  const fb = makeFb(fbW, fbH);
  const { ctx, deflater } = freshZrle();

  const pal = [[255, 0, 0], [0, 0, 255]];
  // 10 px/row at 1 bit => 10 bits used, 6 bits of padding, 2 bytes per row.
  const rows = [
    [1, 0, 1, 0, 1, 0, 1, 0, 1, 0],
    [0, 0, 0, 0, 0, 0, 0, 0, 1, 1],
    [1, 1, 1, 1, 1, 1, 1, 1, 0, 0],
  ];
  const packed = packIndices(rows, 1);
  assert.equal(packed.length, 6, 'expected 2 bytes per row');
  // Pin the layout: if rows were packed as one continuous bitstream these differ.
  assert.deepEqual([...packed], [0xaa, 0x80, 0x00, 0xc0, 0xff, 0x00]);

  const tile = concat(
    new Uint8Array([2]),
    new Uint8Array([...pal[0], ...pal[1]]),
    packed,
  );
  const rect = { x: 1, y: 2, w: 10, h: 3 };
  decodeZrle(await zrlePayload(deflater, tile), rect, PF, fb, fbW, fbH, ctx);

  for (let j = 0; j < 3; j++) {
    for (let i = 0; i < 10; i++) {
      assert.deepEqual(
        px(fb, fbW, 1 + i, 2 + j),
        [...pal[rows[j][i]], 255],
        `pixel ${i},${j}`,
      );
    }
  }
  assert.deepEqual(px(fb, fbW, 0, 2), SENTINEL);
  assert.deepEqual(px(fb, fbW, 11, 4), SENTINEL);
});

test('zrle: packed palette, 4 colours (2 bits), rows padded to whole bytes', async () => {
  const fbW = 8;
  const fbH = 8;
  const fb = makeFb(fbW, fbH);
  const { ctx, deflater } = freshZrle();

  const pal = [[1, 2, 3], [40, 41, 42], [80, 81, 82], [120, 121, 122]];
  // 5 px/row at 2 bits => 10 bits used, 6 bits of padding, 2 bytes per row.
  const rows = [
    [0, 1, 2, 3, 0],
    [3, 2, 1, 0, 3],
    [1, 1, 1, 1, 1],
  ];
  const packed = packIndices(rows, 2);
  assert.deepEqual([...packed], [0x1b, 0x00, 0xe4, 0xc0, 0x55, 0x40]);

  const tile = concat(
    new Uint8Array([4]),
    new Uint8Array(pal.flat()),
    packed,
  );
  const rect = { x: 0, y: 1, w: 5, h: 3 };
  decodeZrle(await zrlePayload(deflater, tile), rect, PF, fb, fbW, fbH, ctx);

  for (let j = 0; j < 3; j++) {
    for (let i = 0; i < 5; i++) {
      assert.deepEqual(
        px(fb, fbW, i, 1 + j),
        [...pal[rows[j][i]], 255],
        `pixel ${i},${j}`,
      );
    }
  }
  assert.deepEqual(px(fb, fbW, 5, 1), SENTINEL);
});

test('zrle: subencoding 128 (plain RLE) with a run longer than 255', async () => {
  const fbW = 64;
  const fbH = 8;
  const fb = makeFb(fbW, fbH);
  const { ctx, deflater } = freshZrle();

  const A = [9, 8, 7];
  const B = [70, 60, 50];
  // One 64x6 tile = 384 pixels. Run of 300 then a run of 84.
  // length-1 = 299 encodes as 255 + 44 (255 means "keep adding").
  const tile = concat(
    new Uint8Array([128]),
    new Uint8Array(A), new Uint8Array([255, 44]),
    new Uint8Array(B), new Uint8Array([83]),
  );

  const rect = { x: 0, y: 0, w: 64, h: 6 };
  decodeZrle(await zrlePayload(deflater, tile), rect, PF, fb, fbW, fbH, ctx);

  for (let i = 0; i < 384; i++) {
    const x = i % 64;
    const y = (i / 64) | 0;
    assert.deepEqual(px(fb, fbW, x, y), [...(i < 300 ? A : B), 255], `pixel index ${i}`);
  }
  assert.deepEqual(px(fb, fbW, 0, 6), SENTINEL, 'wrote past the rectangle');
});

test('zrle: subencoding 130+ (palette RLE)', async () => {
  const fbW = 10;
  const fbH = 6;
  const fb = makeFb(fbW, fbH);
  const { ctx, deflater } = freshZrle();

  const pal = [[11, 22, 33], [44, 55, 66], [77, 88, 99]];
  // 8x2 tile = 16 pixels. High bit on the index byte means a run follows.
  const tile = concat(
    new Uint8Array([131]),
    new Uint8Array(pal.flat()),
    new Uint8Array([0x80, 4]), // index 0, run 5
    new Uint8Array([0x01]),    // index 1, run 1
    new Uint8Array([0x02]),    // index 2, run 1
    new Uint8Array([0x81, 8]), // index 1, run 9
  );

  const rect = { x: 1, y: 1, w: 8, h: 2 };
  decodeZrle(await zrlePayload(deflater, tile), rect, PF, fb, fbW, fbH, ctx);

  const expectedIdx = [
    0, 0, 0, 0, 0, 1, 2, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
  ];
  for (let i = 0; i < 16; i++) {
    const x = 1 + (i % 8);
    const y = 1 + ((i / 8) | 0);
    assert.deepEqual(px(fb, fbW, x, y), [...pal[expectedIdx[i]], 255], `pixel index ${i}`);
  }
  assert.deepEqual(px(fb, fbW, 0, 1), SENTINEL);
  assert.deepEqual(px(fb, fbW, 9, 2), SENTINEL);
});

test('zrle: invalid subencoding throws', async () => {
  const fbW = 8;
  const fbH = 8;
  const fb = makeFb(fbW, fbH);
  const { ctx, deflater } = freshZrle();

  const payload = await zrlePayload(deflater, new Uint8Array([100]));
  assert.throws(
    () => decodeZrle(payload, { x: 0, y: 0, w: 4, h: 4 }, PF, fb, fbW, fbH, ctx),
    /subencoding/i,
  );
});
