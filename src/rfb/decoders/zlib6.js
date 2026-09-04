import { decode as decodeRaw } from './raw.js';

/**
 * Encoding 6 (zlib): u32 length + deflate bytes fed to the connection's
 * long-lived encoding-6 inflate stream. The inflated output is byte-for-byte
 * a Raw rectangle, so it is handed straight to the Raw decoder.
 */
export function decode(payload, rect, pf, fb, fbW, fbH, ctx) {
  if (payload.length < 4) {
    throw new Error(`zlib: payload of ${payload.length} bytes is shorter than the 4-byte length header`);
  }

  const view = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
  const length = view.getUint32(0, false);
  if (payload.length < 4 + length) {
    throw new Error(`zlib: declared length ${length} exceeds payload (${payload.length - 4} bytes available)`);
  }

  const raw = ctx.inflate.zlib6.push(payload.subarray(4, 4 + length));

  const expected = rect.w * rect.h * (pf.bitsPerPixel >>> 3);
  if (raw.length !== expected) {
    throw new Error(`zlib: inflated ${raw.length} bytes, expected ${expected} for ${rect.w}x${rect.h}`);
  }

  decodeRaw(raw, rect, pf, fb, fbW, fbH, ctx);
}
