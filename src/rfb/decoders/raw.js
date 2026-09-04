// Raw encoding (0): w*h*bytesPerPixel bytes, no header, left-to-right / top-to-bottom.

/**
 * Assemble one PIXEL from the wire (RFC 6143 §7.4).
 * Multiplication, not `<<`, because a 32-bit pixel overflows JS signed shifts.
 */
function readPixel(payload, off, bpp, bigEndian) {
  let v = 0;
  if (bigEndian) {
    for (let i = 0; i < bpp; i++) v = v * 256 + payload[off + i];
  } else {
    for (let i = bpp - 1; i >= 0; i--) v = v * 256 + payload[off + i];
  }
  return v;
}

function scale(value, max) {
  if (max === 255) return value;
  if (max <= 0) return 0;
  return Math.round((value * 255) / max);
}

/**
 * @param {Uint8Array} payload
 * @param {{x:number,y:number,w:number,h:number}} rect
 * @param {object} pf
 * @param {Uint8ClampedArray} fb
 * @param {number} fbW
 * @param {number} fbH
 * @param {object} [ctx]
 */
export function decode(payload, rect, pf, fb, fbW, fbH, ctx) {
  const w = rect.w | 0;
  const h = rect.h | 0;
  if (w <= 0 || h <= 0) return;

  const bpp = (pf.bitsPerPixel | 0) >>> 3;
  if (bpp < 1 || bpp > 4) {
    throw new Error(`raw: unsupported bitsPerPixel ${pf.bitsPerPixel}`);
  }

  const srcStride = w * bpp;
  const needed = srcStride * h;
  if (payload.length < needed) {
    throw new Error(`raw: payload too short, need ${needed} bytes, got ${payload.length}`);
  }

  const rx = rect.x | 0;
  const ry = rect.y | 0;

  // Clip to the framebuffer so a malformed rectangle cannot write out of range.
  const x0 = rx < 0 ? 0 : rx;
  const y0 = ry < 0 ? 0 : ry;
  const x1 = Math.min(fbW, rx + w);
  const y1 = Math.min(fbH, ry + h);
  if (x1 <= x0 || y1 <= y0) return;

  const bigEndian = !!pf.bigEndian;
  const redShift = pf.redShift | 0;
  const greenShift = pf.greenShift | 0;
  const blueShift = pf.blueShift | 0;
  const redMax = pf.redMax | 0;
  const greenMax = pf.greenMax | 0;
  const blueMax = pf.blueMax | 0;

  // Fast path: 32bpp little-endian with shifts 0/8/16 puts [R,G,B,unused]
  // straight on the wire — byte-identical to ImageData except the alpha slot.
  const fast =
    bpp === 4 && !bigEndian &&
    redShift === 0 && greenShift === 8 && blueShift === 16 &&
    redMax === 255 && greenMax === 255 && blueMax === 255;

  if (fast) {
    for (let y = y0; y < y1; y++) {
      let si = (y - ry) * srcStride + (x0 - rx) * 4;
      let di = (y * fbW + x0) * 4;
      for (let x = x0; x < x1; x++) {
        fb[di] = payload[si];
        fb[di + 1] = payload[si + 1];
        fb[di + 2] = payload[si + 2];
        fb[di + 3] = 255;
        si += 4;
        di += 4;
      }
    }
    return;
  }

  // Fast path: RGB565 little-endian (our requested format). Expand 5/6/5-bit
  // channels to 8-bit by bit-replication - no division, no Math.round.
  const fast565 =
    bpp === 2 && !bigEndian &&
    redShift === 11 && greenShift === 5 && blueShift === 0 &&
    redMax === 31 && greenMax === 63 && blueMax === 31;

  if (fast565) {
    for (let y = y0; y < y1; y++) {
      let si = (y - ry) * srcStride + (x0 - rx) * 2;
      let di = (y * fbW + x0) * 4;
      for (let x = x0; x < x1; x++) {
        const v = payload[si] | (payload[si + 1] << 8);
        const r5 = (v >> 11) & 0x1f;
        const g6 = (v >> 5) & 0x3f;
        const b5 = v & 0x1f;
        fb[di] = (r5 << 3) | (r5 >> 2);
        fb[di + 1] = (g6 << 2) | (g6 >> 4);
        fb[di + 2] = (b5 << 3) | (b5 >> 2);
        fb[di + 3] = 255;
        si += 2;
        di += 4;
      }
    }
    return;
  }

  for (let y = y0; y < y1; y++) {
    let si = (y - ry) * srcStride + (x0 - rx) * bpp;
    let di = (y * fbW + x0) * 4;
    for (let x = x0; x < x1; x++) {
      const v = readPixel(payload, si, bpp, bigEndian);
      fb[di] = scale((v >>> redShift) & redMax, redMax);
      fb[di + 1] = scale((v >>> greenShift) & greenMax, greenMax);
      fb[di + 2] = scale((v >>> blueShift) & blueMax, blueMax);
      fb[di + 3] = 255;
      si += bpp;
      di += 4;
    }
  }
}
