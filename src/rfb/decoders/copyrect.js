// CopyRect encoding (1): payload is exactly 4 bytes — U16BE srcX, U16BE srcY.
// The source region may overlap the destination (window drag / scroll is the
// normal case), so the row iteration direction is chosen from the sign of dy and
// each row is moved with copyWithin, which has memmove (not memcpy) semantics.

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
  if (payload.length < 4) {
    throw new Error(`copyrect: payload too short, need 4 bytes, got ${payload.length}`);
  }

  let sx = (payload[0] << 8) | payload[1];
  let sy = (payload[2] << 8) | payload[3];
  let dx = rect.x | 0;
  let dy = rect.y | 0;
  let w = rect.w | 0;
  let h = rect.h | 0;
  if (w <= 0 || h <= 0) return;

  // Clip both source and destination into the framebuffer, shifting the other
  // corner by the same amount so the two regions stay aligned.
  if (dx < 0) { sx -= dx; w += dx; dx = 0; }
  if (sx < 0) { dx -= sx; w += sx; sx = 0; }
  if (dy < 0) { sy -= dy; h += dy; dy = 0; }
  if (sy < 0) { dy -= sy; h += sy; sy = 0; }
  w = Math.min(w, fbW - dx, fbW - sx);
  h = Math.min(h, fbH - dy, fbH - sy);
  if (w <= 0 || h <= 0) return;

  if (sx === dx && sy === dy) return;

  const rowBytes = w * 4;
  const stride = fbW * 4;

  if (sy < dy) {
    // Destination is below the source: copy bottom-to-top so rows we still need
    // are not overwritten first.
    for (let r = h - 1; r >= 0; r--) {
      const so = (sy + r) * stride + sx * 4;
      fb.copyWithin((dy + r) * stride + dx * 4, so, so + rowBytes);
    }
  } else {
    for (let r = 0; r < h; r++) {
      const so = (sy + r) * stride + sx * 4;
      fb.copyWithin((dy + r) * stride + dx * 4, so, so + rowBytes);
    }
  }
}
