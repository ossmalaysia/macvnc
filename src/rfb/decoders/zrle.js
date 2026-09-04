const TILE = 64;

/**
 * Paint `count` pixels starting at tile-linear index `start` with one colour.
 * Runs may cross tile row boundaries, so this walks row segments.
 * `ox`/`oy` are the tile's framebuffer origin; writes outside the framebuffer
 * are dropped but still consume run length.
 */
function fillRun(fb, fbW, fbH, ox, oy, tw, th, start, count, r, g, b) {
  const end = start + count;
  if (end > tw * th) {
    throw new Error(`ZRLE: run of ${count} at ${start} overruns ${tw}x${th} tile`);
  }
  let pos = start;
  while (pos < end) {
    const j = (pos / tw) | 0;
    const i = pos - j * tw;
    const n = Math.min(end - pos, tw - i);
    const fy = oy + j;
    if (fy >= 0 && fy < fbH) {
      let fx = ox + i;
      for (let k = 0; k < n; k++, fx++) {
        if (fx >= 0 && fx < fbW) {
          const o = (fy * fbW + fx) << 2;
          fb[o] = r;
          fb[o + 1] = g;
          fb[o + 2] = b;
          fb[o + 3] = 255;
        }
      }
    }
    pos += n;
  }
}

/**
 * Encoding 16 (ZRLE): u32 length + deflate bytes fed to the connection's
 * long-lived ZRLE inflate stream. The decompressed stream is a sequence of
 * 64x64 tiles, left-to-right then top-to-bottom, clipped at the rectangle
 * edges. Tiles are not byte-aligned to each other and the decompressed size
 * is not known in advance, so the tile count is the only stopping condition.
 */
export function decode(payload, rect, pf, fb, fbW, fbH, ctx) {
  if (payload.length < 4) {
    throw new Error(`ZRLE: payload of ${payload.length} bytes is shorter than the 4-byte length header`);
  }
  if (pf.bitsPerPixel !== 32 || pf.depth > 24 || !pf.trueColour) {
    throw new Error(`ZRLE: decoder requires 32bpp/depth<=24 true colour, got ${pf.bitsPerPixel}bpp depth ${pf.depth}`);
  }

  const view = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
  const length = view.getUint32(0, false);
  if (payload.length < 4 + length) {
    throw new Error(`ZRLE: declared length ${length} exceeds payload (${payload.length - 4} bytes available)`);
  }

  const data = ctx.inflate.zrle.push(payload.subarray(4, 4 + length));
  const end = data.length;
  let p = 0;

  const need = (n) => {
    if (p + n > end) {
      throw new Error(`ZRLE: need ${n} bytes at offset ${p}, only ${end - p} decompressed`);
    }
  };

  // Palette RLE tops out at subencoding 255 => 127 entries.
  const palette = new Uint8Array(127 * 3);

  const { x: rx, y: ry, w: rw, h: rh } = rect;

  for (let ty = 0; ty < rh; ty += TILE) {
    const th = Math.min(TILE, rh - ty);
    const oy = ry + ty;

    for (let tx = 0; tx < rw; tx += TILE) {
      const tw = Math.min(TILE, rw - tx);
      const ox = rx + tx;
      const total = tw * th;

      need(1);
      const subenc = data[p++];

      if (subenc === 0) {
        // Raw CPIXELs, row-major within the tile.
        need(total * 3);
        let s = p;
        for (let j = 0; j < th; j++) {
          const fy = oy + j;
          if (fy < 0 || fy >= fbH) {
            s += tw * 3;
            continue;
          }
          for (let i = 0; i < tw; i++, s += 3) {
            const fx = ox + i;
            if (fx < 0 || fx >= fbW) continue;
            const o = (fy * fbW + fx) << 2;
            fb[o] = data[s];
            fb[o + 1] = data[s + 1];
            fb[o + 2] = data[s + 2];
            fb[o + 3] = 255;
          }
        }
        p += total * 3;
      } else if (subenc === 1) {
        need(3);
        fillRun(fb, fbW, fbH, ox, oy, tw, th, 0, total, data[p], data[p + 1], data[p + 2]);
        p += 3;
      } else if (subenc >= 2 && subenc <= 16) {
        const size = subenc;
        need(size * 3);
        palette.set(data.subarray(p, p + size * 3), 0);
        p += size * 3;

        const bits = size === 2 ? 1 : size <= 4 ? 2 : 4;
        const mask = (1 << bits) - 1;
        // Indices are MSB-first within each byte and EVERY TILE ROW restarts
        // on a byte boundary -- a row never continues mid-byte.
        const rowBytes = (tw * bits + 7) >> 3;
        need(rowBytes * th);

        for (let j = 0; j < th; j++) {
          const rowStart = p + j * rowBytes;
          const fy = oy + j;
          let bitPos = 0;
          for (let i = 0; i < tw; i++, bitPos += bits) {
            const idx = (data[rowStart + (bitPos >> 3)] >> (8 - bits - (bitPos & 7))) & mask;
            if (idx >= size) {
              throw new Error(`ZRLE: packed index ${idx} outside palette of ${size}`);
            }
            if (fy < 0 || fy >= fbH) continue;
            const fx = ox + i;
            if (fx < 0 || fx >= fbW) continue;
            const po = idx * 3;
            const o = (fy * fbW + fx) << 2;
            fb[o] = palette[po];
            fb[o + 1] = palette[po + 1];
            fb[o + 2] = palette[po + 2];
            fb[o + 3] = 255;
          }
        }
        p += rowBytes * th;
      } else if (subenc === 128) {
        let pos = 0;
        while (pos < total) {
          need(3);
          const r = data[p];
          const g = data[p + 1];
          const b = data[p + 2];
          p += 3;
          // Run length: 255 bytes accumulate, the first non-255 byte ends it, plus 1.
          let run = 1;
          for (;;) {
            need(1);
            const byte = data[p++];
            run += byte;
            if (byte !== 255) break;
          }
          fillRun(fb, fbW, fbH, ox, oy, tw, th, pos, run, r, g, b);
          pos += run;
        }
      } else if (subenc >= 130) {
        const size = subenc - 128;
        need(size * 3);
        palette.set(data.subarray(p, p + size * 3), 0);
        p += size * 3;

        let pos = 0;
        while (pos < total) {
          need(1);
          let idx = data[p++];
          let run = 1;
          if (idx & 0x80) {
            idx &= 0x7f;
            for (;;) {
              need(1);
              const byte = data[p++];
              run += byte;
              if (byte !== 255) break;
            }
          }
          if (idx >= size) {
            throw new Error(`ZRLE: RLE index ${idx} outside palette of ${size}`);
          }
          const po = idx * 3;
          fillRun(fb, fbW, fbH, ox, oy, tw, th, pos, run, palette[po], palette[po + 1], palette[po + 2]);
          pos += run;
        }
      } else {
        throw new Error(`ZRLE: invalid subencoding ${subenc}`);
      }
    }
  }

  // A mis-parsed tile does not fail on its own -- it silently desyncs every
  // later rectangle on this shared stream. Leftover bytes are that signal.
  if (p !== end) {
    throw new Error(`ZRLE: consumed ${p} of ${end} decompressed bytes`);
  }
}
