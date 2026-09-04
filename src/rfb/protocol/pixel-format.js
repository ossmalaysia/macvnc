/**
 * RFB PIXEL_FORMAT (RFC 6143 §7.4) — 16 bytes, embedded in ServerInit and SetPixelFormat.
 */

/**
 * The format we ask every server for: 32bpp little-endian with the channels
 * already laid out as [R,G,B,X] on the wire, which is what a canvas RGBA buffer
 * wants. depth is 24 (not 32) — the 4th byte is undefined padding, never alpha.
 */
export const CANVAS_PIXEL_FORMAT = {
  bitsPerPixel: 32,
  depth: 24,
  bigEndian: 0,
  trueColour: 1,
  redMax: 255,
  greenMax: 255,
  blueMax: 255,
  redShift: 0,
  greenShift: 8,
  blueShift: 16,
};

export function bytesPerPixel(pf) {
  return pf.bitsPerPixel / 8;
}

/**
 * Writes exactly 16 bytes. The *-max fields are U16 BIG-ENDIAN regardless of
 * bigEndian: that flag describes pixel data on the wire, not this header.
 */
export function writePixelFormat(writer, pf) {
  writer.u8(pf.bitsPerPixel);
  writer.u8(pf.depth);
  writer.u8(pf.bigEndian ? 1 : 0);
  writer.u8(pf.trueColour ? 1 : 0);
  writer.u16(pf.redMax);
  writer.u16(pf.greenMax);
  writer.u16(pf.blueMax);
  writer.u8(pf.redShift);
  writer.u8(pf.greenShift);
  writer.u8(pf.blueShift);
  writer.skip(3);
}

/** Consumes exactly 16 bytes. Padding is read but never validated. */
export function readPixelFormat(reader) {
  const bitsPerPixel = reader.u8();
  const depth = reader.u8();
  const bigEndian = reader.u8();
  const trueColour = reader.u8();
  const redMax = reader.u16();
  const greenMax = reader.u16();
  const blueMax = reader.u16();
  const redShift = reader.u8();
  const greenShift = reader.u8();
  const blueShift = reader.u8();
  reader.skip(3);
  return {
    bitsPerPixel,
    depth,
    bigEndian,
    trueColour,
    redMax,
    greenMax,
    blueMax,
    redShift,
    greenShift,
    blueShift,
  };
}
