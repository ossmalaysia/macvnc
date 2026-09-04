import { Writer } from '../../io/writer.js';
import { writePixelFormat, CANVAS_PIXEL_FORMAT } from '../pixel-format.js';

/** ClientInit — a single unframed shared-flag byte. */
export function clientInit(shared = 1) {
  const w = new Writer(1);
  w.u8(shared ? 1 : 0);
  return w.result;
}

export function setPixelFormat(pf = CANVAS_PIXEL_FORMAT) {
  const w = new Writer(20);
  w.u8(0);
  w.skip(3);
  writePixelFormat(w, pf);
  return w.result;
}

export function setEncodings(encodings) {
  const list = encodings || [];
  const w = new Writer(4 + 4 * list.length);
  w.u8(2);
  w.skip(1);
  w.u16(list.length);
  // Pseudo-encodings live in the same list and are negative — signed i32.
  for (const enc of list) w.i32(enc);
  return w.result;
}

export function framebufferUpdateRequest(incremental, x, y, w_, h) {
  const w = new Writer(10);
  w.u8(3);
  w.u8(incremental ? 1 : 0);
  w.u16(x);
  w.u16(y);
  w.u16(w_);
  w.u16(h);
  return w.result;
}

export function keyEvent(down, keysym) {
  const w = new Writer(8);
  w.u8(4);
  w.u8(down ? 1 : 0);
  w.skip(2);
  w.u32(keysym >>> 0);
  return w.result;
}

export function pointerEvent(buttonMask, x, y) {
  const w = new Writer(6);
  w.u8(5);
  w.u8(buttonMask & 0xff);
  w.u16(x);
  w.u16(y);
  return w.result;
}

/** Body is Latin-1, not UTF-8. Anything above U+00FF becomes '?'. */
export function clientCutText(text) {
  const s = text == null ? '' : String(text);
  // Iterate by codepoint so an astral character collapses to one '?', not two.
  const cps = Array.from(s);
  const body = new Uint8Array(cps.length);
  for (let i = 0; i < cps.length; i++) {
    const c = cps[i].codePointAt(0);
    body[i] = c > 0xff ? 0x3f : c;
  }
  const w = new Writer(8 + body.length);
  w.u8(6);
  w.skip(3);
  w.u32(body.length);
  w.bytes(body);
  return w.result;
}
