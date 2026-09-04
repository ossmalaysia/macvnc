import { decode as decodeRaw } from './raw.js';
import { decode as decodeCopyRect } from './copyrect.js';
import { decode as decodeZlib6 } from './zlib6.js';
import { decode as decodeZrle } from './zrle.js';

export const ENCODING_RAW = 0;
export const ENCODING_COPYRECT = 1;
export const ENCODING_ZLIB = 6;
export const ENCODING_ZRLE = 16;

/** encoding number -> decoder function */
export const DECODERS = new Map([
  [ENCODING_RAW, decodeRaw],
  [ENCODING_COPYRECT, decodeCopyRect],
  [ENCODING_ZLIB, decodeZlib6],
  [ENCODING_ZRLE, decodeZrle],
]);

export function getDecoder(encoding) {
  return DECODERS.get(encoding | 0) || null;
}

export function hasDecoder(encoding) {
  return DECODERS.has(encoding | 0);
}

/**
 * @param {number} encoding
 * @param {Uint8Array} payload
 * @param {{x:number,y:number,w:number,h:number}} rect
 * @param {object} pf
 * @param {Uint8ClampedArray} fb
 * @param {number} fbW
 * @param {number} fbH
 * @param {object} ctx  { inflate }
 */
export function decodeRect(encoding, payload, rect, pf, fb, fbW, fbH, ctx) {
  const decoder = DECODERS.get(encoding | 0);
  if (!decoder) {
    throw new Error(`No decoder registered for RFB encoding ${encoding | 0}`);
  }
  return decoder(payload, rect, pf, fb, fbW, fbH, ctx);
}
