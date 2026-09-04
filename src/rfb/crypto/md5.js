// MD5 — RFC 1321. Pure Uint8Array in / Uint8Array(16) out, no Node crypto,
// so it runs unchanged in a browser worker.
//
// Everything here is LITTLE-endian: the 32-bit words loaded from the message,
// the 64-bit trailing bit-count, and the digest bytes. That is the opposite of
// the SHA family and is the classic source of "almost right" MD5 bugs.

// Per-round left-rotate amounts.
const S = new Uint8Array([
  7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
  5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
  6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
]);

// T[i] = floor(abs(sin(i + 1)) * 2**32). Hard-coded rather than computed:
// Math.sin is implementation-defined in ECMAScript, so deriving the table at
// runtime would risk a one-ULP difference between Node and a browser worker.
const K = new Int32Array([
  0xd76aa478 | 0, 0xe8c7b756 | 0, 0x242070db | 0, 0xc1bdceee | 0,
  0xf57c0faf | 0, 0x4787c62a | 0, 0xa8304613 | 0, 0xfd469501 | 0,
  0x698098d8 | 0, 0x8b44f7af | 0, 0xffff5bb1 | 0, 0x895cd7be | 0,
  0x6b901122 | 0, 0xfd987193 | 0, 0xa679438e | 0, 0x49b40821 | 0,
  0xf61e2562 | 0, 0xc040b340 | 0, 0x265e5a51 | 0, 0xe9b6c7aa | 0,
  0xd62f105d | 0, 0x02441453 | 0, 0xd8a1e681 | 0, 0xe7d3fbc8 | 0,
  0x21e1cde6 | 0, 0xc33707d6 | 0, 0xf4d50d87 | 0, 0x455a14ed | 0,
  0xa9e3e905 | 0, 0xfcefa3f8 | 0, 0x676f02d9 | 0, 0x8d2a4c8a | 0,
  0xfffa3942 | 0, 0x8771f681 | 0, 0x6d9d6122 | 0, 0xfde5380c | 0,
  0xa4beea44 | 0, 0x4bdecfa9 | 0, 0xf6bb4b60 | 0, 0xbebfbc70 | 0,
  0x289b7ec6 | 0, 0xeaa127fa | 0, 0xd4ef3085 | 0, 0x04881d05 | 0,
  0xd9d4d039 | 0, 0xe6db99e5 | 0, 0x1fa27cf8 | 0, 0xc4ac5665 | 0,
  0xf4292244 | 0, 0x432aff97 | 0, 0xab9423a7 | 0, 0xfc93a039 | 0,
  0x655b59c3 | 0, 0x8f0ccc92 | 0, 0xffeff47d | 0, 0x85845dd1 | 0,
  0x6fa87e4f | 0, 0xfe2ce6e0 | 0, 0xa3014314 | 0, 0x4e0811a1 | 0,
  0xf7537e82 | 0, 0xbd3af235 | 0, 0x2ad7d2bb | 0, 0xeb86d391 | 0,
]);

// Module-scope scratch. md5() never yields, and each worker/thread gets its own
// module instance, so reuse is safe and keeps the function allocation-light.
const H = new Int32Array(4);
const M = new Int32Array(16);
const TAIL = new Uint8Array(128);

function loadBlock(src, off) {
  for (let i = 0; i < 16; i++) {
    const j = off + (i << 2);
    M[i] = (src[j] | (src[j + 1] << 8) | (src[j + 2] << 16) | (src[j + 3] << 24)) | 0;
  }
}

function transform() {
  let a = H[0], b = H[1], c = H[2], d = H[3];

  for (let i = 0; i < 64; i++) {
    let f, g;
    if (i < 16) {
      f = (b & c) | (~b & d);
      g = i;
    } else if (i < 32) {
      f = (d & b) | (~d & c);
      g = (5 * i + 1) & 15;
    } else if (i < 48) {
      f = b ^ c ^ d;
      g = (3 * i + 5) & 15;
    } else {
      f = c ^ (b | ~d);
      g = (7 * i) & 15;
    }

    const tmp = d;
    d = c;
    c = b;
    const x = (a + f + K[i] + M[g]) | 0;
    const s = S[i];
    b = (b + ((x << s) | (x >>> (32 - s)))) | 0;
    a = tmp;
  }

  H[0] = (H[0] + a) | 0;
  H[1] = (H[1] + b) | 0;
  H[2] = (H[2] + c) | 0;
  H[3] = (H[3] + d) | 0;
}

/**
 * @param {Uint8Array} data - message of any length, including zero.
 * @returns {Uint8Array} 16-byte digest.
 */
export function md5(data) {
  if (!(data instanceof Uint8Array)) {
    throw new TypeError('md5: data must be a Uint8Array');
  }

  H[0] = 0x67452301 | 0;
  H[1] = 0xefcdab89 | 0;
  H[2] = 0x98badcfe | 0;
  H[3] = 0x10325476 | 0;

  const len = data.length;
  const full = len & ~63; // bytes covered by complete 64-byte blocks

  for (let off = 0; off < full; off += 64) {
    loadBlock(data, off);
    transform();
  }

  // Tail: remaining bytes, 0x80, zero padding, then the 64-bit bit-length.
  // Needs a second block when the remainder leaves no room for the length.
  const rem = len - full;
  const tailLen = rem < 56 ? 64 : 128;
  TAIL.fill(0, 0, tailLen);
  for (let i = 0; i < rem; i++) TAIL[i] = data[full + i];
  TAIL[rem] = 0x80;

  // len * 8 is exact as a double up to 2**53; >>> 0 takes it mod 2**32.
  const bitsLo = (len * 8) >>> 0;
  const bitsHi = Math.floor(len / 536870912) >>> 0; // len * 8 / 2**32
  const lenOff = tailLen - 8;
  TAIL[lenOff] = bitsLo & 0xff;
  TAIL[lenOff + 1] = (bitsLo >>> 8) & 0xff;
  TAIL[lenOff + 2] = (bitsLo >>> 16) & 0xff;
  TAIL[lenOff + 3] = (bitsLo >>> 24) & 0xff;
  TAIL[lenOff + 4] = bitsHi & 0xff;
  TAIL[lenOff + 5] = (bitsHi >>> 8) & 0xff;
  TAIL[lenOff + 6] = (bitsHi >>> 16) & 0xff;
  TAIL[lenOff + 7] = (bitsHi >>> 24) & 0xff;

  loadBlock(TAIL, 0);
  transform();
  if (tailLen === 128) {
    loadBlock(TAIL, 64);
    transform();
  }

  const out = new Uint8Array(16);
  for (let i = 0; i < 4; i++) {
    const w = H[i];
    out[i * 4] = w & 0xff;
    out[i * 4 + 1] = (w >>> 8) & 0xff;
    out[i * 4 + 2] = (w >>> 16) & 0xff;
    out[i * 4 + 3] = (w >>> 24) & 0xff;
  }
  return out;
}
