// Diffie-Hellman helpers over BigInt. No Node crypto, no Buffer - this runs
// unchanged in a browser worker.

/**
 * Right-to-left square-and-multiply, reducing mod `mod` at every step so no
 * intermediate value ever exceeds mod squared.
 * @param {bigint} base
 * @param {bigint} exp - must be non-negative.
 * @param {bigint} mod - must be positive.
 * @returns {bigint}
 */
export function modPow(base, exp, mod) {
  if (typeof base !== 'bigint' || typeof exp !== 'bigint' || typeof mod !== 'bigint') {
    throw new TypeError('modPow: base, exp and mod must all be BigInt');
  }
  if (mod <= 0n) throw new RangeError('modPow: mod must be positive');
  if (exp < 0n) throw new RangeError('modPow: exp must be non-negative');
  if (mod === 1n) return 0n;

  let result = 1n;
  let b = base % mod;
  if (b < 0n) b += mod;
  let e = exp;

  while (e > 0n) {
    if (e & 1n) result = (result * b) % mod;
    e >>= 1n;
    if (e > 0n) b = (b * b) % mod;
  }
  return result;
}

/**
 * @param {Uint8Array} u8 - big-endian, most significant byte first.
 * @returns {bigint} 0n for an empty array.
 */
export function bytesToBigInt(u8) {
  if (!(u8 instanceof Uint8Array)) {
    throw new TypeError('bytesToBigInt: expected a Uint8Array');
  }
  let v = 0n;
  for (let i = 0; i < u8.length; i++) {
    v = (v << 8n) | BigInt(u8[i]);
  }
  return v;
}

/**
 * Big-endian, LEFT-ZERO-PADDED to exactly `byteLength` bytes.
 *
 * The fixed width is the whole point: the DH client public key and the shared
 * secret must each occupy exactly keyLength bytes. A secret that happens to
 * have a zero high byte would otherwise serialize one byte short, the MD5 key
 * would differ from the server's, and auth would fail with nothing but a
 * generic error - roughly 1 connection in 256.
 *
 * @param {bigint} v - must be non-negative.
 * @param {number} byteLength
 * @returns {Uint8Array} exactly `byteLength` bytes.
 */
export function bigIntToBytes(v, byteLength) {
  if (typeof v !== 'bigint') {
    throw new TypeError('bigIntToBytes: value must be a BigInt');
  }
  if (!Number.isInteger(byteLength) || byteLength < 0) {
    throw new RangeError('bigIntToBytes: byteLength must be a non-negative integer');
  }
  if (v < 0n) {
    throw new RangeError('bigIntToBytes: value must be non-negative');
  }

  const out = new Uint8Array(byteLength);
  let x = v;
  for (let i = byteLength - 1; i >= 0; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  if (x !== 0n) {
    throw new RangeError('bigIntToBytes: value does not fit in ' + byteLength + ' bytes');
  }
  return out;
}
