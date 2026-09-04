// AES-128 ECB, encryption only (FIPS-197). Pure Uint8Array, no Node crypto,
// so it runs unchanged in a browser worker.
//
// ECB with NO padding: the caller's plaintext is already a multiple of 16 and
// must come back the same length. Adding PKCS#7 here would silently emit an
// extra block and desynchronize the Apple DH auth submission.

const SBOX = new Uint8Array([
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]);

const RCON = new Uint8Array([0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]);

const ROUNDS = 10;
const KEY_SCHEDULE_BYTES = 176; // (ROUNDS + 1) * 16

// Multiply by x in GF(2**8) with the AES reduction polynomial 0x11b.
function xtime(v) {
  return ((v << 1) ^ (v & 0x80 ? 0x1b : 0)) & 0xff;
}

function expandKey(key) {
  const rk = new Uint8Array(KEY_SCHEDULE_BYTES);
  rk.set(key, 0);

  let rcon = 1;
  for (let i = 16; i < KEY_SCHEDULE_BYTES; i += 4) {
    let t0 = rk[i - 4];
    let t1 = rk[i - 3];
    let t2 = rk[i - 2];
    let t3 = rk[i - 1];

    if ((i & 15) === 0) {
      // RotWord, then SubWord, then xor Rcon into the first byte.
      const prev0 = t0;
      t0 = SBOX[t1] ^ RCON[rcon++];
      t1 = SBOX[t2];
      t2 = SBOX[t3];
      t3 = SBOX[prev0];
    }

    rk[i] = rk[i - 16] ^ t0;
    rk[i + 1] = rk[i - 15] ^ t1;
    rk[i + 2] = rk[i - 14] ^ t2;
    rk[i + 3] = rk[i - 13] ^ t3;
  }
  return rk;
}

function addRoundKey(state, rk, off) {
  for (let i = 0; i < 16; i++) state[i] ^= rk[off + i];
}

function subBytes(state) {
  for (let i = 0; i < 16; i++) state[i] = SBOX[state[i]];
}

// The state is column-major: row r is state[r], state[r+4], state[r+8], state[r+12].
// Row r rotates left by r positions.
function shiftRows(state) {
  let t = state[1];
  state[1] = state[5];
  state[5] = state[9];
  state[9] = state[13];
  state[13] = t;

  t = state[2];
  state[2] = state[10];
  state[10] = t;
  t = state[6];
  state[6] = state[14];
  state[14] = t;

  t = state[15];
  state[15] = state[11];
  state[11] = state[7];
  state[7] = state[3];
  state[3] = t;
}

function mixColumns(state) {
  for (let c = 0; c < 16; c += 4) {
    const s0 = state[c];
    const s1 = state[c + 1];
    const s2 = state[c + 2];
    const s3 = state[c + 3];
    const t = s0 ^ s1 ^ s2 ^ s3;
    state[c] = s0 ^ t ^ xtime(s0 ^ s1);
    state[c + 1] = s1 ^ t ^ xtime(s1 ^ s2);
    state[c + 2] = s2 ^ t ^ xtime(s2 ^ s3);
    state[c + 3] = s3 ^ t ^ xtime(s3 ^ s0);
  }
}

function encryptBlock(state, rk) {
  addRoundKey(state, rk, 0);
  for (let round = 1; round < ROUNDS; round++) {
    subBytes(state);
    shiftRows(state);
    mixColumns(state);
    addRoundKey(state, rk, round * 16);
  }
  // Final round omits MixColumns.
  subBytes(state);
  shiftRows(state);
  addRoundKey(state, rk, ROUNDS * 16);
}

/**
 * AES-128 in ECB mode: every 16-byte block encrypted independently.
 * @param {Uint8Array} key - exactly 16 bytes.
 * @param {Uint8Array} plaintext - length must be a multiple of 16.
 * @returns {Uint8Array} ciphertext, exactly plaintext.length bytes. Never padded.
 */
export function aes128EcbEncrypt(key, plaintext) {
  if (!(key instanceof Uint8Array)) {
    throw new TypeError('aes128EcbEncrypt: key must be a Uint8Array');
  }
  if (key.length !== 16) {
    throw new RangeError('aes128EcbEncrypt: key must be 16 bytes, got ' + key.length);
  }
  if (!(plaintext instanceof Uint8Array)) {
    throw new TypeError('aes128EcbEncrypt: plaintext must be a Uint8Array');
  }
  if (plaintext.length % 16 !== 0) {
    throw new RangeError(
      'aes128EcbEncrypt: plaintext length must be a multiple of 16, got ' + plaintext.length,
    );
  }

  const rk = expandKey(key);
  const out = new Uint8Array(plaintext.length);
  const state = new Uint8Array(16);

  for (let off = 0; off < plaintext.length; off += 16) {
    for (let i = 0; i < 16; i++) state[i] = plaintext[off + i];
    encryptBlock(state, rk);
    out.set(state, off);
  }

  rk.fill(0); // do not leave an expanded key sitting in the heap
  state.fill(0);
  return out;
}
