// Oracle tests for src/rfb/crypto/**.
//
// The modules under test are deliberately hand-rolled (they must run in a
// browser worker), so node:crypto is used here purely as the reference
// implementation. Test files may import node:crypto; src/rfb/** may not.

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createHash,
  createCipheriv,
  getDiffieHellman,
  createDiffieHellman,
} from 'node:crypto';

import { md5 } from '../../src/rfb/crypto/md5.js';
import { aes128EcbEncrypt } from '../../src/rfb/crypto/aes.js';
import { modPow, bytesToBigInt, bigIntToBytes } from '../../src/rfb/crypto/dh.js';

// ---------------------------------------------------------------------------
// Deterministic PRNG. Seeded xorshift32 so a failure is reproducible: an
// intermittent 1-in-256 bug must not be an intermittent 1-in-256 test.
// ---------------------------------------------------------------------------

function makeRng(seed) {
  let s = seed >>> 0;
  if (s === 0) s = 0x9e3779b9;
  return function next() {
    s ^= s << 13;
    s >>>= 0;
    s ^= s >>> 17;
    s ^= s << 5;
    s >>>= 0;
    return s;
  };
}

function makeBytes(next, n) {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) out[i] = next() & 0xff;
  return out;
}

function hex(u8) {
  let s = '';
  for (let i = 0; i < u8.length; i++) s += u8[i].toString(16).padStart(2, '0');
  return s;
}

function fromHex(str) {
  const out = new Uint8Array(str.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(str.substr(i * 2, 2), 16);
  return out;
}

// ---------------------------------------------------------------------------
// MD5
// ---------------------------------------------------------------------------

test('md5: known RFC 1321 vectors', () => {
  const enc = new TextEncoder();
  const vectors = [
    ['', 'd41d8cd98f00b204e9800998ecf8427e'],
    ['a', '0cc175b9c0f1b6a831c399e269772661'],
    ['abc', '900150983cd24fb0d6963f7d28e17f72'],
    ['message digest', 'f96b697d7cb7938d525a2f31aaf161d0'],
    ['abcdefghijklmnopqrstuvwxyz', 'c3fcd3d76192e4007dfb496cca67e13b'],
    [
      'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
      'd174ab98d277d9f5a5611c2c9f419d9f',
    ],
    [
      '12345678901234567890123456789012345678901234567890123456789012345678901234567890',
      '57edf4a22be3c955ac49da2e2107b67a',
    ],
  ];
  for (const [input, expected] of vectors) {
    assert.equal(hex(md5(enc.encode(input))), expected, 'md5("' + input + '")');
  }
});

test('md5: padding-boundary lengths match node:crypto exactly', () => {
  const next = makeRng(0xc0ffee01);
  // 55/56/57 straddle "does the length field still fit in this block", 63/64/65
  // straddle the block size itself, 119/120 straddle the two-block tail.
  const lengths = [0, 1, 54, 55, 56, 57, 63, 64, 65, 119, 120, 121, 127, 128, 129];
  for (const len of lengths) {
    const data = makeBytes(next, len);
    const expected = createHash('md5').update(data).digest('hex');
    assert.equal(hex(md5(data)), expected, 'md5 of ' + len + ' bytes');
  }
});

test('md5: 200 random buffers of random length 0..5000 match node:crypto', () => {
  const next = makeRng(0x5eed1234);
  for (let i = 0; i < 200; i++) {
    const len = next() % 5001;
    const data = makeBytes(next, len);
    const expected = createHash('md5').update(data).digest('hex');
    assert.equal(hex(md5(data)), expected, 'iteration ' + i + ', length ' + len);
  }
});

test('md5: returns a fresh Uint8Array(16) each call, callers may retain it', () => {
  const enc = new TextEncoder();
  const a = md5(enc.encode('first'));
  const b = md5(enc.encode('second'));
  assert.ok(a instanceof Uint8Array);
  assert.equal(a.length, 16);
  assert.equal(b.length, 16);
  assert.notEqual(hex(a), hex(b), 'a must not have been clobbered by the second call');
  assert.equal(hex(a), createHash('md5').update('first').digest('hex'));
});

test('md5: rejects non-Uint8Array input', () => {
  assert.throws(() => md5('abc'), TypeError);
  assert.throws(() => md5([1, 2, 3]), TypeError);
});

// ---------------------------------------------------------------------------
// AES-128-ECB
// ---------------------------------------------------------------------------

function nodeAesEcb(key, plaintext) {
  const c = createCipheriv('aes-128-ecb', Buffer.from(key), null);
  c.setAutoPadding(false);
  return Buffer.concat([c.update(Buffer.from(plaintext)), c.final()]);
}

test('aes: FIPS-197 C.1 single-block vector', () => {
  const key = fromHex('000102030405060708090a0b0c0d0e0f');
  const pt = fromHex('00112233445566778899aabbccddeeff');
  assert.equal(hex(aes128EcbEncrypt(key, pt)), '69c4e0d86a7b0430d8cdb78070b4c55a');
});

test('aes: matches node:crypto over random 16/32/128-byte plaintexts', () => {
  const next = makeRng(0xa1e50000);
  for (const len of [16, 32, 128]) {
    for (let i = 0; i < 60; i++) {
      const key = makeBytes(next, 16);
      const pt = makeBytes(next, len);
      const expected = nodeAesEcb(key, pt).toString('hex');
      assert.equal(hex(aes128EcbEncrypt(key, pt)), expected, 'len ' + len + ' iter ' + i);
    }
  }
});

test('aes: never pads - output length always equals input length', () => {
  const next = makeRng(0xbeef4242);
  for (const len of [0, 16, 32, 48, 128, 256]) {
    const out = aes128EcbEncrypt(makeBytes(next, 16), makeBytes(next, len));
    assert.equal(out.length, len, 'length preserved for ' + len);
  }
});

test('aes: ECB is blockwise independent - repeated block gives repeated ciphertext', () => {
  const key = fromHex('000102030405060708090a0b0c0d0e0f');
  const block = fromHex('00112233445566778899aabbccddeeff');
  const pt = new Uint8Array(32);
  pt.set(block, 0);
  pt.set(block, 16);
  const out = aes128EcbEncrypt(key, pt);
  assert.equal(hex(out.subarray(0, 16)), '69c4e0d86a7b0430d8cdb78070b4c55a');
  assert.equal(hex(out.subarray(16, 32)), '69c4e0d86a7b0430d8cdb78070b4c55a');
});

test('aes: 128-byte plaintext (the Apple DH submission size) matches node:crypto', () => {
  const next = makeRng(0x0dd10dd1);
  const key = makeBytes(next, 16);
  const pt = makeBytes(next, 128);
  assert.equal(hex(aes128EcbEncrypt(key, pt)), nodeAesEcb(key, pt).toString('hex'));
});

test('aes: rejects bad key length and non-multiple-of-16 plaintext', () => {
  assert.throws(() => aes128EcbEncrypt(new Uint8Array(15), new Uint8Array(16)), RangeError);
  assert.throws(() => aes128EcbEncrypt(new Uint8Array(32), new Uint8Array(16)), RangeError);
  assert.throws(() => aes128EcbEncrypt(new Uint8Array(16), new Uint8Array(17)), RangeError);
  assert.throws(() => aes128EcbEncrypt('key', new Uint8Array(16)), TypeError);
});

// ---------------------------------------------------------------------------
// Diffie-Hellman
// ---------------------------------------------------------------------------

const MODP2_PRIME = new Uint8Array(getDiffieHellman('modp2').getPrime());
const MODP2_P = bytesToBigInt(MODP2_PRIME);
const MODP2_G = 2n;
const KEY_LEN = 128; // modp2 is 1024-bit

test('dh: modp2 prime is 128 bytes, so public keys must serialize to 128', () => {
  assert.equal(MODP2_PRIME.length, KEY_LEN);
  assert.equal(MODP2_PRIME[0] & 0x80, 0x80, 'top bit set - full 1024-bit modulus');
});

test('dh: bytesToBigInt is big-endian', () => {
  assert.equal(bytesToBigInt(new Uint8Array([])), 0n);
  assert.equal(bytesToBigInt(new Uint8Array([0x00])), 0n);
  assert.equal(bytesToBigInt(new Uint8Array([0x01, 0x00])), 256n);
  assert.equal(bytesToBigInt(new Uint8Array([0xff, 0xff])), 65535n);
  assert.equal(bytesToBigInt(new Uint8Array([0x00, 0x00, 0x01])), 1n);
  assert.equal(bytesToBigInt(new Uint8Array([0x12, 0x34, 0x56, 0x78])), 0x12345678n);
});

test('dh: modPow edge cases', () => {
  assert.equal(modPow(0n, 0n, 7n), 1n);
  assert.equal(modPow(5n, 0n, 7n), 1n);
  assert.equal(modPow(0n, 5n, 7n), 0n);
  assert.equal(modPow(2n, 10n, 1000n), 24n);
  assert.equal(modPow(123n, 456n, 1n), 0n);
  assert.throws(() => modPow(2n, -1n, 7n), RangeError);
  assert.throws(() => modPow(2n, 3n, 0n), RangeError);
  assert.throws(() => modPow(2, 3n, 7n), TypeError);
});

test('dh: modPow matches node DiffieHellman public keys (modp2)', () => {
  for (let i = 0; i < 25; i++) {
    const dh = getDiffieHellman('modp2');
    dh.generateKeys();
    const priv = bytesToBigInt(new Uint8Array(dh.getPrivateKey()));
    const pub = bytesToBigInt(new Uint8Array(dh.getPublicKey()));
    assert.equal(modPow(MODP2_G, priv, MODP2_P), pub, 'public key mismatch at ' + i);
  }
});

test('dh: modPow matches node computeSecret for both sides (modp2)', () => {
  for (let i = 0; i < 10; i++) {
    const a = getDiffieHellman('modp2');
    const b = getDiffieHellman('modp2');
    a.generateKeys();
    b.generateKeys();

    const privA = bytesToBigInt(new Uint8Array(a.getPrivateKey()));
    const pubB = bytesToBigInt(new Uint8Array(b.getPublicKey()));
    const nodeSecret = bytesToBigInt(new Uint8Array(a.computeSecret(b.getPublicKey())));

    assert.equal(modPow(pubB, privA, MODP2_P), nodeSecret, 'shared secret mismatch at ' + i);

    // And symmetric: the other side derives the same value.
    const privB = bytesToBigInt(new Uint8Array(b.getPrivateKey()));
    const pubA = bytesToBigInt(new Uint8Array(a.getPublicKey()));
    assert.equal(modPow(pubA, privB, MODP2_P), nodeSecret, 'asymmetric at ' + i);
  }
});

test('dh: modPow matches a generic (non-safe) prime via createDiffieHellman', () => {
  // Same prime, generator supplied explicitly - exercises the plain
  // createDiffieHellman path rather than the named-group shortcut.
  const dh = createDiffieHellman(Buffer.from(MODP2_PRIME), Buffer.from([2]));
  for (let i = 0; i < 10; i++) {
    dh.generateKeys();
    const priv = bytesToBigInt(new Uint8Array(dh.getPrivateKey()));
    const pub = bytesToBigInt(new Uint8Array(dh.getPublicKey()));
    assert.equal(modPow(2n, priv, MODP2_P), pub);
  }
});

test('dh: bigIntToBytes left-zero-pads to the exact requested width', () => {
  assert.deepEqual(bigIntToBytes(0n, 4), new Uint8Array([0, 0, 0, 0]));
  assert.deepEqual(bigIntToBytes(1n, 4), new Uint8Array([0, 0, 0, 1]));
  assert.deepEqual(bigIntToBytes(0x1234n, 4), new Uint8Array([0, 0, 0x12, 0x34]));
  assert.deepEqual(bigIntToBytes(0xffffffffn, 4), new Uint8Array([255, 255, 255, 255]));
  assert.equal(bigIntToBytes(0n, 0).length, 0);

  const one128 = bigIntToBytes(1n, 128);
  assert.equal(one128.length, 128);
  assert.equal(one128[127], 1);
  for (let i = 0; i < 127; i++) assert.equal(one128[i], 0, 'byte ' + i + ' must be zero');

  assert.throws(() => bigIntToBytes(0x100n, 1), RangeError, 'overflow must be loud');
  assert.throws(() => bigIntToBytes(-1n, 4), RangeError);
  assert.throws(() => bigIntToBytes(5, 4), TypeError);
});

test('dh: bigIntToBytes round-trips through bytesToBigInt', () => {
  const next = makeRng(0x11223344);
  for (let i = 0; i < 500; i++) {
    const raw = makeBytes(next, 128);
    const v = bytesToBigInt(raw);
    assert.deepEqual(bigIntToBytes(v, 128), raw, 'round trip ' + i);
  }
});

// THE REGRESSION TEST. A DH public key or shared secret whose top byte happens
// to be zero must still serialize to exactly keyLength bytes; a variable-width
// encoding makes MD5(secret) differ from the server's and auth fails for
// roughly 1 connection in 256, with no diagnostic. 3000 iterations at a seeded
// RNG deterministically covers the zero-high-byte case ~12 times.
test('dh: every serialized modp2 public key is exactly 128 bytes (3000 exponents)', () => {
  const next = makeRng(0x0badf00d);
  let leadingZeroCount = 0;
  let shortestSignificant = KEY_LEN;

  for (let i = 0; i < 3000; i++) {
    const priv = (bytesToBigInt(makeBytes(next, 128)) % (MODP2_P - 3n)) + 2n;
    const pub = modPow(MODP2_G, priv, MODP2_P);
    const wire = bigIntToBytes(pub, KEY_LEN);

    assert.equal(wire.length, KEY_LEN, 'iteration ' + i + ': public key was not 128 bytes');
    assert.equal(bytesToBigInt(wire), pub, 'iteration ' + i + ': value corrupted by padding');

    if (wire[0] === 0) {
      leadingZeroCount++;
      let sig = 0;
      while (sig < KEY_LEN && wire[sig] === 0) sig++;
      shortestSignificant = Math.min(shortestSignificant, KEY_LEN - sig);
    }
  }

  // If this ever hits zero, the test stopped exercising the bug it exists for.
  assert.ok(
    leadingZeroCount > 0,
    'expected some public keys with a zero high byte; got ' + leadingZeroCount,
  );
  assert.ok(shortestSignificant < KEY_LEN);
});

test('dh: shared secrets with a zero high byte still pad to 128 before md5', () => {
  // Construct the pathological case directly instead of waiting for it: any
  // value < 2**1016 has a zero high byte at 128-byte width.
  const next = makeRng(0x7e577e57);
  for (let i = 0; i < 50; i++) {
    const small = bytesToBigInt(makeBytes(next, 100)); // ~800 bits
    const padded = bigIntToBytes(small, KEY_LEN);
    assert.equal(padded.length, KEY_LEN);
    assert.equal(padded[0], 0);
    assert.deepEqual(padded.subarray(28), bigIntToBytes(small, 100));

    // The AES key the Apple DH handshake derives is md5 over the padded form.
    const k = md5(padded);
    assert.equal(k.length, 16);
    assert.equal(hex(k), createHash('md5').update(Buffer.from(padded)).digest('hex'));
  }
});
