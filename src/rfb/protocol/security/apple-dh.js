import { md5 } from '../../crypto/md5.js';
import { aes128EcbEncrypt } from '../../crypto/aes.js';
import { modPow, bytesToBigInt, bigIntToBytes } from '../../crypto/dh.js';

const CREDENTIAL_PLAINTEXT_LENGTH = 128;
const CREDENTIAL_SLOT_SIZE = 64;
const MAX_CREDENTIAL_BYTES = CREDENTIAL_SLOT_SIZE - 1; // one byte reserved for the NUL terminator

/**
 * Reads the server's Diffie-Hellman parameters for Apple security type 30.
 *
 * Wire layout (big-endian, no framing, no length prefixes):
 *   off 0      u16  generator g
 *   off 2      u16  keyLength L, in BYTES
 *   off 4      L bytes prime modulus p
 *   off 4+L    L bytes server public key
 *
 * Throws NeedMoreBytes (from the reader) when fewer than 4 + 2L bytes are buffered.
 */
export function parseAppleDhParams(reader) {
  const generator = reader.u16();
  const keyLength = reader.u16();
  if (keyLength <= 0) {
    throw new Error(`Apple DH: invalid keyLength ${keyLength}`);
  }
  const prime = reader.bytes(keyLength);
  // Fixed width, never trimmed: the server left-zero-pads its public key to L and a
  // sample with bit-length 1023 is normal. Scanning for significant bytes desyncs the stream.
  const serverPublic = reader.bytes(keyLength);
  return { generator, keyLength, prime, serverPublic };
}

function encodeCredential(value, label) {
  const bytes = new TextEncoder().encode(value == null ? '' : String(value));
  if (bytes.length > MAX_CREDENTIAL_BYTES) {
    throw new Error(
      `Apple DH: ${label} is ${bytes.length} bytes UTF-8, exceeds the ${MAX_CREDENTIAL_BYTES}-byte limit`,
    );
  }
  return bytes;
}

/**
 * Builds the 128 + keyLength byte credential blob for Apple security type 30.
 *
 * randomBytes: (n) => Uint8Array — injectable so tests can pin the private exponent
 * and the plaintext slack.
 */
export function buildAppleDhResponse(serverParams, username, password, randomBytes) {
  const { generator, keyLength, prime, serverPublic } = serverParams;

  if (!Number.isInteger(keyLength) || keyLength <= 0) {
    throw new Error(`Apple DH: invalid keyLength ${keyLength}`);
  }
  if (prime.length !== keyLength) {
    throw new Error(`Apple DH: prime is ${prime.length} bytes, expected ${keyLength}`);
  }
  if (serverPublic.length !== keyLength) {
    throw new Error(`Apple DH: serverPublic is ${serverPublic.length} bytes, expected ${keyLength}`);
  }

  const usernameBytes = encodeCredential(username, 'username');
  const passwordBytes = encodeCredential(password, 'password');

  const p = bytesToBigInt(prime);
  const g = BigInt(generator);
  const serverPub = bytesToBigInt(serverPublic);

  const privateExponentBytes = randomBytes(keyLength);
  if (privateExponentBytes.length !== keyLength) {
    throw new Error(
      `Apple DH: randomBytes(${keyLength}) returned ${privateExponentBytes.length} bytes`,
    );
  }
  const x = bytesToBigInt(privateExponentBytes);

  // Both values are left-zero-padded to exactly L. Node's getPublicKey() strips leading
  // zeros ~0.5% of the time; hashing a short secret is the classic 1-in-256 auth failure.
  const clientPublic = bigIntToBytes(modPow(g, x, p), keyLength);
  const secret = bigIntToBytes(modPow(serverPub, x, p), keyLength);
  const key = md5(secret);

  // Random fill, not zeros: under ECB, zero padding leaks the exact credential lengths.
  const plaintext = randomBytes(CREDENTIAL_PLAINTEXT_LENGTH);
  if (plaintext.length !== CREDENTIAL_PLAINTEXT_LENGTH) {
    throw new Error(
      `Apple DH: randomBytes(${CREDENTIAL_PLAINTEXT_LENGTH}) returned ${plaintext.length} bytes`,
    );
  }
  plaintext.set(usernameBytes, 0);
  plaintext[usernameBytes.length] = 0x00;
  plaintext.set(passwordBytes, CREDENTIAL_SLOT_SIZE);
  plaintext[CREDENTIAL_SLOT_SIZE + passwordBytes.length] = 0x00;

  const ciphertext = aes128EcbEncrypt(key, plaintext);
  if (ciphertext.length !== CREDENTIAL_PLAINTEXT_LENGTH) {
    throw new Error(
      `Apple DH: ciphertext is ${ciphertext.length} bytes, expected ${CREDENTIAL_PLAINTEXT_LENGTH}`,
    );
  }

  // Ciphertext THEN public key. Reversing the two fails against screensharingd.
  const out = new Uint8Array(CREDENTIAL_PLAINTEXT_LENGTH + keyLength);
  out.set(ciphertext, 0);
  out.set(clientPublic, CREDENTIAL_PLAINTEXT_LENGTH);

  if (out.length !== CREDENTIAL_PLAINTEXT_LENGTH + keyLength) {
    throw new Error(
      `Apple DH: response is ${out.length} bytes, expected ${CREDENTIAL_PLAINTEXT_LENGTH + keyLength}`,
    );
  }
  return out;
}
