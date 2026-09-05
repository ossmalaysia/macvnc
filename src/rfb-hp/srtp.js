// SRTP receive/decrypt for Apple High Performance HEVC media (UDP 5901).
// AES-256-CTR + HMAC-SHA1-80, RFC 3711. Ported byte-for-byte from srtp.py.
import { createCipheriv, createHmac, timingSafeEqual } from 'node:crypto';

const AUTH_TAG_LEN = 10; // HMAC-SHA1-80 truncated to 80 bits
const RTP_HEADER_MIN = 12;

export const SRTP_KEY_BLOB_LEN = 46;
export const SRTP_MASTER_KEY_LEN = 32;
export const SRTP_MASTER_SALT_LEN = 14;

// RFC 3711 §4.3.1 AES-CM KDF. kid = 14 zero bytes with kid[7]=label; the counter
// block is iv0(14)||0x0000 and Node's aes-256-ctr increments the full 128-bit
// value, which matches the Python hand-rolled 16-bit carry add for these tiny
// out_len values. Keystream = AES over zero plaintext, truncated to out_len.
function srtpKdf(masterKey, masterSalt, label, outLen) {
  const iv0 = Buffer.alloc(16); // bytes 14,15 stay 0 (block counter start)
  for (let i = 0; i < 14; i++) iv0[i] = (i === 7 ? label : 0) ^ masterSalt[i];
  const cipher = createCipheriv('aes-256-ctr', masterKey, iv0);
  const rounded = Math.ceil(outLen / 16) * 16;
  const ks = Buffer.concat([cipher.update(Buffer.alloc(rounded)), cipher.final()]);
  return ks.subarray(0, outLen);
}

// SRTP (RTP) session keys from the 46-byte blob: labels 0/1/2.
export function deriveSrtpKeys(keyBlob46) {
  if (keyBlob46.length !== SRTP_KEY_BLOB_LEN) {
    throw new Error(`SRTP key blob must be ${SRTP_KEY_BLOB_LEN} bytes, got ${keyBlob46.length}`);
  }
  const masterKey = keyBlob46.subarray(0, SRTP_MASTER_KEY_LEN);
  const masterSalt = keyBlob46.subarray(SRTP_MASTER_KEY_LEN, SRTP_KEY_BLOB_LEN);
  return {
    cipherKey: srtpKdf(masterKey, masterSalt, 0, 32),
    authKey: srtpKdf(masterKey, masterSalt, 1, 20),
    salt: srtpKdf(masterKey, masterSalt, 2, 14),
  };
}

// RTCP is muxed on the same port (RFC 5761): PT 64..95 => RTCP, else RTP.
export function isRtcp(packet) {
  const pt7 = packet[1] & 0x7f;
  return pt7 >= 64 && pt7 <= 95;
}

export class SrtpReceiver {
  constructor(keyBlob46) {
    const { cipherKey, authKey, salt } = deriveSrtpKeys(keyBlob46);
    this._cipherKey = cipherKey;
    this._authKey = authKey;
    this._salt = salt;
    // salt_int = 16-byte big-endian value with salt in bytes 0..13, 0x0000 tail.
    this._saltInt = BigInt('0x' + Buffer.concat([salt, Buffer.alloc(2)]).toString('hex'));
    this._states = new Map(); // ssrc -> { roc, maxSeq, initialized }
  }

  unprotect(packet) {
    if (packet.length < RTP_HEADER_MIN + AUTH_TAG_LEN) return null;

    const bodyLen = packet.length - AUTH_TAG_LEN;
    const seq = (packet[2] << 8) | packet[3];
    const ssrc = packet.readUInt32BE(8);

    const state = this._states.get(ssrc);
    let rocGuess;
    if (!state || !state.initialized) {
      rocGuess = 0;
    } else {
      const diff = seq - state.maxSeq;
      if (diff > 0x7fff) rocGuess = Math.max(0, state.roc - 1);
      else if (diff < -0x7fff) rocGuess = state.roc + 1;
      else rocGuess = state.roc;
    }

    const baseRoc = state ? state.roc : 0;
    const candidates = [];
    const seen = new Set();
    for (const r of [rocGuess, baseRoc, rocGuess + 1, Math.max(0, rocGuess - 1)]) {
      if (!seen.has(r)) { seen.add(r); candidates.push(r); }
    }

    for (const roc of candidates) {
      const res = this._tryDecrypt(packet, bodyLen, seq, ssrc, roc);
      if (res !== null) {
        this._updateState(ssrc, roc, seq);
        return { ssrc, seq, pt: packet[1] & 0x7f, payload: res };
      }
    }
    return null;
  }

  _tryDecrypt(packet, bodyLen, seq, ssrc, roc) {
    const rocBe = Buffer.alloc(4);
    rocBe.writeUInt32BE(roc >>> 0, 0);
    const h = createHmac('sha1', this._authKey);
    h.update(packet.subarray(0, bodyLen));
    h.update(rocBe);
    const computed = h.digest().subarray(0, AUTH_TAG_LEN);
    const received = packet.subarray(bodyLen, bodyLen + AUTH_TAG_LEN);
    if (!timingSafeEqual(computed, received)) return null;

    const firstByte = packet[0];
    const cc = firstByte & 0x0f;
    let hdrLen = RTP_HEADER_MIN + cc * 4;
    if ((firstByte >> 4) & 1) { // extension bit
      if (hdrLen + 4 > bodyLen) return null;
      const extLen = (packet[hdrLen + 2] << 8) | packet[hdrLen + 3];
      hdrLen += 4 + extLen * 4;
    }
    if (hdrLen > bodyLen) return null;
    if (hdrLen === bodyLen) return Buffer.alloc(0);

    // 128-bit IV = salt_int XOR (ssrc<<64) XOR (index<<16), index=(roc<<16)|seq.
    const index = (BigInt(roc) << 16n) | BigInt(seq);
    const ivInt = this._saltInt ^ (BigInt(ssrc) << 64n) ^ (index << 16n);
    const iv = Buffer.from(ivInt.toString(16).padStart(32, '0'), 'hex');
    const dec = createCipheriv('aes-256-ctr', this._cipherKey, iv);
    return Buffer.concat([dec.update(packet.subarray(hdrLen, bodyLen)), dec.final()]);
  }

  _updateState(ssrc, roc, seq) {
    let state = this._states.get(ssrc);
    if (!state) { state = { roc: 0, maxSeq: 0, initialized: false }; this._states.set(ssrc, state); }
    if (!state.initialized) {
      state.roc = roc;
      state.maxSeq = seq;
      state.initialized = true;
      return;
    }
    const newFull = (roc * 0x10000) + seq;
    const curFull = (state.roc * 0x10000) + state.maxSeq;
    if (newFull > curFull) { state.roc = roc; state.maxSeq = seq; }
  }
}
