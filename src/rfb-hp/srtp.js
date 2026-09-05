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
    const timestamp = packet.readUInt32BE(4);
    // RTP marker bit: authoritative "last packet of this tile's access unit"
    // (burst.py:132 gates AU completion on it). Without it the depacketizer can
    // only guess via timestamp advancement, which delays every frame by one.
    const marker = (packet[1] & 0x80) !== 0;
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
        return { ssrc, seq, timestamp, marker, pt: packet[1] & 0x7f, payload: res };
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

  /** Per-SSRC receive state for RTCP report blocks (extended highest seq). */
  reportStats(ssrc) {
    const st = this._states.get(ssrc >>> 0);
    return st ? { maxSeq: st.maxSeq, roc: st.roc } : {};
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

// ---- SRTCP sender: protect outgoing RTCP (FIR/PLI/RR) with the SEND key (key1) ----

function splitBlob(blob46) {
  return { key: blob46.subarray(0, 32), salt: blob46.subarray(32, 46) };
}

export class SrtcpSender {
  constructor(keyBlob46 /* video key1 = viewer->server */) {
    const { key, salt } = splitBlob(keyBlob46);
    this._cipherKey = srtpKdf(key, salt, 3, 32);
    this._authKey = srtpKdf(key, salt, 4, 20);
    this._salt = srtpKdf(key, salt, 5, 14);
    this._index = 0;
  }

  /** Wrap one RTCP packet as SRTCP (RFC 3711 §3.4). */
  protect(rtcp) {
    const index = this._index++;
    const hdr = rtcp.subarray(0, 8);
    const plaintext = rtcp.subarray(8);
    const ssrc = hdr.readUInt32BE(4);

    const iv = Buffer.alloc(16);
    this._salt.copy(iv, 0);              // salt(14) || 0x0000
    iv[4] ^= (ssrc >>> 24) & 0xff;
    iv[5] ^= (ssrc >>> 16) & 0xff;
    iv[6] ^= (ssrc >>> 8) & 0xff;
    iv[7] ^= ssrc & 0xff;
    iv[10] ^= (index >>> 24) & 0xff;
    iv[11] ^= (index >>> 16) & 0xff;
    iv[12] ^= (index >>> 8) & 0xff;
    iv[13] ^= index & 0xff;

    const c = createCipheriv('aes-256-ctr', this._cipherKey, iv);
    const ciphertext = Buffer.concat([c.update(plaintext), c.final()]);
    const eIndex = Buffer.alloc(4);
    eIndex.writeUInt32BE((0x80000000 | index) >>> 0, 0);
    const body = Buffer.concat([hdr, ciphertext, eIndex]);
    const tag = createHmac('sha1', this._authKey).update(body).digest().subarray(0, 10);
    return Buffer.concat([body, tag]);
  }
}

/** FIR (RFC 5104 §4.3.1.1): forces an IDR on target_ssrc. */
export function buildFir(senderSsrc, targetSsrc, seq) {
  const b = Buffer.alloc(20);
  b[0] = 0x80 | 4; b[1] = 206; b.writeUInt16BE(4, 2); // PSFB FIR, length 4
  b.writeUInt32BE(senderSsrc >>> 0, 4);
  b.writeUInt32BE(0, 8);
  b.writeUInt32BE(targetSsrc >>> 0, 12);
  b[16] = seq & 0xff; // + 3 pad bytes (already zero)
  return b;
}

/** Legacy FIR (PT=192): the keyframe request Apple's native viewer sends. */
export function buildFirLegacy(targetSsrc) {
  const b = Buffer.alloc(8);
  b[0] = 0x80; b[1] = 192; b.writeUInt16BE(1, 2);
  b.writeUInt32BE(targetSsrc >>> 0, 4);
  return b;
}

/**
 * Receiver Report (RFC 3550 §6.4.2, PT=201). Apple's AVConference peer stops
 * sending video if the receiver goes silent — it expects an RR roughly every
 * 0.5s (session.py:3682-3685). Without it the stream dies after ~25-30s.
 * `sources` is the list of tile SSRCs; `stats` maps ssrc -> {maxSeq, roc} so
 * the report carries the extended highest sequence number received.
 */
export function buildRr(senderSsrc, sources = [], stats = new Map()) {
  const list = sources.slice(0, 31);
  if (list.length === 0) {
    const b = Buffer.alloc(8);
    b[0] = 0x80; b[1] = 201; b.writeUInt16BE(1, 2);
    b.writeUInt32BE(senderSsrc >>> 0, 4);
    return b;
  }
  const rc = list.length;
  const b = Buffer.alloc(8 + rc * 24);
  b[0] = 0x80 | rc; b[1] = 201;
  b.writeUInt16BE(1 + rc * 6, 2); // length in 32-bit words minus one
  b.writeUInt32BE(senderSsrc >>> 0, 4);
  let o = 8;
  for (const ssrc of list) {
    const st = stats.get(ssrc) || {};
    b.writeUInt32BE(ssrc >>> 0, o);
    // fraction lost + cumulative lost left at 0: Apple uses the report as a
    // liveness signal, and we recover loss with FIR rather than NACK.
    b.writeUInt32BE(0, o + 4);
    const ext = (((st.roc || 0) & 0xffff) << 16) | ((st.maxSeq || 0) & 0xffff);
    b.writeUInt32BE(ext >>> 0, o + 8);
    b.writeUInt32BE(0, o + 12); // interarrival jitter
    b.writeUInt32BE(0, o + 16); // LSR
    b.writeUInt32BE(0, o + 20); // DLSR
    o += 24;
  }
  return b;
}

/** Empty Sender Report (PT=200) so AVConference accepts us as a live sender. */
export function buildEmptySr(senderSsrc) {
  const b = Buffer.alloc(28);
  b[0] = 0x80; b[1] = 200; b.writeUInt16BE(6, 2);
  b.writeUInt32BE(senderSsrc >>> 0, 4);
  const now = Date.now() / 1000;
  const sec = Math.floor(now);
  b.writeUInt32BE((sec + 2208988800) >>> 0, 8);          // NTP epoch delta
  b.writeUInt32BE(Math.floor((now - sec) * 4294967296) >>> 0, 12);
  b.writeUInt32BE(Math.floor(now * 90000) >>> 0, 16);    // RTP timestamp
  return b;                                              // packet + octet count 0
}

/** Picture Loss Indication (RFC 4585 §6.3.1). Lighter than FIR. */
export function buildPli(senderSsrc, mediaSsrc) {
  const b = Buffer.alloc(12);
  b[0] = 0x80 | 1; b[1] = 206; b.writeUInt16BE(2, 2);
  b.writeUInt32BE(senderSsrc >>> 0, 4);
  b.writeUInt32BE(mediaSsrc >>> 0, 8);
  return b;
}

/**
 * Prefix feedback with an empty RR. Some RTCP peers — screensharingd included —
 * reject feedback that is not part of a compound packet starting with SR or RR
 * (rtcp.py:172-175).
 */
export function compoundWithRr(senderSsrc, payload) {
  return Buffer.concat([buildRr(senderSsrc), payload]);
}
