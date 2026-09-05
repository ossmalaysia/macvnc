// MediaStreamOptions (0x1c) offer builder + answer parser.
//
// The 0x1c body is a FIXED-LAYOUT binary struct (not protobuf) carrying the
// client-generated SRTP master+salt key blobs and the zlib-compressed
// audio/video AVConference offer protobufs. The client originates every key;
// the server's answer returns only canvas geometry. Ported byte-for-byte from
// the Python reference (negotiation.build_0x1c, offers.extract_canvas_dims).
//
// All multi-byte scalars are BIG-ENDIAN. The +0x06 flags word in particular is
// written big-endian on purpose (see negotiation.py:194-205) — do NOT
// "correct" it to little-endian.

import crypto from 'node:crypto';
import zlib from 'node:zlib';

const KEY_BLOB_LEN = 46; // 32B master key + 14B master salt (RFC 3711 KDF input)

/**
 * 46 random bytes: 32-byte SRTP master key + 14-byte master salt.
 * MUST be fresh per session / per direction.
 * @returns {Buffer}
 */
export function makeKeyBlob() {
  return crypto.randomBytes(KEY_BLOB_LEN);
}

/**
 * Build the plaintext 0x1c MediaStreamOptions offer body. The caller encrypts
 * it through the control record layer before sending.
 *
 * @param {object}  o
 * @param {Buffer}  o.audioOffer  zlib-compressed audio offer plist (opaque here)
 * @param {Buffer}  o.videoOffer  zlib-compressed video offer plist (opaque here)
 * @param {{key1:Buffer,key2:Buffer}} o.audioKeys  key1=viewer->server (recv), key2=server->viewer (send)
 * @param {{key1:Buffer,key2:Buffer}} o.videoKeys  key1=viewer->server (recv), key2=server->viewer (send)
 * @param {Buffer} [o.uuid]   16-byte CallID; random if omitted
 * @param {number} [o.flags]  +0x06 config word; default 7 (stream1 60fps + cursor-strip)
 * @returns {Buffer}
 */
export function buildMediaStreamOptions({ audioOffer, videoOffer, audioKeys, videoKeys, uuid, flags }) {
  for (const [name, k] of [['audio', audioKeys], ['video', videoKeys]]) {
    for (const which of ['key1', 'key2']) {
      const b = k && k[which];
      if (!Buffer.isBuffer(b) || b.length !== KEY_BLOB_LEN) {
        throw new Error(`${name}Keys.${which} must be a ${KEY_BLOB_LEN}-byte Buffer`);
      }
    }
  }
  if (uuid !== undefined && (!Buffer.isBuffer(uuid) || uuid.length !== 16)) {
    throw new Error('uuid must be a 16-byte Buffer');
  }

  const AS = audioOffer.length;
  const VS = videoOffer.length;
  const MS = AS + VS + 0xD8;
  const configFlags = flags === undefined ? 7 : (flags >>> 0);

  const buf = Buffer.alloc(MS + 4); // zero-filled

  buf.writeUInt8(0x1C, 0);          // buf[1] stays 0 -> reads as u16 BE 0x001C
  buf.writeUInt16BE(MS, 2);
  buf.writeUInt16BE(3, 4);          // message_version = 3
  buf.writeUInt32BE(configFlags, 6); // BIG-endian on purpose
  buf.writeUInt16BE(AS, 10);        // +0x0a audio_offer_len
  buf.writeUInt16BE(VS, 12);        // +0x0c video_offer_len
  // +0x0e video2_offer_len = 0, +0x10 reserved = 0 (already zeroed)

  (uuid || crypto.randomBytes(16)).copy(buf, 0x14); // 16B CallID

  audioKeys.key1.copy(buf, 0x24);   // 46B audio key1 (recv)
  audioKeys.key2.copy(buf, 0x52);   // 46B audio key2 (send)
  audioOffer.copy(buf, 0x80);

  const vo = 0x80 + AS;
  videoKeys.key1.copy(buf, vo);         // 46B video key1 (recv)
  videoKeys.key2.copy(buf, vo + 0x2E);  // 46B video key2 (send)
  videoOffer.copy(buf, vo + 0x5C);

  return buf;
}

// Protobuf base-128 varint reader. Returns [value, newPos].
function readVarint(data, pos) {
  let val = 0n;
  let shift = 0n;
  while (pos < data.length) {
    const b = data[pos];
    pos += 1;
    val |= BigInt(b & 0x7F) << shift;
    shift += 7n;
    if (!(b & 0x80)) break;
  }
  // Canvas dims / tile counts fit comfortably in a JS number.
  return [Number(val & 0xFFFFFFFFFFFFFFFFn), pos];
}

// Scan `dec` (the decompressed MediaBlob protobuf) for the video-config
// sub-message (top-level field 5) and read F4=canvas_width, F5=canvas_height,
// F6=tile_count, F7=ltrpEnabled from it.
function readVideoConfig(dec) {
  let cw = 0, ch = 0, ct = 0, ltrp = 0;
  let pos = 0;
  while (pos < dec.length) {
    let tag;
    [tag, pos] = readVarint(dec, pos);
    const fn = tag >> 3;
    const wt = tag & 7;
    if (wt === 0) {
      [, pos] = readVarint(dec, pos);
    } else if (wt === 2) {
      let ln;
      [ln, pos] = readVarint(dec, pos);
      if (fn === 5) {
        const sub = dec.subarray(pos, pos + ln);
        let sp = 0;
        while (sp < sub.length) {
          let st;
          [st, sp] = readVarint(sub, sp);
          const sf = st >> 3;
          const sw = st & 7;
          if (sw === 0) {
            let v;
            [v, sp] = readVarint(sub, sp);
            if (sf === 4) cw = v;
            else if (sf === 5) ch = v;
            else if (sf === 6) ct = v;
            else if (sf === 7) ltrp = v;
          } else if (sw === 2) {
            let sl;
            [sl, sp] = readVarint(sub, sp);
            sp += sl;
          } else if (sw === 1) {
            sp += 8;
          } else if (sw === 5) {
            sp += 4;
          } else {
            break;
          }
        }
      }
      pos += ln;
    } else if (wt === 1) {
      pos += 8;
    } else if (wt === 5) {
      pos += 4;
    } else {
      break;
    }
  }
  return { cw, ch, ct, ltrp };
}

/**
 * Parse the server's 0x1c answer. The answer's first byte is 0x00 and embeds a
 * binary plist whose "avcMediaStreamNegotiatorMediaBlob" is a zlib-compressed
 * protobuf. We have no bplist parser in the main process, so we locate the
 * embedded zlib stream(s) directly (a valid zlib header is 0x78 with the two
 * header bytes divisible by 31), inflate, and read the video-config geometry.
 *
 * @param {Buffer} innerMsg  decrypted answer body
 * @returns {{canvasW:number,canvasH:number,tileCount:number,ltrp:number}|null}
 */
export function parseMediaStreamAnswer(innerMsg) {
  if (!Buffer.isBuffer(innerMsg) || innerMsg.length === 0 || innerMsg[0] !== 0x00) {
    return null;
  }
  // Anchor near the embedded plist when present, else scan the whole buffer.
  let start = innerMsg.indexOf(Buffer.from('bplist'));
  if (start < 0) start = 0;

  for (let i = start; i + 1 < innerMsg.length; i++) {
    if (innerMsg[i] !== 0x78) continue;
    if (((innerMsg[i] << 8) | innerMsg[i + 1]) % 31 !== 0) continue;
    let dec;
    try {
      dec = zlib.inflateSync(innerMsg.subarray(i));
    } catch {
      continue; // not a real zlib stream at this offset
    }
    const { cw, ch, ct, ltrp } = readVideoConfig(dec);
    if (cw && ch) {
      return { canvasW: cw, canvasH: ch, tileCount: ct, ltrp };
    }
  }
  return null;
}
