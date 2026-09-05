// Apple HP encrypted control-channel record layer (enc1103).
//
// After the 0x44f rekey gives us cbcKey/cbcIv, every control message is wrapped:
//   plaintext block = u16be(body_len) || body || filler || SHA1(u32be(seq) || framed)
//   filler pads (2 + body_len + 20) up to a multiple of 16; framed = everything
//   before the 20-byte SHA-1 trailer. Each direction is ONE continuous AES-128-CBC
//   stream (IV chains across records), with an independent u32 sequence counter.
// Main-process only; node:crypto.

import crypto from 'node:crypto';

const sha1 = (b) => crypto.createHash('sha1').update(b).digest();
const u16be = (v) => { const b = Buffer.alloc(2); b.writeUInt16BE(v & 0xffff, 0); return b; };
const u32be = (v) => { const b = Buffer.alloc(4); b.writeUInt32BE(v >>> 0, 0); return b; };

export class RecordLayer {
  constructor(cbcKey, cbcIv) {
    this.enc = crypto.createCipheriv('aes-128-cbc', cbcKey, cbcIv);
    this.enc.setAutoPadding(false);
    this.dec = crypto.createDecipheriv('aes-128-cbc', cbcKey, cbcIv);
    this.dec.setAutoPadding(false);
    this.encCtr = 0;
    this.decCtr = 0;
  }

  /** Wrap one raw RFB control message → the on-wire record (u16 len + ciphertext). */
  encrypt(body) {
    const bodyLen = body.length;
    const fillerLen = (-(2 + bodyLen + 20)) & 15;
    const framed = Buffer.concat([u16be(bodyLen), body, Buffer.alloc(fillerLen)]);
    const mac = sha1(Buffer.concat([u32be(this.encCtr), framed]));
    const ct = this.enc.update(Buffer.concat([framed, mac])); // %16 → full block out, chained
    this.encCtr += 1;
    return Buffer.concat([u16be(ct.length), ct]);
  }

  /**
   * Decrypt one record's ciphertext (caller has already read the u16 length).
   * Returns the inner RFB message bytes, or null on MAC miss. The CBC stream is
   * advanced regardless (it must stay chained even on a miss).
   */
  decrypt(ciphertext) {
    const pt = this.dec.update(ciphertext);
    const framed = pt.subarray(0, pt.length - 20);
    const mac = pt.subarray(pt.length - 20);
    for (let c = Math.max(0, this.decCtr - 1); c <= this.decCtr + 5; c++) {
      if (sha1(Buffer.concat([u32be(c), framed])).equals(mac)) {
        this.decCtr = c + 1;
        const innerLen = framed.readUInt16BE(0);
        return framed.subarray(2, 2 + innerLen);
      }
    }
    this.decCtr += 1;
    return null;
  }
}
