// Phase 0 probe for Apple High Performance mode.
//
// Question it answers: can HP mode be reached over our existing type-30 (DH)
// auth, or must we build type-33 SRP? It runs type-30 auth (capturing the DH
// shared secret), sends the HP prelude, receives the 0x44f record-layer rekey,
// derives the wrap key as MD5(shared)[:16], unwraps the CBC key/IV, and uses the
// record layer's SHA-1 MAC as a cryptographic oracle: a matching MAC on the first
// encrypted record proves every derivation is byte-correct => HP works on type-30.
//
// Throwaway diagnostic. Main-process only; node:crypto is fine here.

import crypto from 'node:crypto';
import { modPow, bytesToBigInt, bigIntToBytes } from '../rfb/crypto/dh.js';

const md5 = (buf) => crypto.createHash('md5').update(buf).digest();
const sha1 = (buf) => crypto.createHash('sha1').update(buf).digest();
const hex = (buf, n) => Buffer.from(buf).subarray(0, n ?? buf.length).toString('hex');

// ---- async socket reader (buffers chunks, hands out exact byte counts) ----
class Reader {
  constructor(socket) {
    this.chunks = [];
    this.len = 0;
    this.waiter = null;
    socket.on('data', (d) => {
      this.chunks.push(d);
      this.len += d.length;
      if (this.waiter && this.len >= this.waiter.n) {
        const w = this.waiter;
        this.waiter = null;
        w.resolve(this._take(w.n));
      }
    });
    socket.on('close', () => {
      if (this.waiter) { const w = this.waiter; this.waiter = null; w.reject(new Error('socket closed')); }
    });
  }
  _take(n) {
    let all = Buffer.concat(this.chunks);
    const out = all.subarray(0, n);
    const rest = all.subarray(n);
    this.chunks = rest.length ? [rest] : [];
    this.len = rest.length;
    return out;
  }
  read(n) {
    if (this.len >= n) return Promise.resolve(this._take(n));
    return new Promise((resolve, reject) => { this.waiter = { n, resolve, reject }; });
  }
}

function viewerInfo() {
  const b = Buffer.alloc(66);
  b[0] = 0x21;
  b.writeUInt16BE(0x3e, 2); // msgSize = total-4
  b.writeUInt16BE(1, 4);    // msgVersion
  b.writeUInt32BE(2, 0x06); // app_id
  b.writeUInt32BE(6, 0x0a); // ver maj/min/pat
  b.writeUInt32BE(1, 0x0e);
  b.writeUInt32BE(0, 0x12);
  b.writeUInt32BE(15, 0x16); // os maj/min/pat
  b.writeUInt32BE(3, 0x1a);
  b.writeUInt32BE(0, 0x1e);
  // command_mask[32] at 0x22
  b[0x22 + 0] = 0xb0; b[0x22 + 2] = 0x0c; b[0x22 + 3] = 0x03; b[0x22 + 4] = 0x90; b[0x22 + 10] = 0x40;
  return b;
}
const setEncryptionStart = () => Buffer.from([0x12, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1]);
const setEncryptionToggle = () => Buffer.from('1200000200010000', 'hex');
function setEncodings() {
  const encs = [1010, 1011, 1002, 6, 16, 1104, 1100, -223, 1101, 1105, 1107, 1109, 1110];
  const b = Buffer.alloc(4 + encs.length * 4);
  b[0] = 0x02; b.writeUInt16BE(encs.length, 2);
  encs.forEach((e, i) => b.writeInt32BE(e, 4 + i * 4));
  return b;
}

// ECB single-block decrypt, no padding.
function ecbDecryptBlock(key16, block16) {
  const d = crypto.createDecipheriv('aes-128-ecb', key16, null);
  d.setAutoPadding(false);
  return Buffer.concat([d.update(block16), d.final()]);
}

export async function runHpProbe(socket, { username, password }, log) {
  const r = new Reader(socket);

  // 1) version handshake
  const banner = await r.read(12);
  log(`banner: ${banner.toString('latin1').trim()}`);
  socket.write(Buffer.from('RFB 003.008\n', 'latin1'));

  // 2) security types
  const count = (await r.read(1))[0];
  const types = await r.read(count);
  log(`security types: [${Array.from(types).join(', ')}]`);
  if (!Array.from(types).includes(30)) throw new Error('type 30 not offered');
  socket.write(Buffer.from([30]));

  // 3) DH params
  const head = await r.read(4);
  const generator = head.readUInt16BE(0);
  const keyLength = head.readUInt16BE(2);
  const prime = await r.read(keyLength);
  const serverPublic = await r.read(keyLength);
  log(`DH: g=${generator} keyLen=${keyLength}`);

  // 4) type-30 auth, capturing the shared secret
  const p = bytesToBigInt(prime);
  const g = BigInt(generator);
  const x = bytesToBigInt(crypto.randomBytes(keyLength));
  const clientPublic = bigIntToBytes(modPow(g, x, p), keyLength);
  const shared = bigIntToBytes(modPow(bytesToBigInt(serverPublic), x, p), keyLength);
  const authKey = md5(shared); // 16 bytes — also the type-30 wrap key candidate
  const plaintext = crypto.randomBytes(128);
  const u = Buffer.from(username, 'utf8'); u.copy(plaintext, 0, 0, Math.min(u.length, 63)); plaintext[Math.min(u.length, 63)] = 0;
  const pw = Buffer.from(password, 'utf8'); pw.copy(plaintext, 64, 0, Math.min(pw.length, 63)); plaintext[64 + Math.min(pw.length, 63)] = 0;
  const c = crypto.createCipheriv('aes-128-ecb', authKey, null); c.setAutoPadding(false);
  const ciphertext = Buffer.concat([c.update(plaintext), c.final()]);
  socket.write(Buffer.concat([ciphertext, clientPublic]));

  const secResult = (await r.read(4)).readUInt32BE(0);
  log(`SecurityResult: ${secResult}`);
  if (secResult !== 0) throw new Error('type-30 auth failed (SecurityResult=' + secResult + ')');
  log('type-30 auth OK. wrap_key = MD5(shared)[:16] = ' + hex(authKey));

  // 5) ClientInit -> ServerInit
  socket.write(Buffer.from([1])); // shared=1
  const siHead = await r.read(4);
  const fbw = siHead.readUInt16BE(0), fbh = siHead.readUInt16BE(2);
  await r.read(16); // pixel format
  const nameLen = (await r.read(4)).readUInt32BE(0);
  const name = (await r.read(nameLen)).toString('utf8');
  log(`ServerInit: ${fbw}x${fbh} "${name}"`);

  // 6) HP prelude (cleartext): ViewerInfo + SetEncryption(start), then SetEncodings
  socket.write(Buffer.concat([viewerInfo(), setEncryptionStart()]));
  await new Promise((res) => setTimeout(res, 120));
  socket.write(setEncodings());
  log('sent HP prelude (ViewerInfo + SetEncryption start + SetEncodings)');

  // 7) scan inbound for the 0x44f/1103 rekey rect (CHECKPOINT A)
  const blob = await findRekey(r, log);
  if (!blob) throw new Error('CHECKPOINT A FAILED: no 0x44f/1103 rekey after SetEncryption on type-30 => type-30 does NOT reach the record layer; type-33 required');
  log(`0x44f rekey blob (36B): gen=${blob.readUInt32BE(0)} ${hex(blob.subarray(4))}`);

  // 8) unwrap CBC key/IV under wrap_key
  const cbcKey = ecbDecryptBlock(authKey, blob.subarray(4, 20));
  const cbcIv = ecbDecryptBlock(authKey, blob.subarray(20, 36));
  log(`unwrapped cbcKey=${hex(cbcKey)} cbcIv=${hex(cbcIv)}`);

  // 9) activate + read first encrypted record, run the MAC oracle (CHECKPOINT B)
  socket.write(setEncryptionToggle());
  log('sent SetEncryption toggle (cmd=2)');

  const recLen = (await r.read(2)).readUInt16BE(0);
  log(`first record: ciphertext_len=${recLen} (must be nonzero & %16==0)`);
  if (recLen === 0 || recLen % 16 !== 0) throw new Error('record length not a nonzero multiple of 16: ' + recLen);
  const ct = await r.read(recLen);
  const dec = crypto.createDecipheriv('aes-128-cbc', cbcKey, cbcIv); dec.setAutoPadding(false);
  const pt = Buffer.concat([dec.update(ct), dec.final()]);
  log(`decrypted record (${pt.length}B): ${hex(pt, 48)}...`);

  const body = pt.subarray(0, pt.length - 20);
  const mac = pt.subarray(pt.length - 20);
  for (let seq = 0; seq <= 6; seq++) {
    const want = sha1(Buffer.concat([u32be(seq), body]));
    if (want.equals(mac)) {
      const innerLen = body.readUInt16BE(0);
      log(`>>> CHECKPOINT B PASSED: SHA-1 MAC verifies at seq=${seq}, inner_len=${innerLen}`);
      log('>>> VERDICT: MD5(shared)[:16] is the correct type-30 wrap key. HP mode WORKS on type-30 — SRP/type-33 NOT needed.');
      return { verdict: 'PASS', seq, innerLen, fbw, fbh };
    }
  }
  log('>>> CHECKPOINT B FAILED: no SHA-1 MAC match in seq window [0..6].');
  log('    Either the type-30 wrap key differs from MD5(shared)[:16], or framing/seq differs. Dumping for analysis.');
  log('    mac(got)=' + hex(mac));
  return { verdict: 'FAIL_MAC', fbw, fbh, ctHead: hex(ct, 32), ptHead: hex(pt, 32) };
}

function u32be(v) { const b = Buffer.alloc(4); b.writeUInt32BE(v >>> 0, 0); return b; }

// Walk inbound RFB messages looking for a FramebufferUpdate rect with encoding 1103.
async function findRekey(r, log) {
  const deadline = Date.now() + 6000;
  while (Date.now() < deadline) {
    const type = (await r.read(1))[0];
    if (type === 0x00) {
      await r.read(1); // pad
      const nRects = (await r.read(2)).readUInt16BE(0);
      for (let i = 0; i < nRects; i++) {
        const rh = await r.read(12);
        const enc = rh.readInt32BE(8);
        const w = rh.readUInt16BE(4), h = rh.readUInt16BE(6);
        if (enc === 1103) return await r.read(36);
        if (enc === 1010 || enc === 1011) { const l = (await r.read(2)).readUInt16BE(0); await r.read(l); continue; }
        // Unknown rect with pixel body we cannot size: bail out of this FBU.
        log(`  (rect enc=${enc} ${w}x${h} — cannot size payload, stopping FBU scan)`);
        return null;
      }
    } else if (type === 0x14) {
      await r.read(8); // MiscStatus, skip
    } else {
      log(`  (unexpected server msg type 0x${type.toString(16)} while scanning for rekey)`);
      return null;
    }
  }
  return null;
}
