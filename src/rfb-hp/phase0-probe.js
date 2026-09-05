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
import dgram from 'node:dgram';
import net from 'node:net';
import { modPow, bytesToBigInt, bigIntToBytes } from '../rfb/crypto/dh.js';
import { RecordLayer } from './record-layer.js';
import { buildVideoOffer, buildAudioOffer } from './offers.js';
import { makeKeyBlob, buildMediaStreamOptions, parseMediaStreamAnswer } from './mediastream.js';
import { isRtcp, SrtpReceiver, SrtcpSender, buildFir, buildFirLegacy, buildRr, buildEmptySr, buildPli, compoundWithRr } from './srtp.js';
import { HevcDepacketizer } from './depacketize.js';

// 0x1d SetDisplayConfiguration (308B): virtual display, dynamic resolution, 5 modes.
function setDisplayConfig() {
  const b = Buffer.alloc(308);
  b[0] = 0x1d;
  b.writeUInt16BE(0x0130, 2); b.writeUInt16BE(1, 4); b.writeUInt16BE(1, 6); // msg_size, =1, =1
  const di = 0x0c;
  b.writeUInt16BE(0x0128, di + 0x00);
  b.write('macvnc', di + 0x02, 'utf8'); // name, NUL-padded region
  b.writeUInt32BE(1, di + 0x7a); // display_flags = DYNAMIC_RESOLUTION (MANDATORY)
  b.writeUInt32BE(4, di + 0x7e); // display_type = 4 virtual (MANDATORY)
  b.writeFloatBE(369.4545593261719, di + 0x82);
  b.writeFloatBE(207.81817626953125, di + 0x86);
  b.writeUInt32BE(3840, di + 0x8a); b.writeUInt32BE(2160, di + 0x8e); // max w/h
  b.writeUInt16BE(0, di + 0x92); b.writeUInt16BE(0, di + 0x94); // cur/pref mode
  b.writeUInt32BE(7, di + 0x96); // reserved = 7 (MANDATORY)
  b.writeUInt16BE(5, di + 0x9a); // mode_count
  const modes = [[1920, 1080], [1440, 900], [1920, 1080], [1440, 810], [1312, 848]];
  modes.forEach(([w, h], i) => {
    const m = di + 0x9c + 28 * i;
    b.writeUInt32BE(w, m + 0x00); b.writeUInt32BE(h, m + 0x04);   // pixel w/h
    b.writeUInt32BE(w, m + 0x08); b.writeUInt32BE(h, m + 0x0c);   // scaled w/h (1:1)
    b.writeDoubleBE(60.0, m + 0x10); b.writeUInt32BE(0, m + 0x18); // refresh, flags
  });
  return b;
}
const fbUpdateRequest = () => Buffer.from([0x03, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff]);

// Apple's pre-session "warmup" TCP: connect, do the version handshake, close,
// dwell ~1.4s. Registers the session with screensharingd so the real session
// survives, and (per iShareScreen) is required before the media session.
export function warmupTcp(host, port) {
  return new Promise((resolve) => {
    const s = net.createConnection({ host, port });
    const rr = new Reader(s);
    let done = false;
    const finish = () => { if (done) return; done = true; try { s.destroy(); } catch {} setTimeout(resolve, 1400); };
    s.setTimeout(6000);
    s.on('timeout', finish);
    s.on('error', () => { if (!done) { done = true; resolve(); } });
    s.on('connect', async () => {
      try {
        await rr.read(12);                                   // banner
        s.write(Buffer.from('RFB 003.008\n', 'latin1'));     // version
        const n = (await rr.read(1))[0];
        await rr.read(n);                                    // security types
      } catch { /* ignore */ }
      finish();
    });
  });
}

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

export async function runHpProbe(socket, { host, username, password, onAu, runSeconds }, log) {
  const r = new Reader(socket);

  // Bind UDP media sockets EARLY and punch the firewall the whole time — the Mac
  // streams symmetrically (its 5901 -> our 5901) and the burst lands ~100ms after
  // the 0x1c answer, so the pinhole must already exist.
  const udpCtrl = dgram.createSocket({ type: 'udp4', reuseAddr: true });
  const udpVideo = dgram.createSocket({ type: 'udp4', reuseAddr: true });
  let videoPkts = 0, videoRtp = 0, videoRtcp = 0, firstFrom = null;
  let srtp = null, srtpOk = 0, srtpFail = 0, aus = 0, keyAus = 0;
  const ssrcSeen = new Map();
  // ONE depacketizer for the whole session. It emits PER-TILE access units
  // (each tagged with tileIdx) that all feed ONE shared VideoDecoder — Apple's
  // stream has cross-tile POC references, so per-tile DPBs decode to garbage
  // (hevc.py:1-24). See src/rfb-hp/depacketize.js for the full rationale.
  const depkt = new HevcDepacketizer(4);
  const seenSsrcs = new Set();
  let srtcp = null, ourVideoSsrc = 0, baseSsrc = 0;
  const firSeq = new Map();     // ssrc -> FIR sequence number
  let lastFir = 0, sawKey = false, settled = false;
  let depktErrors = 0, depktFirstError = null;
  // Packet loss leaves a corrupt region frozen until the next IDR, and Apple
  // only emits ~1 IDR / 10s unprompted. Track RTP sequence continuity per tile
  // and FIR on a gap so the damage is repaired instead of persisting
  // (session.py:745-770 does the same from its decode-error path).
  const expectSeq = new Map();  // ssrc -> next expected seq
  const lastLossFir = new Map();
  let lossEvents = 0;
  // Apple's HP encoder only ever emits IDRs on the base SSRC (= tile 0);
  // tiles 1-3 carry P-frames that reference the shared DPB, and FIR-ing them
  // waits for IDRs Apple architecturally never sends (hevc.py:645-652). So
  // re-FIR the BASE tile only, until the first keyframe lands.
  // Keep asking until an IDR lands AFTER every tile is known. An IDR that
  // arrives while tiles 1-3 are still unregistered re-roots a DPB those tiles
  // never contributed to, so their first P-frames reference pictures the
  // pre-IDR gate discarded — silent drift that no later P-frame repairs,
  // because Apple emits only ~1 unprompted IDR per 10s.
  const reFir = setInterval(() => {
    if (settled || !baseSsrc) return;
    if (Date.now() - lastFir > 700) { requestIdr(baseSsrc); lastFir = Date.now(); }
  }, 350);
  // Apple's AVConference peer treats a silent receiver as gone and stops
  // sending video after ~25-30s. It expects an RR every ~0.5s, with an empty
  // SR every 10th tick (session.py:90, :3682-3685). Without this the picture
  // simply freezes mid-session.
  // Periodic refresh FIR. Apple emits only ~2 unprompted IDRs, so a block that
  // decodes wrong stays wrong for the whole session — visible as a smeared
  // patch wherever content changed during a reference glitch. The reference
  // escalates to FIR from a frame-quality gate (quality_gate.py); this is the
  // cheap equivalent. Each IDR is a full 4:4:4 keyframe, so the interval trades
  // repair latency against a bandwidth/latency spike.
  const refreshMs = Number(process.env.VNC_HP_REFRESH_MS) || 5000;
  const refreshFir = setInterval(() => {
    if (!settled || !baseSsrc) return;
    requestIdr(baseSsrc);
  }, refreshMs);
  let txTick = 0;
  const rtcpKeepalive = setInterval(() => {
    if (!srtcp || !ourVideoSsrc) return;
    txTick++;
    const sources = [...seenSsrcs];
    const stats = new Map();
    for (const ssrc of sources) stats.set(ssrc, srtp ? srtp.reportStats(ssrc) : {});
    let pkt = buildRr(ourVideoSsrc, sources, stats);
    if (txTick % 10 === 1) pkt = Buffer.concat([buildEmptySr(ourVideoSsrc), pkt]);
    try { udpCtrl.send(srtcp.protect(pkt), 5900, host); } catch {}
  }, 500);
  // ALL RTCP goes to the CONTROL socket on port 5900, never the video port
  // (session.py:4410-4412 _ctrl_dest_port = udp_ctrl_port or port). It must also
  // be a compound packet starting with an RR, and pairs the AVPF FIR with a PLI
  // and the legacy PT=192 FIR — screensharingd often ignores the AVPF form and
  // answers the legacy one (session.py:4118-4130).
  function requestIdr(targetSsrc) {
    if (!srtcp || !ourVideoSsrc) return;
    const seq = ((firSeq.get(targetSsrc) || 0) + 1) & 0xff;
    firSeq.set(targetSsrc, seq);
    const rtcp = compoundWithRr(ourVideoSsrc, Buffer.concat([
      buildFir(ourVideoSsrc, targetSsrc, seq),
      buildPli(ourVideoSsrc, targetSsrc),
      buildFirLegacy(targetSsrc),
    ]));
    try { udpCtrl.send(srtcp.protect(rtcp), 5900, host); } catch {}
  }
  udpVideo.on('message', (msg, rinfo) => {
    videoPkts++;
    if (!firstFrom) firstFrom = `${rinfo.address}:${rinfo.port}`;
    if (isRtcp(msg)) { videoRtcp++; return; }
    videoRtp++;
    if (!srtp) return;
    let dec;
    try { dec = srtp.unprotect(msg); } catch { srtpFail++; return; }
    if (!dec) { srtpFail++; return; }
    srtpOk++;
    ssrcSeen.set(dec.ssrc, (ssrcSeen.get(dec.ssrc) || 0) + 1);
    // Tile 0 == lowest SSRC (burst.py:98-99). Track it so FIR targets the only
    // tile Apple will actually key.
    if (!seenSsrcs.has(dec.ssrc)) {
      seenSsrcs.add(dec.ssrc);
      if (!baseSsrc || dec.ssrc < baseSsrc) {
        baseSsrc = dec.ssrc;
        if (!sawKey) { requestIdr(baseSsrc); lastFir = Date.now(); }
      }
    }
    // Sequence-gap detection: a hole means a NAL is missing, so every later
    // P-frame in that region references a picture we never decoded.
    const exp = expectSeq.get(dec.ssrc);
    if (exp !== undefined && dec.seq !== exp && ((dec.seq - exp) & 0xffff) < 0x8000) {
      lossEvents++;
      const last = lastLossFir.get(dec.ssrc) || 0;
      if (Date.now() - last > 1000) { requestIdr(dec.ssrc); lastLossFir.set(dec.ssrc, Date.now()); }
    }
    expectSeq.set(dec.ssrc, (dec.seq + 1) & 0xffff);

    try {
      // dec.timestamp / dec.marker come straight off the RTP header. The marker
      // bit is the authoritative end-of-access-unit signal (burst.py:128-133).
      const first = depkt.push(dec.ssrc, dec.payload, dec.timestamp, dec.seq, dec.marker);
      const ready = first ? [first, ...depkt.drain()] : depkt.drain();
      for (const au of ready) {
        aus++;
        if (au.isKey) {
          keyAus++;
          sawKey = true;
          // Only stop FIR-ing once this IDR re-rooted a DPB that all tiles
          // were already feeding.
          if (seenSsrcs.size >= 4) settled = true;
        }
        if (onAu) onAu(au);
      }
    } catch (e) {
      // Never swallow this silently: a repeating exception here stops all AU
      // production while RTP keeps arriving, which looks exactly like the Mac
      // hanging up.
      depktErrors++;
      if (!depktFirstError) depktFirstError = String((e && e.stack) || e);
    }
  });
  await new Promise((res) => { let n = 0; const done = () => (++n === 2 && res());
    udpCtrl.bind(5900, () => { try { udpCtrl.setRecvBufferSize(4 << 20); } catch {} done(); });
    udpVideo.bind(5901, () => { try { udpVideo.setRecvBufferSize(4 << 20); } catch {} done(); });
  });
  const punch = setInterval(() => {
    try { udpCtrl.send(Buffer.from([0]), 5900, host); } catch {}
    try { udpVideo.send(Buffer.from([0]), 5901, host); } catch {}
  }, 100);
  const cleanup = () => { clearInterval(punch); clearInterval(reFir); clearInterval(refreshFir); clearInterval(rtcpKeepalive); try { udpCtrl.close(); } catch {} try { udpVideo.close(); } catch {} };
  log(`UDP bound 5900/5901, firewall-punching ${host}`);

  // Everything past the UDP bind runs under try/finally: an early throw (the
  // CHECKPOINT A rekey desync, a read timeout) would otherwise leak the sockets
  // bound to 5900/5901 and the punch/FIR intervals, so a retry in the same
  // process binds with reuseAddr but the ORPHANED socket keeps receiving the
  // stream — the retry sees no RTP at all.
  try {

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

  // 9) activate the record layer, verify the first record (CHECKPOINT B)
  socket.write(setEncryptionToggle());
  log('sent SetEncryption toggle (cmd=2)');
  const rl = new RecordLayer(cbcKey, cbcIv);

  const inner1 = rl.decrypt(await readRecord(r));
  if (!inner1) { log('>>> CHECKPOINT B FAILED: first record MAC did not verify'); return { verdict: 'FAIL_MAC', fbw, fbh }; }
  log(`>>> CHECKPOINT B PASSED: first record decrypts+MACs, inner type=0x${inner1[0].toString(16)} len=${inner1.length}`);
  log('>>> VERDICT: HP mode WORKS on type-30 — SRP/type-33 NOT needed.');

  // 10) PHASE 2: send encrypted SetEncodings + SetDisplayConfiguration + FBUR,
  //     then decrypt the metadata burst and look for the 0x451 AppleDisplayLayout.
  socket.write(rl.encrypt(setEncodings()));
  socket.write(rl.encrypt(setDisplayConfig()));
  socket.write(rl.encrypt(fbUpdateRequest()));
  log('[phase2] sent encrypted SetEncodings + SetDisplayConfiguration(0x1d) + FBUR');

  let layout = null;
  const deadline = Date.now() + 5000;
  let seen = [];
  while (Date.now() < deadline && !layout) {
    let msg;
    try { msg = rl.decrypt(await readRecord(r)); } catch { break; }
    if (!msg) { log('[phase2] (a record failed MAC; skipping)'); continue; }
    if (msg[0] === 0x00) {
      const rects = walkRects(msg, (enc, x, y, w, h, payload) => {
        seen.push('0x' + (enc >>> 0).toString(16));
        if (enc === 0x451 && payload && payload.length >= 12) {
          log(`[phase2] 0x451 payload ${payload.length}B head=${hex(payload, 24)}`);
          layout = { ver: payload.readUInt16BE(0), scaledW: payload.readUInt16BE(2), scaledH: payload.readUInt16BE(4), backingW: payload.readUInt16BE(6), backingH: payload.readUInt16BE(8) };
        }
      });
      if (!rects) log('[phase2] (FBU had a rect we could not size; continuing)');
    } else {
      seen.push('msg0x' + msg[0].toString(16));
    }
  }
  log('[phase2] metadata rects seen: ' + (seen.join(', ') || '(none)'));
  if (layout) log(`[phase2] 0x451 layout: backing ${layout.backingW}x${layout.backingH}`);

  // ---- PHASE 3: MediaStreamOptions (0x1c) offer -> does the Mac start streaming? ----
  try {
    const width = fbw, height = fbh;
    const video = buildVideoOffer({ width, height });
    const audio = buildAudioOffer({});
    const videoKeys = { key1: makeKeyBlob(), key2: makeKeyBlob() };
    const audioKeys = { key1: makeKeyBlob(), key2: makeKeyBlob() };
    const uuid = crypto.randomBytes(16);
    const body = buildMediaStreamOptions({
      audioOffer: audio.blob,
      videoOffer: video.blob,
      audioKeys, videoKeys, uuid, flags: 7,
      // We advertise LTR by default but never send the RTCP APP acks Apple's
      // encoder expects (session.py:1699). Unacked LTR makes the encoder
      // reference frames it believes we confirmed, so damaged regions never
      // repair. VNC_HP_NO_LTR=1 negotiates plain P-frames instead, which
      // isolates that as the cause.
      ltrpEnabled: !process.env.VNC_HP_NO_LTR,
    });
    socket.write(rl.encrypt(body));
    log(`[phase3] sent 0x1c MediaStreamOptions offer (${body.length}B), video ssrc=${video.ssrc}`);
    // Phase 4/5: decrypt with the server-send key (key2) and depacketize.
    srtp = new SrtpReceiver(videoKeys.key2);
    srtcp = new SrtcpSender(videoKeys.key1); // send FIRs with our send key
    ourVideoSsrc = video.ssrc >>> 0;

    // Read the 0x1c answer (and drain more metadata) for a few seconds while UDP counts.
    let answer = null;
    const t3 = Date.now() + 4000;
    while (Date.now() < t3 && !answer) {
      let msg;
      try { msg = rl.decrypt(await readRecord(r)); } catch { break; }
      if (!msg) continue;
      // The 0x1c answer's inner message starts with 0x00 and embeds a bplist —
      // try to parse it as an answer whenever a bplist is present, else it's metadata.
      if (msg.indexOf(Buffer.from('bplist00')) >= 0) {
        try { const a = parseMediaStreamAnswer(msg); if (a && a.canvasW) answer = a; } catch { /* keep waiting */ }
      }
      if (!answer && msg[0] === 0x00) {
        walkRects(msg, (enc) => { seen.push('0x' + (enc >>> 0).toString(16)); });
      }
    }
    if (answer) log(`[phase3] 0x1c ANSWER: canvas ${answer.canvasW}x${answer.canvasH} tiles=${answer.tileCount}`);
    else log('[phase3] no 0x1c answer parsed (may still stream)');

    // Give the burst time to land (or stream for runSeconds in display mode).
    await new Promise((res) => setTimeout(res, (runSeconds || 2.5) * 1000));
    log(`[phase3] >>> UDP video 5901: ${videoPkts} packets (${videoRtp} RTP, ${videoRtcp} RTCP), first from ${firstFrom || '(none)'}`);
    const streaming = videoRtp > 0;
    log(`[phase4] SRTP: ${srtpOk} decrypted+MAC-verified, ${srtpFail} failed`);
    log(`[phase5] HEVC access units: ${aus} (${keyAus} key/IDR)`);
    const sl = [...ssrcSeen.entries()].map(([k,v]) => k + ':' + v).join('  ');
    log(`[diag] distinct video SSRCs = ${ssrcSeen.size}  ->  ${sl}`);
    if (srtpOk > 0) log('[phase4] >>> SUCCESS: SRTP crypto is byte-correct on live packets.');
    else if (streaming) log('[phase4] >>> RTP arrives but SRTP MAC fails — key2 selection or IV/HMAC formula.');
    if (aus > 0) log('[phase5] >>> Depacketizer produced HEVC access units — ready to feed WebCodecs.');
    return { verdict: 'PASS', phase3: streaming ? 'streaming' : 'no-rtp', videoPkts, videoRtp, srtpOk, srtpFail, aus, keyAus, lossEvents, depktErrors, depktFirstError, depktStats: depkt.stats(), answer, layout };
  } catch (err) {
    log('[phase3] error: ' + (err && err.message));
    return { verdict: 'PASS', phase3: 'error', error: String(err && err.message), layout };
  }
  } finally {
    cleanup();
  }
}

// Read one record: u16be length + that many ciphertext bytes.
async function readRecord(r) {
  const len = (await r.read(2)).readUInt16BE(0);
  if (len === 0 || len % 16 !== 0) throw new Error('bad record length ' + len);
  return r.read(len);
}

// Walk the rects of a decrypted FramebufferUpdate inner message. Returns false if
// a rect payload cannot be sized (so the caller stops). cb(enc,x,y,w,h,payload).
/**
 * Size one metadata rect's payload so the walk can CONTINUE to the next rect.
 * Returning -1 means "unsizeable" and the caller must stop (RFB rects carry no
 * length, so a wrong size desyncs the whole stream - that is the 0x44f<<8 bug).
 */
function metaPayloadLen(enc, buf) {
  try {
    switch (enc) {
      case 1103: return 36;                                   // 0x44f rekey
      case 0x451: {                                           // AppleDisplayLayout
        if (buf.length < 20) return -1;
        return 20 + buf.readUInt16BE(18) * 56;                // hdr + count*56
      }
      case 0x453: return 22;                                  // fixed
      case 0x455: {                                           // +8 u16 id_len
        if (buf.length < 10) return -1;
        return 10 + buf.readUInt16BE(8);
      }
      case 0x456: {                                           // +0 u16 msg_size
        if (buf.length < 2) return -1;
        return buf.readUInt16BE(0);
      }
      case 0x450: {                                           // cursor: u32 id + u32 len + data
        if (buf.length < 8) return -1;
        return 8 + buf.readUInt32BE(4);
      }
      case 1010: case 1011: {                                 // u16-length-prefixed
        if (buf.length < 2) return -1;
        return 2 + buf.readUInt16BE(0);
      }
      default: return -1;
    }
  } catch { return -1; }
}

function walkRects(msg, cb) {
  let p = 2; // u8 type, u8 pad
  if (msg.length < 4) return false;
  const n = msg.readUInt16BE(p); p += 2;
  for (let i = 0; i < n; i++) {
    if (p + 12 > msg.length) return false;
    const x = msg.readUInt16BE(p), y = msg.readUInt16BE(p + 2);
    const w = msg.readUInt16BE(p + 4), h = msg.readUInt16BE(p + 6);
    const enc = msg.readInt32BE(p + 8);
    p += 12;
    if (enc === -224) return true;                            // LastRect ends the update
    const rest = msg.subarray(p);
    const len = metaPayloadLen(enc, rest);
    if (len < 0 || p + len > msg.length) {
      cb(enc, x, y, w, h, null);
      return false;                                           // cannot size -> must stop
    }
    cb(enc, x, y, w, h, rest.subarray(0, len));
    p += len;                                                 // ADVANCE past the payload
  }
  return true;
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
