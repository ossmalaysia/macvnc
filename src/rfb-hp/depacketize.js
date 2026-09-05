// HEVC RTP depacketizer for Apple "High Performance" screen sharing.
//
// Turns SRTP-decrypted RTP payloads (4 SSRC tile streams) into HEVC access
// units ready for a single WebCodecs VideoDecoder configured in Annex-B mode.
//
// Ported from the Python reference:
//   - nalu.py:28-80   reassemble_group() — AP/FU/single-NAL byte layout + Apple's
//                     RFC 7798 DONL deviation (this is where the FU/DONL splitting
//                     actually lives; hevc.py consumes its output).
//   - nalu.py:83-103  first_donl() — DONL offset per structure.
//   - hevc.py:1-24    single-shared-context rationale (all tiles -> one decoder).
//   - hevc.py:344-368 round-robin/tile-interleaved feed order (here: SSRC order
//                     within one whole-frame chunk).
//   - hevc.py:502-503,653-669,662-690  _dpb_has_idr gate + "any IDR resets all
//                     tiles" + drop pre-IDR P-frames.
//   - hevc.py:692-699 Annex-B start-code packetization (_NAL_START_CODE + NAL).
//   - hevc.py:1172-1180 _is_decodable_nalu() filter.
//
// Apple's RFC 7798 DONL deviations (nalu.py module doc):
//   * every structure carries a 2-byte DONL that must be stripped;
//   * AP (48) has ONE DONL after the 2-byte NAL header, NO per-unit DOND;
//   * FU (49) repeats the 2-byte DONL in EVERY fragment (stock: start only),
//     so ALL fragments skip 5 header bytes, not just the first.

const NAL_AGGREGATION = 48;
const NAL_FRAGMENTATION = 49;

// _NAL_START_CODE (decode_common.py:72). Prefixes every emitted NAL — omitting
// `description` in VideoDecoder.configure() selects this Annex-B mode.
const START_CODE = Buffer.from([0x00, 0x00, 0x00, 0x01]);

// Flush an incomplete/stalled frame after this long so one lost tile (UDP loss
// drops the marker / next-frame packet) can't wedge the pipeline forever.
const FLUSH_TIMEOUT_MS = 200;
// Hard cap on buffered frames; forces the oldest out if completion never fires.
const MAX_PENDING = 16;

function nalType(buf) {
  // HEVC 6-bit nal_unit_type: byte0 >> 1 & 0x3F.
  return (buf[0] >> 1) & 0x3f;
}

// True if this NAL should ride in the WebCodecs chunk. Keeps VPS/SPS/PPS
// (32-34, needed in-band before the IDR) and single-slice VCL NALs; drops SEI/
// AUD/EOS/EOB/FD (35-40+) and slices missing first_slice_segment_in_pic_flag.
// (hevc.py:1172-1180 filters nt>31 + the first-slice bit for the decode feed;
// here we additionally *retain* the 32-34 param sets that path handled via
// extradata.)
function includeNal(nal) {
  if (nal.length < 2) return false;
  const nt = nalType(nal);
  if (nt >= 32 && nt <= 34) return true; // VPS / SPS / PPS
  if (nt > 31) return false; // SEI / AUD / EOS / EOB / FD / FU-leftover
  if (nal.length < 3) return false;
  return (nal[2] & 0x80) !== 0; // first_slice_segment_in_pic_flag
}

function isIdrType(nt) {
  return nt >= 16 && nt <= 21; // BLA_W_LP (16) .. CRA_NUT (21)
}

// RTP u32 timestamp "a strictly after b", wraparound-safe.
function tsAfter(a, b) {
  if (a === b) return false;
  return ((a - b) >>> 0) < 0x80000000;
}

// Reassemble one tile's timestamp-ordered payload list into clean NALUs.
// Direct port of nalu.py:28-80. Malformed entries dropped silently (UDP loss
// makes that routine; the decoder errors on what survives).
function reassembleGroup(payloads) {
  const out = [];
  let fuBuf = null;
  let fuActive = false;

  for (const pay of payloads) {
    if (!pay || pay.length < 2) continue;
    const nt = (pay[0] >> 1) & 0x3f;

    if (nt === NAL_AGGREGATION) {
      // header(2) + DONL(2) + [size(2) + data]... ; NO per-unit DOND.
      let pos = 4;
      const n = pay.length;
      while (pos + 2 <= n) {
        const size = pay.readUInt16BE(pos);
        pos += 2;
        if (size === 0 || pos + size > n) break;
        out.push(Buffer.from(pay.subarray(pos, pos + size)));
        pos += size;
      }
    } else if (nt === NAL_FRAGMENTATION) {
      // header(2) + FU_hdr(1) + DONL(2) + payload ; DONL in EVERY fragment.
      if (pay.length < 6) continue;
      const fuHdr = pay[2];
      const start = (fuHdr & 0x80) !== 0;
      const end = (fuHdr & 0x40) !== 0;
      const innerType = fuHdr & 0x3f;
      if (start) {
        // Rebuild the inner NAL header from the FU NAL header: keep F (bit7)
        // and layerId-hi (bit0) from byte0, splice in the real nal_unit_type.
        const hdr0 = (pay[0] & 0x81) | (innerType << 1);
        fuBuf = Buffer.concat([Buffer.from([hdr0, pay[1]]), pay.subarray(5)]);
        fuActive = true;
      } else if (fuActive) {
        fuBuf = Buffer.concat([fuBuf, pay.subarray(5)]);
        if (end) {
          out.push(fuBuf);
          fuBuf = null;
          fuActive = false;
        }
      }
    } else {
      // Single NAL: [0..1] NAL header | [2..3] DONL | [4..] payload.
      if (pay.length < 4) continue;
      out.push(Buffer.concat([pay.subarray(0, 2), pay.subarray(4)]));
    }
  }
  return out;
}

// DONL (16-bit BE decoding-order number) from a group's first packet.
// nalu.py:83-103. FU carries it at [3:5]; single/AP at [2:4].
export function firstDonl(payloads) {
  for (const pay of payloads) {
    if (!pay || pay.length < 2) continue;
    const nt = (pay[0] >> 1) & 0x3f;
    if (nt === NAL_FRAGMENTATION) {
      if (pay.length >= 5) return pay.readUInt16BE(3);
    } else if (pay.length >= 4) {
      return pay.readUInt16BE(2);
    }
  }
  return null;
}

// Order a tile's packets by RTP seq with 16-bit wraparound (burst.py:142-147).
function sortBySeq(packets) {
  if (packets.length <= 1) return packets;
  let min = packets[0].seq;
  let max = packets[0].seq;
  for (const p of packets) {
    if (p.seq < min) min = p.seq;
    if (p.seq > max) max = p.seq;
  }
  if (max - min > 0x8000) {
    const base = min;
    return packets.slice().sort(
      (a, b) => (((a.seq - base) & 0xffff) - ((b.seq - base) & 0xffff)),
    );
  }
  return packets.slice().sort((a, b) => a.seq - b.seq);
}

export class HevcDepacketizer {
  constructor(tileCount = 4) {
    this.tileCount = tileCount;
    // ts -> { ts, t0, tiles: Map<ssrc, {packets:[{seq,payload}]}>, markers:Set<ssrc> }
    this._pending = new Map();
    // Highest RTP ts seen per ssrc — a strictly-newer ts on a tile proves that
    // tile has finished emitting for every older ts (no marker bit in push()).
    this._highestTs = new Map();
    // WebCodecs requires the first chunk after configure() to be a key frame,
    // and Apple emits IDRs on tile 0 only. Drop every AU until the first IDR
    // (mirrors the _dpb_has_idr gate, hevc.py:502-503,662-690).
    this._sawKey = false;
    // Monotonic per-emitted-AU timestamp (mirrors _next_pts, hevc.py:697-703).
    this._nextPts = 0;
    // AUs completed but not yet returned (a stall/timeout flush can complete
    // several at once; push() returns the oldest and queues the rest).
    this._ready = [];
  }

  // Feed one decrypted RTP payload. `marker` (RTP marker bit, optional) is the
  // authoritative "last packet of this tile's AU" signal when available; if
  // omitted the depacketizer falls back to timestamp advancement.
  // Returns the oldest completed AccessUnit, or null.
  push(ssrc, payload, timestamp, seq, marker) {
    ssrc = ssrc >>> 0;
    timestamp = timestamp >>> 0;
    seq &= 0xffff;
    const pay = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);

    if (pay.length >= 2) {
      let group = this._pending.get(timestamp);
      if (!group) {
        group = { ts: timestamp, t0: Date.now(), tiles: new Map(), markers: new Set() };
        this._pending.set(timestamp, group);
      }
      let tile = group.tiles.get(ssrc);
      if (!tile) {
        tile = { packets: [] };
        group.tiles.set(ssrc, tile);
      }
      tile.packets.push({ seq, payload: pay });
      if (marker) group.markers.add(ssrc);
    }

    const prev = this._highestTs.get(ssrc);
    if (prev === undefined || tsAfter(timestamp, prev)) {
      this._highestTs.set(ssrc, timestamp);
    }

    this._collect();
    return this._ready.length ? this._ready.shift() : null;
  }

  // Drain every currently-ready AccessUnit (in emission order).
  drain() {
    this._collect();
    const out = this._ready;
    this._ready = [];
    return out;
  }

  // Move completed (or timed-out) pending frames into _ready, oldest first,
  // preserving strict timestamp order.
  _collect() {
    if (this._pending.size === 0) return;
    const now = Date.now();
    // Sort pending timestamps ascending (wraparound-safe).
    const order = [...this._pending.keys()].sort((a, b) => (tsAfter(a, b) ? 1 : -1));
    const overflow = this._pending.size > MAX_PENDING;

    for (let i = 0; i < order.length; i++) {
      const ts = order[i];
      const group = this._pending.get(ts);
      const complete = this._isComplete(group);
      const stale = now - group.t0 >= FLUSH_TIMEOUT_MS;
      // Force the very oldest out if we're over the buffer cap.
      const forced = overflow && i === 0;

      if (complete || stale || forced) {
        this._pending.delete(ts);
        const au = this._buildAccessUnit(group);
        if (au) this._ready.push(au);
      } else {
        // Cannot emit a newer frame ahead of an incomplete older one.
        break;
      }
    }
  }

  _isComplete(group) {
    if (group.tiles.size < this.tileCount) return false;
    // Marker path: every present tile signalled end-of-AU.
    if (group.markers.size >= this.tileCount) return true;
    // No-marker path: every present tile has advanced to a newer timestamp,
    // which guarantees each tile's contribution to this frame is fully in.
    for (const ssrc of group.tiles.keys()) {
      const hi = this._highestTs.get(ssrc);
      if (hi === undefined || !tsAfter(hi, group.ts)) return false;
    }
    return true;
  }

  // Concatenate this frame's NALs across the 4 tiles in SSRC order (tile 0 =
  // lowest SSRC first), each Annex-B start-code prefixed, into one chunk.
  _buildAccessUnit(group) {
    const ssrcs = [...group.tiles.keys()].sort((a, b) => (a >>> 0) - (b >>> 0));
    const parts = [];
    let isKey = false;

    for (const ssrc of ssrcs) {
      const ordered = sortBySeq(group.tiles.get(ssrc).packets).map((p) => p.payload);
      for (const nal of reassembleGroup(ordered)) {
        if (!includeNal(nal)) continue;
        if (isIdrType(nalType(nal))) isKey = true;
        parts.push(START_CODE, nal);
      }
    }

    if (parts.length === 0) return null;
    // Pre-IDR gate: WebCodecs' first chunk must be key, and Apple only IDRs on
    // tile 0. Drop delta AUs until the first IDR re-roots the shared DPB.
    if (!isKey && !this._sawKey) return null;
    if (isKey) this._sawKey = true;

    const buf = Buffer.concat(parts);
    const pts = this._nextPts++;
    return {
      chunks: new Uint8Array(buf), // owned copy, safe to transfer to the renderer
      isKey,
      timestamp: pts,
      rtpTimestamp: group.ts, // source RTP ts, for the compositor if needed
    };
  }
}

export { reassembleGroup };
export default HevcDepacketizer;
