// HEVC RTP depacketizer for Apple "High Performance" screen sharing.
//
// Turns SRTP-decrypted RTP payloads (4 SSRC tile streams) into PER-TILE HEVC
// access units, each tagged with its tile index, for ONE shared VideoDecoder.
//
// Architecture (hevc.py:1-24) — the part that is easy to get wrong twice:
//   Apple's stream has cross-tile POC references: a P-frame in tile N may
//   reference a POC assigned to a picture in tile M != N. Giving each tile its
//   own decoder gives each tile its own DPB, so those references resolve to
//   nothing and the output is garbage. The ONLY correct architecture is a
//   single decoder fed all tiles' access units in (timestamp, tile) arrival
//   order, with output frames routed back to their tile via the PTS attached
//   on input (hevc.py:697-703 -> _pts_to_tile; hevc.py:759).
//
//   Equally, the four tiles must NOT be concatenated into one chunk: each
//   tile's slice sets first_slice_segment_in_pic_flag, so the decoder sees N
//   separate pictures and emits N frames for one chunk. One AU == one tile.
//
// Ported from the Python reference:
//   - nalu.py:28-80    reassemble_group() — AP/FU/single-NAL byte layout plus
//                      Apple's RFC 7798 DONL deviation.
//   - nalu.py:83-103   first_donl() — DONL offset per structure.
//   - burst.py:94-103  ssrc_to_tile — ascending SSRC == ascending tile index.
//   - burst.py:128-133 AU completion gated on the RTP marker bit.
//   - hevc.py:653-670  "an IDR arriving for ANY tile resets the DPB for ALL
//                      tiles" — the pre-IDR gate is GLOBAL, never per-tile.
//                      Apple architecturally never emits IDRs for tiles 1-3
//                      (hevc.py:645-652), so a per-tile gate starves them.
//   - hevc.py:692-699  Annex-B start-code packetization.
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

// Flush an access unit whose marker packet was lost, so UDP loss on one tile
// cannot wedge that tile forever.
const FLUSH_TIMEOUT_MS = 200;
// Hard cap on in-flight (ssrc, ts) groups; forces the oldest out.
const MAX_PENDING = 32;
// How long to wait for the full SSRC group before trusting tile indices. Tile
// index is assigned by ascending SSRC, so a tile seen before its lower-numbered
// siblings would be mis-indexed; the IDR burst carries all tiles well inside
// this window (burst.py waits for the primary SSRC group the same way).
const TILE_MAP_GRACE_MS = 750;
// How long a completed access unit waits in the reorder buffer for its
// same-timestamp siblings. The four tiles are independent UDP streams, so they
// arrive interleaved; hevc.py:3-4 requires them fed in (timestamp, tile) order
// because cross-tile POC references break if a picture is decoded before the
// one it references. One frame interval at 60fps is ~17ms, so this window
// reorders within a frame without adding a frame of latency.
const REORDER_WINDOW_MS = 40;

function nalType(buf) {
  // HEVC 6-bit nal_unit_type: byte0 >> 1 & 0x3F.
  return (buf[0] >> 1) & 0x3f;
}

// True if this NAL should ride in the WebCodecs chunk. Keeps VPS/SPS/PPS
// (32-34, needed in-band before the IDR) and single-slice VCL NALs; drops SEI/
// AUD/EOS/EOB/FD (35-40+) and slices missing first_slice_segment_in_pic_flag.
// (hevc.py:1172-1180.)
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

// Reassemble one tile's sequence-ordered payload list into clean NALUs.
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
  constructor(tileCount = 4, { now = () => Date.now() } = {}) {
    this.tileCount = tileCount;
    this._now = now;
    // "ssrc:ts" -> { ssrc, ts, t0, packets: [{seq,payload}], marker }
    this._pending = new Map();
    // Highest RTP ts seen per ssrc — a strictly-newer ts on a tile proves that
    // tile finished emitting for every older ts, even if its marker was lost.
    this._highestTs = new Map();
    // Ascending SSRC == ascending tile index (burst.py:98-99).
    this._ssrcs = [];
    this._tileOf = new Map();
    this._firstSeenAt = null;
    // GLOBAL pre-IDR gate. Apple emits IDRs on tile 0 only; an IDR on ANY tile
    // re-roots the shared DPB for ALL tiles (hevc.py:653-670). A per-tile gate
    // waits forever for IDRs tiles 1-3 never receive.
    this._sawKey = false;
    // Monotonic per-emitted-AU PTS. The renderer maps pts -> tileIdx to route
    // each decoded frame back to its band (hevc.py:697-703).
    this._nextPts = 0;
    // Completed-but-unordered AUs, awaiting their same-timestamp siblings.
    this._reorder = [];
    this._newestCompleteTs = null;
    this._ready = [];
  }

  // Assign/refresh tile indices from the SSRCs seen so far.
  _noteSsrc(ssrc) {
    if (this._tileOf.has(ssrc)) return;
    this._ssrcs.push(ssrc);
    this._ssrcs.sort((a, b) => a - b);
    this._tileOf.clear();
    this._ssrcs.forEach((s, i) => this._tileOf.set(s, i));
  }

  // True once tile indices can be trusted: either the whole SSRC group is
  // known, or the grace window expired (a display with fewer bands).
  _tileMapSettled() {
    if (this._ssrcs.length >= this.tileCount) return true;
    return this._firstSeenAt !== null
      && this._now() - this._firstSeenAt >= TILE_MAP_GRACE_MS;
  }

  // Feed one decrypted RTP payload. `marker` (RTP marker bit) is the
  // authoritative end-of-access-unit signal (burst.py:128-133); without it the
  // depacketizer falls back to timestamp advancement, one frame later.
  // Returns the oldest ready AccessUnit, or null. Use drain() for the rest.
  push(ssrc, payload, timestamp, seq, marker) {
    ssrc = ssrc >>> 0;
    timestamp = timestamp >>> 0;
    seq &= 0xffff;
    const pay = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);

    if (this._firstSeenAt === null) this._firstSeenAt = this._now();
    this._noteSsrc(ssrc);

    if (pay.length >= 2) {
      const key = `${ssrc}:${timestamp}`;
      let group = this._pending.get(key);
      if (!group) {
        group = { ssrc, ts: timestamp, t0: this._now(), packets: [], marker: false };
        this._pending.set(key, group);
      }
      group.packets.push({ seq, payload: pay });
      if (marker) group.marker = true;
    }

    const prev = this._highestTs.get(ssrc);
    if (prev === undefined || tsAfter(timestamp, prev)) {
      this._highestTs.set(ssrc, timestamp);
    }

    this._collect();
    return this._ready.length ? this._ready.shift() : null;
  }

  // Drain every currently-ready AccessUnit, in emission order. Pass
  // { flush: true } at teardown to also release AUs still inside their reorder
  // window; during streaming the window must be respected or ordering breaks.
  drain({ flush = false } = {}) {
    this._collect();
    if (flush) this._release(this._now(), true);
    const out = this._ready;
    this._ready = [];
    return out;
  }

  // Move completed (or timed-out) groups into _ready. Emission is in arrival
  // order, which is naturally (timestamp, tile) interleaved — the same order
  // the reference's RX threads enqueue in (session.py:588).
  _collect() {
    if (this._pending.size === 0 || !this._tileMapSettled()) return;
    const now = this._now();
    const overflow = this._pending.size > MAX_PENDING;
    let oldestKey = null;
    let oldestT0 = Infinity;
    for (const [key, group] of this._pending) {
      if (group.t0 < oldestT0) { oldestT0 = group.t0; oldestKey = key; }
    }

    for (const [key, group] of [...this._pending]) {
      const hi = this._highestTs.get(group.ssrc);
      const advanced = hi !== undefined && tsAfter(hi, group.ts);
      const stale = now - group.t0 >= FLUSH_TIMEOUT_MS;
      const forced = overflow && key === oldestKey;

      if (group.marker || advanced || stale || forced) {
        this._pending.delete(key);
        const au = this._buildAccessUnit(group);
        if (au) {
          au._t = now;
          this._reorder.push(au);
          if (this._newestCompleteTs === null || tsAfter(au.rtpTimestamp, this._newestCompleteTs)) {
            this._newestCompleteTs = au.rtpTimestamp;
          }
        }
      }
    }
    this._release(now);
  }

  // Move AUs out of the reorder buffer into _ready, strictly ordered by
  // (rtpTimestamp, tileIdx) — the feed order hevc.py:3-4 requires. An AU is
  // eligible once a strictly newer timestamp has completed (so no earlier
  // sibling can still arrive) or its reorder window expired.
  _release(now, flush = false) {
    if (this._reorder.length === 0) return;
    const eligible = [];
    const held = [];
    for (const au of this._reorder) {
      if (flush || now - au._t >= REORDER_WINDOW_MS) eligible.push(au);
      else held.push(au);
    }
    if (eligible.length === 0) return;
    this._reorder = held;
    eligible.sort((a, b) => (a.rtpTimestamp === b.rtpTimestamp
      ? a.tileIdx - b.tileIdx
      : (tsAfter(a.rtpTimestamp, b.rtpTimestamp) ? 1 : -1)));
    for (const au of eligible) {
      // PTS is assigned at release, not at build, so it stays monotonic in
      // emission order — the renderer's pts -> tile map depends on that.
      au.timestamp = this._nextPts++;
      delete au._t;
      this._ready.push(au);
    }
  }

  // Build ONE tile's access unit: its NALs, Annex-B framed, in a single chunk.
  _buildAccessUnit(group) {
    const ordered = sortBySeq(group.packets).map((p) => p.payload);
    const parts = [];
    let isKey = false;

    for (const nal of reassembleGroup(ordered)) {
      if (!includeNal(nal)) continue;
      if (isIdrType(nalType(nal))) isKey = true;
      parts.push(START_CODE, nal);
    }

    if (parts.length === 0) return null;
    // Global pre-IDR gate: WebCodecs' first chunk must be a keyframe, and no
    // tile's P-frames are decodable until an IDR has rooted the shared DPB.
    if (!isKey && !this._sawKey) return null;
    if (isKey) this._sawKey = true;

    const buf = Buffer.concat(parts);
    return {
      chunks: new Uint8Array(buf), // owned copy, safe to transfer to the renderer
      isKey,
      tileIdx: this._tileOf.get(group.ssrc) ?? 0,
      tiles: Math.max(this._ssrcs.length, 1),
      timestamp: 0,            // assigned at release; routes frames to tiles
      rtpTimestamp: group.ts,
    };
  }
}

export { reassembleGroup };
export default HevcDepacketizer;
