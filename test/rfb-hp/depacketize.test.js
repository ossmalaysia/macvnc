import test from 'node:test';
import assert from 'node:assert/strict';
import { HevcDepacketizer } from '../../src/rfb-hp/depacketize.js';

// --- Synthetic Apple-flavoured RTP payload builders -------------------------
// Single-NAL layout (nalu.py:28-80): [nal hdr(2)][DONL(2)][payload...].
// The first payload byte carries first_slice_segment_in_pic_flag (0x80), which
// includeNal() requires for a VCL NAL to be forwarded.
function singleNal(nalType, body) {
  return Buffer.concat([Buffer.from([nalType << 1, 1, 0x00, 0x00]), body]);
}
const IDR = 19;   // IDR_W_RADL
const TRAIL = 1;  // TRAIL_R (P-frame)
const slice = (tag) => Buffer.from([0x80, tag, 0x5a]);

// Ascending SSRCs == ascending tile index (burst.py:98-99).
const SSRC = [0x1000, 0x1001, 0x1002, 0x1003];

function pushFrame(d, ts, { keyTile = -1 } = {}) {
  const out = [];
  for (let t = 0; t < 4; t++) {
    const nt = t === keyTile ? IDR : TRAIL;
    const au = d.push(SSRC[t], singleNal(nt, slice(t)), ts, ts * 4 + t, true);
    if (au) out.push(...(Array.isArray(au) ? au : [au]));
  }
  return out;
}

test('emits one access unit per tile, tagged with its tile index', () => {
  const d = new HevcDepacketizer(4);
  // Apple emits the IDR on tile 0 only; tiles 1-3 are P-frames from the start.
  const first = pushFrame(d, 1000, { keyTile: 0 }).concat(d.drain({ flush: true }));

  assert.equal(first.length, 4, 'all four tiles must reach the decoder');
  assert.deepEqual(first.map((a) => a.tileIdx), [0, 1, 2, 3]);
  assert.deepEqual(first.map((a) => a.isKey), [true, false, false, false]);
});

test('one access unit carries exactly one picture', () => {
  const d = new HevcDepacketizer(4);
  const aus = pushFrame(d, 1000, { keyTile: 0 }).concat(d.drain({ flush: true }));
  // Exactly one Annex-B start code per AU => exactly one NAL => one picture.
  for (const au of aus) {
    let starts = 0;
    for (let i = 0; i + 3 < au.chunks.length; i++) {
      if (au.chunks[i] === 0 && au.chunks[i + 1] === 0 &&
          au.chunks[i + 2] === 0 && au.chunks[i + 3] === 1) starts++;
    }
    assert.equal(starts, 1, `tile ${au.tileIdx} bundled ${starts} pictures into one chunk`);
  }
});

test('a single IDR on tile 0 opens the gate for every tile', () => {
  const d = new HevcDepacketizer(4);
  pushFrame(d, 1000, { keyTile: 0 });
  d.drain({ flush: true });
  // Later frames are pure P-frames on every tile. Apple architecturally never
  // sends IDRs for tiles 1-3 (hevc.py:645), so a per-tile gate would starve them.
  const second = pushFrame(d, 2000).concat(d.drain({ flush: true }));
  assert.equal(second.length, 4);
  assert.deepEqual(second.map((a) => a.tileIdx), [0, 1, 2, 3]);
});

test('drops P-frames until the first IDR lands', () => {
  const d = new HevcDepacketizer(4);
  const pre = pushFrame(d, 1000).concat(d.drain({ flush: true }));
  assert.equal(pre.length, 0, 'pre-IDR P-frames must not reach the decoder');
  const post = pushFrame(d, 2000, { keyTile: 0 }).concat(d.drain({ flush: true }));
  assert.equal(post.length, 4);
});

test('presentation timestamps are unique and monotonic', () => {
  const d = new HevcDepacketizer(4);
  const aus = pushFrame(d, 1000, { keyTile: 0 }).concat(d.drain({ flush: true }))
    .concat(pushFrame(d, 2000)).concat(d.drain({ flush: true }));
  const ts = aus.map((a) => a.timestamp);
  assert.equal(new Set(ts).size, ts.length, 'PTS must be unique to route frames back to tiles');
  for (let i = 1; i < ts.length; i++) assert.ok(ts[i] > ts[i - 1]);
});

test('emits in (timestamp, tile) order even when tiles arrive interleaved', () => {
  // Four independent UDP streams do not arrive in feed order. Apple's stream
  // has cross-tile POC references (hevc.py:1-24), so a picture decoded ahead of
  // the one it references corrupts exactly the regions that are changing.
  let clock = 0;
  const d = new HevcDepacketizer(4, { now: () => clock });
  pushFrame(d, 1000, { keyTile: 0 });
  d.drain({ flush: true });

  // ts 2000 tile 3 and ts 1500 tile 1 arrive before ts 1500 tile 0.
  const order = [[2000, 3], [1500, 1], [1500, 0], [2000, 0]];
  for (const [ts, t] of order) {
    d.push(SSRC[t], singleNal(TRAIL, slice(t)), ts, ts * 4 + t, true);
  }
  clock += 100; // expire the reorder window
  const out = d.drain({ flush: true });

  const got = out.map((a) => `${a.rtpTimestamp}/${a.tileIdx}`);
  assert.deepEqual(got, ['1500/0', '1500/1', '2000/0', '2000/3']);
  // PTS must still be monotonic in emission order, since it routes frames.
  const pts = out.map((a) => a.timestamp);
  for (let i = 1; i < pts.length; i++) assert.ok(pts[i] > pts[i - 1]);
});
