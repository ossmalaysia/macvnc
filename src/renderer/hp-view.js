import { FrameMetrics } from '../rfb/metrics.js';

// ONE VideoDecoder for the whole session, fed every tile's access units.
//
// Apple's HP stream has cross-tile POC references: a P-frame in tile N can
// reference a picture decoded in tile M != N. Per-tile decoders give each tile
// its own DPB, so those references resolve to nothing and the picture is
// garbage (hevc.py:1-24). The decoder is therefore shared, and each decoded
// frame is routed back to its band via the PTS we attached on input
// (hevc.py:697-703 -> _pts_to_tile, hevc.py:759).
const metrics = new FrameMetrics({ stallMs: 100 });
const canvas = document.getElementById('screen');
const ctx = canvas.getContext('2d');
const hud = document.getElementById('hud');

let decErrors = 0, fed = 0, painted = 0, unrouted = 0;
let tileW = 0, tileH = 0, tiles = 4;
let decoder = null, configured = false;

// pts -> tileIdx. Bounded: an output frame always follows its input closely, so
// anything older than this many entries is unroutable anyway.
const ptsToTile = new Map();
const PTS_MAP_MAX = 512;

function sizeCanvas() {
  const w = tileW, h = tileH * tiles;
  if (w > 0 && (canvas.width !== w || canvas.height !== h)) {
    canvas.width = w;
    canvas.height = h;
  }
}

function onFrame(frame) {
  // Route by PTS: the decoder emits tile pictures, not full frames.
  const tileIdx = ptsToTile.get(frame.timestamp);
  if (tileIdx === undefined) {
    unrouted++;
    frame.close();
    return;
  }
  ptsToTile.delete(frame.timestamp);

  if (frame.displayWidth !== tileW || frame.displayHeight !== tileH) {
    tileW = frame.displayWidth;
    tileH = frame.displayHeight;
    sizeCanvas();
  }
  ctx.drawImage(frame, 0, tileIdx * tileH);
  frame.close();
  painted++;
  // One source frame == one picture per tile, so pace on tile 0's arrivals.
  if (tileIdx === 0) metrics.onFrame(performance.now());
}

function ensureDecoder() {
  if (decoder && decoder.state !== 'closed') return decoder;
  decoder = new VideoDecoder({
    output: onFrame,
    error: (e) => {
      decErrors++;
      metrics.onDropped(1);
      hud.dataset.err = 'decoder error: ' + e.message;
    },
  });
  configured = false;
  return decoder;
}

function onAu(au) {
  if (!au || !au.chunks) return;
  if (typeof au.tiles === 'number' && au.tiles > 0) tiles = au.tiles;
  const d = ensureDecoder();

  if (!configured) {
    // WebCodecs requires the first chunk after configure() to be a keyframe.
    // The depacketizer's global pre-IDR gate guarantees the first AU it emits
    // is tile 0's IDR, so configure lazily on that first key AU.
    if (!au.isKey) return;
    try {
      d.configure({
        codec: 'hev1.4.10.L153.90',
        optimizeForLatency: true,
        hardwareAcceleration: 'no-preference',
      });
      configured = true;
    } catch (e) {
      hud.dataset.err = 'configure failed: ' + e.message;
      return;
    }
  }

  ptsToTile.set(au.timestamp >>> 0, au.tileIdx | 0);
  if (ptsToTile.size > PTS_MAP_MAX) {
    // Drop the oldest insertions; Map preserves insertion order.
    const excess = ptsToTile.size - PTS_MAP_MAX;
    let n = 0;
    for (const k of ptsToTile.keys()) {
      ptsToTile.delete(k);
      if (++n >= excess) break;
    }
  }

  try {
    d.decode(new EncodedVideoChunk({
      type: au.isKey ? 'key' : 'delta',
      timestamp: au.timestamp >>> 0,
      data: au.chunks,
    }));
    fed++;
  } catch (e) {
    decErrors++;
    hud.dataset.err = 'decode threw: ' + e.message;
  }
}

window.addEventListener('message', (ev) => {
  const d = ev.data;
  if (!d || typeof d !== 'object') return;
  if (d.type === 'hp-au') onAu(d.au);
  else if (d.type === 'hp-status') hud.dataset.status = d.text;
});

window.__hpstate = { loaded: true };
setInterval(() => {
  const m = metrics.summary();
  // Electron 44 no longer fires the console-message bridge to the main
  // process, so the document title carries the diagnostics instead.
  document.title = `HP fed=${fed} painted=${painted} unrouted=${unrouted} `
    + `err=${decErrors} ${tileW}x${tileH} fps=${m.fps.toFixed(1)} `
    + `p50=${m.p50.toFixed(0)} p95=${m.p95.toFixed(0)} p99=${m.p99.toFixed(0)} `
    + `max=${m.max.toFixed(0)} jit=${m.jitter.toFixed(0)} stalls=${m.stalls}`;
  hud.textContent =
    `HP HEVC  ${tileW}x${tileH * tiles}  (${tiles} tiles of ${tileW}x${tileH})\n`
    + `${m.fps.toFixed(1)} fps  p50 ${m.p50.toFixed(0)}ms  p95 ${m.p95.toFixed(0)}ms  `
    + `jitter ${m.jitter.toFixed(0)}ms  stalls ${m.stalls}\n`
    + `fed ${fed}  painted ${painted}  unrouted ${unrouted}  errors ${decErrors}`
    + (hud.dataset.status ? `\n${hud.dataset.status}` : '')
    + (hud.dataset.err ? `\n${hud.dataset.err}` : '');
}, 250);
