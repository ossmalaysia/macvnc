import { FrameMetrics } from '../rfb/metrics.js';

// Each screen band (tile) is an INDEPENDENT HEVC stream, so it gets its own
// VideoDecoder. Decoded tile frames are composited vertically by tile index.
const metrics = new FrameMetrics({ stallMs: 100 });
const canvas = document.getElementById('screen');
const ctx = canvas.getContext('2d');
const hud = document.getElementById('hud');

let decErrors = 0, fed = 0, painted = 0;
let tileW = 0, tileH = 0, tiles = 4;

// One decoder + gotKey flag per tile index.
const decoders = new Map(); // tileIdx -> { decoder, gotKey }

function sizeCanvas() {
  const w = tileW, h = tileH * tiles;
  if (w > 0 && (canvas.width !== w || canvas.height !== h)) {
    canvas.width = w;
    canvas.height = h;
  }
}

function decoderFor(tileIdx) {
  let d = decoders.get(tileIdx);
  if (d && d.decoder.state !== 'closed') return d;
  const decoder = new VideoDecoder({
    output: (frame) => {
      // First frame of any tile sets the tile geometry.
      if (frame.displayWidth !== tileW || frame.displayHeight !== tileH) {
        tileW = frame.displayWidth;
        tileH = frame.displayHeight;
        sizeCanvas();
      }
      ctx.drawImage(frame, 0, tileIdx * tileH);
      frame.close();
      painted++;
      // Count a "source frame" once per tiles paints (approximate pacing).
      if (painted % tiles === 0) metrics.onFrame(performance.now());
    },
    error: (e) => { decErrors++; metrics.onDropped(1); hud.textContent = 'decoder error: ' + e.message; },
  });
  try {
    decoder.configure({ codec: 'hev1.4.10.L153.90', optimizeForLatency: true, hardwareAcceleration: 'no-preference' });
  } catch (e) { hud.textContent = 'configure failed: ' + e.message; }
  d = { decoder, gotKey: false };
  decoders.set(tileIdx, d);
  return d;
}

function onAu(au) {
  if (!au || !au.chunks) return;
  if (typeof au.tiles === 'number' && au.tiles > 0) tiles = au.tiles;
  const tileIdx = au.tileIdx | 0;
  const d = decoderFor(tileIdx);
  if (!d.gotKey && !au.isKey) return; // each tile must start on its own keyframe
  if (au.isKey) d.gotKey = true;
  try {
    d.decoder.decode(new EncodedVideoChunk({
      type: au.isKey ? 'key' : 'delta',
      timestamp: (au.timestamp >>> 0),
      data: au.chunks,
    }));
    fed++;
  } catch (e) { decErrors++; hud.textContent = 'decode threw: ' + e.message; }
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
  document.title = `HP fed=${fed} painted=${painted} dec=${decoders.size} err=${decErrors} ${tileW}x${tileH}`;
  hud.textContent =
    `HP HEVC  ${tileW}x${tileH * tiles}  (${tiles} tiles of ${tileW}x${tileH})\n` +
    `${m.fps.toFixed(1)} fps  p50 ${m.p50.toFixed(0)}ms  p95 ${m.p95.toFixed(0)}ms  jitter ${m.jitter.toFixed(0)}ms  stalls ${m.stalls}\n` +
    `fed ${fed}  painted ${painted}  decoders ${decoders.size}  errors ${decErrors}` +
    (hud.dataset.status ? `\n${hud.dataset.status}` : '');
}, 250);
