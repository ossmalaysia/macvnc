// Decode worker: owns the OffscreenCanvas and the RGBA framebuffer.
//
// Receives { port, canvas } once. Compressed rectangle payloads arrive on the
// port straight from the main process, are decoded here, and are painted once
// per animation frame from a single dirty bounding box.

import { decodeRect } from '../../rfb/decoders/index.js';
import { createInflateContext } from '../../rfb/inflate/streams.js';
import { CANVAS_PIXEL_FORMAT } from '../../rfb/protocol/pixel-format.js';

const MAX_REPORTED_DECODE_ERRORS = 32;

let port = null;

let fb = null; // Uint8ClampedArray, fbW * fbH * 4
let image = null; // ImageData over fb
let fbW = 0;
let fbH = 0;

// The two inflate streams are created ONCE per connection and never reset:
// zlib/ZRLE compression state spans rectangles and updates.
let decodeCtx = null;

let dirty = false;
let dx0 = 0;
let dy0 = 0;
let dx1 = 0;
let dy1 = 0;

let frameHandle = 0;
let framesPainted = 0;
let fpsWindowStart = 0;
let decodeErrorsReported = 0;

const raf =
  typeof requestAnimationFrame === 'function'
    ? requestAnimationFrame
    : (cb) => setTimeout(() => cb(now()), 16);

function now() {
  return typeof performance !== 'undefined' ? performance.now() : Date.now();
}

// ------------------------------------------------------------ framebuffer -

function allocate(width, height) {
  const w = Math.max(1, width | 0);
  const h = Math.max(1, height | 0);
  const next = new Uint8ClampedArray(w * h * 4);
  for (let i = 3; i < next.length; i += 4) next[i] = 255;

  if (fb) {
    const copyW = Math.min(w, fbW);
    const copyH = Math.min(h, fbH);
    for (let y = 0; y < copyH; y++) {
      next.set(fb.subarray(y * fbW * 4, y * fbW * 4 + copyW * 4), y * w * 4);
    }
  }

  fb = next;
  fbW = w;
  fbH = h;
  image = new ImageData(fb, fbW, fbH);

  dirty = false;
  markDirty(0, 0, fbW, fbH);
  scheduleFrame();
}

function markDirty(x, y, w, h) {
  const x0 = Math.max(0, x | 0);
  const y0 = Math.max(0, y | 0);
  const x1 = Math.min(fbW, x0 + (w | 0));
  const y1 = Math.min(fbH, y0 + (h | 0));
  if (x1 <= x0 || y1 <= y0) return;

  if (!dirty) {
    dx0 = x0;
    dy0 = y0;
    dx1 = x1;
    dy1 = y1;
    dirty = true;
    return;
  }
  if (x0 < dx0) dx0 = x0;
  if (y0 < dy0) dy0 = y0;
  if (x1 > dx1) dx1 = x1;
  if (y1 > dy1) dy1 = y1;
}

function scheduleFrame() {
  if (frameHandle) return;
  frameHandle = raf(paint) || 1;
}

function paint() {
  frameHandle = 0;
  if (!dirty || !image) return;

  const x = dx0;
  const y = dy0;
  const w = dx1 - dx0;
  const h = dy1 - dy0;
  dirty = false;
  if (w <= 0 || h <= 0) return;

  // Cut out just the dirty region and hand it to the main thread, which owns
  // the visible canvas. createImageBitmap is async; the transfer is zero-copy.
  createImageBitmap(image, x, y, w, h)
    .then((bitmap) => {
      self.postMessage({ kind: 'frame', bitmap, x, y }, [bitmap]);
    })
    .catch((err) => report('error', 'createImageBitmap failed: ' + (err && err.message)));

  framesPainted++;
  const t = now();
  if (fpsWindowStart === 0) {
    fpsWindowStart = t;
  } else if (t - fpsWindowStart >= 1000) {
    const fps = Math.round((framesPainted * 1000) / (t - fpsWindowStart));
    framesPainted = 0;
    fpsWindowStart = t;
    self.postMessage({ kind: 'fps', fps });
  }
}

// --------------------------------------------------------------- status ---

function report(stateName, message) {
  const envelope = { kind: 'status', state: stateName, message };
  self.postMessage(envelope);
  if (port) {
    try {
      port.postMessage(envelope);
    } catch {
      /* port already closed */
    }
  }
}

// ------------------------------------------------------------- envelopes --

function onEnvelope(ev) {
  const msg = ev.data;
  if (!msg || typeof msg !== 'object') return;

  switch (msg.kind) {
    case 'init':
      // A new RFB connection starts brand-new zlib/ZRLE streams on the server.
      // These inflaters carry state across every rectangle of a connection, so
      // reusing the previous connection's pair makes the first reconnect
      // rectangle fail with "incorrect header check" and poisons all the rest.
      decodeCtx = { inflate: createInflateContext() };
      decodeErrorsReported = 0;
      allocate(msg.width, msg.height);
      self.postMessage({ kind: 'init', width: fbW, height: fbH, name: msg.name });
      break;

    case 'resize':
      if (!fb) {
        allocate(msg.width, msg.height);
      } else if ((msg.width | 0) !== fbW || (msg.height | 0) !== fbH) {
        allocate(msg.width, msg.height);
      }
      self.postMessage({ kind: 'resize', width: fbW, height: fbH });
      break;

    case 'rect':
      onRect(msg);
      break;

    case 'updateDone':
      scheduleFrame();
      break;

    case 'status':
      self.postMessage({ kind: 'status', state: msg.state, message: msg.message });
      break;

    default:
      // cutText, bell and anything else the main thread should see.
      self.postMessage(msg);
      break;
  }
}

function onRect(msg) {
  if (!fb) {
    report('error', 'Rectangle arrived before the framebuffer was initialised');
    return;
  }
  const rect = { x: msg.x | 0, y: msg.y | 0, w: msg.w | 0, h: msg.h | 0 };
  try {
    decodeRect(msg.encoding, msg.payload, rect, CANVAS_PIXEL_FORMAT, fb, fbW, fbH, decodeCtx);
  } catch (err) {
    if (decodeErrorsReported < MAX_REPORTED_DECODE_ERRORS) {
      decodeErrorsReported++;
      const detail = err && err.message ? err.message : String(err);
      const tail =
        decodeErrorsReported === MAX_REPORTED_DECODE_ERRORS ? ' (further decode errors suppressed)' : '';
      report(
        'error',
        `Decode failed: encoding ${msg.encoding} rect ${rect.w}x${rect.h}+${rect.x}+${rect.y}: ${detail}${tail}`,
      );
    }
    return;
  }
  markDirty(rect.x, rect.y, rect.w, rect.h);
  scheduleFrame();
}

// ---------------------------------------------------------------- attach --

function attach(data) {
  port = data.port;

  decodeCtx = { inflate: createInflateContext() };

  port.onmessage = onEnvelope;
  port.onmessageerror = () => report('error', 'Undeserializable envelope on the RFB port');
  if (typeof port.start === 'function') port.start();

  port.postMessage({ kind: 'ready' });
  self.postMessage({ kind: 'ready' });
}

self.onmessage = (ev) => {
  const data = ev.data;
  if (!data || typeof data !== 'object') return;

  if (!port && data.port) {
    attach(data);
    return;
  }

  // Disconnect: blank the screen and drop stale stream state, but keep the port
  // and canvas so the next connection can reuse them.
  if (data.kind === 'reset') {
    decodeCtx = { inflate: createInflateContext() };
    decodeErrorsReported = 0;
    if (fb) {
      fb.fill(0);
      for (let i = 3; i < fb.length; i += 4) fb[i] = 255;
      markDirty(0, 0, fbW, fbH);
      scheduleFrame();
    }
    return;
  }

  // Input from the renderer main thread, relayed verbatim to the session.
  if (data.kind === 'input' && port) {
    try {
      port.postMessage(data);
    } catch {
      /* port already closed */
    }
  }
};
