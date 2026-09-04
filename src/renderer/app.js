// Renderer main thread: connection form, input capture, overlays.
//
// The pixel path never touches this file. Main process -> preload -> here we
// receive one MessagePort via the 'vnc-port' window message and hand it to
// the decode worker. The worker decodes rectangles and ships back finished
// frames as ImageBitmaps, which THIS thread paints onto #screen (a transferred
// OffscreenCanvas does not composite from a worker on Electron/Windows).
//
// Input travels app -> worker -> port -> main process, as:
//   { kind: 'input', type: 'pointer', buttonMask, x, y }
//   { kind: 'input', type: 'key',     down, keysym }
//   { kind: 'input', type: 'cutText', text }

import {
  keysymForDomKey,
  PROFILE_CTRL_AS_CMD,
  PROFILE_NATIVE,
  MODIFIER_KEYSYMS,
} from '../rfb/keysym/index.js';

const form = document.getElementById('conn');
const hostEl = document.getElementById('host');
const portEl = document.getElementById('port');
const userEl = document.getElementById('username');
const passEl = document.getElementById('password');
const profileEl = document.getElementById('keyprofile');
const connectBtn = document.getElementById('connect');
const disconnectBtn = document.getElementById('disconnect');
const rememberEl = document.getElementById('remember');
const autoconnectEl = document.getElementById('autoconnect');
const forgetBtn = document.getElementById('forget');

const stateEl = document.getElementById('state');
const detailEl = document.getElementById('detail');
const resEl = document.getElementById('res');
const fpsEl = document.getElementById('fps');

const stage = document.getElementById('stage');
const cardTitle = document.getElementById('cardtitle');
const cardNote = document.getElementById('cardnote');
const errText = document.getElementById('errtext');

const clipPanel = document.getElementById('clip');
const clipText = document.getElementById('cliptext');
const clipClose = document.getElementById('clipclose');

const PROFILES = new Set([PROFILE_CTRL_AS_CMD, PROFILE_NATIVE]);

let canvas = document.getElementById('screen');

const state = {
  phase: 'idle',
  worker: null,
  canvasTransferred: false,
  remoteW: 0,
  remoteH: 0,
  buttons: 0,
  lastX: 0,
  lastY: 0,
  pressed: new Map(), // event.code -> keysym ACTUALLY SENT
  moveQueued: false,
  pendingMove: null,
};

// ---------------------------------------------------------------- status ---

const PHASE_LABEL = {
  idle: 'Idle',
  connecting: 'Connecting',
  connected: 'Connected',
  disconnected: 'Disconnected',
  error: 'Error',
};

function setPhase(phase, detail, opts) {
  if (phase === 'idle' || phase === 'error' || phase === 'disconnected') {
    document.body.classList.remove('has-screen');
  }
  state.phase = phase;
  document.body.dataset.phase = phase;
  stateEl.textContent = PHASE_LABEL[phase] || phase;
  detailEl.textContent = detail || '';
  detailEl.title = detail || '';

  const busy = phase === 'connecting';
  const live = phase === 'connected';
  connectBtn.disabled = busy || live;
  disconnectBtn.disabled = !busy && !live;

  if (phase === 'error') {
    cardTitle.textContent = 'Connection failed';
    cardNote.textContent = 'The server or the protocol layer reported the following:';
    errText.textContent = detail || '(no message)';
    errText.classList.add('show');
  } else if (phase === 'connecting') {
    cardTitle.textContent = 'Connecting';
    cardNote.textContent = detail || '';
    if (!(opts && opts.keepError)) errText.classList.remove('show');
  } else if (phase === 'disconnected') {
    cardTitle.textContent = 'Disconnected';
    cardNote.textContent = detail || 'The session ended.';
    if (!(opts && opts.keepError)) errText.classList.remove('show');
  } else if (phase === 'idle') {
    cardTitle.textContent = 'Not connected';
    cardNote.textContent = 'Enter the host and credentials above, then press Connect.';
    errText.classList.remove('show');
  }

  if (!live) {
    resEl.textContent = '';
    fpsEl.textContent = '';
  }
}

function errorMessage(err) {
  if (err == null) return 'Unknown error';
  if (typeof err === 'string') return err;
  if (err.stack && err.message) return err.message;
  if (err.message) return err.message;
  return String(err);
}

// -------------------------------------------------------------- worker ----

function currentProfile() {
  const v = profileEl.value;
  return PROFILES.has(v) ? v : PROFILE_CTRL_AS_CMD;
}

function send(msg) {
  if (state.worker) state.worker.postMessage(msg);
}

function sendPointer(mask, x, y) {
  send({ kind: 'input', type: 'pointer', buttonMask: mask, x, y });
}

function sendKey(down, keysym) {
  send({ kind: 'input', type: 'key', down, keysym });
}

function sendCutText(text) {
  send({ kind: 'input', type: 'cutText', text });
}

// The canvas stays on THIS thread. A transferred OffscreenCanvas rendered from
// a worker does not composite on Electron/Windows here (pure black even for a
// direct fillRect), so the worker decodes and ships finished frames back as
// ImageBitmaps, and the main thread - which composites normally - paints them.
function attachWorker(port) {
  destroyWorker();

  const worker = new Worker('./workers/vnc-worker.js', { type: 'module' });
  worker.onmessage = onWorkerMessage;
  worker.onerror = (ev) => {
    setPhase('error', ev && ev.message ? ev.message : 'Decode worker crashed');
  };
  worker.onmessageerror = () => {
    setPhase('error', 'Decode worker received an undeserializable message');
  };
  state.worker = worker;

  worker.postMessage({ port }, [port]);
}

function destroyWorker() {
  if (!state.worker) return;
  state.worker.onmessage = null;
  state.worker.onerror = null;
  state.worker.terminate();
  state.worker = null;
}

/** Blank the remote screen without tearing down the worker's port or canvas. */
function resetWorker() {
  if (!state.worker) return;
  try {
    state.worker.postMessage({ kind: 'reset' });
  } catch {
    /* worker already gone */
  }
}

function onWorkerMessage(ev) {
  const msg = ev.data;
  if (!msg || typeof msg !== 'object') return;

  switch (msg.kind) {
    case 'ready':
      break;

    case 'init':
      state.remoteW = msg.width | 0;
      state.remoteH = msg.height | 0;
      canvas.width = state.remoteW;
      canvas.height = state.remoteH;
      state.ctx = canvas.getContext('2d');
      layout();
      document.body.classList.add('has-screen');
      setPhase('connected', msg.name ? String(msg.name) : '');
      resEl.textContent = `${state.remoteW}x${state.remoteH}`;
      canvas.focus();
      break;

    case 'frame':
      if (state.ctx && msg.bitmap) {
        state.ctx.drawImage(msg.bitmap, msg.x | 0, msg.y | 0);
        msg.bitmap.close();
      }
      break;

    case 'resize':
      state.remoteW = msg.width | 0;
      state.remoteH = msg.height | 0;
      resEl.textContent = `${state.remoteW}x${state.remoteH}`;
      layout();
      break;

    case 'fps':
      fpsEl.textContent = `${msg.fps} fps`;
      break;

    case 'cutText':
      receiveRemoteClipboard(String(msg.text == null ? '' : msg.text));
      break;

    case 'bell':
      stage.classList.remove('bell');
      void stage.offsetWidth;
      stage.classList.add('bell');
      break;

    case 'status':
      applyStatus(msg.state, msg.message);
      break;

    default:
      break;
  }
}

function applyStatus(kind, message) {
  const text = message == null ? '' : String(message);
  switch (kind) {
    case 'error':
    case 'failed':
    case 'authFailed':
      releaseEverything();
      setPhase('error', text || 'Connection failed');
      break;
    case 'closed':
    case 'disconnected':
    case 'ended':
      releaseEverything();
      setPhase('disconnected', text || 'The remote host closed the connection');
      break;
    case 'connected':
      setPhase('connected', text);
      break;
    default:
      // Informational: keep the current phase, surface the text verbatim.
      detailEl.textContent = text;
      detailEl.title = text;
      break;
  }
}

// ------------------------------------------------------------- connect ----

async function doConnect() {
  if (state.phase === 'connecting' || state.phase === 'connected') return;

  const host = hostEl.value.trim();
  const port = Number.parseInt(portEl.value, 10);
  if (!host) {
    setPhase('error', 'Host is required');
    return;
  }
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    setPhase('error', `Invalid port: ${portEl.value}`);
    return;
  }

  // Persist before connecting, so a saved profile survives even a failed attempt.
  if (rememberEl.checked && window.vnc.saveCreds) {
    window.vnc.saveCreds({
      host,
      port,
      username: userEl.value,
      password: passEl.value,
      profile: currentProfile(),
      autoConnect: autoconnectEl.checked,
    });
  }

  setPhase('connecting', `Connecting to ${host}:${port}`);

  if (!window.vnc || typeof window.vnc.connect !== 'function') {
    setPhase('error', 'Preload bridge unavailable: window.vnc.connect is not a function');
    return;
  }

  try {
    await window.vnc.connect({
      host,
      port,
      username: userEl.value,
      password: passEl.value,
    });
  } catch (err) {
    setPhase('error', errorMessage(err));
  }
}

form.addEventListener('submit', (ev) => {
  ev.preventDefault();
  doConnect();
});

forgetBtn.addEventListener('click', async () => {
  if (window.vnc && window.vnc.clearCreds) await window.vnc.clearCreds();
  rememberEl.checked = false;
  autoconnectEl.checked = false;
  passEl.value = '';
});

// Prefill from the saved profile on launch, and auto-connect if asked.
(async () => {
  if (!window.vnc || !window.vnc.loadCreds) return;
  const c = await window.vnc.loadCreds();
  if (!c) return;
  if (c.host) hostEl.value = c.host;
  if (c.port) portEl.value = c.port;
  if (c.username) userEl.value = c.username;
  if (c.password) passEl.value = c.password;
  if (c.profile) profileEl.value = c.profile;
  rememberEl.checked = true;
  autoconnectEl.checked = !!c.autoConnect;
  if (c.autoConnect && c.host) doConnect();
})();

disconnectBtn.addEventListener('click', () => {
  releaseEverything();
  try {
    if (window.vnc && typeof window.vnc.disconnect === 'function') window.vnc.disconnect();
  } catch (err) {
    setPhase('error', errorMessage(err));
    return;
  }
  // Do NOT terminate the worker here. It owns the only MessagePort to the main
  // process and the transferred OffscreenCanvas, and both are minted once per
  // window load - killing it makes every later reconnect decode into nothing.
  resetWorker();
  state.remoteW = 0;
  state.remoteH = 0;
  layout();
  setPhase('disconnected', 'Closed locally');
});

// The preload does: ipcRenderer.on('vnc-port', e => window.postMessage('vnc-port', '*', e.ports))
window.addEventListener('message', (ev) => {
  const d = ev.data;
  const isPortMessage =
    d === 'vnc-port' || (d && typeof d === 'object' && (d.type === 'vnc-port' || d.kind === 'vnc-port'));
  if (!isPortMessage) return;
  if (!ev.ports || ev.ports.length === 0) return;
  attachWorker(ev.ports[0]);
});

// -------------------------------------------------------------- layout ----

function layout() {
  if (!state.remoteW || !state.remoteH) {
    canvas.style.width = '0px';
    canvas.style.height = '0px';
    return;
  }
  const sw = stage.clientWidth;
  const sh = stage.clientHeight;
  if (sw <= 0 || sh <= 0) { requestAnimationFrame(layout); return; }
  const scale = Math.min(sw / state.remoteW, sh / state.remoteH);
  canvas.style.width = `${Math.max(1, Math.round(state.remoteW * scale))}px`;
  canvas.style.height = `${Math.max(1, Math.round(state.remoteH * scale))}px`;
}

new ResizeObserver(layout).observe(stage);
window.addEventListener('resize', layout);

// ------------------------------------------------------------- pointer ----

// Displayed size != remote size: map through the live bounding box.
function mapPoint(ev) {
  if (!state.remoteW || !state.remoteH) return null;
  const r = canvas.getBoundingClientRect();
  if (r.width <= 0 || r.height <= 0) return null;
  const x = Math.floor(((ev.clientX - r.left) / r.width) * state.remoteW);
  const y = Math.floor(((ev.clientY - r.top) / r.height) * state.remoteH);
  return {
    x: Math.min(state.remoteW - 1, Math.max(0, x)),
    y: Math.min(state.remoteH - 1, Math.max(0, y)),
  };
}

function buttonBit(button) {
  // bit0 left, bit1 middle, bit2 right
  if (button === 0) return 1;
  if (button === 1) return 2;
  if (button === 2) return 4;
  return 0;
}

function flushMove() {
  state.moveQueued = false;
  const p = state.pendingMove;
  state.pendingMove = null;
  if (!p || state.phase !== 'connected') return;
  state.lastX = p.x;
  state.lastY = p.y;
  sendPointer(state.buttons, p.x, p.y);
}

function onPointerDown(ev) {
  if (state.phase !== 'connected') return;
  const p = mapPoint(ev);
  if (!p) return;
  ev.preventDefault();
  canvas.focus();
  try {
    canvas.setPointerCapture(ev.pointerId);
  } catch {
    /* capture is best-effort */
  }
  state.buttons |= buttonBit(ev.button);
  state.lastX = p.x;
  state.lastY = p.y;
  sendPointer(state.buttons, p.x, p.y);
}

function onPointerUp(ev) {
  if (state.phase !== 'connected') return;
  const p = mapPoint(ev) || { x: state.lastX, y: state.lastY };
  ev.preventDefault();
  state.buttons &= ~buttonBit(ev.button);
  state.lastX = p.x;
  state.lastY = p.y;
  sendPointer(state.buttons, p.x, p.y);
  try {
    canvas.releasePointerCapture(ev.pointerId);
  } catch {
    /* ignore */
  }
}

function onPointerMove(ev) {
  if (state.phase !== 'connected') return;
  const p = mapPoint(ev);
  if (!p) return;
  state.pendingMove = p;
  if (!state.moveQueued) {
    state.moveQueued = true;
    requestAnimationFrame(flushMove);
  }
}

function onPointerLeave() {
  if (state.phase !== 'connected' || state.buttons === 0) return;
  state.buttons = 0;
  sendPointer(0, state.lastX, state.lastY);
}

function onWheel(ev) {
  if (state.phase !== 'connected') return;
  ev.preventDefault();
  const p = mapPoint(ev) || { x: state.lastX, y: state.lastY };
  state.lastX = p.x;
  state.lastY = p.y;

  // Wheel is a button press/release pair: 3 = up, 4 = down (5/6 horizontal).
  let bit = 0;
  if (ev.deltaY < 0) bit |= 1 << 3;
  else if (ev.deltaY > 0) bit |= 1 << 4;
  if (ev.deltaX < 0) bit |= 1 << 5;
  else if (ev.deltaX > 0) bit |= 1 << 6;
  if (!bit) return;

  sendPointer(state.buttons | bit, p.x, p.y);
  sendPointer(state.buttons, p.x, p.y);
}

function bindCanvas(el) {
  el.addEventListener('pointerdown', onPointerDown);
  el.addEventListener('pointerup', onPointerUp);
  el.addEventListener('pointercancel', onPointerUp);
  el.addEventListener('pointermove', onPointerMove);
  el.addEventListener('pointerleave', onPointerLeave);
  el.addEventListener('wheel', onWheel, { passive: false });
  el.addEventListener('contextmenu', (ev) => ev.preventDefault());
  el.addEventListener('dragstart', (ev) => ev.preventDefault());
}

bindCanvas(canvas);

// ------------------------------------------------------------ keyboard ----

function isTypingTarget(node) {
  if (!node) return false;
  const tag = node.tagName;
  return tag === 'INPUT' || tag === 'SELECT' || tag === 'TEXTAREA' || node.isContentEditable === true;
}

// Ctrl+Shift+V is reserved locally so the browser still fires a 'paste' event,
// which is the only way to read the clipboard without a permission prompt.
function isLocalPasteGesture(ev) {
  return ev.ctrlKey && ev.shiftKey && ev.code === 'KeyV';
}

function onKeyDown(ev) {
  // Fullscreen is a LOCAL concern: F11 or Ctrl+Shift+F toggles it and must
  // never reach the remote, otherwise there is no way back out.
  if (ev.key === 'F11' || (ev.ctrlKey && ev.shiftKey && ev.code === 'KeyF')) {
    ev.preventDefault();
    if (window.vnc && window.vnc.toggleFullscreen) window.vnc.toggleFullscreen();
    return;
  }
  if (state.phase !== 'connected') return;
  if (isTypingTarget(ev.target) || isTypingTarget(document.activeElement)) return;
  if (isLocalPasteGesture(ev)) return;

  // Swallow Tab / arrows / F-keys before the browser acts on them.
  ev.preventDefault();

  const keysym = keysymForDomKey(ev.key, ev.code, currentProfile());
  if (keysym == null) return;

  // Ledger stores the keysym ACTUALLY SENT. Replaying a freshly computed
  // keysym on keyup latches modifiers: Shift+2 presses '@' but would release
  // '2', leaving '@' held down on the remote forever.
  state.pressed.set(ev.code, keysym);
  sendKey(true, keysym);
}

function onKeyUp(ev) {
  if (state.phase !== 'connected') return;
  if (isTypingTarget(ev.target) || isTypingTarget(document.activeElement)) return;
  if (isLocalPasteGesture(ev)) return;

  ev.preventDefault();

  const keysym = state.pressed.get(ev.code);
  if (keysym == null) return;
  state.pressed.delete(ev.code);
  sendKey(false, keysym);
}

function releaseAllKeys() {
  if (state.pressed.size === 0) return;
  for (const keysym of state.pressed.values()) sendKey(false, keysym);
  state.pressed.clear();
}

function releaseAllButtons() {
  if (state.buttons === 0) return;
  state.buttons = 0;
  sendPointer(0, state.lastX, state.lastY);
}

function releaseEverything() {
  releaseAllKeys();
  releaseAllButtons();
}

// A blur can be swallowed entirely (UAC prompt, lock screen), so on regaining
// focus sweep every modifier up unconditionally.
function sweepModifiers() {
  if (state.phase !== 'connected') return;
  for (const keysym of MODIFIER_KEYSYMS) sendKey(false, keysym);
}

window.addEventListener('keydown', onKeyDown);
window.addEventListener('keyup', onKeyUp);
window.addEventListener('blur', releaseEverything);
window.addEventListener('focus', sweepModifiers);
window.addEventListener('beforeunload', releaseEverything);
document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'hidden') releaseEverything();
});

// ------------------------------------------------------------ clipboard ---

window.addEventListener('paste', (ev) => {
  if (state.phase !== 'connected') return;
  if (isTypingTarget(document.activeElement)) return;
  const text = ev.clipboardData ? ev.clipboardData.getData('text/plain') : '';
  if (!text) return;
  ev.preventDefault();
  sendCutText(text);
});

function receiveRemoteClipboard(text) {
  if (!text) return;
  const writer = navigator.clipboard && navigator.clipboard.writeText;
  if (!writer || !document.hasFocus()) {
    showClipboardPanel(text);
    return;
  }
  navigator.clipboard.writeText(text).catch(() => showClipboardPanel(text));
}

function showClipboardPanel(text) {
  clipText.textContent = text;
  clipPanel.hidden = false;
}

clipClose.addEventListener('click', () => {
  clipPanel.hidden = true;
  clipText.textContent = '';
});

// ---------------------------------------------------------------- boot ----

setPhase('idle', '');
layout();
