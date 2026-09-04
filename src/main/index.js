import { app, BrowserWindow, ipcMain, MessageChannelMain } from 'electron';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomFillSync } from 'node:crypto';
import { RfbSession } from '../rfb/rfb-session.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const DEFAULT_PORT = 5900;
// Preferred first. -223 DesktopSize / -224 LastRect are pseudo-encodings.
const DEFAULT_ENCODINGS = [16, 6, 1, 0, -223, -224];

const ECONNREFUSED_HELP =
  'no VNC server listening - if the Mac just rebooted with FileVault on, ' +
  'screensharingd does not start until someone unlocks it locally';

/** Injected into RfbSession so src/rfb/** never touches node:crypto itself. */
function randomBytes(n) {
  const out = new Uint8Array(n);
  randomFillSync(out);
  return out;
}

let win = null;
let port1 = null;
let socket = null;
let session = null;
let sawAuthFailure = false;
let authFailureReason = '';

// Electron's MessagePortMain has historically accepted only MessagePortMain in its
// transfer list. Probe once: if ArrayBuffer transfer throws, fall back to
// structured-clone copies rather than throwing on every rectangle.
let bufferTransferOk = null;

function portSend(msg, transfer) {
  if (!port1) return;
  if (transfer && transfer.length && bufferTransferOk !== false) {
    try {
      port1.postMessage(msg, transfer);
      bufferTransferOk = true;
      return;
    } catch {
      bufferTransferOk = false;
    }
  }
  try {
    port1.postMessage(msg);
  } catch {
    /* renderer went away mid-flight */
  }
}

function status(state, message = '') {
  portSend({ kind: 'status', state, message });
}

// ---------------------------------------------------------------- window

function createWindow() {
  win = new BrowserWindow({
    width: 1280,
    height: 860,
    backgroundColor: '#111111',
    webPreferences: {
      preload: path.join(__dirname, '..', 'preload', 'index.cjs'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
    },
  });

  // Renderer/worker errors otherwise vanish - surface them in the main log.
  // Electron changed this signature mid-life; accept both shapes.
  win.webContents.on('console-message', (...args) => {
    const d = args[0] && typeof args[0] === 'object' && 'message' in args[0] ? args[0] : null;
    const message = d ? d.message : args[2];
    const source = d ? d.sourceId : args[4];
    const line = d ? d.lineNumber : args[3];
    console.log(`[renderer] ${message}  (${source || '?'}:${line || '?'})`);
  });

  // A MessagePort can only be transferred once, so mint a fresh channel per load.
  // This also makes a renderer reload recover cleanly.
  win.webContents.on('did-finish-load', () => {
    closePort();
    const { port1: p1, port2: p2 } = new MessageChannelMain();
    port1 = p1;
    port1.on('message', (event) => onRendererMessage(event.data));
    port1.start();
    win.webContents.postMessage('vnc-port', null, [p2]);
  });

  win.on('closed', () => {
    win = null;
    teardown();
    closePort();
  });

  win.loadFile(path.join(__dirname, '..', 'renderer', 'index.html'));
}

function closePort() {
  if (!port1) return;
  try {
    port1.close();
  } catch {
    /* already closed */
  }
  port1 = null;
}

// ---------------------------------------------------------------- session pumping

function flushOutbound() {
  if (!session || !socket || socket.destroyed) return;
  const out = session.takeOutbound();
  if (out && out.length) {
    socket.write(out);
  }
}

function forwardRect(ev) {
  let payload = ev.payload || new Uint8Array(0);
  // Only transfer a buffer we exclusively own; transferring a view into a shared
  // buffer would detach bytes the session still holds.
  if (payload.byteOffset !== 0 || payload.byteLength !== payload.buffer.byteLength) {
    payload = new Uint8Array(payload);
  }
  const msg = {
    kind: 'rect',
    encoding: ev.encoding,
    x: ev.x,
    y: ev.y,
    w: ev.w,
    h: ev.h,
    payload,
  };
  portSend(msg, [msg.payload.buffer]);
}

function forwardEvent(ev) {
  switch (ev.type) {
    case 'serverInit':
      portSend({ kind: 'init', width: ev.width, height: ev.height, name: ev.name });
      status('connected', ev.name || '');
      break;
    case 'rect':
      forwardRect(ev);
      break;
    case 'updateDone':
      portSend({ kind: 'updateDone' });
      break;
    case 'desktopSize':
      portSend({ kind: 'resize', width: ev.width, height: ev.height });
      break;
    case 'bell':
      portSend({ kind: 'bell' });
      break;
    case 'cutText':
      portSend({ kind: 'cutText', text: ev.text });
      break;
    case 'authFailed':
      sawAuthFailure = true;
      authFailureReason = ev.reason || 'authentication or authorization failure';
      status('auth-failed', authFailureReason);
      break;
    case 'error':
      status('error', ev.message || 'protocol error');
      break;
    default:
      break;
  }
}

function feed(chunk) {
  if (!session) return;
  let events;
  try {
    events = session.feed(chunk);
  } catch (err) {
    const detail = err && err.message ? err.message : String(err);
    status('error', 'protocol error: ' + detail);
    teardown();
    return;
  }
  flushOutbound();
  if (events) {
    for (const ev of events) forwardEvent(ev);
  }
}

function teardown() {
  if (socket) {
    socket.removeAllListeners();
    socket.destroy();
    socket = null;
  }
  session = null;
}

// ---------------------------------------------------------------- renderer -> session

function onRendererMessage(msg) {
  if (!msg || typeof msg !== 'object') return;
  if (msg.kind !== 'input') return;
  if (!session) return;

  const what = msg.type || msg.input || msg.action;
  switch (what) {
    case 'pointer':
    case 'mouse':
      session.sendPointer(msg.buttonMask | 0, msg.x | 0, msg.y | 0);
      break;
    case 'key':
    case 'keyboard':
      session.sendKey(!!msg.down, msg.keysym | 0);
      break;
    case 'cutText':
    case 'clipboard':
      session.sendCutText(String(msg.text == null ? '' : msg.text));
      break;
    case 'requestUpdate':
    case 'update':
      session.requestUpdate(msg.incremental === undefined ? true : !!msg.incremental);
      break;
    default:
      return;
  }
  flushOutbound();
}

// ---------------------------------------------------------------- IPC

ipcMain.handle('vnc:connect', (_event, opts) => {
  const o = opts || {};
  const host = o.host;
  const port = Number(o.port) || DEFAULT_PORT;
  const username = o.username || '';
  const password = o.password || '';

  if (!host) return Promise.resolve({ ok: false, error: 'no host given' });

  teardown();
  sawAuthFailure = false;
  authFailureReason = '';

  // Never log the password.
  console.log('[vnc] connecting host=' + host + ' port=' + port + ' username=' + username);
  status('connecting', host + ':' + port);

  session = new RfbSession({ username, password, encodings: DEFAULT_ENCODINGS, randomBytes });

  return new Promise((resolve) => {
    let settled = false;
    const settle = (value) => {
      if (settled) return;
      settled = true;
      resolve(value);
    };

    const sock = net.createConnection({ host, port });
    socket = sock;
    sock.setNoDelay(true);

    sock.on('connect', () => {
      console.log('[vnc] tcp connected host=' + host + ' port=' + port + ' username=' + username);
      flushOutbound();
      settle({ ok: true });
    });

    sock.on('data', (buf) => {
      if (sock !== socket) return;
      feed(new Uint8Array(buf)); // copy off Node's socket pool; no Buffer past this line
    });

    sock.on('error', (err) => {
      if (sock !== socket) return;
      const code = (err && err.code) || null;
      let message;
      if (code === 'ECONNREFUSED') message = ECONNREFUSED_HELP;
      else if (code === 'ETIMEDOUT') message = 'timed out connecting to ' + host + ':' + port;
      else if (code === 'ENOTFOUND' || code === 'EAI_AGAIN') message = 'cannot resolve host ' + host;
      else if (sawAuthFailure) message = authFailureReason;
      else message = (err && err.message) || 'socket error';
      console.error('[vnc] socket error host=' + host + ' port=' + port + ' code=' + (code || 'none'));
      status(sawAuthFailure ? 'auth-failed' : 'error', message);
      settle({ ok: false, error: message, code });
    });

    sock.on('close', () => {
      if (sock !== socket) return;
      if (sawAuthFailure) {
        status('disconnected', 'connection closed after authentication failure: ' + authFailureReason);
      } else {
        status('disconnected', 'connection closed');
      }
      teardown();
      settle({ ok: false, error: 'connection closed before handshake' });
    });
  });
});

ipcMain.handle('vnc:toggleFullscreen', () => {
  if (win) win.setFullScreen(!win.isFullScreen());
});

ipcMain.handle('vnc:disconnect', () => {
  console.log('[vnc] disconnect requested');
  const wasConnected = socket !== null;
  teardown();
  if (wasConnected) status('disconnected', 'disconnected by user');
  return { ok: true };
});

// ---------------------------------------------------------------- app lifecycle

app.whenReady().then(() => {
  createWindow();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  teardown();
  if (process.platform !== 'darwin') app.quit();
});

app.on('before-quit', () => {
  teardown();
});
