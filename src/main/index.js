import { app, BrowserWindow, ipcMain, MessageChannelMain, safeStorage } from 'electron';
import net from 'node:net';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { randomFillSync } from 'node:crypto';
import { RfbSession } from '../rfb/rfb-session.js';
import { loadCredentials, saveCredentials, clearCredentials } from './credentials.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Probe reads creds saved under the pre-rename identity; point userData there so
// safeStorage decrypts with the same OS-keychain scope that wrote them.
if (process.env.VNC_HP_PROBE) {
  app.setName('vnc-client');
  app.commandLine.appendSwitch('enable-features', 'PlatformHEVCDecoderSupport');
}

const DEFAULT_PORT = 5900;
// We request a 16bpp RGB565 pixel format (half the bytes of 32bpp). ZRLE is
// dropped because its decoder is written for 3-byte CPIXELs; zlib(6), CopyRect
// and Raw all handle 16bpp and cover everything Apple sends.
// -223 DesktopSize / -224 LastRect are pseudo-encodings.
const DEFAULT_ENCODINGS = [6, 1, 0, -223, -224];

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
      // Keep decoding/painting at full rate even when the window isn't the
      // foreground app - otherwise Chromium throttles rAF/timers toward ~1fps.
      backgroundThrottling: false,
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
  if (out && out.length) socket.write(out);
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
      teardown();
      break;
    case 'error':
      status('error', ev.message || 'protocol error');
      teardown();
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
  const port = o.port == null || o.port === '' ? DEFAULT_PORT : Number(o.port);
  const username = o.username || '';
  const password = o.password || '';

  if (typeof host !== 'string' || !host.trim()) return { ok: false, error: 'no host given' };
  if (!Number.isInteger(port) || port < 1 || port > 65535) return { ok: false, error: 'invalid port' };

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

    // HP probe runs from the app-ready hook (VNC_HP_PROBE), not this UI path.
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

// ---------------------------------------------------------------- credentials
// Saved to userData, with the password encrypted at rest via the OS keychain
// (safeStorage -> Windows DPAPI, tied to this OS account). The rest is plain so
// the form can prefill even when encryption is briefly unavailable.

ipcMain.handle('creds:load', () => loadCredentials(app.getPath('userData'), safeStorage));

ipcMain.handle('creds:save', (_event, c) => {
  try {
    saveCredentials(app.getPath('userData'), safeStorage, c);
    return { ok: true };
  } catch (err) {
    return { ok: false, error: err.message };
  }
});

ipcMain.handle('creds:clear', () => {
  try {
    clearCredentials(app.getPath('userData'));
    return { ok: true };
  } catch (err) {
    return { ok: false, error: err.message };
  }
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
  if (!process.env.VNC_HP_PROBE) createWindow();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });

  // HP mode: open the HEVC viewer window, negotiate the media session, and stream
  // decoded access units to it.
  if (process.env.VNC_HP_PROBE) {
    const hpWin = new BrowserWindow({
      width: 1280, height: 780, backgroundColor: '#000000',
      webPreferences: { preload: path.join(__dirname, '..', 'preload', 'index.cjs'), contextIsolation: true, nodeIntegration: false, sandbox: false },
    });
    hpWin.webContents.on('console-message', (...a) => {
      const d = a[0] && typeof a[0] === 'object' && 'message' in a[0] ? a[0] : null;
      console.log('[hp-view] ' + (d ? d.message : a[2]));
    });
    hpWin.webContents.on('did-fail-load', (_e, code, desc, url) => console.log('[hp-view] LOAD FAILED ' + code + ' ' + desc + ' ' + url));
    hpWin.webContents.on('preload-error', (_e, p, err) => console.log('[hp-view] PRELOAD ERROR ' + (err && err.message)));
    hpWin.webContents.on('render-process-gone', (_e, det) => console.log('[hp-view] RENDER GONE ' + JSON.stringify(det)));
    // Surface any uncaught error/rejection from inside the page.
    hpWin.webContents.on('did-finish-load', () => {
      hpWin.webContents.executeJavaScript(
        "window.addEventListener('error', e => console.log('PAGE ERROR: ' + (e.message||e) + ' @ ' + (e.filename||'') + ':' + (e.lineno||'')));" +
        "window.addEventListener('unhandledrejection', e => console.log('PAGE REJECT: ' + (e.reason && (e.reason.message||e.reason))));"
      ).catch(() => {});
    });
    // Electron 44 no longer fires 'console-message' for renderer logs, so the
    // viewer publishes its counters via document.title and we poll them here.
    const titlePoll = setInterval(() => {
      if (hpWin.isDestroyed()) { clearInterval(titlePoll); return; }
      const t = hpWin.getTitle();
      if (t && t.startsWith('HP ')) console.log('[hp-view] ' + t);
    }, 1000);
    hpWin.on('closed', () => clearInterval(titlePoll));
    // Visual proof: dump the composited canvas to a PNG mid-stream. Counters can
    // look healthy while the picture is still wrong, so verify the pixels.
    if (process.env.VNC_HP_SHOT) {
      setTimeout(async () => {
        if (hpWin.isDestroyed()) return;
        try {
          // Read the canvas directly. capturePage() goes through the GPU
          // compositor and throws UnknownVizError on this box; toDataURL reads
          // the 2D backing store, which is what we actually want to verify.
          const dataUrl = await hpWin.webContents.executeJavaScript(
            "document.getElementById('screen').toDataURL('image/png')");
          fs.writeFileSync(process.env.VNC_HP_SHOT,
            Buffer.from(String(dataUrl).split(',')[1], 'base64'));
          // Per-band mean luminance proves each tile carries real content
          // rather than a black or uniform fill.
          const bands = await hpWin.webContents.executeJavaScript(`(() => {
            const c = document.getElementById('screen');
            const g = c.getContext('2d');
            const n = 4, h = Math.floor(c.height / n), out = [];
            for (let t = 0; t < n; t++) {
              const d = g.getImageData(0, t * h, c.width, h).data;
              let sum = 0, min = 255, max = 0;
              for (let i = 0; i < d.length; i += 4 * 97) {
                const v = (d[i] + d[i+1] + d[i+2]) / 3;
                sum += v; if (v < min) min = v; if (v > max) max = v;
              }
              out.push({ tile: t, mean: +(sum / (d.length / (4 * 97))).toFixed(1), min, max });
            }
            return JSON.stringify(out);
          })()`);
          console.log('[hp] canvas bands ' + bands);
          console.log('[hp] screenshot -> ' + process.env.VNC_HP_SHOT);
        } catch (e) { console.log('[hp] screenshot failed: ' + e.message); }
      }, 16000);
    }
    hpWin.loadFile(path.join(__dirname, '..', 'renderer', 'hp-view.html'));
    hpWin.webContents.on('did-finish-load', async () => {
      try {
        const rec = JSON.parse(fs.readFileSync(credsPath(), 'utf8'));
        const password = rec.enc && safeStorage.isEncryptionAvailable()
          ? safeStorage.decryptString(Buffer.from(rec.enc, 'base64')) : '';
        console.log('[hp] host=' + rec.host + ' user=' + rec.username);
        const send = (ch, v) => { if (!hpWin.isDestroyed()) hpWin.webContents.send(ch, v); };
        const hp = await import('../rfb-hp/phase0-probe.js');
        const runSeconds = Number(process.env.VNC_HP_SECONDS) || 20;
        // The post-auth rekey scan intermittently desyncs on a metadata rect we
        // cannot size, which aborts an otherwise healthy session. Authentication
        // has already succeeded at that point (SecurityResult: 0), so retrying
        // re-runs a handshake the Mac accepted — it is NOT a password attempt
        // and cannot contribute to an account lockout. A rejected password is
        // never retried.
        const MAX_ATTEMPTS = 6;
        const attempt = (n) => new Promise((resolve) => {
          send('hp-status', n === 1 ? 'connecting…' : `retrying (${n}/${MAX_ATTEMPTS})…`);
          const sock = net.createConnection({ host: rec.host, port: rec.port || DEFAULT_PORT });
          sock.setNoDelay(true);
          let settled = false;
          const done = (v) => { if (!settled) { settled = true; try { sock.destroy(); } catch {} resolve(v); } };
          sock.on('connect', async () => {
            try {
              const res = await hp.runHpProbe(sock, {
                host: rec.host, username: rec.username, password, runSeconds,
                onAu: (au) => send('hp-au', au),
              }, (m) => { console.log('[hp] ' + m); send('hp-status', m); });
              console.log('[hp] RESULT ' + JSON.stringify({ ...res, answer: undefined }));
              done(true);
            } catch (err) {
              const msg = String((err && err.message) || err);
              console.log('[hp] PROBE ERROR: ' + msg);
              // Only the post-auth desync is retryable. Anything touching
              // credentials must fail loudly and stay failed.
              done(/CHECKPOINT A FAILED|rekey|could not size/i.test(msg) ? false : true);
            }
          });
          sock.on('error', (e) => { console.log('[hp] socket error: ' + e.message); done(true); });
        });
        for (let n = 1; n <= MAX_ATTEMPTS; n++) {
          await hp.warmupTcp(rec.host, rec.port || DEFAULT_PORT);
          if (await attempt(n)) break;
          console.log(`[hp] post-auth desync on attempt ${n}; retrying`);
        }
      } catch (err) { console.log('[hp] SETUP ERROR: ' + (err && err.message)); }
    });
    return; // don't open the normal RFB window in HP mode
  }
});

app.on('window-all-closed', () => {
  teardown();
  if (process.platform !== 'darwin') app.quit();
});

app.on('before-quit', () => {
  teardown();
});
