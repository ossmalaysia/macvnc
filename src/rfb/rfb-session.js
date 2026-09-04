import { Reader, NeedMoreBytes } from './io/reader.js';
import {
  CLIENT_VERSION,
  SECURITY_TYPE_APPLE_DH,
  parseSecurityTypes,
  parseVersion,
} from './protocol/handshake.js';
import { parseAppleDhParams, buildAppleDhResponse } from './protocol/security/apple-dh.js';
import { CANVAS_PIXEL_FORMAT, bytesPerPixel, readPixelFormat } from './protocol/pixel-format.js';
import {
  clientInit,
  setPixelFormat,
  setEncodings,
  framebufferUpdateRequest,
  keyEvent,
  pointerEvent,
  clientCutText,
} from './protocol/messages/client.js';

export const State = {
  VERSION: 'version',
  SECURITY: 'security',
  AUTH_PARAMS: 'auth-params',
  AUTH_RESULT: 'auth-result',
  SERVER_INIT: 'server-init',
  RUNNING: 'running',
  FAILED: 'failed',
};

const MSG_FRAMEBUFFER_UPDATE = 0;
const MSG_SET_COLOUR_MAP_ENTRIES = 1;
const MSG_BELL = 2;
const MSG_SERVER_CUT_TEXT = 3;

const ENC_RAW = 0;
const ENC_COPYRECT = 1;
const ENC_ZLIB = 6;
const ENC_ZRLE = 16;
const ENC_CURSOR = -239;
const ENC_DESKTOP_SIZE = -223;
const ENC_LAST_RECT = -224;

const DEFAULT_ENCODINGS = [16, 6, 1, 0, -239, -223, -224];

const RECT_HEADER_BYTES = 12;
const RANDOM_CHUNK = 65536;

// Every u32 length on the wire is attacker-influenced; cap before allocating.
const MAX_NAME_BYTES = 64 * 1024;
const MAX_REASON_BYTES = 64 * 1024;
const MAX_CUT_TEXT_BYTES = 1024 * 1024;
const MAX_ZLIB_CHUNK_BYTES = 32 * 1024 * 1024;
const MAX_RECT_PAYLOAD_BYTES = 128 * 1024 * 1024;

function latin1(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i += 8192) {
    out += String.fromCharCode.apply(null, bytes.subarray(i, Math.min(i + 8192, bytes.length)));
  }
  return out;
}

function decodeName(bytes) {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return latin1(bytes);
  }
}

function defaultRandomBytes(n) {
  const c = globalThis.crypto;
  if (!c || typeof c.getRandomValues !== 'function') {
    throw new Error('no CSPRNG available; pass randomBytes to the RfbSession constructor');
  }
  const out = new Uint8Array(n);
  for (let off = 0; off < n; off += RANDOM_CHUNK) {
    c.getRandomValues(out.subarray(off, Math.min(off + RANDOM_CHUNK, n)));
  }
  return out;
}

function log(level, message) {
  if (typeof console !== 'undefined' && typeof console[level] === 'function') console[level](message);
}

/**
 * The pure RFB state machine. Knows every rectangle's payload length without
 * decoding it, so the transport can slice rectangles straight onto the wire to
 * the decoder worker.
 */
export class RfbSession {
  constructor({ username, password, encodings, randomBytes } = {}) {
    this.username = username ?? '';
    this.password = password ?? '';
    this.encodings = Array.isArray(encodings) && encodings.length ? encodings.slice() : DEFAULT_ENCODINGS.slice();
    this.randomBytes = randomBytes ?? defaultRandomBytes;

    this.reader = new Reader();
    this.outbound = [];
    this.state = State.VERSION;

    this.serverVersion = null;
    this.width = 0;
    this.height = 0;
    this.name = '';
    this.serverPixelFormat = null;
    // Until SetPixelFormat is sent nothing has been rendered, but keep the
    // field honest: it is what payload lengths are computed from.
    this.pixelFormat = CANVAS_PIXEL_FORMAT;

    // FramebufferUpdate progress kept on the instance, not in a local loop:
    // one rectangle can span many TCP reads.
    this.fbuActive = false;
    this.rectsRemaining = 0;
    this.updateOutstanding = false;
    this.pendingFullUpdate = false;
  }

  /**
   * @param {Uint8Array} chunk
   * @returns {object[]} events produced by the bytes available so far
   */
  feed(chunk) {
    const events = [];
    if (chunk && chunk.length) this.reader.push(chunk);
    if (this.state === State.FAILED) return events;

    for (;;) {
      if (this.reader.remaining === 0) break;
      this.reader.mark();
      try {
        this.step(events);
        this.reader.commit();
      } catch (err) {
        this.reader.rewind();
        if (err instanceof NeedMoreBytes) break;
        this.state = State.FAILED;
        events.push({ type: 'error', message: err.message });
        break;
      }
      if (this.state === State.FAILED) break;
    }
    return events;
  }

  /** @returns {Uint8Array|null} */
  takeOutbound() {
    if (this.outbound.length === 0) return null;
    let total = 0;
    for (const b of this.outbound) total += b.length;
    const out = new Uint8Array(total);
    let off = 0;
    for (const b of this.outbound) {
      out.set(b, off);
      off += b.length;
    }
    this.outbound.length = 0;
    return out;
  }

  sendPointer(buttonMask, x, y) {
    if (this.state !== State.RUNNING) return;
    this.outbound.push(pointerEvent(buttonMask, x, y));
  }

  sendKey(down, keysym) {
    if (this.state !== State.RUNNING) return;
    this.outbound.push(keyEvent(down, keysym));
  }

  sendCutText(text) {
    if (this.state !== State.RUNNING) return;
    this.outbound.push(clientCutText(text));
  }

  /**
   * A full refresh asked for while a request is already outstanding is deferred
   * to the next re-arm rather than sent immediately — two updates in flight
   * would re-arm twice on completion and never converge again.
   */
  requestUpdate(incremental = 0) {
    if (this.state !== State.RUNNING) return;
    if (!incremental) this.pendingFullUpdate = true;
    if (this.updateOutstanding) return;
    this.queueUpdateRequest();
  }

  // --- internals -----------------------------------------------------------

  step(events) {
    switch (this.state) {
      case State.VERSION:
        return this.stepVersion(events);
      case State.SECURITY:
        return this.stepSecurity(events);
      case State.AUTH_PARAMS:
        return this.stepAuthParams(events);
      case State.AUTH_RESULT:
        return this.stepAuthResult(events);
      case State.SERVER_INIT:
        return this.stepServerInit(events);
      case State.RUNNING:
        return this.stepRunning(events);
      default:
        throw new Error(`session is not accepting data (state ${this.state})`);
    }
  }

  stepVersion() {
    const version = parseVersion(this.reader);
    this.serverVersion = version;
    log('info', `[rfb] server banner ${JSON.stringify(version.raw)}; replying RFB 003.008`);
    this.outbound.push(CLIENT_VERSION);
    this.state = State.SECURITY;
  }

  stepSecurity(events) {
    const offered = parseSecurityTypes(this.reader);
    if (!offered.includes(SECURITY_TYPE_APPLE_DH)) {
      this.state = State.FAILED;
      events.push({
        type: 'error',
        message: `server offers no supported security type; offered: ${offered.join(', ')}`,
      });
      return;
    }
    this.outbound.push(new Uint8Array([SECURITY_TYPE_APPLE_DH]));
    this.state = State.AUTH_PARAMS;
  }

  stepAuthParams() {
    const params = parseAppleDhParams(this.reader);
    log('info', `[rfb] apple dh params: generator=${params.generator} keyLength=${params.keyLength}`);
    if (params.generator !== 2 || params.keyLength !== 128) {
      log('warn', '[rfb] unexpected DH parameters (expected generator=2 keyLength=128); continuing');
    }
    this.outbound.push(buildAppleDhResponse(params, this.username, this.password, this.randomBytes));
    this.state = State.AUTH_RESULT;
  }

  stepAuthResult(events) {
    const status = this.reader.u32();
    if (status === 0) {
      this.outbound.push(clientInit(1));
      this.state = State.SERVER_INIT;
      return;
    }
    const length = this.reader.u32();
    if (length > MAX_REASON_BYTES) {
      throw new Error(`auth failure reason too long (${length} bytes)`);
    }
    const reason = latin1(this.reader.bytes(length));
    // Apple appends one 0x00 that is NOT counted in the declared length.
    if (this.reader.remaining >= 1) {
      this.reader.mark();
      if (this.reader.u8() !== 0) this.reader.rewind();
    }
    this.state = State.FAILED;
    events.push({ type: 'authFailed', reason });
  }

  stepServerInit(events) {
    const r = this.reader;
    const width = r.u16();
    const height = r.u16();
    const pf = readPixelFormat(r);
    const nameLength = r.u32();
    if (nameLength > MAX_NAME_BYTES) {
      throw new Error(`ServerInit name too long (${nameLength} bytes)`);
    }
    const name = decodeName(r.bytes(nameLength));

    this.width = width;
    this.height = height;
    this.name = name;
    this.serverPixelFormat = pf;
    this.pixelFormat = CANVAS_PIXEL_FORMAT;
    this.state = State.RUNNING;

    events.push({ type: 'serverInit', width, height, name });

    // Order matters: changing the pixel format while an update request is
    // outstanding leaves the next update's format ambiguous.
    this.outbound.push(setPixelFormat(CANVAS_PIXEL_FORMAT));
    this.outbound.push(setEncodings(this.encodings));
    this.pendingFullUpdate = true;
    this.queueUpdateRequest();
  }

  stepRunning(events) {
    if (this.fbuActive) {
      this.readRectangle(events);
      return;
    }
    const type = this.reader.u8();
    switch (type) {
      case MSG_FRAMEBUFFER_UPDATE: {
        this.reader.skip(1);
        const numRects = this.reader.u16();
        this.fbuActive = true;
        // Untrusted upper bound: never preallocate from it, never require it to
        // reach zero (LastRect can end the update early).
        this.rectsRemaining = numRects;
        if (numRects === 0) this.finishUpdate(events);
        return;
      }
      case MSG_SET_COLOUR_MAP_ENTRIES: {
        // Never legitimate with true-colour, but must be consumed to stay in sync.
        this.reader.skip(1);
        this.reader.u16();
        const numColours = this.reader.u16();
        this.reader.skip(numColours * 6);
        return;
      }
      case MSG_BELL:
        // ONE byte total. No padding, no body.
        events.push({ type: 'bell' });
        return;
      case MSG_SERVER_CUT_TEXT: {
        this.reader.skip(3);
        const length = this.reader.u32();
        // A negative S32 length (Extended Clipboard, which we never request)
        // reads here as a huge u32 and trips the same cap.
        if (length > MAX_CUT_TEXT_BYTES) {
          throw new Error(`ServerCutText too long (${length} bytes)`);
        }
        events.push({ type: 'cutText', text: latin1(this.reader.bytes(length)) });
        return;
      }
      default:
        throw new Error(`unknown server message type ${type}`);
    }
  }

  readRectangle(events) {
    const r = this.reader;
    r.mark();
    const x = r.u16();
    const y = r.u16();
    const w = r.u16();
    const h = r.u16();
    const encoding = r.i32(); // SIGNED: -224/-223/-239 read unsigned breaks every pseudo-encoding

    if (encoding === ENC_LAST_RECT) {
      this.finishUpdate(events);
      return;
    }

    if (encoding === ENC_DESKTOP_SIZE) {
      this.width = w;
      this.height = h;
      this.pendingFullUpdate = true;
      events.push({ type: 'desktopSize', width: w, height: h });
      this.consumeRect(events);
      return;
    }

    const bpp = bytesPerPixel(this.pixelFormat);
    let payload;
    switch (encoding) {
      case ENC_RAW:
        payload = r.bytes(this.checkedLength(w * h * bpp, encoding));
        break;
      case ENC_COPYRECT:
        payload = r.bytes(4);
        break;
      case ENC_CURSOR:
        payload = r.bytes(this.checkedLength(w * h * bpp + ((w + 7) >> 3) * h, encoding));
        break;
      case ENC_ZLIB:
      case ENC_ZRLE: {
        const length = r.u32();
        if (length > MAX_ZLIB_CHUNK_BYTES) {
          throw new Error(`encoding ${encoding} chunk too long (${length} bytes)`);
        }
        // The u32 length prefix is part of what the decoder receives, so rewind
        // over the header and take header-payload in one slice.
        r.rewind();
        this.reader.skip(RECT_HEADER_BYTES);
        payload = r.bytes(4 + length);
        break;
      }
      default:
        // No length is transmitted, so there is nothing to skip: unrecoverable.
        throw new Error(`unsupported encoding ${encoding} for rect ${w}x${h} at ${x},${y}`);
    }

    events.push({ type: 'rect', encoding, x, y, w, h, payload });
    this.consumeRect(events);
  }

  consumeRect(events) {
    this.rectsRemaining -= 1;
    if (this.rectsRemaining <= 0) this.finishUpdate(events);
  }

  finishUpdate(events) {
    this.fbuActive = false;
    this.rectsRemaining = 0;
    this.updateOutstanding = false;
    events.push({ type: 'updateDone' });
    this.queueUpdateRequest();
  }

  queueUpdateRequest() {
    const incremental = this.pendingFullUpdate ? 0 : 1;
    this.pendingFullUpdate = false;
    this.outbound.push(framebufferUpdateRequest(incremental, 0, 0, this.width, this.height));
    this.updateOutstanding = true;
  }

  checkedLength(n, encoding) {
    if (n > MAX_RECT_PAYLOAD_BYTES) {
      throw new Error(`encoding ${encoding} rectangle payload too long (${n} bytes)`);
    }
    return n;
  }
}
