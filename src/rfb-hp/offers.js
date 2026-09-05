// AVConference media-stream negotiation offer payloads for the 0x1c message.
//
// Direct port of the reference offers.py (`_build_mediablob` mode 7=video /
// mode 8=audio) plus a hand-rolled binary-plist (bplist00) writer, because
// Node has no plist encoder. Each exported builder returns the FINAL bytes
// that go into the 0x1c body: a binary plist wrapping a zlib-compressed
// MediaBlob protobuf.
//
// Wire format is BIG-ENDIAN for the bplist scalar sizes; the protobuf itself
// is little-endian base-128 varints (protobuf standard), matching offers.py.
//
// PLIST SHAPE: matches offers.py create_offers._plist (L316-327), a FOUR-key
// dict:
//   avcMediaStreamOptionRemoteEndpointInfo -> data (RemoteEndpointInfo proto)
//   avcMediaStreamNegotiatorMode           -> integer (7=video, 8=audio)
//   avcMediaStreamNegotiatorMediaBlob      -> data (zlib-compressed MediaBlob)
//   avcMediaStreamOptionCallID             -> ASCII string (uppercase uuid4)
// plistlib.dumps(fmt=FMT_BINARY) defaults sort_keys=True, so keys are emitted
// in sorted order; the writer below sorts to byte-match.

import { randomBytes } from 'node:crypto';
import { deflateSync } from 'node:zlib';

// iShareScreen client version stamped into MediaBlob field 6. The reference
// pulls this from the package root (`from ... import __version__`), which is
// NOT present in the ported source, so it cannot be confirmed. Override via
// opts.version. This string is part of the offer bytes.
const DEFAULT_VERSION = '1.0.0';

// ── protobuf helpers (port of offers.py _varint / _field_varint / _field_bytes)

// base-128 LEB varint. Accepts number or bigint; coerces to BigInt so 32-bit
// SSRCs and 64-bit nanosecond timestamps encode correctly (JS bitwise ops are
// signed-32-bit and would corrupt values >= 2**31).
function varint(v) {
  let n = BigInt(v);
  const out = [];
  while (n > 0x7fn) {
    out.push(Number((n & 0x7fn) | 0x80n));
    n >>= 7n;
  }
  out.push(Number(n & 0x7fn));
  return Buffer.from(out);
}

function fieldVarint(fieldNum, value) {
  return Buffer.concat([varint((fieldNum << 3) | 0), varint(value)]);
}

function fieldBytes(fieldNum, value) {
  const val = Buffer.isBuffer(value) ? value : Buffer.from(value);
  return Buffer.concat([varint((fieldNum << 3) | 2), varint(val.length), val]);
}

// ── audio f9 codec tier list (offers.py _AUDIO_F9_TIERS) ──────────────────
// [f1, f2, f3|null]. f3 omitted when null.
const AUDIO_F9_TIERS = [
  [0, 40_000_000, 12288],
  [0, 6_000_000, 131072],
  [4074, 0, 16384],
  [16, 4100, null],
  [0, 75_000_000, 524288],
  [0, 20_000_000, 98304],
  [4, 6500, null],
  [0, 60_000_000, 262144],
  [1, 299, null],
  [0, 100_000_000, 1048576],
];

function buildAudioF9Entry(f1, f2, f3) {
  // body: field1 (0x08) + field2 (0x10) [+ field3 (0x18)], entry = field9 (0x4a)
  let body = Buffer.concat([
    Buffer.from([0x08]), varint(f1),
    Buffer.from([0x10]), varint(f2),
  ]);
  if (f3 !== null) {
    body = Buffer.concat([body, Buffer.from([0x18]), varint(f3)]);
  }
  return Buffer.concat([Buffer.from([0x4a]), varint(body.length), body]);
}

const APPLE_AUDIO_F9 = Buffer.concat(
  AUDIO_F9_TIERS.map((t) => buildAudioF9Entry(t[0], t[1], t[2]))
);

// ── HEVC + AVC parameter strings (offers.py) ──────────────────────────────
const HEVC_PARAMS_LTR = Buffer.from(
  'FLS;MS:-1;LF:-1;LTR;CABAC;POS:0;EOD:1;HTS:2;RR:3;AR:16/9,5/8;XR:16/9,5/8;',
  'ascii'
);
const HEVC_PARAMS_NO_LTR = Buffer.from(
  'FLS;MS:-1;LF:-1;CABAC;POS:0;EOD:1;HTS:2;RR:3;AR:16/9,5/8;XR:16/9,5/8;',
  'ascii'
);
const AVC_PARAMS = Buffer.from(
  'FLS;LF:-1;POS:5;EOD:1;HTS:2;RR:3;POSE:4;AR:16/9,5/8;XR:16/9,5/8;',
  'ascii'
);

// Audio field4 gate (offers.py _AUDIO_F4_ON / _AUDIO_F4_OFF).
const AUDIO_F4_ON = 24191;
const AUDIO_F4_OFF = 1000;

// ── MediaBlob construction (offers.py _build_mediablob) ───────────────────

function buildMediaBlob(mode, sessionId, timestamp, opts) {
  const version = opts.version ?? DEFAULT_VERSION;
  let descField;

  if (mode === 7) {
    // Defaults match Apple's byte-identical "both" offer: HEVC bank (field1=123)
    // then AVC bank (field1=100); LTRP on (HEVC path); tilesPerFrame = 4.
    const ltrpOn = opts.ltrpEnabled ?? true;
    const tilesPerFrame = opts.tilesPerFrame ?? 4;
    const hevcParams = ltrpOn ? HEVC_PARAMS_LTR : HEVC_PARAMS_NO_LTR;

    const resEntry = Buffer.concat([
      fieldVarint(1, 1), fieldVarint(2, 1),
      fieldVarint(3, 50115), fieldVarint(4, 0),
    ]);
    const resEntryAlt = Buffer.concat([
      fieldVarint(1, 1), fieldVarint(2, 2),
      fieldVarint(3, 50115), fieldVarint(4, 0),
    ]);

    const hevcBank = Buffer.concat([
      fieldVarint(1, 123),
      fieldBytes(2, resEntry), fieldBytes(2, resEntryAlt),
      fieldBytes(2, resEntry), fieldBytes(2, resEntryAlt),
      fieldBytes(3, hevcParams),
      fieldVarint(4, 1),
    ]);
    const avcBank = Buffer.concat([
      fieldVarint(1, 100),
      fieldBytes(2, resEntry), fieldBytes(2, resEntryAlt),
      fieldBytes(3, AVC_PARAMS),
      fieldVarint(4, 14),
    ]);

    // "both": server-preferred (HEVC 4:4:4) path — do NOT reorder.
    const codecBanks = Buffer.concat([fieldBytes(3, hevcBank), fieldBytes(3, avcBank)]);

    const desc = Buffer.concat([
      fieldVarint(1, sessionId),        // field1 = advertised SSRC (session_id)
      fieldVarint(2, ltrpOn ? 1 : 0),
      codecBanks,
      fieldVarint(6, tilesPerFrame),
      fieldVarint(7, ltrpOn ? 1 : 0),
      fieldVarint(8, 63),
      fieldVarint(9, 1),
      fieldVarint(12, 1),
    ]);
    descField = fieldBytes(5, desc);
  } else if (mode === 8) {
    const af4 = opts.audioEnabled === false ? AUDIO_F4_OFF : AUDIO_F4_ON;
    const desc = Buffer.concat([
      fieldVarint(1, sessionId),        // field1 = advertised SSRC (session_id)
      fieldVarint(2, 0),
      fieldVarint(3, 0),
      fieldVarint(4, af4),
      fieldVarint(5, 0),
      fieldVarint(6, 0),
    ]);
    descField = fieldBytes(3, desc);
  } else {
    throw new Error(`unsupported negotiation mode ${mode}`);
  }

  return Buffer.concat([
    fieldVarint(1, 1), fieldVarint(2, 1),
    descField,
    fieldBytes(6, Buffer.from(`iShareScreen ${version}`, 'ascii')),
    fieldVarint(8, 0),
    APPLE_AUDIO_F9,
    fieldVarint(13, timestamp),        // 64-bit ns timestamp (dynamic)
    fieldVarint(14, 2), fieldVarint(16, 0), fieldVarint(18, 1),
  ]);
}

// ── RemoteEndpointInfo protobuf (offers.py _build_remote_endpoint_info L150-185)
//
// Fields: f1(0x08)=0, f2(0x10)=1, f3(0x1a)=hw_model, f4(0x22)=avc_version,
// f5(0x2a)=os_build. Each string is _str(tag, s) = [tag, len] + utf8[:127].
// offers.py derives hw_model/os_build at runtime (sysctl / sw_vers on Darwin,
// platform info elsewhere); we ship fixed Mac-like defaults so the daemon gets
// a well-formed, plausible endpoint. Override via opts.endpoint.
function buildRemoteEndpointInfo(opts) {
  const ep = opts.endpoint ?? {};
  const hwModel = ep.hwModel ?? 'MacBookPro18,3';
  const avcVersion = ep.avcVersion ?? '1.0.0';
  const osBuild = ep.osBuild ?? '24A335';

  const strField = (tag, s) => {
    const b = Buffer.from(String(s), 'utf8').subarray(0, 127); // matches Python [:127]
    return Buffer.concat([Buffer.from([tag, b.length]), b]);
  };

  return Buffer.concat([
    Buffer.from([0x08, 0x00]),   // f1 = 0
    Buffer.from([0x10, 0x01]),   // f2 = 1
    strField(0x1a, hwModel),     // f3 = hw_model
    strField(0x22, avcVersion),  // f4 = avc_version
    strField(0x2a, osBuild),     // f5 = os_build
  ]);
}

// ── CallID (offers.py L325: str(uuid.uuid4()).upper()) ────────────────────
// uuid4 in 8-4-4-4-12 dashed form, UPPERCASE. Synthesize from randomBytes with
// version (0x4X) and variant (0x8..0xB) bits set, matching uuid4's layout.
function makeCallId(existing) {
  if (existing) return String(existing);
  const b = randomBytes(16);
  b[6] = (b[6] & 0x0f) | 0x40; // version 4
  b[8] = (b[8] & 0x3f) | 0x80; // RFC 4122 variant
  const h = b.toString('hex');
  const s = `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
  return s.toUpperCase();
}

// ── binary plist writer (matches plistlib FMT_BINARY, sort_keys=True) ──────
//
// Object table order (plistlib _flatten: root dict first, then ALL keys in
// sorted order, then ALL values in the same order):
//   obj0 = dict, obj1..objN = key strings, objN+1..obj2N = value objects.
// Values here are ASCII string (0x5X), integer (0x1X), or data (0x4X).
// Trailer is the fixed 32-byte plist trailer.

function writeSize(token, size) {
  // plistlib _write_size: low nibble is the size when < 15, else 0xF plus an
  // int object encoding the true size (0x10=1B, 0x11=2B, 0x12=4B, 0x13=8B).
  if (size < 15) return Buffer.from([token | size]);
  if (size < 0x100) return Buffer.from([token | 0x0f, 0x10, size]);
  if (size < 0x10000) {
    const b = Buffer.from([token | 0x0f, 0x11, 0, 0]);
    b.writeUInt16BE(size, 2);
    return b;
  }
  // 4-byte length (sizes beyond this are not reachable for our payloads).
  const b = Buffer.from([token | 0x0f, 0x12, 0, 0, 0, 0]);
  b.writeUInt32BE(size, 2);
  return b;
}

function countToSize(count) {
  if (count < 0x100) return 1;
  if (count < 0x10000) return 2;
  if (count < 0x100000000) return 4;
  return 8;
}

function packOffset(value, size) {
  const b = Buffer.alloc(size);
  if (size === 1) b.writeUInt8(value, 0);
  else if (size === 2) b.writeUInt16BE(value, 0);
  else if (size === 4) b.writeUInt32BE(value, 0);
  else b.writeBigUInt64BE(BigInt(value), 0);
  return b;
}

// Encode a plist integer exactly as plistlib _write_object does: token 0x1<k>
// where 2^k is the byte width, big-endian. Our ints (mode 7/8) are tiny, but
// the full ladder is kept for correctness. No negatives are ever passed.
function encodeIntObject(value) {
  if (value < 0x100) return Buffer.from([0x10, value]);
  if (value < 0x10000) {
    const b = Buffer.alloc(3); b[0] = 0x11; b.writeUInt16BE(value, 1); return b;
  }
  if (value < 0x100000000) {
    const b = Buffer.alloc(5); b[0] = 0x12; b.writeUInt32BE(value, 1); return b;
  }
  const b = Buffer.alloc(9); b[0] = 0x13; b.writeBigUInt64BE(BigInt(value), 1); return b;
}

// Encode one value object. kind: 'string' (ASCII, 0x5X), 'int' (0x1X), 'data' (0x4X).
function encodeValueObject(obj) {
  if (obj.kind === 'string') {
    const b = Buffer.from(obj.value, 'ascii');
    return Buffer.concat([writeSize(0x50, b.length), b]);
  }
  if (obj.kind === 'data') {
    return Buffer.concat([writeSize(0x40, obj.value.length), obj.value]);
  }
  if (obj.kind === 'int') {
    return encodeIntObject(obj.value);
  }
  throw new Error(`unsupported plist value kind ${obj.kind}`);
}

// entries: [{ key, value: {kind, value} }, ...]. Keys are sorted to match
// plistlib.dumps(fmt=FMT_BINARY) default sort_keys=True, then flattened as
// [dict, ...keys, ...values].
function buildBinaryPlist(entries) {
  const sorted = [...entries].sort((a, b) =>
    a.key < b.key ? -1 : a.key > b.key ? 1 : 0);
  const n = sorted.length;
  const numObjects = 1 + n + n; // dict + keys + values
  const refSize = countToSize(numObjects);

  // obj0: dict — marker 0xD0|count, then all key refs (1..n) then all value
  // refs (n+1..2n), in sorted-key order.
  const refs = [];
  for (let i = 0; i < n; i++) refs.push(1 + i);       // key refs
  for (let i = 0; i < n; i++) refs.push(1 + n + i);   // value refs
  const dictObj = Buffer.concat([
    writeSize(0xd0, n),
    ...refs.map((r) => packOffset(r, refSize)),
  ]);

  const keyObjs = sorted.map((e) => {
    const kb = Buffer.from(e.key, 'ascii');
    return Buffer.concat([writeSize(0x50, kb.length), kb]);
  });
  const valObjs = sorted.map((e) => encodeValueObject(e.value));

  const allObjs = [dictObj, ...keyObjs, ...valObjs];

  const header = Buffer.from('bplist00', 'ascii');
  const offsets = [];
  let cursor = header.length;
  for (const o of allObjs) { offsets.push(cursor); cursor += o.length; }

  const offsetTableOffset = cursor;
  const offsetSize = countToSize(offsetTableOffset);
  const offsetTable = Buffer.concat(offsets.map((o) => packOffset(o, offsetSize)));

  const trailer = Buffer.alloc(32);
  // bytes 0..4 unused (0), byte5 = sortVersion (0)
  trailer.writeUInt8(offsetSize, 6);
  trailer.writeUInt8(refSize, 7);
  trailer.writeBigUInt64BE(BigInt(numObjects), 8);          // numObjects
  trailer.writeBigUInt64BE(0n, 16);                         // topObject
  trailer.writeBigUInt64BE(BigInt(offsetTableOffset), 24);  // offsetTableOffset

  return Buffer.concat([header, ...allObjs, offsetTable, trailer]);
}

// ── public API ────────────────────────────────────────────────────────────

function buildOffer(mode, opts = {}) {
  // session_id doubles as the advertised SSRC (offers.py: desc field1).
  const ssrc = (opts.ssrc ?? randomBytes(4).readUInt32BE(0)) >>> 0;
  const timestamp = opts.timestamp ?? BigInt(Date.now()) * 1_000_000n;

  const blob = buildMediaBlob(mode, ssrc, timestamp, opts);
  const compressed = deflateSync(blob); // zlib format, default level 6 == Python zlib.compress
  const callId = makeCallId(opts.callId);
  const endpoint = buildRemoteEndpointInfo(opts);

  // Four-key dict per offers.py L321-326 (writer sorts keys to match plistlib).
  const plist = buildBinaryPlist([
    { key: 'avcMediaStreamOptionRemoteEndpointInfo', value: { kind: 'data', value: endpoint } },
    { key: 'avcMediaStreamNegotiatorMode', value: { kind: 'int', value: mode } },
    { key: 'avcMediaStreamNegotiatorMediaBlob', value: { kind: 'data', value: compressed } },
    { key: 'avcMediaStreamOptionCallID', value: { kind: 'string', value: callId } },
  ]);
  return { blob: plist, ssrc };
}

export function buildVideoOffer(opts = {}) {
  // opts: {width, height, ssrc?}. NOTE: width/height are accepted for API
  // symmetry but are NOT encoded — the reference offer is resolution-independent
  // (resolution field3 is the constant 50115; the server reports canvas dims in
  // the answer). Mode 7.
  return buildOffer(7, opts);
}

export function buildAudioOffer(opts = {}) {
  // opts: {ssrc?, audioEnabled?}. audioEnabled=false gates the server audio
  // transmitter off (field4 below the tier floor). Mode 8.
  return buildOffer(8, opts);
}
