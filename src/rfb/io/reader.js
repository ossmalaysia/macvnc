// Incremental big-endian byte reader for RFB. Pure: Uint8Array + DataView only.

const INITIAL_CAPACITY = 8192;
// Above this, commit() re-allocates down instead of holding on to a peak-sized buffer.
const SHRINK_THRESHOLD = 1 << 20;

export class NeedMoreBytes extends Error {
  constructor(needed = 0, available = 0) {
    super('NeedMoreBytes: need ' + needed + ', have ' + available);
    this.name = 'NeedMoreBytes';
    this.needed = needed;
    this.available = available;
  }
}

export class Reader {
  constructor() {
    this._buf = new Uint8Array(INITIAL_CAPACITY);
    this._view = new DataView(this._buf.buffer);
    this._len = 0; // valid bytes in _buf
    this._pos = 0; // cursor
    this._mark = 0;
  }

  push(chunk) {
    if (!chunk || chunk.length === 0) return;
    this._reserve(chunk.length);
    this._buf.set(chunk, this._len);
    this._len += chunk.length;
  }

  get remaining() {
    return this._len - this._pos;
  }

  mark() {
    this._mark = this._pos;
  }

  rewind() {
    this._pos = this._mark;
  }

  commit() {
    if (this._pos > 0) {
      this._buf.copyWithin(0, this._pos, this._len);
      this._len -= this._pos;
      this._pos = 0;
    }
    this._mark = 0;
    if (this._buf.length > SHRINK_THRESHOLD && this._len * 4 < this._buf.length) {
      const cap = Math.max(INITIAL_CAPACITY, this._len * 2);
      const next = new Uint8Array(cap);
      next.set(this._buf.subarray(0, this._len));
      this._adopt(next);
    }
  }

  u8() {
    this._require(1);
    const v = this._view.getUint8(this._pos);
    this._pos += 1;
    return v;
  }

  u16() {
    this._require(2);
    const v = this._view.getUint16(this._pos, false);
    this._pos += 2;
    return v;
  }

  u32() {
    this._require(4);
    const v = this._view.getUint32(this._pos, false);
    this._pos += 4;
    return v;
  }

  // Signed: RFB encoding types are negative for pseudo-encodings
  // (-224 LastRect, -239 Cursor, -223 DesktopSize).
  i32() {
    this._require(4);
    const v = this._view.getInt32(this._pos, false);
    this._pos += 4;
    return v;
  }

  // Returns a COPY: commit() may compact or replace the backing buffer.
  bytes(n) {
    if (!(n >= 0)) throw new RangeError('Reader.bytes: bad length ' + n);
    this._require(n);
    const out = this._buf.slice(this._pos, this._pos + n);
    this._pos += n;
    return out;
  }

  skip(n) {
    if (!(n >= 0)) throw new RangeError('Reader.skip: bad length ' + n);
    this._require(n);
    this._pos += n;
  }

  _require(n) {
    const have = this._len - this._pos;
    if (have < n) throw new NeedMoreBytes(n, have);
  }

  _reserve(extra) {
    const needed = this._len + extra;
    if (needed <= this._buf.length) return;
    let cap = this._buf.length || INITIAL_CAPACITY;
    while (cap < needed) cap *= 2;
    const next = new Uint8Array(cap);
    next.set(this._buf.subarray(0, this._len));
    this._adopt(next);
  }

  _adopt(next) {
    this._buf = next;
    this._view = new DataView(next.buffer, next.byteOffset, next.byteLength);
  }
}
