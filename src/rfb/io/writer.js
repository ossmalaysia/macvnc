// Fixed-length big-endian byte writer for RFB. Pure: Uint8Array + DataView only.

export class Writer {
  constructor(length) {
    if (!(length >= 0)) throw new RangeError('Writer: bad length ' + length);
    this._buf = new Uint8Array(length);
    this._view = new DataView(this._buf.buffer);
    this._pos = 0;
  }

  u8(v) {
    this._require(1);
    this._view.setUint8(this._pos, v & 0xff);
    this._pos += 1;
    return this;
  }

  u16(v) {
    this._require(2);
    this._view.setUint16(this._pos, v & 0xffff, false);
    this._pos += 2;
    return this;
  }

  u32(v) {
    this._require(4);
    this._view.setUint32(this._pos, v >>> 0, false);
    this._pos += 4;
    return this;
  }

  i32(v) {
    this._require(4);
    this._view.setInt32(this._pos, v | 0, false);
    this._pos += 4;
    return this;
  }

  bytes(u8arr) {
    const n = u8arr.length;
    this._require(n);
    this._buf.set(u8arr, this._pos);
    this._pos += n;
    return this;
  }

  // Leaves the constructor's zero fill in place -- RFB padding is always zeroed.
  skip(n) {
    if (!(n >= 0)) throw new RangeError('Writer.skip: bad length ' + n);
    this._require(n);
    this._pos += n;
    return this;
  }

  get result() {
    return this._buf;
  }

  get position() {
    return this._pos;
  }

  _require(n) {
    if (this._pos + n > this._buf.length) {
      throw new RangeError(
        'Writer overflow: need ' + n + ' at ' + this._pos + ' of ' + this._buf.length,
      );
    }
  }
}
