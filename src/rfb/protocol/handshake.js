// RFB version / security-list handshake. Pure: Reader in, plain objects out.

const TEXT_ENCODER = new TextEncoder();

/**
 * We announce 3.8 even against Apple's "RFB 003.889\n" banner: measured against
 * screensharingd, 003.889 yields a bare 4-byte SecurityResult and an immediate
 * close, while 003.008 yields the RFC 6143 failure-reason string — the only
 * diagnostic available. The security list and the type-30 payload are identical
 * either way.
 */
export const CLIENT_VERSION = TEXT_ENCODER.encode('RFB 003.008\n');

export const VERSION_BYTES = 12;

/** Apple Diffie-Hellman / ARD authentication. Selected by value, never by index. */
export const SECURITY_TYPE_APPLE_DH = 30;

/** Guard before allocating on a server-declared length. */
const MAX_REASON_BYTES = 64 * 1024;

const VERSION_PATTERN = /^RFB (\d{3})\.(\d{3})\n$/;

function latin1(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i += 8192) {
    out += String.fromCharCode.apply(null, bytes.subarray(i, Math.min(i + 8192, bytes.length)));
  }
  return out;
}

/**
 * Reads exactly 12 bytes.
 * @returns {{ major: number, minor: number, raw: string }} raw is the banner verbatim.
 */
export function parseVersion(reader) {
  const raw = latin1(reader.bytes(VERSION_BYTES));
  const m = VERSION_PATTERN.exec(raw);
  if (!m) throw new Error(`malformed RFB version banner: ${JSON.stringify(raw)}`);
  return { major: Number(m[1]), minor: Number(m[2]), raw };
}

/**
 * RFB 3.7+ security list: u8 count, then that many type bytes.
 * count === 0 means the server rejected the connection and a u32-prefixed
 * reason string follows; that is thrown as an Error carrying `.reason`.
 * @returns {number[]} the offered type numbers, in wire order.
 */
export function parseSecurityTypes(reader) {
  const count = reader.u8();
  if (count === 0) {
    const length = reader.u32();
    if (length > MAX_REASON_BYTES) {
      throw new Error(`security failure reason too long (${length} bytes)`);
    }
    const reason = latin1(reader.bytes(length));
    const err = new Error(reason || 'connection rejected by server (no reason given)');
    err.reason = reason;
    throw err;
  }
  return Array.from(reader.bytes(count));
}
