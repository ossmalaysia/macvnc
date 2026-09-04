import pako from '../../vendor/pako.esm.mjs';

const Z_SYNC_FLUSH = pako.constants.Z_SYNC_FLUSH;
const CHUNK_SIZE = 1 << 18;

/**
 * One long-lived inflate stream. Created once per connection and NEVER reset:
 * only the first rectangle carries a zlib header, every later one resumes
 * mid-DEFLATE against the earlier sliding window.
 */
function createStream(name) {
  const inf = new pako.Inflate({ chunkSize: CHUNK_SIZE });
  const chunks = [];
  let total = 0;

  inf.onData = (chunk) => {
    chunks.push(chunk);
    total += chunk.length;
  };

  return {
    push(bytes) {
      chunks.length = 0;
      total = 0;

      // Z_SYNC_FLUSH: emit everything decodable so far without ending the
      // stream, so the next rectangle can continue where this one stopped.
      const ok = inf.push(bytes, Z_SYNC_FLUSH);
      if (ok === false || inf.err) {
        throw new Error(
          `inflate stream '${name}' failed: ${inf.msg || `zlib error ${inf.err}`}`,
        );
      }

      const out = new Uint8Array(total);
      let off = 0;
      for (let i = 0; i < chunks.length; i++) {
        out.set(chunks[i], off);
        off += chunks[i].length;
      }
      chunks.length = 0;
      total = 0;
      return out;
    },
  };
}

export function createInflateContext() {
  return {
    zrle: createStream('zrle'),
    zlib6: createStream('zlib6'),
  };
}
