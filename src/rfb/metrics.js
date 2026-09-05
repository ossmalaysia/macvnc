// Frame-pacing metrics — the engineering definition of "smoothness".
//
// An average frame rate hides stutter: 30 fps with even pacing feels smooth,
// 30 fps that stalls 200 ms once a second feels broken. So we report the
// distribution of frame INTERVALS (p50/p95/p99, max) and jitter, not just a mean.
//
// Pure and dependency-free so it runs in the worker, the main process, and tests.

/** Exact-ish percentile over a sorted copy (linear interpolation between ranks). */
export function percentile(sortedAsc, p) {
  const n = sortedAsc.length;
  if (n === 0) return 0;
  if (n === 1) return sortedAsc[0];
  const rank = (p / 100) * (n - 1);
  const lo = Math.floor(rank);
  const hi = Math.ceil(rank);
  if (lo === hi) return sortedAsc[lo];
  return sortedAsc[lo] + (sortedAsc[hi] - sortedAsc[lo]) * (rank - lo);
}

export class FrameMetrics {
  /**
   * @param {object} [opts]
   * @param {number} [opts.capacity]   ring size for retained intervals
   * @param {number} [opts.stallMs]    an interval at/above this counts as a stall
   * @param {number} [opts.tiles]      decoded pictures per source frame (HP tiles);
   *                                   frames are counted per SOURCE frame, not per tile
   */
  constructor({ capacity = 600, stallMs = 100, tiles = 1 } = {}) {
    this.capacity = capacity;
    this.stallMs = stallMs;
    this.tiles = Math.max(1, tiles | 0);
    this.reset();
  }

  reset() {
    this.intervals = [];
    this.lastT = null;
    this.frames = 0;      // source frames
    this.subFrames = 0;   // raw decoded pictures (tiles)
    this.stalls = 0;
    this.dropped = 0;
    this.firstT = null;
  }

  /** Count one decoded picture. Only every `tiles`-th one closes a source frame. */
  onDecoded(tNowMs) {
    this.subFrames += 1;
    if (this.subFrames % this.tiles !== 0) return;
    this.onFrame(tNowMs);
  }

  /** Count one completed SOURCE frame presented at tNowMs. */
  onFrame(tNowMs) {
    this.frames += 1;
    if (this.firstT === null) this.firstT = tNowMs;
    if (this.lastT !== null) {
      const dt = tNowMs - this.lastT;
      this.intervals.push(dt);
      if (this.intervals.length > this.capacity) this.intervals.shift();
      if (dt >= this.stallMs) this.stalls += 1;
    }
    this.lastT = tNowMs;
  }

  /** Frames the pipeline discarded (queue overflow, decode error, etc). */
  onDropped(n = 1) {
    this.dropped += n;
  }

  /**
   * @returns {{frames:number,seconds:number,fps:number,mean:number,p50:number,
   *            p95:number,p99:number,max:number,jitter:number,stalls:number,
   *            dropped:number,dropRate:number}}
   * All times in milliseconds. `jitter` is the stddev of frame intervals —
   * the single best scalar for "does this feel even".
   */
  summary() {
    const iv = this.intervals;
    const n = iv.length;
    const seconds = this.firstT !== null && this.lastT !== null
      ? (this.lastT - this.firstT) / 1000 : 0;
    if (n === 0) {
      return { frames: this.frames, seconds, fps: 0, mean: 0, p50: 0, p95: 0,
        p99: 0, max: 0, jitter: 0, stalls: this.stalls, dropped: this.dropped, dropRate: 0 };
    }
    const mean = iv.reduce((a, b) => a + b, 0) / n;
    const variance = iv.reduce((a, b) => a + (b - mean) * (b - mean), 0) / n;
    const sorted = [...iv].sort((a, b) => a - b);
    const presented = this.frames;
    const dropRate = presented + this.dropped > 0
      ? this.dropped / (presented + this.dropped) : 0;
    return {
      frames: this.frames,
      seconds,
      fps: seconds > 0 ? this.frames / seconds : 0,
      mean,
      p50: percentile(sorted, 50),
      p95: percentile(sorted, 95),
      p99: percentile(sorted, 99),
      max: sorted[sorted.length - 1],
      jitter: Math.sqrt(variance),
      stalls: this.stalls,
      dropped: this.dropped,
      dropRate,
    };
  }

  /** One-line human summary for logs/HUD. */
  format() {
    const s = this.summary();
    return `${s.fps.toFixed(1)}fps  p50 ${s.p50.toFixed(1)}ms  p95 ${s.p95.toFixed(1)}ms  ` +
      `p99 ${s.p99.toFixed(1)}ms  max ${s.max.toFixed(0)}ms  jitter ${s.jitter.toFixed(1)}ms  ` +
      `stalls ${s.stalls}  dropped ${s.dropped}`;
  }
}

/**
 * Latency tracker: time from an input/change being emitted to the frame that
 * reflects it. Feed it (id, tSent) then (id, tSeen).
 */
export class LatencyMetrics {
  constructor({ capacity = 300 } = {}) {
    this.capacity = capacity;
    this.pending = new Map();
    this.samples = [];
  }
  mark(id, tSentMs) { this.pending.set(id, tSentMs); }
  complete(id, tSeenMs) {
    const t0 = this.pending.get(id);
    if (t0 === undefined) return null;
    this.pending.delete(id);
    const rtt = tSeenMs - t0;
    this.samples.push(rtt);
    if (this.samples.length > this.capacity) this.samples.shift();
    return rtt;
  }
  summary() {
    const n = this.samples.length;
    if (n === 0) return { n: 0, mean: 0, p50: 0, p95: 0, max: 0 };
    const sorted = [...this.samples].sort((a, b) => a - b);
    const mean = this.samples.reduce((a, b) => a + b, 0) / n;
    return { n, mean, p50: percentile(sorted, 50), p95: percentile(sorted, 95), max: sorted[n - 1] };
  }
}
