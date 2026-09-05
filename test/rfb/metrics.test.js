import test from 'node:test';
import assert from 'node:assert/strict';
import { FrameMetrics, LatencyMetrics, percentile } from '../../src/rfb/metrics.js';

const close = (a, b, eps = 1e-6) => assert.ok(Math.abs(a - b) < eps, `${a} !~= ${b}`);

test('percentile: exact ranks and interpolation', () => {
  const s = [10, 20, 30, 40, 50];
  close(percentile(s, 0), 10);
  close(percentile(s, 50), 30);
  close(percentile(s, 100), 50);
  close(percentile([10, 20], 50), 15); // interpolates between ranks
  close(percentile([], 50), 0);
  close(percentile([7], 99), 7);
});

test('perfectly even 60fps: fps correct, jitter zero, no stalls', () => {
  const m = new FrameMetrics();
  for (let i = 0; i <= 60; i++) m.onFrame(i * (1000 / 60)); // 61 frames over 1s
  const s = m.summary();
  close(s.frames, 61);
  close(s.jitter, 0, 1e-9);            // even pacing => zero jitter
  close(s.p50, 1000 / 60, 1e-9);
  close(s.p99, 1000 / 60, 1e-9);
  assert.equal(s.stalls, 0);
  assert.ok(Math.abs(s.fps - 61) < 0.001, `fps ${s.fps}`); // 61 frames across exactly 1.0s
});

test('a RARE stall is caught by max/stalls/jitter — but NOT by p99', () => {
  const m = new FrameMetrics({ stallMs: 100 });
  let t = 0;
  for (let i = 0; i < 100; i++) { m.onFrame(t); t += 10; }  // 100 frames @10ms
  m.onFrame(t + 300);                                        // ONE 300ms stall
  const s = m.summary();
  assert.equal(s.stalls, 1, 'stall counted');
  close(s.max, 310);
  assert.ok(s.p50 <= 10.0001, `p50 ${s.p50} stays at the healthy median`);
  // The mean barely moves — why a mean alone is a bad smoothness metric.
  assert.ok(s.mean < 14, `mean ${s.mean} hides the stall`);
  assert.ok(s.jitter > 25, `jitter ${s.jitter} exposes it`);
  // Honest limitation: 1 outlier in 100 samples is BELOW the 99th percentile, so
  // p99 cannot see it. Only max/stalls/jitter can. Don't trust p99 alone for rare hitches.
  assert.ok(s.p99 < 100, `p99 ${s.p99} provably cannot catch a 1-in-100 stall`);
});

test('a stall rate above 1% IS caught by p99', () => {
  const m = new FrameMetrics({ stallMs: 100 });
  let t = 0;
  for (let i = 0; i < 100; i++) {          // 5 stalls in 100 => 5% > 1%
    m.onFrame(t);
    t += (i % 20 === 19) ? 300 : 10;
  }
  const s = m.summary();
  // 5 long gaps were scheduled, but the final frame's gap never becomes an
  // interval (no frame follows it) — N frames yield N-1 intervals.
  assert.equal(s.stalls, 4);
  assert.equal(m.intervals.length, 99);
  assert.ok(s.p99 > 100, `p99 ${s.p99} now exposes the stalls`);
  assert.ok(s.p50 <= 10.0001, 'median still healthy');
});

test('two streams with the SAME fps are ranked by jitter, not rate', () => {
  const even = new FrameMetrics();
  const stuttery = new FrameMetrics({ stallMs: 100 });
  // Both: 30 frames in 1000ms => same fps.
  for (let i = 0; i < 30; i++) even.onFrame(i * (1000 / 30));
  let t = 0;
  for (let i = 0; i < 30; i++) {           // bursts of 5ms then a 150ms gap
    stuttery.onFrame(t);
    t += (i % 10 === 9) ? 150 : (850 / 27);
  }
  const a = even.summary(), b = stuttery.summary();
  assert.ok(Math.abs(a.fps - b.fps) < 6, 'comparable frame rates');
  assert.ok(b.jitter > a.jitter * 5, `stuttery jitter ${b.jitter} >> even ${a.jitter}`);
  assert.ok(b.p95 > a.p95 * 2, 'p95 separates them');
  assert.ok(b.stalls > 0 && a.stalls === 0);
});

test('tiles: 4 decoded pictures make ONE source frame (the 113fps mistake)', () => {
  const m = new FrameMetrics({ tiles: 4 });
  // 4 tiles per source frame, 40 source frames over 1s.
  for (let f = 0; f < 40; f++) {
    for (let tIdx = 0; tIdx < 4; tIdx++) m.onDecoded(f * 25);
  }
  const s = m.summary();
  assert.equal(m.subFrames, 160, 'raw decoded pictures');
  assert.equal(s.frames, 40, 'source frames, NOT 160');
  // Counting tiles as frames would have claimed 4x the real rate.
  assert.ok(s.frames * 4 === m.subFrames);
});

test('dropped frames feed a drop rate', () => {
  const m = new FrameMetrics();
  for (let i = 0; i < 90; i++) m.onFrame(i * 10);
  m.onDropped(10);
  const s = m.summary();
  assert.equal(s.dropped, 10);
  close(s.dropRate, 10 / 100);
});

test('empty and single-frame metrics do not throw or divide by zero', () => {
  const m = new FrameMetrics();
  let s = m.summary();
  assert.equal(s.fps, 0); assert.equal(s.jitter, 0); assert.equal(s.p95, 0);
  m.onFrame(1000);
  s = m.summary();
  assert.equal(s.frames, 1);
  assert.equal(s.fps, 0, 'one frame spans no time');
});

test('reset clears all state', () => {
  const m = new FrameMetrics();
  for (let i = 0; i < 10; i++) m.onFrame(i * 16);
  m.onDropped(3);
  m.reset();
  const s = m.summary();
  assert.equal(s.frames, 0); assert.equal(s.dropped, 0); assert.equal(s.max, 0);
});

test('LatencyMetrics pairs marks with completions', () => {
  const l = new LatencyMetrics();
  l.mark('a', 100); l.mark('b', 200);
  assert.equal(l.complete('a', 145), 45);
  assert.equal(l.complete('b', 260), 60);
  assert.equal(l.complete('missing', 999), null, 'unknown id yields null');
  const s = l.summary();
  assert.equal(s.n, 2);
  close(s.mean, 52.5);
  close(s.max, 60);
});
