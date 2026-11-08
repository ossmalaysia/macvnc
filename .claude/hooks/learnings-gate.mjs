#!/usr/bin/env node
// Stop hook (ported from EzyChat Lite): before Claude finishes a turn that changed code, make sure
// lessons from the run were recorded in docs/LEARNINGS.md. Blocks the stop once with
// instructions; never loops (stop_hook_active) and stays silent for turns that changed nothing.
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

const LEARNINGS = 'docs/LEARNINGS.md';

let input = {};
try {
  input = JSON.parse(readFileSync(0, 'utf8') || '{}');
} catch {
  /* no stdin */
}
if (input.stop_hook_active) process.exit(0);

const git = (...args) => {
  try {
    return execFileSync('git', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
  } catch {
    return '';
  }
};

const changed = git('status', '--porcelain')
  .split('\n')
  .map((l) => l.slice(3).trim())
  .filter(Boolean);
if (changed.includes(LEARNINGS)) process.exit(0); // already being recorded this run

const lastLearnings = git('log', '-1', '--format=%H', '--', LEARNINGS);
const commitsSince = lastLearnings
  ? git('rev-list', '--count', `${lastLearnings}..HEAD`)
  : git('rev-list', '--count', 'HEAD');
const codeChanged = changed.some((f) => !f.startsWith('docs/')) || Number(commitsSince || 0) > 0;
if (!codeChanged) process.exit(0);

process.stdout.write(
  JSON.stringify({
    decision: 'block',
    reason:
      `Before finishing: if this run taught a real, re-usable lesson, record it in ${LEARNINGS} as one short ` +
      'rule bullet in the matching section (or sharpen an existing bullet instead of adding a near-duplicate). ' +
      'The file is a compact summary: no dated stories, no "no new lessons" filler. If nothing new was learned, ' +
      'say so and finish. If a lesson changes how agents must work in this repo, also update AGENTS.md.',
  }),
);
