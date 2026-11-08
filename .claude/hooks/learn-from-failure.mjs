#!/usr/bin/env node
// PostToolUseFailure / PostToolUse hook: when a tool call fails, or CI logs are read, remind the
// agent to record the lesson in docs/LEARNINGS.md while the cause is fresh. Reminds once per
// distinct failure per session so repeated retries do not flood the context. Never blocks.
import { readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';

let input = {};
try {
  input = JSON.parse(readFileSync(0, 'utf8') || '{}');
} catch {
  process.exit(0);
}
const event = input.hook_event_name || 'PostToolUseFailure';
const tool = String(input.tool_name || '');
const isCiLog = /get_job_logs/.test(tool);
if (event === 'PostToolUse' && !isCiLog) process.exit(0);

// What failed, in one line: the error text, else the command or file the tool acted on.
const firstLine = (v) => String(v || '').split('\n').find((l) => l.trim()) || '';
const detail = firstLine(input.error) || firstLine(input.tool_input?.command) ||
  firstLine(input.tool_input?.file_path) || firstLine(input.tool_input?.job_id);
const key = createHash('sha256').update(`${tool}\0${detail.slice(0, 200)}`).digest('hex').slice(0, 16);

const seenFile = join(tmpdir(), `macvnc-learn-${String(input.session_id || 'none').replace(/\W/g, '')}.json`);
let seen = [];
try {
  seen = JSON.parse(readFileSync(seenFile, 'utf8'));
} catch {
  /* first reminder this session */
}
if (seen.includes(key)) process.exit(0);
try {
  writeFileSync(seenFile, JSON.stringify([...seen, key].slice(-200)));
} catch {
  /* reminder still useful without dedupe */
}

const what = isCiLog ? 'You just read CI logs' : `${tool} just failed${detail ? ` (${detail.slice(0, 160)})` : ''}`;
process.stdout.write(
  JSON.stringify({
    hookSpecificOutput: {
      hookEventName: event,
      additionalContext:
        `${what}. Once you know the root cause, if it is a re-usable lesson (a tool, toolchain, ` +
        'protocol or process trap that could bite again), record it in docs/LEARNINGS.md as one ' +
        'short rule bullet in the matching section (`rule — why`), or sharpen an existing bullet. ' +
        'Skip one-off typos and transient network errors.',
    },
  }),
);
