// A bounded working-tree hygiene check, not a complete secret/history audit.
// Never print matched values: reports identify only the file and line.
import { execFileSync } from 'node:child_process';
import { readFileSync, lstatSync } from 'node:fs';

const files = [...new Set(execFileSync('git', ['ls-files', '-z', '--cached', '--others', '--exclude-standard'], { encoding: 'utf8' }).split('\0').filter(Boolean))];
const forbidden = /(^|\/)(\.validation|dist|target|node_modules|runtime)(\/|$)|(^|\/)(rust-profile\.json|vnc-creds\.json|Local State|\.env(?:\..*)?)$|\.(?:pem|key|p12|pfx)$/i;
const patterns = [
  /-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/,
  /\bgh[pousr]_[A-Za-z0-9]{30,}\b/,
  /\bgithub_pat_[A-Za-z0-9_]{40,}\b/,
  /\bAKIA[0-9A-Z]{16}\b/,
  /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/,
];
let issues = 0;
for (const file of files) {
  const exampleEnv = file.endsWith('/.env.example') || file === '.env.example';
  if (forbidden.test(file) && !exampleEnv) {
    console.error(`${file}: private/generated file must not be published`); issues++; continue;
  }
  let stat;
  try { stat = lstatSync(file); } catch { continue; } // tracked file deleted locally
  if (stat.isSymbolicLink()) {
    console.error(`${file}: review symlink before publishing`); issues++; continue;
  }
  if (!stat.isFile()) continue;
  if (stat.size > 5 * 1024 * 1024) {
    console.error(`${file}: file exceeds public source review size limit`); issues++; continue;
  }
  const bytes = readFileSync(file);
  if (bytes.includes(0)) continue; // binary assets require separate manual review
  bytes.toString('utf8').split(/\r?\n/).forEach((line, index) => {
    if (patterns.some(pattern => pattern.test(line))) {
      console.error(`${file}:${index + 1}: possible secret (value redacted)`); issues++;
    }
  });
}
console.log(`Checked ${files.length} non-ignored source files; ${issues} hygiene findings. Binary contents and Git history are not scanned.`);
process.exitCode = issues ? 1 : 0;
