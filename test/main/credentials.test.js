import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { credentialPaths, loadCredentials, saveCredentials, clearCredentials } from '../../src/main/credentials.js';
function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'macvnc-test-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const dir = path.join(root, 'macvnc');
  fs.mkdirSync(dir); fs.mkdirSync(path.join(root, 'vnc-client'));
  return dir;
}
const secure = { isEncryptionAvailable: () => true, encryptString: s => Buffer.from(s), decryptString: b => b.toString() };
test('missing or undecryptable passwords never auto-connect', t => {
  const dir = fixture(t);
  for (const rec of [{}, { enc: 'dGVzdA==' }]) {
    fs.writeFileSync(credentialPaths(dir)[0], JSON.stringify({ host: 'test', autoConnect: true, ...rec }));
    const loaded = loadCredentials(dir, { isEncryptionAvailable: () => false });
    assert.equal(loaded.host, 'test'); assert.equal(loaded.password, ''); assert.equal(loaded.autoConnect, false);
  }
});
test('Forget removes current and legacy profiles, without resurrection', t => {
  const dir = fixture(t);
  for (const p of credentialPaths(dir)) fs.writeFileSync(p, JSON.stringify({ host: 'test' }));
  clearCredentials(dir);
  assert.equal(loadCredentials(dir, secure), null);
});
test('secure storage failure preserves the existing profile', t => {
  const dir = fixture(t);
  saveCredentials(dir, secure, { host: 'test', password: 'fixture', autoConnect: true });
  const before = fs.readFileSync(credentialPaths(dir)[0], 'utf8');
  for (const storage of [{ isEncryptionAvailable: () => false }, { ...secure, getSelectedStorageBackend: () => 'basic_text' }]) {
    assert.throws(() => saveCredentials(dir, storage, { password: 'new' }), /unavailable/);
    assert.equal(fs.readFileSync(credentialPaths(dir)[0], 'utf8'), before);
  }
  assert.equal(loadCredentials(dir, secure).autoConnect, true);
});
test('corrupt current profile does not fall back to stale credentials', t => {
  const dir = fixture(t); const [current, legacy] = credentialPaths(dir);
  fs.writeFileSync(current, 'null'); fs.writeFileSync(legacy, JSON.stringify({ host: 'old' }));
  assert.equal(loadCredentials(dir, secure), null);
});
