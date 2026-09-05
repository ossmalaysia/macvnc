import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
const source = fs.readFileSync(new URL('../../src/renderer/app.js', import.meta.url), 'utf8').replace(/import\s*\{[\s\S]*?\}\s*from[^;]+;/, '');
function app(bridge) {
  const elements = new Map();
  const el = id => {
    if (!elements.has(id)) elements.set(id, { value: '', checked: false, disabled: false, style: {}, dataset: {}, classList: { add() {}, remove() {} }, addEventListener() {}, focus() {}, getContext() { return {}; } });
    return elements.get(id);
  };
  const ctx = vm.createContext({ document: { getElementById: el, body: el('body'), addEventListener() {} }, window: { vnc: bridge, addEventListener() {} }, ResizeObserver: class { observe() {} }, PROFILE_CTRL_AS_CMD: 'ctrl-as-cmd', PROFILE_NATIVE: 'native', MODIFIER_KEYSYMS: [], keysymForDomKey() {}, console });
  vm.runInContext(source, ctx);
  el('host').value = 'localhost'; el('port').value = '5900';
  return { el, run: code => vm.runInContext(code, ctx) };
}
test('DesktopSize updates backing canvas dimensions', () => {
  const a = app();
  a.run("onWorkerMessage({data:{kind:'resize',width:1920,height:1080}})");
  assert.equal(a.el('screen').width, 1920); assert.equal(a.el('screen').height, 1080);
});
test('authentication failure survives subsequent socket close', () => {
  const a = app();
  a.run("applyStatus('auth-failed', 'Denied'); applyStatus('disconnected', 'closed')");
  assert.equal(a.el('state').textContent, 'Error'); assert.equal(a.el('errtext').textContent, 'Denied');
});
test('missing preload with Remember checked reports a useful error', async () => {
  const a = app(); a.el('remember').checked = true; await a.run('doConnect()');
  assert.match(a.el('errtext').textContent, /Preload bridge unavailable/);
});
test('non-numeric suffixes are rejected before connecting', async () => {
  let calls = 0; const a = app({ connect() { calls++; } }); a.el('port').value = '5900oops';
  await a.run('doConnect()'); assert.equal(calls, 0); assert.match(a.el('errtext').textContent, /Invalid port/);
});
test('IPC connection failure is displayed', async () => {
  const a = app({ connect: async () => ({ ok: false, error: 'Connection refused' }) });
  await a.run('doConnect()'); assert.equal(a.el('errtext').textContent, 'Connection refused');
});
test('save failure is displayed and prevents a connection attempt', async () => {
  let calls = 0; const a = app({ saveCreds: async () => ({ ok: false, error: 'Storage unavailable' }), connect() { calls++; } });
  a.el('remember').checked = true; await a.run('doConnect()');
  assert.equal(calls, 0); assert.equal(a.el('errtext').textContent, 'Storage unavailable');
});
