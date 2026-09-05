// CommonJS on purpose: Electron preload scripts are CJS even in an ESM project.
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('vnc', {
  connect: (opts) => ipcRenderer.invoke('vnc:connect', opts),
  disconnect: () => ipcRenderer.invoke('vnc:disconnect'),
  toggleFullscreen: () => ipcRenderer.invoke('vnc:toggleFullscreen'),
  loadCreds: () => ipcRenderer.invoke('creds:load'),
  saveCreds: (c) => ipcRenderer.invoke('creds:save', c),
  clearCreds: () => ipcRenderer.invoke('creds:clear'),
});

// Hand the MessagePort straight through to the page so the preload never sits on
// the per-frame data path. window.postMessage is the only way to move a port
// across the isolated-world boundary.
ipcRenderer.on('vnc-port', (event) => {
  window.postMessage({ type: 'vnc-port' }, '*', event.ports);
});

// HP (HEVC) viewer: forward access units + status to the page.
ipcRenderer.on('hp-au', (_e, au) => window.postMessage({ type: 'hp-au', au }, '*'));
ipcRenderer.on('hp-status', (_e, text) => window.postMessage({ type: 'hp-status', text }, '*'));
