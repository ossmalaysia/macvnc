// CommonJS on purpose: Electron preload scripts are CJS even in an ESM project.
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('vnc', {
  connect: (opts) => ipcRenderer.invoke('vnc:connect', opts),
  disconnect: () => ipcRenderer.invoke('vnc:disconnect'),
  toggleFullscreen: () => ipcRenderer.invoke('vnc:toggleFullscreen'),
});

// Hand the MessagePort straight through to the page so the preload never sits on
// the per-frame data path. window.postMessage is the only way to move a port
// across the isolated-world boundary.
ipcRenderer.on('vnc-port', (event) => {
  window.postMessage({ type: 'vnc-port' }, '*', event.ports);
});
