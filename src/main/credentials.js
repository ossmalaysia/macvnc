import fs from 'node:fs';
import path from 'node:path';

/** Current profile plus the pre-rename fallback, both scoped to this app. */
export function credentialPaths(userData) {
  return [...new Set([
    path.join(userData, 'vnc-creds.json'),
    path.join(userData, '..', 'vnc-client', 'vnc-creds.json'),
  ].map(p => path.resolve(p)))];
}

export function loadCredentials(userData, safeStorage) {
  let rec;
  for (const file of credentialPaths(userData)) {
    try {
      rec = JSON.parse(fs.readFileSync(file, 'utf8'));
      break;
    } catch (err) {
      // A corrupt current profile must not resurrect an old login.
      if (err.code !== 'ENOENT') return null;
    }
  }
  if (!rec || typeof rec !== 'object' || Array.isArray(rec)) return null;
  let password = '';
  if (typeof rec.enc === 'string' && rec.enc) {
    try {
      if (safeStorage.isEncryptionAvailable()) {
        password = safeStorage.decryptString(Buffer.from(rec.enc, 'base64'));
      }
    } catch { /* Preserve non-secret fields when decryption is unavailable. */ }
  }
  return {
    host: rec.host || '', port: rec.port || 5900, username: rec.username || '',
    profile: rec.profile || '', password,
    autoConnect: !!rec.autoConnect && password.length > 0,
  };
}

export function saveCredentials(userData, safeStorage, c) {
  if (c.password && (!safeStorage.isEncryptionAvailable() ||
      safeStorage.getSelectedStorageBackend?.() === 'basic_text')) {
    throw new Error('Secure password storage is unavailable; credentials were not saved');
  }
  const rec = {
    host: c.host || '', port: Number(c.port) || 5900, username: c.username || '',
    profile: c.profile || '', autoConnect: !!c.autoConnect && !!c.password,
  };
  if (c.password) rec.enc = safeStorage.encryptString(String(c.password)).toString('base64');
  fs.writeFileSync(credentialPaths(userData)[0], JSON.stringify(rec), { mode: 0o600 });
}

export function clearCredentials(userData) {
  // Otherwise loadCredentials would bring back the pre-rename password.
  for (const file of credentialPaths(userData)) fs.rmSync(file, { force: true });
}
