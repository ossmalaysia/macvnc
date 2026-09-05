# Security Policy

## Reporting a vulnerability

Please report security issues privately via
[GitHub Security Advisories](https://github.com/jazztong/macvnc/security/advisories/new)
rather than a public issue. Include reproduction steps and the affected version or
commit. Expect an acknowledgement within a few days; this is a personal-time project,
so please allow reasonable time before public disclosure.

## Supported versions

Only the latest commit on `main` is supported. There are no release branches yet.

## What this software does with your data

Stated plainly, because this tool handles a macOS account password.

- **Your macOS credentials are used only to authenticate to the Mac you specify.**
  They are sent to that host and nowhere else. There is no telemetry, no analytics,
  no crash reporting, no cloud service, and no network destination other than the
  host and port you enter.
- **Passwords are encrypted at rest** with Electron's
  [`safeStorage`](https://www.electronjs.org/docs/latest/api/safe-storage) (Windows
  DPAPI / macOS Keychain / libsecret), scoped to your OS user account. The file in
  the app's `userData` directory stores only a base64 ciphertext for the password;
  host and username are stored in clear text so the form can prefill.
- **Credentials are never written to logs.** The DH shared secret, the derived MD5
  key, the AES record-layer keys, the SRTP master keys and the credential blob are
  all excluded from every logging path, including debug output.
- **"Forget" deletes the stored credential file.**

## Threat model and known risks

### RFB traffic is not encrypted
The standard VNC/RFB path transports framebuffer and input data **in the clear**.
Only the authentication handshake is cryptographically protected. Anyone able to
observe traffic between you and the Mac can reconstruct the screen and your
keystrokes.

**Use this on a trusted local network, or tunnel it over SSH or a VPN.** Do not
expose port 5900 to the internet.

### Authentication is real, and failures are real
Apple security type 30 authenticates against a genuine macOS account through
OpenDirectory. Every failed attempt is a real failed login on that Mac and can
contribute to account lockout and MDM alerting. The client therefore **never
auto-retries a rejected password**.

### The High Performance (HEVC) path is reverse-engineered and experimental
`src/rfb-hp/` implements Apple's undocumented high-performance protocol, ported
from an independent reverse-engineering reference. It is **not** an Apple-sanctioned
or specified interface. Consequences:

- It can break without warning on any macOS update.
- Its crypto (AES-128-CBC record layer, SRTP AES-256-CTR + HMAC-SHA1) is implemented
  from a reverse-engineered description. The SRTP layer **verifies** the server's
  HMAC on every packet and rejects mismatches, but this code has **not** been
  independently audited.
- The HP path is gated behind the `VNC_HP_PROBE` environment variable and is **not**
  enabled in normal use. It is developer-only. See "Limitations" in the README.
- It sends experimental control messages to the Mac. Only run it against a machine
  you own or administer.

### Electron hardening
- `contextIsolation: true`, `nodeIntegration: false` on every window.
- A strict `Content-Security-Policy` (`default-src 'none'; script-src 'self'; …`)
  is set on both renderer pages; no inline scripts, no remote code, no `connect-src`.
- The preload exposes a minimal, explicit API over `contextBridge` and never sits on
  the per-frame data path.
- **`sandbox: false`** — a known, deliberate weakening. The renderer needs Node-backed
  preload messaging for the `MessagePort` and HEVC access-unit transport. This is a
  gap: a renderer compromise would have a larger blast radius than with the sandbox
  on. Contributions to move to a sandboxed design are welcome.
- Renderers load only local `file://` content. The app makes no outbound HTTP requests.

### Untrusted input from the network
The client parses attacker-influenceable data (framebuffer rectangles, clipboard,
RTP/SRTP packets). Mitigations in place:
- Every `u32` length from the wire is bounds-capped before allocation (1 MiB
  clipboard, 64 KiB desktop name, 32 MiB zlib chunk); overflow aborts the connection.
- Decoders clip all writes to the framebuffer bounds.
- Unknown/unsizeable encodings terminate the update rather than guessing offsets.
- SRTP packets failing HMAC verification are dropped.

These reduce, but do not eliminate, memory-safety-adjacent risks in a hand-written
parser. This is JavaScript, so the failure mode is an exception or bad pixels rather
than memory corruption — but a malicious or compromised server could still cause a
denial of service.

## Dependency and supply-chain posture

- **Runtime dependencies: one** — [`pako`](https://github.com/nodeca/pako) (DEFLATE).
  A vendored copy of its ESM build lives at `src/vendor/pako.esm.mjs` so the browser
  worker can import it. Keep the vendored copy in sync when upgrading.
- **Build dependency: one** — `electron`.
- All cryptography used by the RFB path (MD5, AES-128-ECB, modular exponentiation) is
  implemented in-repo under `src/rfb/crypto/`, deliberately, so the portable protocol
  core has no crypto dependency. It is **cross-checked against Node's `crypto`** in
  the unit tests (RFC 1321 and FIPS-197 vectors, plus randomised differential tests).
  Hand-rolled crypto is a risk; these implementations are used **only** for Apple's
  legacy authentication scheme, which mandates exactly these primitives.

### Scan results (last reviewed 2026-09-05)

```
npm audit            -> 0 vulnerabilities (runtime and dev)
runtime dep tree     -> pako@2.2.0 only
secret scan          -> no credentials, keys or tokens in tracked files
electron             -> 44.2.0 (upgraded from 38.8.6 to clear a HIGH advisory:
                        use-after-free in offscreen child window paint callback)
CSP                  -> enforced on both renderer pages, no violations observed
```

Re-run with:

```bash
npm audit
npm ls --omit=dev --depth=1
npm test
```

## Hardening checklist for operators

1. Run on a trusted LAN, or tunnel over SSH/VPN. Never expose 5900 publicly.
2. Use a dedicated macOS account for screen sharing where practical.
3. Leave the HP (`VNC_HP_PROBE`) path off unless you are developing it.
4. Use **Forget** to remove stored credentials from a shared machine.
5. Keep `npm audit` clean and Electron current — most of this project's realistic
   attack surface is Chromium's.
