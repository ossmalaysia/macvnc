# Security policy

MacVNC is an experimental native Rust Windows client for Apple's High Performance
Screen Sharing. Developed by [AnchorSprint](https://anchorsprint.com). Security
fixes are accepted for the current development branch; older experimental builds
do not have a separate maintenance commitment.

## Report a vulnerability privately

Use [GitHub private vulnerability reporting](https://github.com/ossbusinessmy/macvnc/security/advisories/new)
when available. Do not put passwords, keys, saved profiles, private hostnames,
desktop captures or exploitable vulnerability details in a public issue. If
private reporting is unavailable, open a public issue requesting a private
contact channel without disclosing the vulnerability. No response-time guarantee
or independent security audit is claimed.

## Credentials and local storage

- Authentication is attempted only against the configured Mac. Rejected logins
  are never automatically retried. The default host is blank.
- Windows DPAPI encrypts remembered passwords for the current OS account. New
  saved secrets bind the host, port and username inside the protected payload;
  changing those visible fields invalidates password reuse and auto-connect.
- Older profiles retain the remembered password but require an explicit Connect
  after checking the destination. Saving upgrades them to the bound format.
- Profile writes replace the previous file atomically. Profile and legacy
  encryption-state reads have size limits. Password buffers are zeroized where
  owned; this does not guarantee removal of all copies from process memory,
  operating-system paging or crash dumps.
- Host and username remain visible in the local profile. DPAPI does not protect
  against malicious software already running as the same Windows user.
- Forget replaces the native profile with an empty record so legacy credentials
  are not imported again. Older Electron files are left untouched.

## Network and decoder boundaries

- HP media packets are authenticated with SRTP and checked for replay before
  acceptance. Encrypted control traffic uses Apple's legacy AES-CBC protocol.
  Apple type-30 authentication does not provide modern server identity
  verification. Encryption is not a substitute for trusting the destination.
- Use a trusted network or a correctly configured private tunnel. Do not expose
  Screen Sharing directly to the public internet. HP needs its UDP media path
  as well as TCP; a TCP-only tunnel does not cover the full native session.
- Network lengths, packet queues and decoded image sizes are bounded. Malformed
  records fail closed. FFmpeg is C code accessed through an unsafe Rust ABI
  adapter; a memory-safe UI does not make the decoder memory-safe.
- FFmpeg is loaded from the application directory or the explicitly configured
  developer runtime directory. Keep executable and DLL directories trusted and
  retain replaceable DLLs and their license/source notices.
- The reverse-engineered protocol can change with macOS updates. Authentication,
  playback, input and recovery need separate live validation; passing offline
  tests does not establish interoperability or security on every Mac.

## Diagnostics and dependencies

There is no automatic upload of diagnostics. Opt-in `MACVNC_DIAGNOSTICS_PATH`
writes local aggregate timing and decoder counters; do not attach saved profiles,
raw traffic or private screen contents to issues. Review logs before sharing.
The developer website opens only when its link is clicked.

Rust and Node dependency versions are recorded in lockfiles. Use `cargo audit`
and `npm audit` for current advisory results; a clean scan only covers known
advisories in the scanned dependency set. FFmpeg and its bundled native libraries
require separate upstream review. There is no claim that all dependencies have
been independently audited.

Published binaries must include matching licenses and corresponding source
materials described in [THIRD_PARTY.md](docs/THIRD_PARTY.md). Builds are unsigned
unless a release explicitly states otherwise. A checksum detects changed bytes
but does not by itself establish publisher identity or a reproducible build.

## Legacy Electron implementation

`src/` and `test/` retain an Electron reference implementation. Its ordinary RFB
path does not encrypt screen/input traffic. Its threat model differs from the
native application. See [historical notes](docs/legacy-security.md); those notes
are not current native security guarantees.
