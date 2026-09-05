# Rust implementation

The user's full native Rust rewrite makes HP the primary mode for this app.
The older opt-in HP rule applies to the retained JavaScript reference, not the
new Rust binary. Do not claim HP playback is correct until native live validation.

- hp-protocol owns authentication and encrypted TCP control/HP negotiation.
- hp-media owns authenticated UDP, packet ordering, HEVC decode and compositing.
- macvnc-app owns the native egui UI, input, credentials and session integration.
- Root Cargo workspace owns dependency resolution and release profile.
- Never log or derive Debug for credentials, keys or decrypted control payloads.
- Authenticate packets before updating replay state; bound every network buffer.
- Request one complete HEVC picture per frame; multi-tile live output showed
  corruption. Do not re-enable multi-tile offers without visual regression checks.
  One shared HEVC decoder retains reference pictures. Frame
  geometry comes from negotiated display dimensions, not tile count multiplied
  by padded decoder height. Do not count decoded tiles as full screen FPS.
- Use bounded transport to the UI; keep the newest complete framebuffer.
- Keep all VCL slices belonging to an HEVC picture, including continuation slices.
  Require a first slice to establish picture completeness, not to filter later slices.
- Suppress decoder-concealed/error pictures. Keep the last good screen while waiting
  for a clean keyframe, and keep requesting recovery until that keyframe arrives.
  A new encoder generation must not reuse the previous generation's reference state.
- Windows credentials use OS DPAPI; missing secure storage must fail closed.
- Run cargo fmt --all --check, cargo test --workspace, cargo clippy --workspace
  --all-targets -- -D warnings, and release build before delivering.
- Native UI validation uses synthetic content; real desktop images stay out of git.
- Never auto-retry a rejected login. Report live validation separately from tests.
