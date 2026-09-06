# Repository guidance

MacVNC is a native Rust Windows client for Apple's macOS Screen Sharing
(RFB 3.889, security type 30). Read `README.md`, `SECURITY.md`, and
`docs/CONTRACTS.md` before changing protocol behavior. HP mode is experimental;
preserve its compatibility and recovery checks.

## Architecture

- `rust/crates/hp-protocol/`: transport, authentication, encrypted records and metadata.
- `rust/crates/hp-media/`: SRTP, RTP depacketizing, HEVC decoding and compositing.
- `rust/crates/macvnc-app/`: native egui UI, input, backend and DPAPI profiles.

## Invariants

- Keep protocol and media crates free of UI, credential and platform dependencies.
- Bound network lengths, queues and image allocations; fail closed on malformed input.
- Keep credentials, keys and real desktop captures out of logs and git.
- Never auto-retry rejected authentication or connect without a usable saved password.

## Validation

- Run `cargo fmt --all --check`, `cargo test --workspace --locked`, and
  `cargo clippy --workspace --all-targets --locked -- -D warnings`.
- Package with `powershell -File scripts/build-rust.ps1 -Package`.
- Use synthetic fixtures by default. Live tests require authorization.
- Do not commit generated packages, temporary validation artifacts or credentials.
