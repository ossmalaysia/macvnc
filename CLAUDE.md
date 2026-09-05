# Contributor and coding-agent entry point

The current application is the native Rust HP client. Start with [README.md](README.md),
[AGENTS.md](AGENTS.md), [rust/AGENTS.md](rust/AGENTS.md) and [CONTRIBUTING.md](CONTRIBUTING.md).

- Native workspace: `rust/crates/`; run `cargo test --workspace --locked`.
- Native Windows package: `powershell -File scripts/build-rust.ps1 -Package`.
- Retained Electron reference: `src/`; `npm test` runs its offline tests.
- `npm start` launches the native app; `npm run start:electron` launches the reference.
- Read [SECURITY.md](SECURITY.md) before changing credentials, transport or decoding.
- Preserve third-party notices and consult [LICENSING.md](LICENSING.md).
- Never commit credentials, private captures, generated packages or validation output.
- Use synthetic fixtures by default; live connections require authorization.
