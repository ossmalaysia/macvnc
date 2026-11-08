# Contributor and coding-agent entry point

MacVNC is the native Rust HP client. Start with [README.md](README.md),
[AGENTS.md](AGENTS.md), [rust/AGENTS.md](rust/AGENTS.md), and
[CONTRIBUTING.md](CONTRIBUTING.md).

- Run `cargo test --workspace --locked` for the full test suite.
- Package with `powershell -File scripts/build-rust.ps1 -Package`.
- Read [SECURITY.md](SECURITY.md) before changing credentials, transport or decoding.
- Preserve third-party notices and consult [LICENSING.md](LICENSING.md).
- Never commit credentials, private captures, generated packages or validation output.
- Use synthetic fixtures by default; live connections require authorization.
- Record re-usable lessons in [docs/LEARNINGS.md](docs/LEARNINGS.md). Hooks in `.claude/settings.json`
  remind after failed tool calls and CI log reads, and a Stop hook blocks finishing a code-changing
  turn until the file is updated (Node.js required).
