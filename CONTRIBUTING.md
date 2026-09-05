# Contributing to MacVNC

MacVNC's active application is the experimental native Rust HP client. The
JavaScript/Electron implementation remains as a protocol reference and has its
own tests. Open an issue before a large architectural change so its scope and
compatibility can be discussed.

## Get started

Follow [the README](README.md#build-and-run-windows-x64) for Windows x64 setup,
Rust, the Visual Studio C++ tools, and FFmpeg runtime DLLs. Run commands from the
repository root. Node is not needed to build the native application.

Read [repository guidance](AGENTS.md), [Rust guidance](rust/AGENTS.md), and the
guidance in the crate you change. Read [SECURITY.md](SECURITY.md) before changing
authentication, transport, credentials, or decoder boundaries. Changes to the
legacy protocol also need [its contracts](docs/CONTRACTS.md).

## Validate your change

The native checks are:

```powershell
cargo fmt --all --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
```

Add a regression fixture for a protocol, input, or lifecycle bug. Prefer synthetic
wire data and small, deterministic examples. When changing decoder behavior, run
the synthetic native decoder test with `MACVNC_FFMPEG_DIR` set as described in
the README:

```powershell
cargo test -p hp-media --test native_decode --locked -- --ignored
```

For UI changes, run `cargo run -p macvnc-app -- --smoke-ui` and inspect the native
window. `--smoke-ui-seconds 30` keeps that synthetic view open longer.
`--no-autoconnect` opens the normal form without connecting on launch. A browser
fixture does not validate the native window or a real HP session.

For packaging changes, run `powershell -File scripts/build-rust.ps1 -Package`
and check the portable folder with its DLLs, notices, and source materials.
Legacy JavaScript changes additionally need `npm ci` and `npm test`; those tests
do not cover the Rust application.

Live testing is optional for ordinary contributions. Only connect to a Mac you
own or are authorized to test, and use your own locally configured profile. Do
not retry rejected passwords automatically. Report what you actually tested;
distinguish synthetic checks, native decoding, and live connection results.

## Submit a pull request

Describe the observed problem, resulting behavior, and relevant validation.
Include limitations and skipped checks with their reasons. Performance claims
need a repeatable workload and measurement definition: the UI's frame submission
count, decoder throughput, TCP RTT, and input-to-screen latency differ.

Do not commit credentials, encrypted credential profiles, key material, packet
captures from private sessions, private desktop images, `dist/`, `target/`, or
temporary validation output. Before posting diagnostics, remove addresses,
hostnames, account names, tokens, and local paths containing personal information.
Use synthetic images when showing a rendering defect.

Preserve upstream notices and record the origin and license of added code or
assets. The native executable is not MIT-only; review
[licenses and provenance](docs/THIRD_PARTY.md). Dependency or codec changes must
also update the matching package notices and source materials. Submit only work
you have the right to contribute under the applicable license.

Report suspected vulnerabilities through the private route in
[SECURITY.md](SECURITY.md#report-a-vulnerability-privately), not a public bug report.

Run `node scripts/check-public-files.mjs` before submitting to catch common
private/generated files and token formats. This is a limited working-tree check;
review binary assets and Git history separately before making a private repo public.
Read [LICENSING.md](LICENSING.md) before contributing: proposed future commercial
terms are not current license restrictions or a contributor license agreement.
