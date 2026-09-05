# Security and public-source preparation — 2026-09-05

Scope: MacVNC v0.1.5 native Rust application, native distribution
metadata, contributor documentation and build workflows. This is a development
review, not an independent penetration test or a guarantee of security.

## Changes

- Saved DPAPI secrets bind host, port and account. Profile changes invalidate
  reuse, older formats require explicit connection before upgrade, and bounded
  reads plus atomic replacement protect saved-profile handling. Temporary
  decrypted buffers are zeroized where owned.
- Authentication temporaries and AES schedules are cleared on drop. Control
  verification failures poison the record state; invalid lengths return errors.
  Handshake deadlines and protobuf/decompression work limits bound peer input.
- Windows codec dependencies load only from the chosen absolute codec directory
  and System32. Frame sizes use checked arithmetic and fallible RGBA allocation.
  Pending compressed video is capped at 32 MiB; oversized datagrams are rejected.
- Contributor/issue/PR guidance excludes credentials and private captures.
  Current security guidance is separated from historical notes.
  AnchorSprint branding preserves existing notices and upstream attribution.
- GitHub actions are pinned to commits, dependency update checks are configured,
  and tagged release output is drafted for review. FFmpeg source-material
  downloads now verify committed SHA-256 values as well as the runtime archive.
- Source hygiene checks report file/line locations without printing secret
  matches. Generated files and common credential filenames are ignored. The
  check does not scan binary contents or establish that Git history is clean.

## Verification

69 Rust unit tests and four native FFmpeg tests pass. The 114 retained JavaScript
tests pass. Formatting and strict Clippy pass. Tests include destination tampering,
legacy password handling, oversized profiles, malformed records, decompression
bounds, invalid frame sizes and codec loading restrictions.

The release build and portable package succeeded. Synthetic native UI inspection
verified the AnchorSprint footer; Windows metadata reports AnchorSprint and
version 0.1.5. One authorized 30-second live connection authenticated and produced
530 screen updates with zero decoder/reference errors and no pending recovery
at completion. No rejected-login retries occurred.

The non-ignored source hygiene check found no matches. A separate limited token
and private-key pattern scan covered 25 available commits in the non-shallow
local repository with no matches. This is not an exhaustive secret or private-data
audit, and neither scan examines private content inside binary assets.

`npm audit` reported zero vulnerabilities. `cargo audit` reported zero known
vulnerabilities and two informational unmaintained-package warnings:

- `paste 1.0.15`: [RUSTSEC-2024-0436](https://rustsec.org/advisories/RUSTSEC-2024-0436.html).
  Present in the lockfile; not shown in the current enabled dependency tree.
- `ttf-parser 0.25.1`: [RUSTSEC-2026-0192](https://rustsec.org/advisories/RUSTSEC-2026-0192.html).
  Reached through egui's font stack. A compatible upstream replacement is pending.

These advisory checks do not audit the bundled FFmpeg native dependencies.
No warnings were hidden with blanket ignores.

## Remaining limits and release decisions

The codec ABI still uses unsafe code and FFmpeg remains a native attack surface.
DPAPI trusts the current OS account; the directory selected for DLLs must be
trusted. DH bigint operations remain variable-time and do not guarantee erasure
of internal allocations. Legacy Apple authentication lacks modern server identity.
Memory caps are per subsystem, not a total process memory quota.

Public source preparation does not publish the repository, enable GitHub private
reporting/secret protection, comprehensively audit history, sign binaries, or establish
complete corresponding-source coverage for optional libraries in FFmpeg's binary
distribution. Those remaining checks must precede public binary distribution.

The proposed restricted commercial model in [LICENSING.md](../LICENSING.md) is
not an operative license. Current AGPL/MIT grants remain applicable. Resolve
rights for AGPL-derived code before offering a restricted edition; retain
third-party copyright notices under every model.
