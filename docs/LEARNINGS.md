# Learnings

Rules learned from building, releasing and running MacVNC, so agents (and humans) don't repeat mistakes.
This file is a compact summary; the dated history lives in git (`git log -p docs/LEARNINGS.md`).

**Adding a lesson:** add one short rule bullet to the matching section (`rule — why`), or sharpen an
existing bullet instead of adding a near-duplicate. No dated stories, no "no new lessons" filler.
Claude Code hooks enforce the loop (`.claude/settings.json`): a failed tool call or a CI log read
injects a reminder to record its lesson here, and a Stop hook blocks finishing a code-changing turn
until this file changes. Promote anything that changes _how_ agents work into AGENTS.md.

## Input and keyboard

- egui merges left/right Ctrl and drops the Windows key on Windows; read the sides with
  `GetKeyState(VK_LCONTROL/VK_RCONTROL/VK_LWIN/VK_RWIN)` and keep egui's combined `ctrl` flag
  authoritative — a stale side reading must never latch a modifier on the Mac.
- egui turns Ctrl+C/X/V into `Event::Copy/Cut/Paste` and swallows the letter key; any shortcut that
  must reach the Mac as a key (Control-C in Terminal) has to be rebuilt from those events.
- egui eats Ctrl +, − and 0 for its own zoom unless `options.zoom_with_keyboard = false`.
- Verify a user's "it still doesn't work" against the build they ran first: a fix on a PR branch is
  not in any installed release (v0.1.8 had no updater, so it never received later fixes).

## Apple protocol

- Mac → viewer clipboard: send `0x15` (cmd 1) once, fetch with an **8-byte** `0x0b` on a `0x14`
  status-2 notice (9 bytes desynchronises the Mac's parser), and reassemble `0x1f` across records —
  continuation records carry no type byte, so route them before the file/metadata decoders.
- Apple's pasteboard zlib stream ends with a sync flush and no final block: inflate with
  `FlushDecompress::Sync`, not a read-to-end decoder that expects `StreamEnd`.
- A malformed or oversized optional message (clipboard) is skipped, never a session error; skip an
  oversized multi-record message byte-for-byte without buffering it.

- Mid-session resize is the connect-time `0x1d` display configuration sent again (dynamic flag,
  type 4, reserved 7); the Mac answers with a new layout and the existing re-offer path rebuilds
  the stream. Debounce window drags (settle 0.5 s, ≥32 px, ≥2.5 s apart): each request restarts
  the Mac's encoder.

## Build, CI and dependencies

- CI's Rust/Clippy can be newer than the local toolchain (1.99 vs 1.97 flagged
  `chunks_exact_to_as_chunks`); prefer `as_chunks::<N>()` and expect new lints to appear only in CI.
- Windows-only code (`#[cfg(windows)]`, FFI) is not compiled by Linux checks: run
  `cargo clippy --target x86_64-pc-windows-gnu --all-targets -- -D warnings` (mingw-w64) before pushing.
- The Linux synthetic UI check (`--smoke-ui` under `xvfb-run`) needs `libxkbcommon-x11-0`; without
  it winit panics before the app starts — install it rather than reading that as a regression.
- `cargo audit` failures come from `Cargo.lock`, so they fail on `main` too; fix them by upgrading
  (`zip` 4→9 changed `ZipFile::name()` to return `Result`), not by waiting.

## Installer and releases

- Windows makensis does not expand `${SOURCE}/*.*` after a Windows path; Linux makensis needs `/`.
  Use the host separator (`NSIS_WIN32_MAKENSIS`) for `File` wildcards only.
- Official Windows NSIS ships only the x86 stub; build a `/DAMD64` installer with Linux makensis to
  test silent install/uninstall under 64-bit Wine (`wine setup.exe /S`).
- The per-user installer keeps the install folder writable so the verified in-place updater covers
  installed copies; refresh the HKCU uninstall `DisplayVersion` only when `InstallLocation` matches.
- Release with **Actions → Release (approved)** (version typed twice) after the version bump merges;
  a tag created with `GITHUB_TOKEN` does not trigger `on: push: tags`, so the workflow dispatches
  `release.yml` itself. Agents in this environment cannot push tags or approve the
  `github-release` environment — the owner approves publishing.
- After a squash merge, restart the branch from `origin/main` and reconnect it with
  `git merge -s ours origin/<branch>` instead of force-pushing (force-push is blocked).
- Check a published release end to end: assets present, `SHA256SUMS.txt` matches the downloaded
  installer, and `package::parse_release` offers it to the previous version.
