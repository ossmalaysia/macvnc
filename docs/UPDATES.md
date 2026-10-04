# Native Windows updates

The portable Windows x64 app checks the public GitHub latest-release API at
startup and at most once every 24 hours while running. Checks and downloads run
off the UI/session thread. The Updates window also supports manual checks,
release notes, progress and cancellation. Development builds may check releases
but installation requires an extracted portable package in a writable folder.
Synthetic UI smoke tests show a sample update without making network requests.

## Release contract

- Repository: `ossmalaysia/macvnc`; stable tags `vMAJOR.MINOR.PATCH` only.
- Assets: `macvnc-rust-windows-x64.zip` and `SHA256SUMS.txt`, from the exact
  repository/tag download URLs. Drafts, prereleases and downgrades are ignored.
- Archive root: `macvnc-rust/`, matching the existing release workflow.
- Package identity: `UPDATE.json` with `schema: 1`, the app manifest version,
  and `target: "windows-x64"`. Packaging generates this file without a BOM.
  Its `runtime` array names the DLLs; all must be present, including the FFmpeg
  codec, utility, resampler and scaler libraries.
- The ZIP includes the executable, runtime DLLs, license/notices and complete
  corresponding `source/` tree. The helper updates these as a bundle.
- The published checksum must identify the archive exactly once. It detects
  corrupted bytes; these releases are not signed independently of GitHub/TLS.

Older release artifacts without the identity file cannot be installed through
this updater. Version 0.1.11 is the first portable release with the updater and
package metadata; users of earlier versions must download and extract it manually.
The 0.1.10 tag contains the implementation, but its publication was blocked by
the repository's release-action policy. Subsequent compatible stable releases
can be installed through the Updates window.

## Download and restart lifecycle

1. One click on **Download and restart** starts a bounded streamed download.
   Existing screen sharing continues during download. File-transfer submission
   is disabled until updating finishes; an already active transfer blocks the
   update action.
2. Verify archive SHA-256 and exact size. Extract into a private temporary
   directory inside the app folder, with path, link, duplicate-entry, platform
   and version checks. Hash every extracted file. Cancellation or failure here
   removes staging and keeps the installed app open and unchanged.
3. Copy the current native executable into staging as the helper. It verifies
   the owning process and obtains a Windows lock excluding other helpers for
   this installation. Only after it signals readiness does the app disconnect
   the Mac session and close.
4. The helper waits for the actual app process to exit before touching installed
   files. It rechecks the staged inventory, moves existing managed entries into
   a backup directory and installs the new entries by same-volume renames. The
   complete bundled source directory is replaced; unrelated files are preserved.
5. Launch the app with its normal working directory and `--no-autoconnect`.
   Once its native UI context exists, the app verifies the outcome/version and
   acknowledges startup. It displays the installed version, or the restored
   version's error. Profiles remain in their existing DPAPI-backed location.
6. If replacement or initial startup fails, restore backed-up files and restart
   the previous app. Remove staging only after the helper has exited and marked
   the transaction finished. A failed rollback keeps backups for recovery.

The helper is native Rust. No PowerShell execution-policy change, service,
installer or administrator prompt is required at runtime. Package size is
limited to 512 MiB compressed and 2 GiB expanded, with at most 100,000 entries.
Prepare sufficient free disk space for download, extracted files and backups.
The app folder must be writable; protected installations should be moved to a
user-writable folder or updated manually.

## Recovery and limits

Close other MacVNC instances before updating; another process can hold the
executable or DLLs open. The updater attempts rollback on ordinary errors. A
power interruption or failure to restore locked files can require manual
recovery: retained `.macvnc-update-*/backup/` entries contain the prior managed
files. With all app/helper processes closed, restore those entries into the
application folder before starting it. Never delete that backup when the helper
reports that rollback failed. The `.macvnc-update.lock` file is harmless when
closed; Windows sharing restrictions on its open handle enforce the lock.

Checks use `api.github.com`; downloads use `github.com` and its HTTPS release
asset hosts. A blocked API, offline connection or rate limit produces a visible
check error and a manual retry action. There is no silent downgrade or fallback
to another distributor. The updater does not transfer credentials or real Mac
files to GitHub.

## Validation

Synthetic tests exercise stable-version selection, exact asset URLs, checksum
parsing, archive traversal/link rejection, release/platform identity,
cancellation, staged-file tampering, preservation of unrelated files and
rollback after each injected replacement failure. Windows conditional code is
also cross-compiled. Full acceptance additionally requires the supported MSVC
package on Windows, a newer GitHub release and both successful installation
and failure recovery. A Linux UI smoke test or Windows cross-compilation alone
does not establish that end-to-end result.

Current cloud validation (2026-10-04): 109 workspace tests and four native
decoder tests pass; formatting, Linux and Windows strict Clippy, Linux release
build and synthetic UI, Windows GNU application compilation, and source-hygiene
checks pass. `cargo audit` reports no
vulnerabilities, with the existing `paste` and `ttf-parser` maintenance warnings.
The Windows updater tests also execute under Wine: 12 pass, including a child
process fixture testing native process handles, replacement and rollback. Wine
is supplementary emulation, not supported Windows/MSVC package acceptance.
Two additional synthetic process cycles run the actual Windows helper: successful
replacement/restart and restoration/restart after an injected startup failure.
Both verify that files remain unchanged while the parent runs and unrelated user
files survive. Their restarted processes simulate the startup acknowledgement;
they do not test the real egui window or its staging-cleanup thread.

The full Windows GUI smoke test is blocked under this Wine runtime: winit's
`RegisterDragDrop` call fails with `E_NOINTERFACE` before app construction. The
existing drag/drop feature was retained; no test or product capability was
disabled to bypass the emulator failure. Supported Windows GUI/restart and MSVC
packaging acceptance remain pending.
The live GitHub release API returned HTTP 403 from this cloud environment;
version/asset parsing was verified with synthetic GitHub-format responses.
