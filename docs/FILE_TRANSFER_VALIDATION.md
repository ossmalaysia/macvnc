# Experimental file-transfer validation

Validated in the Linux cloud workspace on 2026-10-04. These results cover the
implementation and synthetic fixtures. No live Mac transfer or Windows runtime
test has been performed; Apple `0x22` compatibility remains unverified.

## Results

| Check | Result |
| --- | --- |
| `cargo fmt --all --check` | Passed |
| `cargo test --workspace --locked` | 98 passed: protocol 39, media 26, app 33; four native decoder tests ignored here |
| `cargo test -p hp-media --test native_decode --locked -- --ignored` | Four passed using native FFmpeg 7 |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | Passed |
| `cargo build --release -p macvnc-app --locked` | Passed |
| `cargo check --workspace --all-targets --target x86_64-pc-windows-gnu --locked` | Passed; compilation only |
| Synthetic native UI (`bash /workspace/.setup/smoke-ui.sh`) | Passed; Files window open, no saved profile or connection used |
| `git diff --check` | Passed |

Activate the prepared environment before Rust checks with
`. /workspace/.setup/activate.sh`, then work in `/workspace/macvnc`.
Detailed current-run logs are in `/workspace/.setup/validate-*.log` outside the
checkout. Release-build validation is recorded in `validate-release.log`.
Windows MSVC packaging requires Windows and its SDK; the GNU compilation check
does not substitute for `powershell -File scripts/build-rust.ps1 -Package`.

## File-transfer behavior exercised

- A 32 KiB binary payload spans three chained authenticated control records,
  including a split message header. Seven-byte transport fragments are decoded
  without losing file data or a following non-file control message.
- Partial writes, would-block backpressure and interrupted writers preserve
  ciphertext order and yield to the session loop.
- Uploads stream multiple chunks and require matching completion. A request
  without replacement consent emits no network message.
- Downloads publish only after matching completion, consistent regular-file
  metadata and the exact declared size. Empty and binary files are exercised.
- A destination created after initial validation survives final publication;
  the failed download removes its staging file. Initially existing destinations
  also survive. Truncated transfers never publish their partial contents.
- Cancellation interrupts reply waits and a full upload queue. Old-session
  updates and replies for another transfer ID cannot complete the current job.
- Oversized messages/files, invalid paths/names and non-regular-file metadata
  are rejected.

The added encrypted-record test exercises the actual record decoder and file
decoder together. The synthetic peer uses MacVNC's codecs; this establishes
internal integration, not an independent Apple protocol implementation.

## Remaining live acceptance test

No Mac host, test folder or usable test credentials were configured in this
workspace. Connection-related environment variable names were checked without
printing values. Passwords must not be supplied in chat or diagnostic output.
The existing live video smoke command does not test file transfer.

Use a Windows build and an authorized Mac account with a dedicated empty test
folder. Record the client build, macOS version, Screen Sharing versus Remote
Management settings and the active HP mode. Use the existing authenticated screen
sharing session for every transfer; no alternate file transport is permitted.

1. Send an empty file, a binary file larger than one chunk and a Unicode-named
   regular file into the dedicated Mac folder using **Files → Send file**.
2. Compare each source and destination SHA-256 (`Get-FileHash -Algorithm SHA256`
   on Windows; `shasum -a 256` locally on the Mac). Confirm the actual files,
   sizes and hashes, not just the UI's completion status.
3. Receive those Mac files into new Windows destination names and compare hashes
   again. Confirm both directions keep input, video and heartbeats usable.
4. Verify denied reads/writes and unsupported responses fail visibly. Cancel a
   larger transfer and disconnect mid-transfer; confirm local partial downloads
   are removed and existing destinations remain intact. Inspect the dedicated
   Mac folder for partial uploads before any retry.
5. Reconnect explicitly and verify no old job or reply affects the new session.
   Authentication rejection must not trigger an automatic retry.

Do not mark macOS compatibility passed until both directions deliver matching
hashes after normal authentication. Native acknowledgement, permission/capability
negotiation and cancellation semantics still need observation on the target Mac.
Finder/Explorer file clipboard, remote drag/drop, folders and resource forks are
outside the implemented first version.
