# File transfer through Apple Screen Sharing

Status: experimental implementation with synthetic tests. Native Mac
interoperability and Windows release packaging have not been validated.
Based on MacVNC `4ce9766`. Local host means Windows running MacVNC;
remote means the Mac being controlled.

Requirement: both directions use Apple's Screen Sharing protocol. No SSH/SFTP,
SMB, additional credentials or installed Mac companion. See
[research findings and pinned sources](FILE_TRANSFER_RESEARCH.md).

## Implemented first version

The **Files** window supports explicit Send/Receive actions for one regular file
below 4 GiB. Dropping a local file selects its upload source. Uploads require
explicit replacement consent; downloads require a new local destination name.
All requests use Apple's `0x22` messages through the existing authenticated HP
control connection. No extra service, login or authentication bypass is used.

- `hp-protocol/src/file_transfer.rs`: request/metadata/data/end codecs, bounded
  message reassembly and single-file metadata validation.
- `hp-protocol/src/control_io.rs`: ordered ciphertext queue with partial-write
  tracking, bounded work per poll and backpressure.
- `macvnc-app/src/transfer.rs`: disk worker, bounded job/chunk/reply queues,
  generation/transfer IDs, deadlines, progress and temporary-file publication.
- `macvnc-app/src/transfer_ui.rs`: file selection, destinations, consent,
  progress and explicit cancel-and-disconnect action.

Disk work does not own the socket or cipher state. Upload chunks are 32 KiB;
one active job uses a job queue of one, outgoing queue of two and reply queue of
eight. The session sends at most one bulk message per media iteration. Downloads
are flushed and synchronized before publication without replacing existing
files. Source links and Windows reparse points are rejected. Failed downloads
discard their staging files; stale sessions cannot update a new session's status.

Completion currently requires a matching `END` reply with zero argument and no
payload. Downloads additionally require consistent regular-file metadata and
the exact declared byte count. These are conservative experimental assumptions,
not verified native acknowledgement semantics. Missing or unsupported replies
fail visibly. Cancellation or a failure after transmission starts closes the
owning screen-sharing session because safe native cancellation is unverified.
Remote partial files may remain.

Synthetic tests cover framing fragmentation/malformed input, partial writes,
streaming, empty/binary files, completion checks, download cleanup, destination
preservation, stale replies/session generations and cancellation under
backpressure. They do not establish interoperability with macOS. Finder/Explorer
file clipboard, seamless remote drag/drop, folders and resource forks remain
future work.

See the [validation results and live acceptance procedure](FILE_TRANSFER_VALIDATION.md).

## User workflow

Target Finder/Explorer copy and paste through the existing screen-sharing
session. Local files copied in Explorer can be pasted into the remote Finder;
files copied in the remote Finder can be pasted into a local Explorer folder.
Destination handling must follow the real Apple protocol discovered in testing.

The current first version uses explicit Send/Receive actions backed by the native
file-message family. For future clipboard integration, offer only operations demonstrated
by that mechanism; arbitrary remote filesystem browsing is not assumed. Add
progress and cancellation once their native semantics are established. Initial
scope is regular files in both directions; folders, resource forks, resumable
transfers and seamless cross-window drag/drop follow separately.

## Research findings that guide implementation

- iShareScreen implements Apple rich pasteboard messages `0x15`, `0x0b`, `0x1f`
  and compressed typed items across encrypted records. Its file-byte transport
  is not implemented in the inspected source.
- noVNC-ARD names drag messages `0x0e` and `0x20`, but skips server drag payloads.
  Its pasteboard header meanings differ from iShareScreen in places.
- A historical Screen Sharing app bug report describes native file drag/drop.
  That establishes a historical feature, not current HP interoperability.
- A broader GitHub search found Apple `0x22` read/write message builders in
  security proof-of-concept repositories. They supply concrete file-byte framing
  leads, but normal authenticated operation on a patched HP server is unverified.
- sortOfRemoteNG has Rust upload/download code but explicitly reports the file
  capability as false; it is not confirmed Apple interoperability evidence.
- MacVNC's clipboard is text-only; sending file paths or replaying Ctrl+V does
  not transfer file contents.
- Existing ViewerInfo command-mask bytes already match iShareScreen. File
  permission/capability negotiation still needs verification.

## Architecture

```text
Windows clipboard / explicit file actions
                 |
        App transfer coordinator
                 |
       Existing HP session owner
        +-- logical control-message dispatch
        +-- Apple pasteboard codec / file-promise state
        +-- serialized bounded record I/O
                 |
       Apple's Screen Sharing server

Local disk worker <--> bounded transfer buffers <--> session owner
```

Keep Apple wire codecs, state and platform-neutral events in `hp-protocol`;
keep Windows clipboard/OLE, local filesystem operations and UI in `macvnc-app`.
`hp-media` stays focused on media. The wire path and any native auxiliary channel
must follow evidence; do not assume that all file bytes are inline `0x1f` data.
Investigate `0x22` before assuming `0x1f` carries the file bytes. Public example
builders are research references; authentication bypass code is outside this
feature. The existing successful login and record verification remain required.
No new generic transfer transport crate or SSH dependencies are planned.

Additional modules planned for clipboard integration:

- `hp-protocol/src/pasteboard.rs`: bounded typed archive and multipart parsing.
- `macvnc-app/src/windows_clipboard.rs`: platform clipboard integration.

Only the session owner mutates `RecordLayer` and writes encrypted control records.
Do not let disk workers clone cipher state or write to its TCP socket. Dispatch
logical messages before passing bodies into metadata/layout processing.
Preserve every continuation/trailing byte according to verified framing.

## Delivery sequence and gates

| Phase | Work | Required evidence |
| --- | --- | --- |
| 1. Native interoperability research | First validate the newly found `0x22` message family after normal authentication on patched Macs; then trace how native pasteboard/drag actions initiate transfers, capability flags, requests, acknowledgements and cancel | Document verified field layouts and sanitized fixtures for the targeted macOS versions; establish both directions in HP mode |
| 2. Rich pasteboard foundation | Encode/decode text and typed items; status/fetch routing; bounded multipart reassembly and decompression | Offline fragmentation/malformed-input tests plus native UTF-8 text exchange; existing media/layout tests remain green |
| 3. Minimal native file proof | Stream one synthetic regular file each direction using the discovered Apple mechanism | Source/destination hashes match; no extra Mac service or credentials; HP remains usable |
| 4. Transfer engine | Bounded disk buffers, session/job IDs, cancellation, partial-file cleanup, conflicts and typed progress events | Large-file/failure tests; no input queue overflow or heartbeat starvation |
| 5. Windows integration | CF_HDROP for local files; materialized received files or virtual IDataObject formats as needed; Explorer/Finder copy/paste | Actual Windows-to-Mac and Mac-to-Windows file delivery, with correct shortcut routing and destination semantics |
| 6. Release validation | Windows package tests, documentation/licenses and macOS compatibility matrix | Passed acceptance checks for supported modes/versions; unsupported capability has a clear UI result |

Live interoperability remains a release gate for the experimental implementation.
Do not advertise file support based solely on text clipboard success. The user
has selected Screen Sharing only; no fallback transport is assumed.

## Bounds, scheduling and lifetime

Use a separate bounded file-job queue, initial limit one entry, one active
file, `u64` byte counters and bounded disk chunks. Tune chunk size only after
verifying Apple's framing; every encrypted body remains within 65,498 bytes.
Use coalesced progress updates, bounded archive/item/alias lengths and total
reassembly/decompression budgets with deadlines. Reject advertised sizes beyond
limits before allocation; never read a whole large file into RAM.

Replace blocking bulk writes with serialized bounded I/O as needed. Prioritize
key releases, pointer/control requests, layout recovery and media heartbeats at
legal message boundaries. A multipart message may forbid interleaving other
messages; establish that first. Input queue fullness must not be caused by file
chunks. Partial writes must retain exact ciphertext offsets and record order.

Cancelling/disconnecting invalidates all file jobs and pending promises for that
session. Late worker events cannot update a reconnected session. Do not trigger
new authentication automatically. Integrity failures remain fatal; transfer-level
errors leave screen sharing usable where the verified protocol allows recovery.

## Filesystem and clipboard behavior

Treat remote names as untrusted. Reject traversal, reserved Windows names,
separators in single-name fields, unsafe links/reparse points and collisions.
Stage downloads in exclusively created temporary files, with explicit
publication/overwrite decisions. Remove only the current job's partial files;
report cleanup failures. Do not execute received files.

Do not promise remote atomic overwrite or cleanup until Apple's behavior is
verified. Local completion requires successful flush/close and byte-count checks;
product checksum claims require a verified native mechanism or read-back.

Windows CF_HDROP points to existing local files. Remote promises may need
CFSTR_FILEDESCRIPTORW/CFSTR_FILECONTENTS through IDataObject, or explicit staging
before CF_HDROP. Evaluate delayed rendering/OLE lifetime, cancellation and UI
thread requirements before choosing. Clipboard generation, source and session
IDs prevent echo loops and stale transfers. File paste must not fall through to
the current typed-text path. Read/transfer user-selected file content only in
response to an explicit copy/paste/send action.

## Acceptance checks

- Byte-identical empty, binary, Unicode-named, multi-file and multi-record
  transfers in both directions. Exercise large files with bounded memory; verify
  counters above 4 GiB if the discovered native protocol supports them.
- Malformed/truncated archives, decompression bombs, conflicting sizes, illegal
  continuation order, trailing data, unknown UTIs and permissions/capabilities.
- Clipboard changes mid-transfer, stale promises, cancelled jobs, dropped
  connections, source mutation, permission denial, disk exhaustion and conflicts.
- Normal input/video and recovery while transferring; existing destinations
  survive failures; jobs cannot cross session boundaries.
- Reference compatibility on recorded macOS versions, standard versus HP mode,
  shared versus virtual display, and observe/control permissions. Disable file
  actions for modes where capability is absent or unverified.
- Repository formatting, workspace tests, strict Clippy and Windows release
  packaging. The Rust 1.99 atomic deprecation was corrected while preserving
  the decoder counter's saturating behavior.

Next prerequisite: an authorized pair of Macs (native reference viewer and
server), or equivalent authorized application-layer observations. The Linux
cloud environment cannot establish native Apple file interoperability alone.
