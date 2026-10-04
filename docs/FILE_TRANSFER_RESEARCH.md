# Apple Screen Sharing file-transfer research

Research date: 2026-10-04. MacVNC reviewed at `4ce9766`.
Requirement: copy files between the Windows host and the remote Mac using
Apple's Screen Sharing protocol. No SSH/SFTP, SMB or companion service.
This report records source inspection, not a live interoperability test.

## Findings and confidence

| Finding | Evidence | Confidence / limit |
| --- | --- | --- |
| Apple's native Screen Sharing app has transferred files | A mirrored Apple bug report describes dragging two files into Screen Sharing 1.5 on OS X 10.9.1 and the close-session warning for active transfers | Historical product behavior; does not establish current HP-mode framing or both directions |
| Apple has a rich pasteboard protocol beyond RFB cut-text | iShareScreen implements `0x15`, `0x0b`, and `0x1f`; its documentation describes typed items and compressed payloads across encrypted records | Concrete third-party implementation; not an Apple specification or a file-transfer implementation |
| Drag messages are a further research lead | noVNC-ARD names client `0x0e` and server `0x20`; its server drag handler skips a length-delimited payload | Candidate identifiers and framing only; not independently validated against MacVNC's HP session |
| Windows/Mac file clipboard support is absent in MacVNC | Current clipboard code handles text, and the backend drops returned control bodies after protocol inspection | Directly established by local source inspection |
| Standard VNC file-transfer code cannot be assumed compatible | LibVNCServer defines a type-7 file-transfer family associated with UltraVNC; noVNC-ARD labels type 7 as NOP | Evidence of vendor-specific dialects; never probe Apple with this packet family without evidence |
| A ready implementation was not found in the inspected projects | iShareScreen's handler extracts text; noVNC-ARD handles text and skips drag payloads; iVNC uses standard text cut-text | Limited to these source snapshots; not a claim that none exists anywhere |

## Source snapshots

Use these pinned links when implementing; moving `main` links may change.

1. iShareScreen, commit `9ab40d3a3151524f954cff9d6239d891197c1705`:
   [protocol documentation](https://github.com/renegadelink/iShareScreen/blob/9ab40d3a3151524f954cff9d6239d891197c1705/docs/apple_vnc_rfc.md),
   [clipboard codec](https://github.com/renegadelink/iShareScreen/blob/9ab40d3a3151524f954cff9d6239d891197c1705/src/isharescreen/proxy/protocol/clipboard.py),
   [session dispatch](https://github.com/renegadelink/iShareScreen/blob/9ab40d3a3151524f954cff9d6239d891197c1705/src/isharescreen/proxy/session.py),
   [viewer command mask](https://github.com/renegadelink/iShareScreen/blob/9ab40d3a3151524f954cff9d6239d891197c1705/src/isharescreen/proxy/protocol/apple.py).
   The documentation explicitly states it is experimental and not endorsed by Apple.
2. noVNC-ARD, commit `cb2da939757e344cce1172745c1d09a8bc69b3dd`:
   [message identifiers](https://github.com/peetinc/noVNC-ARD/blob/cb2da939757e344cce1172745c1d09a8bc69b3dd/ard/ard-constants.js),
   [clipboard and drag handlers](https://github.com/peetinc/noVNC-ARD/blob/cb2da939757e344cce1172745c1d09a8bc69b3dd/ard/ard-patch.js).
3. LibVNCServer, commit `42494999e6492aaab9c1db785ecd293ef10b3aed`:
   [UltraVNC file-transfer structures](https://github.com/LibVNC/libvncserver/blob/42494999e6492aaab9c1db785ecd293ef10b3aed/include/rfb/rfbproto.h).
4. iVNC, commit `ceb7a54393b1fef25843943913b9342b79dbd3e7`:
   [text clipboard implementation](https://github.com/hendkai/iVNC/blob/ceb7a54393b1fef25843943913b9342b79dbd3e7/src/rfb/session.rs).
5. [Historical Screen Sharing transfer report](https://github.com/lionheart/openradar-mirror/issues/3854):
   report 16093528, product version OS X 10.9.1 (13B42), Screen Sharing 1.5 (480.53).
   This is a public mirror of a reported bug, not official protocol documentation.

Apple Support, Google search and the GitHub API returned HTTP 403 from this
cloud environment. Public GitHub HTML search and HTTPS Git checkouts worked.
The blocked pages were not used as evidence. Logged-out GitHub code search also
required sign-in; its lack of results was not treated as absence of code.

## Pasteboard wire details worth investigating

The iShareScreen implementation builds:

- `0x15`: an eight-byte AutoPasteboard enable command with mode 1. Its protocol
  document also describes mode 2 as disabling monitoring.
- `0x14`: a server status message; command 2 triggers a `0x0b` clipboard fetch.
- `0x0b`: an eight-byte request. Its implementation treats byte 1 as a
  promises-only flag. The zero form requests full pasteboard data.
- `0x1f`: a sixteen-byte header followed by zlib-compressed typed pasteboard data.
  Header lengths are at offsets 8 and 12. The inner archive contains an item
  count, length-prefixed UTI names, aliases and data. A logical payload can span
  several encrypted records; continuation records do not carry a message type.
- The text encoder sends `public.utf8-plain-text` through `0x1f` rather than
  standard `0x06`, because the latter does not populate the modern pasteboard
  used by many Mac apps, according to that project's investigation.

Do not treat these details as a complete file protocol. In particular:

- File URLs identify files on one machine; sending a URL is not transferring bytes.
- The meaning of the promise flag for file items and the request that resolves a
  promised file remain unverified.
- noVNC-ARD calls the word at `0x1f` offset 4 a session ID, while iShareScreen calls
  it reserved. Their request/header interpretations differ. Verify those fields
  against a specific macOS version before implementing correlation logic.
- iShareScreen's clipboard module introduction says the request is nine bytes,
  while its builder and later comment specify eight and warn that nine corrupts
  parsing. Likewise the introductory enable-mode notes conflict with the
  builder/documentation. Prefer tested bytes and independently validate them.
- Its reassembler appends continuation bodies and truncates at the declared
  size. MacVNC must bound total size/time and correctly handle trailing bytes,
  malformed lengths and decompression expansion rather than copying that behavior.
- noVNC-ARD identifies status 3 as PasteboardDataNeeded. This is an unverified
  candidate for deferred data supply in HP mode, not proof of file-byte transport.

## Local architecture implications

MacVNC already advertises the same nonzero ViewerInfo command-mask bytes as
this iShareScreen snapshot: indices 0, 2, 3, 4, 10 contain `b0`, `0c`, `03`, `90`,
`40` in the 32-byte mask. That does not prove file permission/capability and is
not a reason to enable arbitrary additional bits.

`HpConnection::poll_control` currently authenticates/decrypts records and calls
`inspect_control` on each body. `backend::run_session` does not dispatch the
returned bodies into clipboard/transfer events. A new logical-message decoder
must handle multipart payloads before continuation bytes can be mistaken for
new framebuffer or metadata messages. Existing layout/media handling must
remain correct.

`RecordLayer::encrypt` limits each plaintext record body to 65,498 bytes and
maintains mutable CBC/sequence state. One session owner must perform all record
reads/writes in wire order. Disk workers cannot independently write to its TCP
socket or copy its cipher state. Simply splitting a large buffer into records is
insufficient until the matching Apple continuation rules are verified.

The current write path can block for three seconds, and the session loop also
owns input, video decode, recovery and the 500 ms audio heartbeat. Plan bounded,
nonblocking serialized writes and bounded reads; do not route transfer chunks
through the 256-entry key/pointer queue. If a multipart message requires contiguous
records, prioritization may occur only at protocol-permitted boundaries.

## Research needed to establish actual file delivery

Use two authorized Macs initially: Apple's reference Screen Sharing client and
the server. Record exact macOS/app versions and session modes. Start with a
three-byte synthetic file, then empty, Unicode-named, incompressible and
multi-record files. Exercise local-to-remote and remote-to-local copy/paste and
supported drag/drop independently. Confirm both directions in HP mode; classic
mode behavior alone is insufficient.

Observe/decode the authenticated post-login application messages, not just
ciphertext packet sizes. A packet capture by itself does not reveal encrypted
payloads. Use local instrumentation on test machines or a controlled test client;
never disable record verification or store real credentials, keys or desktop
captures in Git. Keep sanitized synthetic wire fixtures and field-level traces.

Map each operation to capability/permission advertisement, pasteboard item types,
file IDs, promise resolution, byte source, chunk framing, acknowledgements,
completion, destination choice, overwrite handling and cancellation. Determine
whether Apple opens a native auxiliary connection or stays on the control
connection; do not invent a side protocol or assume either result.

Proof required before implementing product file controls: MacVNC sends one
synthetic file and receives one through Apple's native mechanism, with matching
hashes and the HP session remaining usable. If further messages are undocumented,
inspect the relevant ScreenSharing.framework/screensharingd/agent dispatch paths
on the authorized test machines and connect those findings to observed traffic.

## Updated conclusion after the second search

The broader GitHub search found concrete Apple file read/write message builders,
so the earlier result that only pasteboard/drag leads were available was
incomplete. Message `0x22` is now the strongest file-byte transport lead. The
public example is a security proof of concept, not a verified authenticated
Windows file-copy client. A working Apple-native drag/drop implementation was
not established by the reviewed sources. Verify the ordinary authenticated
`0x22` path on patched Macs before designing the UI around it.


## Second search: concrete native read/write source found

The second pass searched public GitHub repository, issue and commit results,
including Apple/ARD file transfer, Screen Sharing drag/drop, file promises and
specific protocol terms. GitHub code search remained unavailable while logged
out. Relevant follow-up results were cloned/read; no network exploit or live
file operation was executed.

### Apple read/write protocol example

[rfbproto discussion #74](https://github.com/rfbproto/rfbproto/issues/74)
explicitly connects newly published security research to Apple's file-transfer
extensions. Following that reference found:

- [acheong08/CVE-2026-65400](https://github.com/acheong08/CVE-2026-65400), reviewed at
  `360589c69386428d9563a2f6eb4964d187d58549`:
  [wire builders](https://github.com/acheong08/CVE-2026-65400/blob/360589c69386428d9563a2f6eb4964d187d58549/exploit.py).
  The author reports successful writing; source includes read requests,
  destination/item metadata, chunked file data, end-of-transfer and reply parsing.
- [panchocosil/CVE-2026-65400-poc](https://github.com/panchocosil/CVE-2026-65400-poc),
  reviewed at `d19ddf6218910233e73735d485afc16489ef968d`:
  [read-side example](https://github.com/panchocosil/CVE-2026-65400-poc/blob/d19ddf6218910233e73735d485afc16489ef968d/poc_screensharing.py).
  This is a read-only demonstration with a published run screenshot; its license
  is MIT.

Both examples are security proof-of-concept code involving an authentication
bypass. Their success claims do not establish success after normal authentication
on a patched Mac or compatibility with HP record encryption. They were inspected
as protocol references and were not executed. There is no reason for MacVNC to
adopt their bypass, malformed authentication framing, privilege assumptions or
retry behavior. The acheong08 snapshot has no explicit license file; do not copy
its implementation into MacVNC without resolving code licensing.

The reusable research finding is a separate Apple file-message family, `0x22`,
with version/session fields, metadata, data chunks and completion messages.
This makes a pure rich-clipboard implementation an insufficient first hypothesis.
Map the normal permission checks, replies, record framing and session setup for
`0x22`, then map pasteboard/drag events to these transfers. Large-file limits,
resource forks, cancellation and overwrite semantics remain unverified.

### Candidate application: sortOfRemoteNG

[supermarsx/sortOfRemoteNG](https://github.com/supermarsx/sortOfRemoteNG), reviewed
at `e9b88cb1a5afa9b277a89acece9fd1e1948906a0`, contains a Rust ARD file module:
[file_transfer.rs](https://github.com/supermarsx/sortOfRemoteNG/blob/e9b88cb1a5afa9b277a89acece9fd1e1948906a0/src-tauri/crates/sorng-ard/src/ard/file_transfer.rs)
and [session integration](https://github.com/supermarsx/sortOfRemoteNG/blob/e9b88cb1a5afa9b277a89acece9fd1e1948906a0/src-tauri/crates/sorng-ard/src/ard/session_runner.rs).

It has upload/download and directory-listing functions, but the session snapshot
explicitly sets `supports_file_transfer: false`, explaining that requesting an
extension is not a positive capability acknowledgement. Its file protocol uses
ClientCutText with a `FE FE FE` marker and a claimed pseudo-encoding
`0x574D5602`, which differs from the native `0x22` examples. Inspected file-module
tests cover constants, serialization, safety bounds and local behavior rather
than demonstrated Apple interoperability. This is application-level code, not
proof of successful Mac file copying; do not port its wire contract uncritically.

### False positives excluded

- [ahimsalabs/vncx](https://github.com/ahimsalabs/vncx), snapshot
  `710dabfb72e41c050937c092ce9a58fdd5c48e83`, documents drag/drop but explicitly
  says dropped files are uploaded over SSH. It does not meet Screen Sharing-only.
- [psmux/DeskVNC](https://github.com/psmux/DeskVNC) advertises SFTP file transfer
  alongside Apple authentication in its initial-release commit. That is not an
  Apple-native transfer claim and was not counted as such.
- [thomas-luebker/amimcp](https://github.com/thomas-luebker/amimcp) has a commit
  reporting tested file drag/drop, but states bytes use its agent GET/PUT/LIST
  protocol and target an Amiga. It does not meet this requirement.
- iShareScreen and noVNC-ARD remain useful clipboard/drag references; their
  inspected sources still do not show a complete native file-copy workflow.

Result: public native read/write source exists and materially narrows protocol
research. An authenticated, patched-Mac-compatible Apple drag/drop client has
not been verified here. Prioritize validating `0x22` inside MacVNC's normal
session before investing in clipboard/OLE integration.

## Implementation follow-up

MacVNC now has an experimental, independently written `0x22` codec and explicit
Send/Receive UI using its normal authenticated HP connection. Public references
provided wire-field facts only; their bypass code was not executed or ported.
Synthetic framing, streaming and failure tests pass. This does not change the
research conclusion about unverified patched-Mac/HP compatibility or supply a
successful Finder/Explorer drag/drop demonstration. See the
[implementation status and remaining gates](FILE_TRANSFER_PLAN.md).
