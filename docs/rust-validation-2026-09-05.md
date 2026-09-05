# Native Rust HP validation — 2026-09-05

This is separate from the earlier Electron/browser fixture validation in
`validation-2026-09-05.md`. The native package uses egui/OpenGL and FFmpeg 7;
a browser cannot validate its native window or TCP/UDP transport.

## Completed checks

- Workspace tests: 44 passed (20 protocol, 13 media, 11 native app).
- Native FFmpeg HEVC 4:4:4 synthetic tests: two passed separately, including
  missing-reference concealment that still returns a successfully decoded frame.
- `cargo fmt --all --check` and strict workspace Clippy: passed.
- Optimized Windows x64 release compilation: passed.
- Legacy JavaScript regression tests: 114 passed.
- Native synthetic UI: displayed the expected generated gradient.
- Packaging: pinned FFmpeg checksum verified; packaged Rust source and vendored
  dependencies resolve offline (377 workspace/dependency packages).

## Live investigation

Live checks used only the app's saved profile under the user's authorization.
Reports contain aggregate counters; no passwords, keys, desktop payloads or
desktop screenshots were written into the repository.

The initial zero-frame failure was an inverted Apple codec-bank mapping: the
HEVC-labelled bank selected AVC output. Selecting bank 100 enabled HEVC decoding.
A 10-second debug check authenticated 6,403 media packets, decoded 1,192 tile
pictures and submitted 367 composed updates, with no authentication or decoder
errors. Those counters were **not evidence of correct complete screen playback**:
native visual inspection and the user's test showed band corruption and grey
output. Tile decode counts must not be reported as full-screen FPS.

The current offer requests one complete picture instead of cross-referenced
tiles. The Mac omits the tile-count field for that mode; the parser now defaults
an absent field to one while rejecting explicit zero. The resulting RTP stream
uses standard HEVC packetization without Apple's tile DONL fields. Validated
parameter packets select the framing mode, and bounded source handoff handles
the Mac's initial encoder generations. Missing references and incomplete packets
trigger rate-limited FIR recovery on the active source without reauthentication.

The final optimized 30.001-second check authenticated 45,826 media packets,
decoded 1,154 complete 1920x1080 pictures and published 755 latest-frame updates
(25.2 updates/sec including startup). Authentication rejects, decode errors and
concealed missing-reference errors were all zero. Three startup source handoffs
and four keyframe requests occurred. This probe measures backend frame delivery,
not display scanout; it is not an apples-to-apples benchmark against Electron.

The packaged release was then opened and inspected through native-window tooling.
The complete image was visibly coherent, including the formerly corrupted lower
region, and the UI showed approximately 35 FPS at that observation. This is an
instantaneous UI submission count, not a sustained 35-FPS guarantee. The app was
left open at the Mac login screen for the user's interactive test. Remote login
input and subsequent desktop interaction were left to the user.

## Version 0.1.1 window and branding checks

- New MacVNC monitor icon verified in the native window; multi-size ICO embedded
  in the executable and PNG supplied to the window toolkit.
- Windows executable metadata reports ProductName `MacVNC`, FileVersion `0.1.1`
  and ProductVersion `0.1.1`; toolbar and title display the same version.
- Synthetic native-window drag moved the window from (40,32) to (165,107).
  Header double-click maximized it. Fullscreen button interaction also passed.
- Header dragging processes press/move/release events even when delivered in a
  single frame; OS drag capture was too late for those batched events.
- Workspace tests (44) and strict Clippy passed; release build succeeded.

## Version 0.1.2 recurrent grey-frame repair

The user's longer interactive session reproduced grey output on 0.1.1, so the
earlier short live checks did not establish that corruption was fully resolved.
A confirmed packet-assembly bug discarded continuation VCL slices from pictures
containing multiple slices. The corrected assembler preserves all slices and
rejects pictures that lack a first slice. A real two-slice synthetic HEVC fixture
now produces pixel-identical output through RTP assembly and direct FFmpeg decode.

Recovery suppresses pictures with decoder/reference errors, holds the last good
screen, requests a new keyframe until one decodes cleanly, and resets decoder
reference state at encoder-generation boundaries. Broader native error counters
catch errors beyond missing references. Four native decoder regressions pass,
alongside the 47 workspace tests and strict Clippy.

Two 120-second live probes authenticated successfully and recovered from one
deliberately dropped video fragment in 0.32 and 0.37 seconds. Neither reported
decoder or reference errors. Video arrivals stopped around 28 seconds; these
checks do not establish continuous playback on an actively changing desktop.

Subsequent review corrected RTCP feedback routing to UDP control port 5900 and
added the empty video sender report every five seconds, alongside receiver
reports and audio heartbeats every 500 ms. Sender-report wire-format and clock
wraparound tests pass. Interactive validation of these final transport changes
is pending in the newly packaged 0.1.2 app.

## Version 0.1.3 network latency display

The toolbar now displays OS-estimated TCP RTT alongside presented FPS, sampled
once per second from the existing socket without probes. Unsupported or absent
statistics display an em dash; reconnect/disconnect clears the prior value.
The tooltip distinguishes network round trip from decoding/display latency.
All 49 workspace tests, formatting and strict Clippy passed; release packaging
succeeded. Native live UI validation showed `RTT 17.2 ms`, matching aggregate
telemetry of 17.235 ms, with successful authentication and no decoder/reference
errors at the observation. The updated app was left open for user testing.

## Version 0.1.4 stalled recovery investigation

The user's 0.1.3 aggregate log recorded 2,955 authenticated packets, 98 access
units, one incomplete FU sequence and no decoder/reference errors. The last
good picture was around 9 seconds; at 45 seconds it was still waiting for a
keyframe despite 19 recovery requests. The native window remained responsive.

Recovery now matches the reference compound packet: empty RR, standard AVPF
FIR with an advancing sequence, PLI, then legacy FIR. Reordering waits from
marker arrival instead of the first fragment. Ordered loss epochs prevent
stale packets from freezing playback and prevent an earlier keyframe in a
batch from clearing a later loss. Incomplete groups remain bounded.

All 53 workspace tests, four native decoder tests, formatting and strict Clippy
pass. New fixtures cover delayed fragment arrival, stale orphan packets,
ordered keyframe/loss handling, bounded incomplete groups and FIR wire format.
The 120-second live probe recovered from a deliberately omitted fragment in
0.662 seconds, ending with no pending keyframe recovery and zero decode,
reference or native decoder-log errors. It authenticated 45,524 packets and
published 414 screen updates. Packets stopped around 28 seconds on the unattended
Mac; this may reflect a static screen and does not establish continuous video
under active interaction. The repaired native app is reopened for that check.

## Version 0.1.4 user navigation check

While the user opened and navigated the remote desktop, six aggregate samples
from session seconds 45 through 95 showed screen updates increasing from 863
to 1,589 and authenticated packets from 59,591 to 81,765. Every sample had
`waiting_for_keyframe=false`; recovery requests stayed at three, with zero
decode/reference/native decoder errors. Latest-good-picture age ranged from
about 1 ms to 290 ms at sampling. TCP RTT varied from about 9 ms to 114 ms.
No frozen recovery state was observed during this interval; this is a bounded
interactive check, not a long-duration stability guarantee. No UI actions or
restarts interrupted the user's test, and only aggregate diagnostics were read.

## Remaining scope

The decoder uses software HEVC slice threading; hardware acceleration, audio,
file transfer, monitor scanout measurement and end-to-end latency measurement
are not implemented. No performance improvement is claimed from language choice
or unit tests alone. No public release has been published.
