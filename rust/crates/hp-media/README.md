# HP media

RustCrypto SRTP AES-256-CTR/HMAC-SHA1-80 receive, replay protection, Apple
HEVC DONL/AP/FU reassembly, shared HEVC decoder, and CTU-padded band composition.
The decoder loads **FFmpeg 7** shared libraries from `MACVNC_FFMPEG_DIR`, or
from beside the executable. Required Windows DLL majors: avutil-59,
swresample-5, avcodec-61, swscale-8 (and their distribution's dependencies).
Other majors are rejected before ABI structure access. Keep FFmpeg license
and corresponding source information with distributed libraries.

One shared decoder context retains Apple's cross-band reference pictures.
Slice threading uses the host CPU without frame-thread reorder latency.
No hardware decode claim is made: Apple's HEVC 4:4:4 format commonly requires
software decoding. Decoder errors do not flush the shared reference buffer.

Groups are bounded by time, bytes, packet count, and source count. Marker
packets are held briefly so reordered earlier fragments can arrive. Incomplete
fragment units and sequence gaps are discarded. The caller should rate-limit
FIR requests after loss; cryptographic failures must never trigger auth retry.

The canvas keeps its negotiated size and clips CTU padding from the final
band. It does not wait for matching timestamps across unchanged bands.

`cargo test` runs synthetic tests. `cargo test --test native_decode -- --ignored`
also validates real libavcodec HEVC 4:4:4 decoding and PTS routing. The tiny
red-frame fixture was generated locally using FFmpeg/libx265 and contains no
desktop content.

Protocol references inspected: RFC 3711 and RFC 7798; iShareScreen
`proxy/media/hevc.py`, `proxy/media/nalu.py`, `frontend/desktop/gpu.py` at
https://github.com/renegadelink/iShareScreen (AGPL-3.0-or-later).
FFI struct prefix definitions match the FFmpeg n7.1 public headers.

Security boundaries: `MACVNC_FFMPEG_DIR` must be an absolute directory. On
Windows, dependency loading searches only that DLL's directory and System32
using `LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32`; it
does not fall back to the working directory or PATH. See Microsoft's
[LoadLibraryEx documentation](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryexw).
All four native-library major versions are checked. This is not signature or
integrity verification: the chosen directory and its DLLs must remain trusted.
The dependency-search hardening is Windows-specific.

Frame dimensions are checked before arithmetic or allocation (16,384 per axis,
32 million pixels); initial RGBA allocations report reservation failure instead
of aborting. The same checks cover decoder output and compositor input. Pending
compressed packet groups have a combined 32 MiB cap as well as individual AU,
packet-count and lifetime limits. These bounds do not impose a whole-process
memory quota: FFmpeg's reference-picture buffers, framebuffer snapshots and UI
textures require additional memory. The C decoder and unsafe ABI adapter remain
trusted native code, and allocation failure in other components can still end
the process.
