# Native build licenses and provenance

The existing repository MIT license remains in `LICENSE`; it is not replaced.
The native `hp-protocol`, `hp-media` and application crates declare **AGPL-3.0-or-later**. The native executable
links that crate, so the portable native package is supplied on conservative
AGPL-3.0-or-later terms, with the MIT notices for independently licensed source
retained. The package is not an MIT-only application. The complete AGPL text is
in `rust/LICENSE-AGPL-3.0.txt`.

## HP protocol implementation provenance

The Rust implementation was newly written in this repository. Its authors
inspected this repository's earlier JavaScript HP implementation and the
[iShareScreen project](https://github.com/renegadelink/iShareScreen), including
`proxy/media/nalu.py`, `proxy/media/hevc.py`, `proxy/session.py`,
`proxy/protocol/burst.py`, and `frontend/desktop/gpu.py`. That upstream project
is licensed AGPL-3.0-or-later. Its findings informed Apple packet framing,
decoder state sharing, codec negotiation and band placement. The older local
JavaScript modules themselves describe portions as ports of that reference.

The new Rust source is not a pasted copy of the upstream Python source or a
line-for-line translation. It is also **not represented as a clean-room
implementation**: upstream source was read during development. The AGPL license
on `hp-media` conservatively preserves that provenance; it is not a claim that
protocol facts, algorithms or public ABI declarations alone determine copyright.
Credit belongs to the iShareScreen contributors for their reverse-engineering
work. The upstream license text is preserved without modification.

The retained JavaScript `src/rfb-hp/` modules identify direct ports of upstream
code. Their AGPL notice is in `src/rfb-hp/LICENSE`; Native distributions that
include them retain those terms and ship the notices. The root MIT notice does
not turn this subtree or a combined distribution into an MIT-only work.
See [LICENSING.md](../LICENSING.md) for the proposed future business model;
its proposed restrictions do not change upstream license rights.

SRTP uses established RustCrypto implementations of the RFC 3711 primitives.
The FFmpeg adapter was written against the public FFmpeg 7 headers. Its small
red HEVC test image was generated locally; it contains no captured desktop.

## FFmpeg runtime

The Windows package dynamically loads FFmpeg 7 (`avcodec-61`, `avutil-59`,
`swscale-8`, with the distribution's dependent DLLs). The pinned BtbN archive is:

`ffmpeg-n7.1.5-12-g1fdbca85aa-win64-lgpl-shared-7.1.zip`

SHA-256: `0f376f96fb38554ccefb1b2ae9c7c6a7b351f0e60a372b38262c320e8392c5d0`

The selected archive contains the **LGPL version 3** text. This differs from
FFmpeg's usual LGPL-2.1-or-later baseline because build configuration determines
the applicable license. The package preserves that exact text as
`FFMPEG-LICENSE.txt` and supplies the GPLv3 text incorporated by LGPLv3 as
`FFMPEG-GPL-3.0.txt`. FFmpeg copyright remains with its respective contributors.
The DLLs are separately replaceable; no restriction on replacement or reverse
engineering for debugging modifications is imposed here.

Build and source references:

- [BtbN binary/build release](https://github.com/BtbN/FFmpeg-Builds/releases/tag/autobuild-2026-07-31-14-10)
- [FFmpeg source revision](https://github.com/FFmpeg/FFmpeg/commit/1fdbca85aa)
- [FFmpeg license guidance](https://ffmpeg.org/legal.html)

## Included source and dependency notices

`scripts/package-rust.ps1` includes a snapshot of the current Rust application
source, tests, build scripts, manifests, lockfile and these notices under
`source/` in the local portable folder. It vendors the Cargo dependencies with
their original license files and writes the corresponding Cargo source
configuration. The snapshot does not depend on these new changes already
existing in a public Git repository. Credentials, `.validation/`, desktop
captures, Git internals and compiled build caches are excluded.

The package also includes the pinned FFmpeg source archive, BtbN build-recipe
archive, and their SHA-256 values under `source/third-party/ffmpeg/`. BtbN recipes
identify additional native dependencies used in its FFmpeg distribution. These
materials record the local build's provenance; they do not claim a complete
audit of every optional library in the third-party FFmpeg binary. Any public
release must retain the matching notices and corresponding source materials.
