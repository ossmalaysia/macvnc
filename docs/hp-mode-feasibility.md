# High Performance mode — feasibility and scope

Investigating Apple's **High Performance** Screen Sharing (HEVC video stream) as
a path to dramatically lower latency than standard RFB allows. This documents
what was verified, the protocol shape, and a phased plan.

## Verified so far

- **HEVC 4:4:4 decode works in Electron.** A real `yuv444p` HEVC Range-Extensions
  bitstream (generated with x265, confirmed by ffprobe) decoded through the
  renderer's WebCodecs `VideoDecoder` — **30/30 frames** out as BGRA `VideoFrame`s.
  This removes the single biggest technical risk: we do **not** need a bundled
  native decoder. Chromium's is enough.
- **The target Mac qualifies** — Apple Silicon on macOS Sonoma 14+, which is the
  prerequisite for the Mac to offer HP mode at all.

## Why HP mode is faster

Standard RFB is demand-driven: request → one frame → request, and the Mac
CPU-encodes rectangles. HP mode instead **streams HEVC video over UDP/SRTP** —
hardware-encoded on the Mac, hardware-decoded here, no per-frame round trip.
This is what Apple's own Screen Sharing.app and commercial tools use.

## Protocol shape (from iShareScreen's reverse-engineered spec)

Reference: https://github.com/renegadelink/iShareScreen (`docs/apple_vnc_rfc.md`).
The full sequence from TCP connect to decodable frames:

1. TCP 5900, RFB `003.889` banner exchange.
2. **Authentication** — iShareScreen uses **security type 33 (RSA-SRP)**, not the
   type 30 (Apple DH) our current client implements. **Open question below.**
3. ClientInit / ServerInit.
4. **Cleartext prelude**: ViewerInfo (0x21), SetEncryption cmd=1 method=1 (0x12);
   server sends 0x44f rekey; SetEncryption cmd=2 activates the cipher.
5. **AES-128-CBC encrypted record layer** wraps all further control messages.
6. Inside it: SetDisplayConfiguration (0x1d, virtual display), SetEncodings (0x02,
   advertise 0x3f2/0x3f3/0x3ea), AutoFrameBufferUpdate (0x09), a metadata burst
   (0x451 layout, 0x453/0x455/0x456 keyboard/device).
7. **MediaStreamOptions (0x1c)** offer/answer — carries the **SRTP keys**
   (46-byte master+salt per stream) and codec/geometry.
8. **UDP 5901**: four horizontal tile streams, RTP payload type 100, **SRTP
   AES-256-CTR + HMAC-SHA1**, RTCP-muxed.
9. **Depacketize** (RFC 7798 HEVC with Apple's DONL variant), feed **all four
   SSRC tiles to one shared HEVC decoder** (cross-tile references), composite the
   strips vertically, paint.

## The key open question — auth

**Does HP negotiation require security type 33 (RSA-SRP), or can it follow our
existing type 30 (Apple DH) auth?**

- If **type 30 is enough**: we reuse our working auth and go straight to step 4.
  Large project, but the crypto we'd add is "only" the AES-128-CBC record layer
  and SRTP.
- If **type 33 is required**: we must first implement **RSA-SRP** (SRP-6a with an
  RSA-wrapped identity, M1/M2 proofs) — a substantial crypto module on its own —
  before any HP work begins. Much larger.

This is the first thing to resolve, because it changes the size of the project
by a lot. It's answerable with a small probe against the live Mac.

## Phased plan

**Phase 0 — de-risk auth (small).** Probe whether the Mac will proceed to the HP
prelude after type-30 auth, or demands type-33. Decides the scope below.

**Phase 1 — control channel (medium/large).** Type-33 SRP if needed; the
SetEncryption handshake; the AES-128-CBC record layer; the encrypted prelude and
metadata burst; send a MediaStreamOptions offer and parse the answer + SRTP keys.
Milestone: we hold valid SRTP keys and the Mac has agreed to stream.

**Phase 2 — media receive (large).** UDP socket in the main process; SRTP decrypt
(RFC 3711 KDF, AES-256-CTR, HMAC-SHA1); RTP depacketization with DONL; reassemble
four SSRC tiles into HEVC access units. Milestone: raw HEVC access units in hand.

**Phase 3 — decode & render (small — already proven).** Feed access units to the
WebCodecs decoder we validated; composite four tiles; paint each `VideoFrame`.
Reuse the existing input/clipboard path over the control channel.

## Risk assessment

| Risk | Level | Note |
|---|---|---|
| HEVC 4:4:4 decode | ✅ resolved | proven, 30/30 frames in Electron |
| Mac supports HP | ✅ resolved | Apple Silicon + Sonoma confirmed |
| Auth (type 33 SRP) | ⚠️ unknown | Phase 0 decides; biggest scope swing |
| SRTP crypto | 🔨 hard | AES-256-CTR + HMAC + RFC 3711 KDF, but well-specified |
| RTP/DONL depacketization + tile sync | 🔨 hard | 4 SSRCs to one decoder, IDR = DPB reset |
| Protocol drift | ⚠️ ongoing | reverse-engineered; Apple can change it per macOS release |

## Honest bottom line

This is viable and no longer blocked on any "can it even be done" unknown — but
it is a **large** build (comparable to, or bigger than, the RFB client), and the
reverse-engineered protocol means ongoing maintenance risk. The RFB client stays
the reliable default that works on any Mac; HP mode would be an opt-in "fast path"
for capable Macs. Recommended to proceed one phase at a time, starting with the
Phase 0 auth probe.
