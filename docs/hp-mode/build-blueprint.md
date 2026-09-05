# Apple High Performance mode — build blueprint

> Produced by a 13-agent research workflow studying the iShareScreen reference
> (1.25M tokens). Byte-level claims are cited to that reference and adversarially verified.

## Auth verdict (the scope-decider)

HEADLINE: Type-33 SRP is NOT required. HP mode is a SESSION property, not an authentication property (RFC §1 L25: "MUST NOT infer high-performance capability... from the selected authentication branch. The same high-performance session behavior is reachable through more than one authentication branch"). The gate into HP is the RECORD LAYER (0x44f rekey → AES-128-CBC), and every auth branch (30/33/35/36) converges on the SAME record layer (§4.2.2 L162, §6.2.2). Therefore our EXISTING type-30 (DH) auth can in principle reach HP with NO new auth code.

THE ONE CATCH (this sets project size): the record layer needs a 16-byte WRAP KEY that is auth-branch-specific (§6.2.2 table L324-328):
  type 30 (DH):  wrap_key = MD5(dh_shared)[0:16]   (node: crypto.createHash('md5'))
  type 33/36:    wrap_key = SHA-256(SRP_K)[0:16]   (node: crypto.createHash('sha256'))
  type 35 (Krb): server-sent random 16B.
Only type 33 is BYTE-CONFIRMED BY CAPTURE (§4.2.7 L264); types 30/35/36 are flagged revision gaps. The MD5(shared)[:16] derivation for type 30 is documented (sub_100068030, L171,326) but UNVERIFIED against a live 0x44f unwrap. So the real question is not "SRP vs not" but "does MD5(shared)[:16] correctly ECB-unwrap the 0x44f blob our Mac pushes on the type-30 path." Phase 0 answers exactly that with zero media/SRP code.

DECISION TREE:
  Phase-0 probe PASSES (MAC verifies) → ship HP on type-30, SKIP all of type-33/SRP. Smallest project.
  Phase-0 probe FAILS → implement type-33 selector (0x21) + authtype=1 NON-SRP path first (RSA-2048 PKCS1v15 + AES-128-ECB creds, wrap_key = raw random aes_key per auth.py:121 — note this differs from SRP's sha256(K)[:16]); it reaches SecurityResult=0 on all tested macOS. Add full SRP-6a (authtype=2, 4096-bit RFC5054, SHA-512, PBKDF2) ONLY if a macOS-15+ host rejects non-SRP. Full SRP is the largest single sub-component (BigInt modpow + M1 chain hand-rolled) and is the LAST resort, not the default.

Evidence the reference always sends 0x21: both do_srp_auth and do_nonsrp_auth call _rsa1_init (auth.py:57-68) which fuses selector 0x21 with the RSA1 body — but that is the reference's choice, not a protocol requirement; the type-30→HP path is asserted by RFC and simply never exercised by iShareScreen.

## Module layout

Proposed layout under src/rfb-hp/. MAIN PROCESS (node:net TCP control, node:dgram UDP, node:crypto) vs RENDERER WORKER (WebCodecs decode + compositing). Main and renderer exchange only: (a) the decoded-frame feed as start-code HEVC chunks + tile/timestamp metadata over IPC/MessagePort, and (b) control events back.

MAIN PROCESS:
  src/rfb-hp/auth/
    type30-dh.js        EXISTING (reuse) — DH handshake, exposes dh_shared for wrap-key derivation.
    type33-rsa1.js      NEW, only if Phase-0 fails. _rsa1_init selector 0x21 + pubkey request (authtype=0); authtype=1 non-SRP (RSA publicEncrypt RSA_PKCS1_PADDING + aes-128-ecb creds). [auth.py:57-121]
    srp6a.js            NEW, last resort. BigInt modPow, PBKDF2-HMAC-SHA512, M1 chain, sha256(K)[:16]. [auth.py:149-357] HAND-ROLLED bignum.
    wrap-key.js         NEW, tiny. Branch→wrap_key: md5(shared)[:16] (t30) | sha256(K)[:16] (t33/36) | raw aes_key (t33 authtype=1). [§6.2.2]
  src/rfb-hp/record/
    record-layer.js     NEW. enc1103 StreamCipher: ECB-unwrap 0x44f 36B blob → cbcKey/cbcIv; per-direction AES-128-CBC with manual IV chaining; SHA-1(u32be(seq)||framed) trailer (NOT HMAC); filler = (-(2+body_len+20))&15; u16be outer len. [enc1103.py]
    set-encryption.js   NEW. Cleartext 0x12 cmd=1 (12B: 12 00 0001 0001 0001 00000001) + cmd=2 toggle (8B: 1200000200010000). [apple.py:54-72, rfb.py:177-181]
  src/rfb-hp/control/
    messages.js         NEW. Fixed-offset Buffer builders: 0x21 ViewerInfo(66B), 0x1d SetDisplayConfiguration(308B), 0x02 SetEncodings(56B), 0x03 FBUR(10B), 0x09 AutoFBU(16B). [rfb.py, apple.py]
    metadata-parse.js   NEW. FramebufferUpdate rect walker; parsers for 0x451 layout, 0x453, 0x455, 0x456, 0x450 cursor (zlib inflate). Tolerate 0x14(8B)/0x1f/1010/1011. [negotiation.py:825-888, rfb.py:36-73]
    negotiation.js      NEW. Prelude state machine + ordering (ViewerInfo→SetEnc1→[1d]→02 plaintext→await 0x44f→SetEnc2→drain→encrypted 02→0x1c→0x03).
  src/rfb-hp/media/
    mediastream-0x1c.js NEW. Build 0x1c offer (MS=AS+VS+0xD8; 4×46B key blobs; UUID; flags BE=3|4; zlib offers). Parse answer canvas dims. [negotiation.py:137-216, offers.py]
    srtp-keys.js        NEW. RFC3711 AES-CM KDF (labels 0/1/2 RTP, 3/4/5 RTCP) via aes-256-ctr-of-zeros over iv0||0x0000. [srtp.py:45-90]
    srtp-recv.js        NEW. dgram 5901; RTP/RTCP demux (pt7 64-95); per-SSRC ROC recovery; HMAC-SHA1-80 verify; aes-256-ctr payload decrypt; 16B IV assembly. [srtp.py:137-218]
    rtcp.js             NEW. RR/FIR/PLI/NACK/APP-LTR builders + SRTCP protect. [rtcp.py]
    depacketize.js      NEW. RFC7798 Apple-DONL variant (single/AP-48/FU-49, DONL in every fragment); (ssrc,ts) grouping; marker=complete; seq-wraparound sort; SSRC→tile. [nalu.py, burst.py]

RENDERER WORKER (proven WebCodecs path):
  src/rfb-hp/renderer/
    decoder.js          NEW. ONE shared VideoDecoder for all 4 tiles (cross-tile shared DPB); Annex-B (omit description); round-robin feed by frame index; IDR gate (drop pre-IDR P until tile-0 IDR); timestamp→tile map. [hevc.py]
    compositor.js       NEW. 4 horizontal strips stacked vertically by SSRC order; crop each to logical height via SPS conformance_window / 0x451 backing geometry; I444 blit. [tiles.py, §10.7]
    param-sets.js       NEW. VPS/SPS/PPS extraction (pps_id via exp-Golomb, hand-rolled BitReader) + extradata build. [bitstream.py, burst.py]

SHARED: src/rfb-hp/util/buffers.js (u16be/u32be/writeBigUInt64BE, toFixedBE for BigInt, byte-xor). BigInt modPow lives in srp6a.js only.

## Build phases

PHASE 0 — AUTH/WRAP-KEY LIVE PROBE (days, no media). Gate for whole project size. Design in phase0Probe field. Deliverable: a throwaway script on existing type-30 auth that either MAC-verifies the first inbound record (→ skip type-33 entirely) or fails (→ build type-33). DO NOT proceed to Phase 2+ until this is answered.

PHASE 1 — RECORD LAYER + PRELUDE (only the branch Phase-0 selected). Build record/ + control/messages.js + control/negotiation.js. Milestone: complete cleartext prelude, receive+ECB-unwrap 0x44f, send SetEncryption(2), then successfully SEND encrypted SetEncodings and RECEIVE+decrypt the server metadata burst (0x451 etc.) with every SHA-1 trailer verifying. This proves the entire encrypted control channel independent of media. If Phase-0 failed, type33-rsa1.js (authtype=1) is built here first; srp6a.js deferred until a host actually rejects non-SRP.

PHASE 2 — METADATA + VIRTUAL DISPLAY. Build metadata-parse.js fully; send 0x1d SetDisplayConfiguration (display_type=4, display_flags=0x01, reserved=7, non-degenerate mode table — these are the load-bearing MUSTs) and confirm the server accepts the virtual display and emits 0x451 AppleDisplayLayout with sane backing/scaled geometry. Milestone: correct on-screen geometry known; still-image RFB path renders (no HEVC yet).

PHASE 3 — MEDIA NEGOTIATION (0x1c). Build media/mediastream-0x1c.js + srtp-keys.js. Send the offer inside the record layer, parse the answer canvas dims. Milestone: server returns non-zero canvas w/h and begins emitting RTP on UDP 5901. RESOLVE the flags-endianness unknown HERE by observing whether cursor-strip/60fps behave (try BE first per iShareScreen; flip to LE if wrong).

PHASE 4 — SRTP RECEIVE + DEPACKETIZE. Build srtp-recv.js + rtcp.js + depacketize.js. Milestone: HMAC-SHA1-80 verifies on live packets (key2/server-send blob), AES-256-CTR yields clean HEVC NALUs, depacketizer emits ordered access units per (ssrc,ts). Send RR + FIR to trigger an IDR. Prove decrypt correctness BEFORE touching the decoder.

PHASE 5 — DECODE + COMPOSITE (renderer). Wire renderer/decoder.js + compositor.js + param-sets.js to the proven single-tile WebCodecs path. Milestone: 4-tile interleaved feed into ONE VideoDecoder produces 4 VideoFrames/source-frame; composite to full screen. This phase carries the #1 blocking risk (cross-tile shared DPB in Chromium WebCodecs) — spike it EARLY with a captured 4-SSRC stream, in parallel with Phase 1, since a failure here forces an architectural rethink.

PHASE 6 — STEADY STATE. AutoFBU 0x09 re-arm on every 0x451, keyframe-request on loss, replay window per SSRC, dynamic-resolution/SSRC-switch handling, teardown.

PARALLELISM: Phase 0 and the Phase 5 DPB spike (offline, on a captured stream) can run concurrently — they are the two make-or-break risks and both should be de-risked in week 1. Phases 1-4 are strictly sequential (each proves its predecessor's output).

## Phase 0 probe (run this first)

GOAL: answer "does HP work on our existing type-30 auth, or must we build type-33?" against the live Mac, building NOTHING beyond a ~150-line throwaway script (main process, node:net + node:crypto). No SRP, no UDP, no WebCodecs.

PROCEDURE:
1. Run our EXISTING working type-30 (DH) auth to SecurityResult=0. CAPTURE the DH shared secret bytes (instrument the existing handler). Send ClientInit(0xC1), read ServerInit.
2. Derive candidate wrap_key = MD5(dh_shared)[0:16]  →  crypto.createHash('md5').update(shared).digest().subarray(0,16). (Keep the raw shared and a couple of variants — full digest, shared-with-leading-zero-trim — ready as fallbacks; the exact byte form fed to MD5 is the sub-unknown.)
3. Send cleartext prelude: 0x21 ViewerInfo (66B) glued to 0x12 SetEncryption cmd=1 (12 00 0001 0001 0001 00000001). Then send 0x02 SetEncodings (56B, plaintext) advertising 0x451/0x453/0x455/0x456/0x450 so the server has reason to talk.
4. READ the inbound stream; walk FramebufferUpdate rects looking for encoding==1103 (0x44f). Tolerate interleaved 0x14 (skip 8B). Capture the 36-byte rekey blob (u32 generation || 16B enc_key || 16B enc_iv).
   CHECKPOINT A: if NO 0x44f ever arrives after SetEncryption(1) → type-30 does NOT reach the record layer on this host → MUST implement type-33. STOP.
5. ECB-unwrap under wrap_key: cbcKey = aes-128-ecb-decrypt(wrap_key, blob[4:20]); cbcIv = aes-128-ecb-decrypt(wrap_key, blob[20:36]) with setAutoPadding(false).
6. Send 0x12 SetEncryption cmd=2 (1200000200010000, plaintext). Then READ the next inbound record: u16be ciphertext_len (must be nonzero, %16==0). AES-128-CBC-decrypt with cbcKey/cbcIv (setAutoPadding false).
7. THE VERDICT TEST: split plaintext into body=pt[:-20], mac=pt[-20:]. Compute SHA1(u32be(seq)||pt[0:len-20]) for seq in the tolerance window [max(0,0-1)..5]. 
   CHECKPOINT B (DEFINITIVE): if any seq gives mac match (timingSafeEqual) AND body[0:2] u16be inner_len is sane → MD5(shared)[:16] is the correct type-30 wrap key → HP works on type-30 → we can SKIP type-33/SRP ENTIRELY. 
   If MAC never matches across all wrap_key variants AND all window seqs → either the wrap-key derivation for type-30 differs from the documented MD5(shared)[:16], or this host requires type-33. Fall back to building type-33 authtype=1 (cheap) and re-run the same steps 4-7 with wrap_key = raw random aes_key.

WHY THIS IS THE RIGHT PROBE: the SHA-1 record trailer is a hard cryptographic oracle — a matching MAC after CBC-decrypt is only possible if wrap_key, ECB-unwrap, CBC key/IV, and framing are ALL byte-correct. It cannot false-positive. One probe collapses the entire "SRP required?" question and fixes the project's size before a line of media code is written. Instrument every step to dump hex on failure so a mismatch tells us WHICH stage broke (no 0x44f = branch issue; unwrap junk = wrap-key issue; MAC miss = framing/seq issue).

## Risks

RANKED (blocking first):

1. [BLOCKING, verify week 1] Cross-tile shared-DPB in Chromium/Electron WebCodecs. Reference proves libavcodec's single CodecContext resolves tile-N P-frames against POCs produced by tile-M; it is UNVERIFIED that one WebCodecs VideoDecoder does the same. Per-tile decoders are NOT viable (§10.7). If WebCodecs rejects foreign/out-of-order references, the whole 4-tile architecture needs rethink. Mitigation: spike offline on a captured 4-SSRC stream in parallel with Phase 0.

2. [PROJECT-SIZE, Phase 0] Type-30 wrap-key derivation unverified. MD5(shared)[:16] is documented but not capture-confirmed (only type 33 is, §4.2.7 L264). If the type-30→HP path or its wrap key is wrong on our host, we inherit the full type-33 build (and possibly SRP). Phase-0 probe resolves this before any media work. Sub-risk: exact byte form of `shared` fed to MD5 (leading-zero handling).

3. [Phase 3, resolvable live] 0x1c flags endianness CONTRADICTION. iShareScreen writes BE (00 00 00 07, struct.pack('>I'), with emphatic MIG/NDR double-byteswap rationale); RFC says LE (07 00 00 00). Cannot both be right. Follow iShareScreen (writeUInt32BE) since empirically proven; flip to LE if cursor-strip/60fps bits misbehave. Cheap to A/B live.

4. [Phase 5] Coded vs logical strip height / CTU padding is a documented spec revision gap (§10.7 L808). Crop each tile to logical height from SPS conformance_window or 0x451 backing geometry — do NOT assume the 544/540 example.

5. [Phase 4, security] No replay window in reference (only advances max_seq). Add per-SSRC 64-bit sliding replay window — BUT if the client's NACK triggers same-seq retransmission, a naive window would drop legit retransmits. Confirm Apple's retransmit behavior before enabling strict replay.

6. [Phase 4] PT=101 client→server media keepalive: RFC marks OPTIONAL (§10.5, not in native capture) but srtp.py docstring calls it "expected". Keep the SRTPEncryptor/keepalive path until proven unnecessary.

7. [Phase 4] RTCP-mux demux rule (pt7 in 64-95) is INFERRED (RFC 5761) — not present in srtp.py/rtcp.py. Sound but the exact byte the native client tests is unverified; validate against live traffic.

8. [Phase 5] Exact WebCodecs codec string for HEVC RExt 4:4:4 8-bit (e.g. hev1.4.10.L153.B0) must be derived from SPS profile_idc/level_idc at runtime via isConfigSupported() — do NOT ship a literal.

9. [Phase 2] 0x451 AppleDisplayLayout has two conflicting field models (rfb.py working parser vs RFC §8.4, ~2-byte payload_len prefix skew). Implement the rfb.py parser; keep RFC model as fallback.

10. [Phase 1, minor] Reference SetEncoding double-send (plaintext then encrypted) and never sends an encrypted 0x1d; RFC lists each once encrypted. Follow the reference. Also: 0x1f (16B header + variable zlib, may span record frames) cannot be fixed-size-skipped like 0x14 — handle explicitly in the metadata walker.

CORRECTION FOLDED IN (supersedes original blueprint): SRP c2s1 block-length field is 2 bytes (>H, 01 00) not 4 (00 00 01 00) — the diagram was internally inconsistent; use buf.writeUInt16BE(256). Node decryptRecord must include the `if(pt.length<=20)return pt;` guard for parity with enc1103.py L121-122.

## Crypto coverage (node:crypto vs hand-rolled)

COVERED BY node:crypto (no hand-roll):
- RSA load + encrypt: crypto.createPublicKey({format:'der',type:'spki'}) + crypto.publicEncrypt({padding: crypto.constants.RSA_PKCS1_PADDING}). CRITICAL: default is OAEP; MUST override to PKCS1 or type-33 fails.
- AES-128-ECB rekey unwrap & non-SRP creds: crypto.createDecipheriv/createCipheriv('aes-128-ecb', key, null) with setAutoPadding(false).
- AES-128-CBC record layer: createCipheriv/createDecipheriv('aes-128-cbc', cbcKey, iv) setAutoPadding(false); chain IV = last 16B of prior ciphertext (do NOT keep one long-lived object — Node finalizes per call; manage IV manually).
- AES-256-CTR SRTP payload + KDF: createDecipheriv('aes-256-ctr', key, iv16). KDF trick: aes-256-ctr(masterKey, iv0||0x0000) over zeros == RFC3711 AES-CM keystream (verified byte-identical to the Python ECB counter loop for labels 0/1/2).
- Hashes: createHash('sha512'|'sha256'|'sha1'|'md5'). NOTE the record trailer and SRTP tag are PLAIN SHA-1, NOT HMAC — do not reach for createHmac there.
- HMAC-SHA1-80 SRTP auth: createHmac('sha1',authKey).digest().subarray(0,10) + timingSafeEqual.
- PBKDF2: crypto.pbkdf2Sync(pw, salt, iterations, 128, 'sha512') (dkLen=128B).
- Randomness: crypto.randomBytes(16|46|64). UUID: prefer a real v4 (set version/variant bits) not raw randomBytes(16).
- zlib offers/cursor: node:zlib deflateSync/inflateSync.
- Transport: node:dgram (udp4) media, node:net control.

MUST BE HAND-ROLLED (no native primitive):
- SRP-6a modular exponentiation g^a/g^x/S=base^exp mod N — Node has NO bignum modpow. BigInt square-and-multiply: function modPow(b,e,m){b%=m;let r=1n;while(e>0n){if(e&1n)r=r*b%m;e>>=1n;b=b*b%m;}return r;} with ((v%N)+N)%N sign-fix (JS % keeps dividend sign). Only needed if SRP path is built.
- Fixed-width 512-byte BE BigInt↔Buffer (Python .to_bytes(512,'big')); bytes→BigInt = BigInt('0x'+buf.toString('hex')) (guard empty→0n).
- H(N) XOR H(g) byte loop for SRP M1.
- exp-Golomb ue/se + MSB-first BitReader + emulation-prevention strip (for pps_id / SPS parse) — no stdlib equivalent.
- ALL framing/byte-assembly: writeUInt16BE/writeUInt32BE/writeBigUInt64BE. Watch mixed endianness: struct.pack('<H',1)=bytes 01 00 (LE) for SRP version field while all length prefixes are BE — do NOT normalize.
- Record filler/MAC layout, per-record IV chaining bookkeeping, SRTP 16-byte IV assembly (direct-XOR form: salt into 0-13, ssrc_be^=4-7, roc_be^=8-11, seq_be^=12-13, zero 14-15 — byte-identical to BigInt form, faster on hot path), per-SSRC ROC state machine.
