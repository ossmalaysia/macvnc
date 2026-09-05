# HP mode — per-component byte blueprints

> Verified study output for each protocol component.

## Security type 33 (RSA1 / RSA-SRP) authentication — Node.js blueprint

Type 33 (selector 0x21) is the security type the reference selects for BOTH of its auth paths; it is the gateway into HP mode but full SRP-6a is NOT mandatory. The RSA1 envelope carries an `authtype` field: authtype=1 is a simple RSA-2048/PKCS1v15 + AES-128-ECB credential exchange (non-SRP), authtype=2 is the SRP-6a (RFC5054 4096-bit, SHA-512, PBKDF2) exchange. Both terminate in SecurityResult=0 and yield a 16-byte wrap key that seeds the post-auth record layer. Almost everything maps to node:crypto; only SRP modpow (BigInt) and the M1 hash chain are hand-rolled.

### Blueprint

## Q1 — Is type 33 REQUIRED for HP mode? Is SRP required?

RFC §1/§11 (apple_vnc_rfc.md:25, :11): "High-performance mode is a SESSION property, not an authentication property... reachable through more than one authentication branch." So HP does NOT require type 33 in principle (types 30/33/35/36 all lead to the same record layer, §6.2.2 rfc:322-330).

BUT what the reference ACTUALLY does: both `do_srp_auth` and `do_nonsrp_auth` call `_rsa1_init` (auth.py:57-68), which sends selector byte `0x21` (=type 33). So the reference ALWAYS selects type 33. The two paths differ ONLY by the `authtype` u16 inside the RSA1 envelope that follows:
- authtype=1 → non-SRP: RSA-PKCS1v15(aes_key) + AES-128-ECB(username/password). (auth.py:87-121)
- authtype=2 → SRP-6a. (auth.py:149-357)

`_phase_auth` (negotiation.py:243-265) runs one as primary and the OTHER as fallback on AuthError; default primary is SRP for macOS 15+, but auth.py:10-11 states the non-SRP path "works against every shipping macOS we've tested and is used as fallback."

CONCLUSION: You MUST implement type-33 SELECTION (0x21) and the RSA1 authtype=0 pubkey request. You do NOT strictly need SRP: the far simpler authtype=1 non-SRP path reaches SecurityResult=0 → HP on all tested macOS. Implement authtype=1 first; add SRP (authtype=2) only for macOS-15+ hosts that reject non-SRP. Both return a 16-byte wrap key with identical downstream role.

═══════════════════════════════════════════════════════════
## Q2/Q4 — Exact byte flow

### Handshake preamble (before type 33), RFC §4.1 (rfc:130-146)
1. Read 12 bytes server banner `RFB 003.889\n` = `52 46 42 20 30 30 33 2e 38 38 39 0a`.
2. Send same 12 bytes back.
3. Read `u8 count` then `count` type bytes; observed `04 1e 21 24 23` (types 30,33,36,35). count=0 → close.
4. Select: send single byte `0x21`.

### STEP A — RSA1 pubkey request (authtype=0), shared by both paths
auth.py:61. Send these 15 bytes VERBATIM (selector already sent OR coalesce; reference sends 0x21 here as first byte):
```
21                            selector (type 33)
00 00 00 0A                   u32 BE total_len = 10
01 00                         u16 version = 0x0100  (little-endian-looking, emit as-is)
52 53 41 31                   "RSA1"
00 00                         u16 authtype = 0
00 00                         u16 inner_len = 0
```
NOTE: auth.py sends selector 0x21 fused with the 14-byte RSA1 body in one sendall. If your state machine already sent 0x21 as the selector, send only the 14 bytes `00 00 00 0A 01 00 52 53 41 31 00 00 00 00`.

Read response (auth.py:62-66):
```
u32 BE pkt_len
byte[pkt_len] pkt:
   pkt[0:2]   = 2-byte direction/version prefix (skip)
   pkt[2:6]   = u32 BE key_len
   pkt[6:6+key_len] = DER SubjectPublicKeyInfo (RSA-2048 pubkey)
```
(RFC §4.2.4.1 rfc:191 documents the server framing as `u32_be(n+7) || u32_le 0x100 || u16_be n || DER[n]` + 1 trailing zero — the reference's simpler pkt[2:6]/pkt[6:] slice works because it reads u32 at offset 2 as key length. Follow auth.py's slice: key_len=u32BE at [2:6], DER at [6:6+key_len].)

──────────────────────────────────────────
### PATH 1 — NON-SRP (authtype=1) — RECOMMENDED FIRST
auth.py:73-121.

**ARD credential slot** (`_pack_ard_credential`, auth.py:73-84): each of username & password →
```
value_utf8 || 0x00 || random_pad   → exactly 64 bytes (truncate if longer)
```
creds = slot(username)[64] || slot(password)[64] = 128 bytes.

**Encrypt** (auth.py:92-94):
- enc_creds = AES-128-ECB(key=aes_key, NO IV, NO PKCS padding).encrypt(creds) → 128 bytes. aes_key = 16 random bytes (os.urandom(16)).
- enc_aes_key = RSA_encrypt(server_pub, aes_key, PKCS#1 v1.5) → 256 bytes.

**c2s1 blob** (auth.py:96-101):
```
01 00                 u16 version 0x0100
52 53 41 31           "RSA1"
00 01                 u16 authtype = 1        (marker/count)
<enc_creds>           128 bytes
00 01                 u16 = 1                 (marker/count)
<enc_aes_key>         256 bytes
```
blob length = 6+2+128+2+256 = 394. Send `u32 BE 394` || blob.

**Result** (auth.py:104-110): read 4 bytes padding (M2 placeholder), then `u32 BE result`. result==0 → SUCCESS. Return aes_key (the raw 16 bytes) as the enc1103/wrap key.

──────────────────────────────────────────
### PATH 2 — SRP (authtype=2)
auth.py:149-357. RFC §4.2.4.

**c2s1: RSA-wrapped identity** (`_send_srp_modulus`, auth.py:149-170):
inner identity plaintext (RFC §4.2.4.3 rfc:203-209):
```
u32 BE len(inner)          where inner is the block below
  inner:
  u32 BE username_len
  byte[username_len] username (UTF-8)
  00 00 00                 (u16 empty_string_len=0 || u8 empty_opaque_len=0)
```
Precisely (auth.py:156-158): `inner = u32BE(len(user)) || user || 00 00 00`; `payload = u32BE(len(inner)) || inner`. RSA_encrypt(payload, PKCS1v15) → MUST be exactly 256 bytes (else AuthError).

c2s1 wire (auth.py:165-170):
```
01 00                  u16 LE = 1  (struct.pack("<H",1) → bytes 01 00)
52 53 41 31            "RSA1"
00 02                  u16 authtype = 2
00 00 01 00            u16 BE 0x0100 (=256, the RSA block len)
<encrypted>            256 bytes
00 × 384               zero tail
```
Total c2s1 = 2+4+2+2+256+384 = 650. Send `u32 BE 650` || c2s1.

**s2c1: SRP challenge** (`_read_srp_challenge`/`_parse_apple_srp_challenge`, auth.py:173-248):
Read `u32 BE s2c1_len` (must be ≥1000 or server fell back), then s2c1 bytes. Parse:
```
offset 0..11   12-byte TLV header (skip)
offset 12      0x00 DER positive-int marker (must be 0)
offset 13      N modulus, 512 bytes  (Nb)
   +2          u16 BE g_len (=1)
   +g_len      g (1 byte, =5)
   +1          u8 salt_len (=32)
   +salt_len   salt
   +2          u16 BE B_len (=512)
   +B_len      B (Bb)
   +8          u64 BE iterations   (reject if >1_000_000)
   +2          u16 BE cap_len
   +cap_len    cap (options ASCII string — echo verbatim)
```
N=int(Nb,BE), B=int(Bb,BE).

**SRP-6a math** (`_derive_x` + `_solve_srp`, auth.py:251-305). KL=512, all PAD to 512 BE.
```
g_padded = g.to_bytes(512,BE)
k  = H(Nb || g_padded)                              # int, SHA-512
a  = int(random 64 bytes) % (N-1) + 1
A  = g^a mod N ;  Ab = A.to_bytes(512,BE)
u  = H(Ab || Bb)
# x derivation (Apple SALTED-SHA512-PBKDF2, auth.py:251-267):
dk    = PBKDF2_HMAC_SHA512(password_utf8, salt, iterations, dkLen=128)
inner = SHA512( 0x3a || dk )                        # 0x3a = ":", empty username prefix
x     = int(SHA512(salt || inner), BE) mod N
# premaster:
S  = ( (B - k*(g^x mod N)) mod N ) ^ (a + u*x)  mod N
K  = SHA512( S.to_bytes(512,BE) )                   # 64-byte digest
# client proof M1 = H( H(N) XOR H(g) || H("") || salt || A || B || K ):
h_n = SHA512(Nb) ; h_g = SHA512(g_padded)
xor = bytes(h_n[i]^h_g[i])
M1  = SHA512( xor || SHA512(b"") || salt || Ab || Bb || K )    # 64 bytes
```

**c2s2: proof** (`_send_srp_proof`, auth.py:308-326):
```
sd = u16BE(512) || Ab(512)
   || u8(64) || M1(64)
   || u16BE(len(cap)) || cap
   || u8(16) || civ(16 random)
pay = 01 00 || "RSA1" || 00 02
    || u16BE(len(sd)+4)
    || u32BE(len(sd)) || sd
pay = pay padded with 0x00 up to 1076 bytes
send u32BE(1076) || pay
```
(struct.pack("<H",1) → 01 00; "RSA1"; authtype 00 02.)

**Result** (`_read_srp_result`, auth.py:329-338): `u32BE m2_len`, read m2_len bytes (M2, NOT verified), `u32BE result`. result==0 → success. Wrap key = `SHA-256(K)[0:16]` (auth.py:356; RFC §4.2.4.8 rfc:237).

═══════════════════════════════════════════════════════════
## Q3 — node:crypto mapping vs hand-roll

MAPS DIRECTLY to node:crypto:
- Load server pubkey: `crypto.createPublicKey({key: derBuf, format:'der', type:'spki'})`.
- RSA PKCS1v15 encrypt: `crypto.publicEncrypt({key: pub, padding: crypto.constants.RSA_PKCS1_PADDING}, aesKeyBuf)`. CRITICAL: node default is OAEP — you MUST pass RSA_PKCS1_PADDING or it will not match.
- AES-128-ECB creds (non-SRP): `crypto.createCipheriv('aes-128-ecb', aesKey, null); c.setAutoPadding(false)` (input is exactly 128 B = 8 blocks, no padding). Encrypt the 128-byte creds.
- SHA-512 / SHA-256: `crypto.createHash('sha512'|'sha256')`.
- PBKDF2-HMAC-SHA512: `crypto.pbkdf2Sync(password, salt, iterations, 128, 'sha512')` (dkLen=128 bytes).
- Randomness: `crypto.randomBytes(16|64)`.

HAND-ROLL (no native primitive):
- SRP modular exponentiation `g^a mod N`, `g^x mod N`, `S = base^exp mod N`: node has NO bignum modpow. Use BigInt with a square-and-multiply modPow helper: `function modPow(b,e,m){b%=m;let r=1n;while(e>0n){if(e&1n)r=r*b%m;e>>=1n;b=b*b%m;}return r;}`. Convert bytes↔BigInt: `BigInt('0x'+buf.toString('hex'))` and back with fixed-width left-zero-pad to 512 bytes.
- The `(B - k*g^x) mod N` subtraction must be kept positive: `((v % N)+N)%N`.
- The H(N) XOR H(g) byte-xor loop for M1 (trivial Buffer loop).
- All the length-prefixed framing (struct.pack equivalents): use Buffer.writeUInt16BE/writeUInt32BE; emulate u64 with `writeBigUInt64BE`. Note struct.pack("<H",1) = bytes 01 00 (little-endian) — emit `Buffer.from([0x01,0x00])`.
- Fixed-width int→bytes PAD: write a `toFixedBE(bigint, 512)` (Python `.to_bytes(512,'big')`).

int.from_bytes(x,'big') → `BigInt('0x'+Buffer.from(x).toString('hex'))` (guard empty → 0n).

### Node crypto

RSA: crypto.createPublicKey({format:'der',type:'spki'}) + crypto.publicEncrypt({padding: crypto.constants.RSA_PKCS1_PADDING}) — MUST override the default OAEP padding. AES creds: crypto.createCipheriv('aes-128-ecb', key, null) with setAutoPadding(false) over exactly 128 bytes. Hashes: crypto.createHash('sha512') for k,u,x,K,M1 and 'sha256' for the SRP wrap key. KDF: crypto.pbkdf2Sync(pw, salt, iterations, 128, 'sha512'). Random: crypto.randomBytes. HAND-ROLLED: BigInt square-and-multiply modPow (g^a, g^x, S=base^exp mod N — no native modpow), fixed-width 512-byte BE int↔Buffer conversion, H(N)^H(g) xor loop, and all Buffer-based length-prefix framing (writeUInt16BE/UInt32BE, writeBigUInt64BE; note struct '<H' little-endian = bytes 01 00).

### Unknowns

- The 2-byte RSA1 pubkey-response prefix (pkt[0:2]) is skipped by auth.py but RFC §4.2.4.1 (rfc:191) describes a richer u32_le 0x100 framing; auth.py's key_len=u32BE at pkt[2:6] works empirically — trust auth.py's slice, but verify pkt[0:2] against a live capture before relying on exact prefix bytes.
- The two `00 01` u16 markers in the non-SRP c2s1 blob (auth.py:98-99) are labeled authtype/count in comments but their precise server-side meaning is not documented; emit them verbatim.
- SRP c2s1 uses struct.pack('<H',1) (little-endian → 01 00) for the leading version while the length prefixes are big-endian; this mixed endianness is intentional per auth.py:166 — do not 'normalize' it.
- M2 is never verified by the reference (auth.py:333-335); server's u32 result is canonical. Skipping M2 verification is acceptable for pass/fail but leaves server-impersonation undetected.
- Non-SRP path returns the RAW random aes_key as the wrap key (auth.py:121), NOT sha256(K); SRP returns sha256(K)[:16] (auth.py:356). The two paths yield different key-derivation but both feed the identical enc1103/record layer — confirm which auth actually succeeded before seeding the cipher.
- Whether a Node client can SKIP the 0x21 selector entirely and reach HP via type 30/36 is asserted possible by RFC §1 but NOT exercised by the reference; only the 0x21 (type 33) selection path is byte-confirmed.

---

## SRTP media receive/decrypt over UDP 5901 (AES-256-CTR + HMAC-SHA1-80), Node.js main process

Receives Apple "High Performance" HEVC media as SRTP/RTP packets on UDP 5901 via node:dgram, demuxes RTP (PT 100) from rtcp-muxed RTCP (PT 200-207), verifies the 80-bit HMAC-SHA1 tag with per-SSRC ROC recovery, and AES-256-CTR-decrypts the payload into HEVC NAL data for the renderer's WebCodecs decoder. Also derives the six SRTP/SRTCP session keys from the 46-byte "key2" blob via the RFC 3711 AES-CM KDF and builds RTCP receiver feedback (RR/FIR/PLI/NACK/APP-LTR) to keep the four-SSRC tile stream alive. All primitives map cleanly onto node:crypto (aes-256-ctr, aes-256-ecb/ctr for KDF, createHmac sha1); only the 128-bit big-endian IV arithmetic and the ROC state machine are hand-rolled.

### Blueprint

=== 0. KEY MATERIAL & KDF (srtp.py:37-65,83-90) ===

Input: the 46-byte SRTP "key2" (server->client / receive) blob from the 0x1c MediaStreamOptions answer (spec:739-740,891). key2 authenticates; key1 does not.
  blob[0:32]  = master_key (32 B)  -> AES-256
  blob[32:46] = master_salt (14 B)

Derive 6 values via _srtp_kdf(master_key, master_salt, label, out_len):
  RTP:  cipher_key = kdf(...,label=0,32)  auth_key = kdf(...,1,20)  salt = kdf(...,2,14)
  RTCP: cipher_key = kdf(...,label=3,32)  auth_key = kdf(...,4,20)  salt = kdf(...,5,14)

_srtp_kdf algorithm (byte-exact, srtp.py:45-65):
  1. kid = 14 zero bytes; kid[7] = label (single byte).
  2. iv0[i] = kid[i] XOR master_salt[i]  for i in 0..13   (14 bytes).
  3. counter block = iv0(14) || 0x00 0x00  (16 B), then ADD the 16-bit block counter
     (0,1,2,...) into the low bytes with carry — i.e. treat the 16-byte block as a
     128-bit big-endian integer whose low 16 bits = counter.
  4. out = AES-256-ECB(master_key, block_0) || AES-256-ECB(master_key, block_1) || ...
     truncated to out_len. (32 B -> 2 blocks, 20 B -> 2 blocks, 14 B -> 1 block.)
  This is AES-CM keystream with IV=iv0||0000. NODE SHORTCUT: identical to
  aes-256-ctr(master_key, iv=iv0||0x0000).update(Buffer.alloc(out_len_rounded_to_16)).

Precompute once: salt_int = BigInt over (salt(14) || 0x00 0x00)  == salt in bytes 0..13
of a 16-byte big-endian value, bytes 14-15 = 0 (srtp.py:87).

=== 1. RTP HEADER PARSE (srtp.py:140-146,185-198; spec:770,773) ===

SRTP packet on UDP 5901, min length = 12(hdr) + 10(tag) = 22 B. Big-endian throughout.
  byte 0      : V(2)|P(1)|X(1)|CC(4).  V=2 (0x80 base).  X = (b0>>4)&1 extension flag. CC = b0&0x0F CSRC count.
  byte 1      : M(1)|PT(7).  PT must == 100 for video HEVC.
  bytes 2-3   : sequence number seq (u16 BE)  = (pkt[2]<<8)|pkt[3].
  bytes 4-7   : RTP timestamp (u32 BE) — not needed for decrypt.
  bytes 8-11  : SSRC (u32 BE) = pkt.readUInt32BE(8). Demux key.
  bytes 12.. : CC*4 CSRC (usually 0).
  If X: at offset (12+CC*4): [u16 profile][u16 ext_len_words]; header extends by 4 + ext_len*4.
  hdr_len = 12 + CC*4 (+ ext block if X). Validate hdr_len <= body_len else drop.

body_len = packet.length - 10   (everything except the trailing 10-byte auth tag).
Encrypted payload = pkt[hdr_len : body_len]. Header pkt[0:hdr_len] is CLEARTEXT (authenticated, not encrypted).

SSRC demux: four consecutive SSRCs = four horizontal tiles (spec:773,805-807). Base SSRC
carries IDRs; maintain independent state per SSRC in a Map<ssrc, {roc, max_seq, initialized}>.
Feed all four, ordered by DONL, into ONE WebCodecs decoder (out of scope for this component,
but demux must tag each depacketized NAL with its SSRC + seq for the ordering stage).

=== 2. ROC (ROLLOVER COUNTER) RECOVERY (srtp.py:147-173,207-218; spec:787) ===

Per-SSRC state: {roc:u32=0, max_seq:u16=0, initialized:bool=false}.
Guess ROC for an arriving seq (srtp.py:147-157):
  if !state or !initialized: roc_guess = 0
  else:
    diff = seq - state.max_seq        (signed)
    if diff >  0x7FFF: roc_guess = max(0, state.roc - 1)   // old packet, prev cycle
    elif diff < -0x7FFF: roc_guess = state.roc + 1          // wrapped forward
    else: roc_guess = state.roc
Candidate ROCs tried in order, de-duped preserving order (srtp.py:159-165):
  [roc_guess, state.roc(or 0), roc_guess+1, max(0, roc_guess-1)]
For each candidate, run auth-verify (§3). First that passes -> accept, update state, return.
If none pass -> drop packet (return null), do NOT close transport (spec:919).

Update on success (srtp.py:207-218): if !initialized set roc/max_seq=accepted; else compare
48-bit index new=(roc<<16)|seq vs cur=(state.roc<<16)|state.max_seq, advance only if new>cur.

Replay: spec calls for a replay window; Python only advances max_seq (no explicit bitmap).
Minimum viable = accept; production SHOULD add a 64-bit sliding replay window per SSRC keyed
on index and drop duplicates/too-old (spec:790,919). Note as enhancement.

=== 3. AUTH-TAG VERIFY (srtp.py:175-183; spec:787) ===

roc_be = 4-byte BE of candidate ROC.
tag_input = pkt[0 : body_len]  (RTP header + encrypted payload, i.e. whole packet minus 10-B tag)  ++  roc_be
computed = HMAC-SHA1(auth_key, tag_input)  -> take first 10 bytes.
received = pkt[body_len : body_len+10].
Constant-time compare (crypto.timingSafeEqual on 10-byte slices). Mismatch -> this ROC fails.

=== 4. AES-256-CTR DECRYPT — BYTE-EXACT IV (srtp.py:200-205; spec:786) ===

After auth passes and header parsed:
  if hdr_len == body_len: payload = empty, return (header, "").
  seq  = u16 from bytes 2-3;  ssrc = u32 from bytes 8-11;  roc = accepted candidate.
  index = (roc << 16) | seq            // 48-bit
  IV(128-bit) = salt_int  XOR  (ssrc << 64)  XOR  (index << 16)
  iv = 16-byte BE of that integer.

Concrete 16-byte IV layout (byte 0 = MSB):
  bytes 0-3   : salt[0..3]
  bytes 4-7   : salt[4..7]  XOR  ssrc_be(4)
  bytes 8-11  : salt[8..11] XOR  roc_be(4)          // high 32 bits of index<<16
  bytes 12-13 : salt[12..13] XOR seq_be(2)          // low 16 bits of index<<16
  bytes 14-15 : 0x00 0x00                            // AES-CTR block counter start = 0

plaintext = AES-256-CTR(cipher_key, iv).update(pkt[hdr_len:body_len])
Node increments the full 128-bit counter; SRTP only intends the low 16 bits, but payloads are
<< 2^16*16 bytes (1 MiB) so no divergence. Return (header, plaintext). plaintext = HEVC/DONL NAL
bytes for depacketization (spec:792-800).

=== 5. WORKED ONE-PACKET PROCEDURE ===
 1. dgram 'message' handler gets Buffer `pkt`, rinfo.
 2. If pkt.length < 22 -> drop.
 3. pt7 = pkt[1] & 0x7F. If 64<=pt7<=95 -> route to RTCP handler (§6). Else RTP.
 4. If (pkt[1]&0x7F) != 100 -> drop (unexpected RTP PT on video port).
 5. body_len = pkt.length-10; seq = pkt.readUInt16BE(2); ssrc = pkt.readUInt32BE(8).
 6. Compute candidate ROCs (§2).
 7. For each ROC: build roc_be, HMAC-SHA1(auth_key, pkt[0:body_len]++roc_be)[0:10],
    timingSafeEqual vs pkt[body_len:body_len+10]. On match go to 8.
 8. Parse header length (CC, X). Build 16-byte IV (§4). AES-256-CTR decrypt pkt[hdr_len:body_len].
 9. Update per-SSRC ROC state. Emit {ssrc, seq, header, hevcPayload} to depacketizer.
10. No candidate matched -> drop silently, increment a drop counter.

=== 6. RTCP-MUX DEMUX + FEEDBACK (rtcp.py; spec:770-773,810-822) ===

Demux (RFC 5761, not shown in Python but required): on the same socket, pt7 = pkt[1]&0x7F.
RTCP PTs 200-207 (and legacy 192/193) all satisfy 64<=pt7<=95; RTP PT 100/101 do not.
So: isRtcp = ((pkt[1]&0x7F) >= 64 && (pkt[1]&0x7F) <= 95). Video RTP PT=100 (0x64), audio PT=101.

Inbound RTCP is SRTCP -> unprotect via SRTCPDecryptor (srtp.py:288-322):
  min len = 8+4+10. body = pkt[:-10]; tag = pkt[-10:]; e_index_word = u32 BE at pkt[-14:-10].
  Verify HMAC-SHA1(rtcp_auth_key, body)[0:10] == tag (note: RTCP authenticates `body` WITHOUT a
  ROC append — differs from RTP). encrypted = e_index_word & 0x80000000; index = e_index_word & 0x7FFFFFFF.
  hdr = pkt[0:8]; ciphertext = pkt[8:-14]. If !encrypted return hdr++ciphertext.
  Else ssrc = u32 at hdr[4:8]; IV = rtcp_salt(14)||0000 XOR ssrc into bytes 4-7 XOR index_be into
  bytes 10-13 (srtp.py:311-322). AES-256-CTR(rtcp_cipher_key, iv) decrypt ciphertext. Return hdr++plaintext.

Then walk compound RTCP (rtcp.py:154-169): each sub-packet [b0,pt,len_words]; pkt_len=(len+1)*4;
PT 200 (SR) -> capture (ssrc, ntp_mid32, arrival) for RR's LSR/DLSR.

Outbound feedback the client SHOULD send to keep stream alive (spec:810-822; rtcp.py). Build,
then SRTCP-protect (SRTCPEncryptor srtp.py:341-365: 31-bit incrementing index, E-bit set, IV same
shape as decrypt, tag over hdr++ciphertext++e_index), send on 5901:
  - build_rr(sender_ssrc, source_ssrcs, ssrc_stats): PT=201; per-SSRC report block carries
    ext_seq = (roc<<16)|max_seq from ROC state (rtcp.py:115-151). Periodic (~1/s).
  - Keyframe request on loss/startup: build_fir_legacy(target_ssrc) PT=192 8 bytes (native path,
    server answers with IDR, rtcp.py:34-39) OR AVPF build_fir(...) PT=206 FMT4 / build_pli PT=206
    FMT1 / build_nack PT=205 FMT1 (rtcp.py:24-78). Server accepts both styles.
  - build_rtcp_app_ltrp(sender_ssrc, ltr_id) PT=204 subtype 5 — LTR ack, ~30/s in healthy session
    (rtcp.py:81-100).
  - build_empty_sr(sender_ssrc) PT=200 so AVConference accepts us as live sender (rtcp.py:103-112).
  - compound_with_rr(): prefix feedback with an empty RR since some peers reject non-compound
    feedback (rtcp.py:172-175).
Without this feedback loop the shared decoder cannot recover a lost reference (spec:822).

=== 7. node:dgram USAGE ===
  const sock = dgram.createSocket('udp4');
  sock.bind(localPort);  // Apple sends server->client media to the port the client sourced its
                         // 0x1c offer / RTCP from; bind that ephemeral/known local port, remote 5901.
  sock.on('message', (buf, rinfo) => handle(buf, rinfo));  // buf is a Buffer, already one datagram.
  sock.send(feedbackBuf, 5901, serverHost);                // RTCP + optional keepalive.
  One socket per media port (5901 video, 5900 audio) carries both that port's RTP and its muxed RTCP.

### Node crypto

KDF keystream (labels 0-5): crypto.createCipheriv('aes-256-ctr', master_key, Buffer.concat([iv0(14), Buffer.from([0,0])])).update(Buffer.alloc(ceil(out_len/16)*16)) then slice to out_len — replaces Python's manual AES-256-ECB counter loop (equivalent output). Alternatively crypto.createCipheriv('aes-256-ecb', master_key, null) with setAutoPadding(false) on hand-built counter blocks.
Payload decrypt: crypto.createDecipheriv('aes-256-ctr', cipher_key, iv16).update(ciphertext) (no final() needed for CTR; a stream cipher so decipher/cipher are interchangeable).
Auth tag: crypto.createHmac('sha1', auth_key).update(pkt.subarray(0,body_len)).update(roc_be).digest().subarray(0,10). Compare with crypto.timingSafeEqual (both args length 10).
RTCP auth: same createHmac('sha1', rtcp_auth_key).update(body).digest().subarray(0,10) — NO roc append.
IV math: use BigInt (salt_int, ssrc, index) with XOR, then write to a 16-byte Buffer via a BE conversion, OR (faster, avoids BigInt) build the 16-byte Buffer directly: copy salt(14) into bytes0-13, zero bytes14-15, then buf[4..7]^=ssrc_be, buf[8..11]^=roc_be, buf[12..13]^=seq_be. The direct-XOR form is byte-identical to the BigInt form and is recommended for the hot path.
node:dgram (udp4) for socket; node:net not needed for media. All AES/HMAC covered by node:crypto — nothing must be hand-rolled except the 16-byte IV assembly and the ROC state machine.

### Citations

srtp.py:37-65 (KDF), :83-90 (key derive + salt_int), :137-173 (decrypt/ROC recovery), :175-205 (auth+IV+CTR decrypt), :207-218 (state update), :288-322 (SRTCP unprotect), :341-365 (SRTCP protect). rtcp.py:24-112 (FIR/PLI/NACK/APP-LTR/empty-SR builders), :115-151 (build_rr ext_seq), :154-175 (parse_sr_arrivals, compound_with_rr). apple_vnc_rfc.md:768-773 (UDP flows, PT100/101, four SSRCs, per-SSRC ROC), :781-790 (SRTP cipher, KDF labels, IV formula, tag-over-ROC, replay), :805-807 (tiling/single decoder), :810-822 (RTCP feedback), :891-896 (Profile C reqs, key2 for receive), :919 (discard-not-close on auth fail).

### Unknowns

- Replay protection: srtp.py only advances max_seq and does NOT implement an explicit RFC 3711 sliding replay window/bitmap; spec:790,919 says duplicates/out-of-window MUST be discarded. A production Node impl should add a per-SSRC 64-bit replay window keyed on the 48-bit index. Confirm whether Apple's server ever retransmits (NACK) into a window that would make a naive drop harmful.
- RTCP demux rule (RFC 5761 pt7 in 64-95) is inferred — it is NOT present in srtp.py/rtcp.py (those files never show the RTP-vs-RTCP branch). The 100/101 vs 200-207 PT ranges (spec:770-773) make the rule safe, but the exact byte the native client tests is unverified.
- Which local UDP port to bind: spec/Python show media on 5901 but not the client's own source port binding; Apple likely sends server->client media to the address:port the client used for its 0x1c offer / first RTCP. Needs confirmation from the session/transport layer (not in these two files).
- CTR 16-bit block-counter vs Node's 128-bit counter: only diverges for payloads >= 1 MiB per packet, which never occurs for tiled HEVC, but not formally proven for jumbo/aggregation packets.
- RTP header extension (X bit) parsing path in srtp.py:188-192 is present but the capture may never exercise it; ext_len units and whether Apple ever sets X is unconfirmed.
- Audio port 5900 shares the same SRTP scheme with PT=101 (AAC-ELD); this blueprint targets video 5901 only — audio keys come from the separate audio stream's key2 blob, not the video blob (spec:739).
- Whether the client must also send an RTP PT=101 media keepalive: spec:775 marks it OPTIONAL / not seen in native capture; SRTPEncryptor (srtp.py:229-271) exists for it but may be unnecessary.

---

## Encrypted control-channel record layer (SetEncryption 0x12, 0x44f/1103 rekey, AES-128-CBC framing)

The record layer wraps every post-handshake RFB control message in an AES-128-CBC frame carrying a 20-byte plain-SHA-1 integrity trailer keyed by a per-direction u32 sequence counter. Keys/IV arrive in a server-pushed 0x44f (decimal 1103) "EncodeEncryptionInfo" rectangle: two 16-byte blocks AES-128-ECB-wrapped under an auth-derived wrap key (SHA-256(SRP_K)[0:16] for types 33/36). All primitives map directly onto node:crypto — nothing must be hand-rolled except IV chaining bookkeeping and the framing/padding/MAC layout.

### Blueprint

=========================================================
PART 1 — SetEncryption HANDSHAKE (cleartext, msg 0x12)
=========================================================
Note: 0x44f = 1103 decimal. The Python reference calls the rekey encoding "1103"; the spec calls it 0x44f/EncodeEncryptionInfo. Same thing.

--- 1a. SetEncryption command=1 (START, method=AES-128) ---
Reference: enc1103/apple.py L61-72 (APPLE_0X12_FOLLOWUP = struct.pack(">BBHHHI",0x12,0,1,1,1,1)); spec §5.6 L295-296 "Full byte form 12 00 0001 0001 0001 00000001".
This is a 12-byte, all-big-endian message sent IN CLEARTEXT immediately after ViewerInfo (0x21):
  off 0x00  u8   type          = 0x12
  off 0x01  u8   reserved      = 0x00
  off 0x02  u16  command       = 0x0001   (start encryption)
  off 0x04  u16  method_count  = 0x0001
  off 0x06  u16  method        = 0x0001   (1 = AES-128; only accepted value)
  off 0x08  u32  trailer       = 0x00000001  (load-bearing; all-zero variant fails handshake per apple.py L57-60)
  total 12 bytes. Byte-exact: 12 00 00 01 00 01 00 01 00 00 00 01
  Node: Buffer.from([0x12,0x00,0x00,0x01,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x01])
  (spec §5.6 abstract framing = "u8 type || u8 reserved || u16 command || cmd-specific"; the cmd-specific tail for cmd=1 is method_count(u16)||method(u16)||u32=1.)

--- 1b. Server 0x44f / 1103 rekey payload (server->client) ---
Reference: spec §6.1-6.2 L306-314; negotiation.py L825-884 (_read_until_enc1103); enc1103.py L49-54.
Transport: a standard RFB FramebufferUpdate (msg 0x00) whose rectangle has x=y=w=h=0 and a 32-bit signed encoding == 1103 (0x0000044f). Parser (negotiation.py L855-867):
  u8   msgtype = 0x00 (FramebufferUpdate)
  u8   pad
  u16  n_rects
  per rect: u16 x, u16 y, u16 w, u16 h, s32 encoding  (12-byte rect header)
    if encoding == 1103: the NEXT 36 bytes are the rekey blob.
  NOTE tolerance: a 0x14 MiscStatus (8 bytes) may interleave in the burst (negotiation.py L855-857); skip 8 bytes on 0x14. Encodings 1010/1011 are u16-length-prefixed and skipped.

36-byte rekey blob layout (spec §6.2 L313; enc1103.py L49-54), big-endian:
  off 0x00  u32       generation           (first fresh session = 1; enc1103.py IGNORES this field — see unknowns)
  off 0x04  byte[16]  encrypted_key        (AES-128-ECB-wrapped record key)
  off 0x14  byte[16]  encrypted_iv         (AES-128-ECB-wrapped record IV)

--- 1c. SetEncryption command=2 (ACTIVATE/toggle) ---
Reference: rfb.py L177-181 build_post_encryption_toggle() = bytes.fromhex("1200000200010000"); spec §5.6 L296.
Sent CLEARTEXT after the cipher is constructed. 8 bytes, big-endian:
  off 0x00  u8   type      = 0x12
  off 0x01  u8   reserved  = 0x00
  off 0x02  u16  command   = 0x0002   (activate/stop-toggle)
  off 0x04  u16  value     = 0x0001
  off 0x06  u16  reserved  = 0x0000
  Byte-exact: 12 00 00 02 00 01 00 00
ORDERING (spec §3.3 L106-108, §5.4 L284): native order ViewerInfo -> SetEncryption(1) -> [SetMode 0x0a OPTIONAL] -> SetEncryption(2); the server MAY push 0x44f between (1) and (2). Client MUST accept the rekey as soon as it has sent SetEncryption(1). The reference client builds the cipher from the 1103 blob, THEN sends SetEncryption(2), then drains (negotiation.py L537-546).

=========================================================
PART 2 — KEY / IV DERIVATION FOR THE RECORD LAYER
=========================================================
Reference: auth.py L341-356; enc1103.py L49-67; spec §6.2.1-6.2.2 L316-329, §4.2.4.8 L236-237.

Step A — wrap key (a.k.a. ecb_key / initial wrap key), per auth branch (spec §6.2.2 table L324-329):
  type 33 (RSA-SRP) & 36 (Direct SRP):  wrap_key = SHA-256(K)[0:16]   where K = SRP-6a session key.
      auth.py L356: hashlib.sha256(proof.K).digest()[:16].
  type 30 (DH):        wrap_key = MD5(shared)[0:16].
  type 35 (Kerberos):  server-generated random 16 bytes sent over GSS channel (not derived).
  (Only 33/36 are byte-confirmed by capture.)

Step B — unwrap the 36-byte rekey blob under wrap_key using AES-128-ECB single-block DECRYPT (enc1103.py L52-54):
  cbc_key = AES128_ECB_decrypt(wrap_key, blob[0x04:0x14])   # the encrypted_key block
  cbc_iv  = AES128_ECB_decrypt(wrap_key, blob[0x14:0x24])   # the encrypted_iv block
  Each is exactly one 16-byte ECB block, NO padding.
  (spec §6.2.1 L318: "decrypts encrypted_key and encrypted_iv INDEPENDENTLY using AES-128-ECB single-block decryption under the 16-byte wrap key".)

Step C — install two independent AES-128-CBC contexts, one per direction, BOTH seeded with the same cbc_key and cbc_iv (enc1103.py L66-67):
  enc_ctx = CBC(cbc_key, iv=cbc_iv)   # client->server
  dec_ctx = CBC(cbc_key, iv=cbc_iv)   # server->client
  enc_ctr = 0 ; dec_ctr = 0            # u32 per-direction sequence counters (enc1103.py L68-69)

Rekey rotation (spec §6.2.1 L319; multi-rekey NOT exercised by the reference StreamCipher): on a SUBSEQUENT 0x44f, the recovered next_key becomes BOTH the new cbc_key AND the new wrap key for decrypting the following rekey; next_iv becomes the new CBC IV in both directions. Sequence counters are NOT reset across rekey/activation (spec §6.3-6.4.4 L333, L352-353). The Python StreamCipher only implements the FIRST rekey (always ECB-unwraps under the original ecb_key) — a compliant Node impl must re-seed wrap_key := cbc_key on each rekey. See unknowns.

=========================================================
PART 3 — AES-128-CBC RECORD FRAMING (each control message)
=========================================================
Reference: enc1103.py L72-131; spec §6.4 L336-361.

--- 3a. Outer wire form (spec §6.4.1 L338-339; enc1103.py L82,143-144) ---
  u16 BE  ciphertext_len          (MUST be nonzero AND a multiple of 16, else close)
  byte[ciphertext_len] ciphertext

--- 3b. Plaintext block layout BEFORE encryption (spec §6.4.2 L343; enc1103.py L76-79) ---
  u16 BE  body_len                (length of the RFB message that follows)
  byte[body_len]  body            (the raw RFB control message, e.g. 0x1d, 0x02, 0x03...)
  byte[filler_len] filler         (zero or random; receiver MUST NOT validate)
  byte[20]  integrity             (plain SHA-1 tag)
  where filler_len = (-(2 + body_len + 20)) mod 16   (enc1103.py L76: pad = (-(2+len(pt)+_MAC_LEN)) % _BLOCK)
  => total block length = 2 + body_len + filler_len + 20 is a multiple of 16.

--- 3c. Integrity trailer (spec §6.4.5 L356-357; enc1103.py L78,125) — PLAIN SHA-1, NOT HMAC ---
  integrity = SHA1( u32_BE(seq) || framed )
  where framed = u16_BE(body_len) || body || filler   (i.e. EVERYTHING in the block before the 20-byte trailer)
  seq = the per-direction counter value for THIS record (its value at emit time, before increment).
  Equivalent to spec wording: SHA-1( u32_be(seq) || plaintext[0 : ciphertext_len-20] ).

--- 3d. ENCRYPT one record (client->server), enc1103.py L72-82 ---
  1. counter = enc_ctr
  2. filler_len = (-(2 + body_len + 20)) mod 16
  3. framed = u16_BE(body_len) || body || (filler_len bytes, zero or random)
  4. mac = SHA1( u32_BE(counter) || framed )                # 20 bytes
  5. block = framed || mac                                   # length % 16 == 0
  6. ciphertext = CBC_encrypt_continue(enc_ctx, block)       # chains from persistent IV; NO PKCS padding
  7. enc_ctr = counter + 1
  8. emit: u16_BE(len(ciphertext)) || ciphertext

--- 3e. DECRYPT one record (server->client), enc1103.py L103-131 ---
  1. plaintext = CBC_decrypt_continue(dec_ctx, ciphertext)   # MUST run for every block to keep CBC IV chained, even on MAC miss (enc1103.py L110-113)
  2. body = plaintext[:-20] ; mac = plaintext[-20:]
  3. for c in [max(0,dec_ctr-1) .. dec_ctr+5]:               # tolerance window (enc1103.py L124, _DECRYPT_COUNTER_WINDOW=6)
        if mac == SHA1(u32_BE(c) || body): dec_ctr = c+1; break
     (strict-spec behavior §6.4.5 L357 = MUST close on mismatch; the window is a defensive reference quirk — see unknowns)
  4. inner_len = u16_BE(body[0:2]); return body[2 : 2+inner_len]
  5. dec_ctr advances by 1 even on outright miss (enc1103.py L119-120).

--- 3f. CBC state / IV chaining (spec §6.4.3 L348-349; enc1103.py L66-67 uses ONE persistent PyCryptodome CBC object per direction) ---
  Each direction is a SINGLE CBC stream spanning the whole post-rekey session: the last 16 bytes of ciphertext of record N are the IV of record N+1. Initial IV = cbc_iv from the rekey. Contexts MUST NOT be reset between records.

--- 3g. Message boundaries (spec §6.4.6 L360-361) ---
  Small control msgs: one record == exactly one RFB message (body_len delimits it). Large server payloads (zlib framebuffer rects) MAY span consecutive records — reassemble by concatenating successive record BODIES in order. Records never multiplex two messages nor fragment a small control message.

--- 3h. Streaming reader (enc1103.py L133-150) ---
  Loop: need >=2 bytes for length; length must be nonzero, %16==0, and fully present else stop (keep tail buffered). Decrypt, advance pos by 2+length, collect non-None messages.

=========================================================
PART 4 — ENCRYPTED PREFACE (first two client records)
=========================================================
Reference: spec §6.5 L365. After SetEncryption(2), client send-seq 0 = SetDisplayConfiguration (0x1d), send-seq 1 = SetEncodings (0x02), each wrapped per Part 3.

### Node crypto

All primitives are covered by node:crypto; nothing must be hand-rolled except the framing/padding/MAC byte-assembly and the per-record IV bookkeeping.

1) AES-128-ECB single-block unwrap of the rekey blob (enc1103.py L52-54):
   function ecbUnwrap(wrapKey /*16B*/, block /*16B*/) {
     const d = crypto.createDecipheriv('aes-128-ecb', wrapKey, null);
     d.setAutoPadding(false);                       // REQUIRED: exactly one block, no PKCS#7
     return Buffer.concat([d.update(block), d.final()]);
   }
   cbcKey = ecbUnwrap(wrapKey, blob.subarray(4,20));
   cbcIv  = ecbUnwrap(wrapKey, blob.subarray(20,36));
   (Pass null/empty IV for ECB. On some Node versions use crypto.createDecipheriv('aes-128-ecb', wrapKey, Buffer.alloc(0)).)

2) Wrap-key derivation (SRP branch, auth.py L356) — SHA-256, node covers it:
   wrapKey = crypto.createHash('sha256').update(K).digest().subarray(0,16);
   (DH branch would be crypto.createHash('md5').update(shared).digest().subarray(0,16).)

3) AES-128-CBC record encrypt/decrypt — node covers it, but node finalizes per call, so DO NOT keep one long-lived Cipher object. Instead manage the chaining IV manually (equivalent to PyCryptodome's persistent object):
   // state: encIv (init = cbcIv), encCtr=0 ; decIv (init = cbcIv), decCtr=0
   function encryptRecord(body) {
     const fillerLen = (-(2 + body.length + 20)) & 15;
     const framed = Buffer.concat([u16be(body.length), body, Buffer.alloc(fillerLen)]); // or crypto.randomBytes(fillerLen)
     const mac = crypto.createHash('sha1').update(u32be(encCtr)).update(framed).digest(); // 20B, PLAIN sha1
     const block = Buffer.concat([framed, mac]);                                          // %16==0
     const c = crypto.createCipheriv('aes-128-cbc', cbcKey, encIv);
     c.setAutoPadding(false);                                                             // REQUIRED
     const ct = Buffer.concat([c.update(block), c.final()]);
     encIv = ct.subarray(ct.length-16);                                                   // chain IV for next record
     encCtr++;
     return Buffer.concat([u16be(ct.length), ct]);
   }
   function decryptRecord(ct /* the ciphertext, len%16==0 */) {
     const d = crypto.createDecipheriv('aes-128-cbc', cbcKey, decIv);
     d.setAutoPadding(false);
     const pt = Buffer.concat([d.update(ct), d.final()]);
     decIv = ct.subarray(ct.length-16);            // chain BEFORE any MAC decision
     const body = pt.subarray(0, pt.length-20), mac = pt.subarray(pt.length-20);
     for (let c=Math.max(0,decCtr-1); c<decCtr+6; c++){
       const t = crypto.createHash('sha1').update(u32be(c)).update(body).digest();
       if (crypto.timingSafeEqual(t, mac)) { decCtr=c+1; const n=body.readUInt16BE(0); return body.subarray(2,2+n); }
     }
     decCtr++; return null;
   }
   helpers: u16be(n)=>Buffer.from([n>>8&255,n&255]); u32be(n)=>{const b=Buffer.alloc(4);b.writeUInt32BE(n>>>0);return b;}

4) SHA-1 integrity tag: crypto.createHash('sha1') — plain hash, NOT crypto.createHmac. The reference explicitly is NOT HMAC (enc1103.py L8-9,L21,L41; spec §6.4.5 L357 "_CCHmac is absent"). Do not reach for createHmac here.

Endianness note: every length/counter is BIG-ENDIAN on the wire (struct.pack(">H"/">I") in Python == writeUInt16BE/writeUInt32BE). generation, ciphertext_len, body_len, seq are all BE.

### Citations

enc1103.py L1-27 (module doc: wire format, plaintext layout, counter, plain-SHA1-not-HMAC); L41-43 (_MAC_LEN=20, _BLOCK=16, window=6); L49-54 (36-byte blob split, ECB unwrap of [4:20] key and [20:36] iv under ecb_key); L66-69 (two CBC ctxs same key+iv, counters=0); L72-82 (encrypt: pad formula, framed, sha1(u32be(ctr)||framed), block, seq++, u16 len prefix); L103-131 (decrypt: per-block CBC, counter window, inner_len parse); L133-150 (stream framing, len%16 rule). auth.py L341-356 (SRP wrap key = sha256(K)[:16]). negotiation.py L537-546 (build cipher then send toggle then drain); L825-884 (1103 rectangle discovery, 12-byte rect header, s32 encoding==1103 -> 36-byte blob, 0x14/1010/1011 tolerance). rfb.py L170-181 (build_set_encodings; build_post_encryption_toggle = 1200000200010000). apple.py L54-72 (APPLE_0X12_FOLLOWUP = 12-byte SetEncryption cmd=1: BBHHHI 0x12,0,1,1,1,1). apple_vnc_rfc.md §3.3 L106-108 (prelude/rekey interleave); §5.4 L284 (prelude order); §5.6 L293-297 (0x12 cmd=1/cmd=2 byte forms, method=1 only); §6.1-6.2 L306-314 (0x44f transport, 36-byte blob u32 generation||16 key||16 iv); §6.2.1 L316-320 (ECB unwrap, wrap-key rotation, close-on-fail); §6.2.2 L322-329 (per-branch wrap key table); §6.3 L331-333 (activation, no counter reset); §6.4.1 L338-339 (outer u16 len, %16); §6.4.2 L342-345 (plaintext layout, filler_len formula, random filler); §6.4.3 L347-349 (single persistent CBC per direction); §6.4.4 L351-353 (u32 counters from 0); §6.4.5 L355-357 (integrity = SHA1(u32be(seq)||pt[0:len-20]), plain SHA1 not HMAC, MUST close on mismatch); §6.4.6 L359-361 (message boundaries/reassembly); §6.5 L363-365 (encrypted preface 0x1d then 0x02); §4.2.4.8 L236-237 (sha256(K)[0:16] wrap key).

### Unknowns

- generation u32 semantics are a spec revision gap; reference ignores it
- multi-rekey wrap-key rotation (wrapKey:=cbcKey) is specified but unverified by capture
- decrypt counter tolerance window is a client heuristic, not protocol; strict spec = close on MAC mismatch
- SetEncryption cmd=1 carries a trailing u32=1 beyond the abstract framing; 12-byte byte-exact form is authoritative
- only SRP wrap key sha256(K)[:16] is capture-confirmed; DH/Kerberos derivations unverified
- cbc_key is also reused by the 0x10 EncryptedInputEvent ECB path (separate component)

---

## HEVC RTP depacketization + tile reassembly + WebCodecs access-unit feeding + vertical compositing (Node.js/JS)

This component takes SRTP-decrypted RTP packets (12-byte header + payload) for four SSRC tile streams, depacketizes Apple's RFC 7798 DONL variant (single-NAL, AP-48, FU-49) into clean HEVC NALUs, groups them into access units per (SSRC,timestamp), feeds all four tiles' NALUs in interleaved decode order into ONE WebCodecs VideoDecoder as Annex-B start-code chunks, then dispatches decoded tiles by a timestamp→tile map and stitches the four horizontal strips vertically post-decode. It is pure buffer manipulation plus WebCodecs; no node:crypto is needed here (decryption is upstream).

### Blueprint


=== 0. INPUT: RTP header (from SRTP decrypt step; hdr[0:12]) ===
Byte-exact, big-endian. Ref: burst.py:117-121.
  off 0  u8   V/P/X/CC   (V=2; this stream has no CSRC/ext → header is 12 bytes)
  off 1  u8   M|PT       marker = (hdr[1] & 0x80) != 0  ; PT = hdr[1]&0x7F
  off 2  u16  sequence   seq = hdr.readUInt16BE(2)
  off 4  u32  timestamp  ts  = hdr.readUInt32BE(4)
  off 8  u32  SSRC       ssrc= hdr.readUInt32BE(8)
  payload = packet.subarray(12)
Node: Python struct.unpack(">H",hdr[2:4]) → hdr.readUInt16BE(2); ">I" → readUInt32BE.

=== 1. DEPACKETIZATION — Apple RFC 7798 DONL variant ===
Ref: nalu.py:28-80; spec §10.6 (lines 794-800). DONL present on EVERY structure.
NAL type dispatch: nt = (payload[0] >> 1) & 0x3F.  (require payload.length >= 2)

(a) SINGLE NAL  (nt != 48 && nt != 49). Ref nalu.py:74-78; spec:796.
    Layout:  [0..1] 2-byte NAL header | [2..3] 2-byte DONL | [4..] NAL payload
    require len >= 4. OUTPUT NALU = concat(payload[0:2], payload[4:]).  (strip DONL only)

(b) AGGREGATION PACKET  nt == 48. Ref nalu.py:42-52; spec:797.
    Layout: [0..1] AP NAL header | [2..3] ONE DONL | then repeated { [u16 BE size][size bytes NAL] }
    ***Apple deviation: NO per-unit DOND between sub-NALUs (stock RFC7798 has a 1-byte DOND before every unit after the first).***
    Algo: pos=4; n=len. while pos+2<=n: size=readUInt16BE(pos); pos+=2; if size==0||pos+size>n break; emit payload[pos:pos+size]; pos+=size.

(c) FRAGMENTATION UNIT  nt == 49. Ref nalu.py:54-72; spec:798.
    Layout: [0..1] FU NAL header | [2] FU header | [3..4] 2-byte DONL | [5..] fragment data
    ***Apple deviation: DONL is in EVERY fragment (stock RFC7798 = start fragment only). So all fragments skip 5 header bytes.***
    require len >= 6. fu = payload[2]; S=(fu&0x80); E=(fu&0x40); inner_type=(fu&0x3F).
    START (S set): reconstruct inner NAL header:
        hdr0 = (payload[0] & 0x81) | (inner_type << 1)   // keep F(bit7)+layerId-hi(bit0), splice type
        hdr1 = payload[1]
        buf  = concat([hdr0,hdr1], payload[5:]); active=true.
    MIDDLE/END (S clear, active): buf += payload[5:]; if E set → emit buf; active=false.
    (loss makes a group lack S or E → drop silently.)

(d) first_donl (for LTR ack, optional for this component). Ref nalu.py:83-103; spec:786-789.
    16-bit BE Decoding-Order-Number: FU → readUInt16BE(payload[3:5]); single/AP → readUInt16BE(payload[2:4]). +1 per frame in decode order.

=== 2. GROUPING (SSRC,timestamp) → access unit, and SSRC→tile ===
Ref: burst.py:90-146; spec §10.7 (804-808).
- Bucket decrypted packets by key=(ssrc,ts): list of {seq,marker,payload}. (burst.py:122)
- A group is COMPLETE when any packet in it has marker=1 (RTP marker = last pkt of the AU). (burst.py:133)
- Order within group by seq WITH wraparound: if max(seq)-min(seq) > 0x8000: base=min; sort by (seq-base)&0xFFFF; else sort by seq. (burst.py:142-147)
- reassemble_group(sorted payloads) → ordered NALUs for that tile's AU.
- SSRC→tile index: sorted(distinct SSRCs ascending) → map[ssrc]=0..3. (burst.py:98-99). tile 0 = lowest/base SSRC.
- Base SSRC (tile 0) is the ONLY stream carrying IDR (nt 19/20, range 16-21) AND the in-band VPS(32)/SPS(33)/PPS(34). Tiles 1-3 carry inter (P) frames only. (spec:806-807; hevc.py:644-652)
- PPS id parse: strip 2-byte NAL hdr, remove emulation-prevention, read_ue → pps_id. (burst.py:184-186)

=== 3. FEED ORDER into the SINGLE shared decoder ===
Ref: hevc.py:1-24, 344-368; spec:806.
- ONE decoder instance for all 4 tiles (cross-tile POC references: a P-frame on SSRC N references a POC produced on SSRC M). Per-tile decoders fail "missing reference".
- Decode order = round-robin by frame index across tiles: for i in 0..maxlen: tile0 nal[i], tile1 nal[i], tile2 nal[i], tile3 nal[i]. This is the encoder's real-time emit order → shared DPB sees POCs in natural order. (hevc.py:344-368)
- Gate: DO NOT submit any tile's delta AU until the first IDR (from tile 0) has been decoded (_dpb_has_idr). Drop pre-IDR P-frames. (hevc.py:502-503, 662-690)
- "Any IDR = DPB reset for ALL tiles": on IDR arrival, clear per-tile await/keyframe flags for every tile, not just tile 0. (hevc.py:653-669; spec:807)
- Decodable filter before feeding: len>=3 AND ((b0>>1)&0x3F)<=31 AND (nalu[2]&0x80)!=0 (first_slice_segment_in_pic_flag). Drops SEI/EOB/leftover FU control. (hevc.py:1172-1180)

=== 4. WebCodecs access-unit form ===
Ref: hevc.py:692-699, 1004-1012; spec §10.9(835); proven "Annex-B hev1 works".
- FORMAT = Annex-B (start codes), NOT length-prefixed hvcC. Start code = 00 00 00 01 (_NAL_START_CODE, decode_common.py:72). Prefix EVERY NALU.
- VideoDecoder.configure({ codec:"hev1.*", description: OMITTED }). Omitting `description` selects Annex-B mode (a supplied `description` would switch it to hvcC/length-prefixed). Codec string per SPS profile/level, e.g. "hev1.4.10.L153.B0" for RExt 4:4:4 (verify tier/level from SPS; the exact string may need adjustment — see unknowns).
- Parameter sets: send VPS+SPS+all-PPS (each start-code-prefixed, sorted by pps_id) as the leading bytes before/with the first IDR, exactly as libav extradata is built (hevc.py:1004-1012). Simplest: prepend them to the IDR key chunk, or feed as their own chunks first.
- Chunking into EncodedVideoChunk: feed each tile's AU (its ordered NALUs concatenated, each start-code-prefixed) as one chunk. type='key' iff the AU contains an IDR NAL (nt in 16..21) — i.e. tile-0 IDR AUs; all other tiles' AUs = 'delta'. First chunk after configure MUST be key (the tile-0 IDR).
- timestamp field: assign a monotonically increasing integer per fed AU/NALU and record timestamp→tile in a map (mirrors _pts_to_tile, hevc.py:697-700). On decoder output, VideoFrame.timestamp → look up tile index → route to that tile's slot. Prune the map (keep last ~2000) on lossy streams (hevc.py:704-707).

=== 5. VERTICAL COMPOSITING ===
Ref: spec §10.7 (805-808), §10.9 (835); tiles.py.
- Geometry: screen split into 4 HORIZONTAL strips, one per SSRC, stacked vertically in SSRC order (tile0 top → tile3 bottom). Example: 3840×2160 source → four 3840×544 coded strips (4×540=2160 logical rows; coded height 544 is CTU-padded, logical 540). CTU padding / exact strip height rules = revision gap (spec:808).
- Tiles decode as FOUR SEPARATE pictures (each tile's SPS is sized to the strip, e.g. width×544), NOT one HEVC picture. They MUST be stitched POST-decode. The single shared decoder emits 4 distinct VideoFrames per source frame (one per timestamp/tile); composite by drawing tile t at y = Σ(heights of tiles 0..t-1), cropping each strip to its logical (unpadded) height.
- Surface sizing: use BACKING geometry from AppleDisplayLayout 0x451 (decoded pixel dims) for the framebuffer/canvas; SCALED geometry for window sizing + input mapping (2× HiDPI). (spec:835)
- Chroma: HEVC RExt 4:4:4 8-bit; WebCodecs yields I444/444 planar (proven). Full-range. Composite in YUV or convert per-tile to RGB then blit at the strip offset.
- On dynamic-resolution / SSRC-switch: new 4-SSRC group + new in-band VPS/SPS/PPS + fresh IDR → re-map SSRC→tile, re-configure decoder with new param sets, reset gate. (spec:833-835)


### Node crypto

NONE required in this component — it is pure Buffer/WebCodecs work, no AES/HMAC/SHA/RSA (SRTP decryption is the upstream component). Python→Node mapping used here: struct.unpack(">H",b)→buf.readUInt16BE(off); struct.unpack(">I",b)→buf.readUInt32BE(off); struct.pack(">H",v)→buf.writeUInt16BE(v,off); bytes slicing b[i:j]→Buffer.subarray(i,j) (zero-copy) or Buffer.concat([...]) to build NALUs; b[0]&0x80 bit tests are identical. Emulation-prevention strip (bitstream.py:12-24) and exp-Golomb ue/se + MSB-first BitReader (bitstream.py:27-69) must be HAND-ROLLED in JS (no stdlib equivalent) — only needed here to read pps_id (read_ue) and, if you keep the RPS pre-check, slice headers. Decode itself is WebCodecs VideoDecoder (renderer worker), not node.

### Citations

nalu.py:28-103 (reassemble_group AP/FU/single byte layout, DONL placement, first_donl offsets); bitstream.py:12-69 (emulation-prevention strip, MSB-first BitReader, read_ue/read_se); burst.py:90-205 (RTP header offsets, (ssrc,ts) grouping, marker-complete, seq wraparound sort, SSRC→tile via sorted ssrcs, VPS/SPS/PPS+pps_id extraction, IDR handling); hevc.py:1-24,285-368,502-707,1004-1012,1172-1180 (single shared context rationale, round-robin decode order, _dpb_has_idr gate, any-IDR-resets-all-tiles, start-code packetization, extradata build, decodable filter, pts→tile map); tiles.py:12-45 (TileFrame planar 4:4:4 shape, strides); decode_common.py:72 (_NAL_START_CODE=00 00 00 01); apple_vnc_rfc.md:794-808 (§10.6 DONL variant, §10.7 four horizontal strips/base-SSRC-IDR/single-decoder/vertical recomposite), 833-837 (dynamic-resolution new SSRC group + new param sets, backing vs scaled geometry), 773-787 (four RTP streams on four SSRCs, per-SSRC ROC).

### Unknowns

- Whether Chrome/Electron WebCodecs HEVC VideoDecoder honors CROSS-TILE shared-DPB references the way libavcodec's single CodecContext does. The proven test decoded a SINGLE tile's 4:4:4 stream; feeding four interleaved tile streams into one VideoDecoder and relying on tile-N P-frames resolving POCs produced by tile-M is UNVERIFIED. If WebCodecs internally treats it as one picture sequence this works; if it rejects out-of-order/foreign references it may need a different arrangement (worst case: one decoder per tile is NOT viable per spec:806).
- Exact WebCodecs codec string for HEVC RExt 4:4:4 8-bit (e.g. 'hev1.4.10.L153.B0' vs '.1.6.'); must be derived from the actual SPS profile_idc/general_level_idc, and Chrome's HEVC support may gate on platform/flags. Needs runtime isConfigSupported() check.
- Whether omitting `description` reliably selects Annex-B for HEVC in this Chromium build (documented behavior; confirm empirically — the team already proved 'Annex-B hev1 works' so likely fine).
- Coded vs logical strip height / CTU padding (spec explicitly a revision gap, line 808): example shows 544 coded vs 540 logical per strip. The post-decode crop amount per tile must come from SPS conformance_window or the 0x451 backing geometry, not assumed.
- AU-boundary detection when a tile's AU spans concerns: ref feeds each NALU with its own start code and lets the decoder split on 'first VCL after non-VCL'. Whether to submit one EncodedVideoChunk per NALU or one per whole-AU (concatenated NALUs) — both plausible; per-AU chunk with correct key/delta typing is cleaner for WebCodecs and recommended, but verify the decoder accepts multiple NALUs (param sets + slice) in one chunk.
- Marker-bit reliability as the sole AU-complete signal under UDP loss (a dropped marker packet stalls the group); ref relies on it (burst.py:133) plus a session-level FIR/timeout fallback that lives outside this component.

---

## MediaStreamOptions (0x1c) offer/answer + SRTP key derivation (Node.js)

The 0x1c message is a fixed-layout binary struct (NOT protobuf) that carries the client-generated SRTP master+salt key blobs plus zlib-compressed audio/video AVConference "offer" protobufs. The client generates all keys itself, sends them in the offer, and reads only canvas geometry back from the server's answer (keys are never returned/rotated by the server). Each direction's 46-byte blob (32B master key + 14B master salt) feeds the RFC 3711 AES-CM KDF (labels 0/1/2 for SRTP, 3/4/5 for SRTCP) to produce the actual cipher/auth/salt keys; key2 (server-send) is used for receive-decrypt.

### Blueprint

=== 1. 0x1c BODY BYTE LAYOUT (build_0x1c, negotiation.py:137-216; RFC md:745-760) ===
All sizes: total buffer = MS+4 bytes, where MS = audio_offer_len + video_offer_len + 0xD8.
(0xD8 derivation: fixed header up to audio_offer = 0x80; video key pair = 0x5C (2*0x2E); MS = 0x80 + AS + 0x5C + VS - 4 = 0xD8 + AS + VS.)

Absolute offsets into `buf`:
 +0x00  u8/u16  message_type   = 0x1C   (iSS writes buf[0]=0x1C, buf[1]=0 -> reads as u16 BE 0x001C)
 +0x02  u16 BE  message_size   = MS
 +0x04  u16 BE  message_version= 3      (if server sees version<=1 it force-ORs flags|=0x03)
 +0x06  u32     flags/config   = 3 (0x07 with cursor-strip bit)  <-- ENDIANNESS: SEE UNKNOWNS
 +0x0a  u16 BE  audio_offer_len (AS)
 +0x0c  u16 BE  video_offer_len (VS)     [RFC calls this video1_offer_len]
 +0x0e  u16 BE  video2_offer_len = 0     [iSS leaves 0; single video stream]
 +0x10  u32     reserved       = 0
 +0x14  16B     CallID / session UUID    (uuid.uuid4().bytes, raw 16 bytes)
 +0x24  46B     audio key1 (audio_key_v / akv)  -- viewer->server / server-RECEIVE
 +0x52  46B     audio key2 (audio_key_s / aks)  -- server->viewer / server-SEND
 +0x80  AS      audio_offer plist (zlib-compressed MediaBlob, mode 8)
 then, at vo = 0x80 + AS:
 vo+0x00  46B   video key1 (video_key_v / vkv)  -- viewer->server / server-RECEIVE
 vo+0x2E  46B   video key2 (video_key_s / vks)  -- server->viewer / server-SEND
 vo+0x5C  VS    video_offer plist (zlib-compressed MediaBlob, mode 7)
(RFC md:758-759 allows a 3rd "video2" stream = 6 key blobs total; iSS uses 2 streams / 4 keys with video2_offer_len=0. Support the 2-stream form; guard the video2 tail on video2_offer_len!=0.)

FLAGS bits (RFC md:741): 0x01=stream1 60fps (always), 0x02=stream2 60fps, 0x04=do-not-send-cursor, 0x08=AVC client-name selector. iSS sets config_flags=3, then |=4 to strip cursor unless ISS_LEGACY_CURSOR=1; alt-session path uses (3 & ~2)|4 = 5.

Each 46-byte key blob (srtp.py:30-42): blob[0:32]=master key, blob[32:46]=master salt (14B).

=== NODE build steps (main process) ===
const buf = Buffer.alloc(MS + 4);              // zero-filled
buf.writeUInt8(0x1C, 0);                        // buf[1] stays 0
buf.writeUInt16BE(MS, 2);
buf.writeUInt16BE(3, 4);
buf.writeUInt32BE(config_flags, 6);             // iSS-proven; see UNKNOWNS re LE
buf.writeUInt16BE(AS, 10);
buf.writeUInt16BE(VS, 12);
// +0x0e video2_len and +0x10 reserved already 0
crypto.randomBytes(16).copy(buf, 0x14);         // or a proper v4 UUID's 16 bytes
keys.audio_key_v.copy(buf, 0x24);               // 46B
keys.audio_key_s.copy(buf, 0x52);               // 46B
audio_offer.copy(buf, 0x80);
const vo = 0x80 + AS;
keys.video_key_v.copy(buf, vo);                 // 46B
keys.video_key_s.copy(buf, vo + 0x2E);          // 46B
video_offer.copy(buf, vo + 0x5C);
// buf is the plaintext 0x1c body; it is then wrapped/encrypted by the enc1103/AES-128-CBC control record layer (separate component) before send.

Key generation (negotiation.py:127-134): each of the 4 blobs = crypto.randomBytes(46). MUST be fresh per session (RFC md:941).
Offer plists: Python plistlib.dumps(FMT_BINARY) with zlib.compress(protobuf) inside -> Node: build bplist + zlib.deflateSync(protobuf). (Offer protobuf construction is a separate component; here it is an opaque byte blob.)

=== 2. OFFER (client-sent) vs ANSWER (server-sent) ===
OFFER: client writes EVERYTHING above -- it originates all 4 SRTP master+salt blobs, the UUID, flags, and both compressed offer protobufs. The server does not supply keys.
ANSWER: server returns a 0x1c whose first byte is 0x00 (extract_canvas_dims checks answer_msg[0]==0x00, offers.py:378). The answer embeds a bplist -> "avcMediaStreamNegotiatorMediaBlob" -> zlib -> protobuf. Client reads ONLY geometry from it: top-level protobuf field 5 (video config) sub-fields F4=canvas_width, F5=canvas_height (luma samples), F6=tile_count, F7=negotiated ltrpEnabled (offers.py:370-451). Client REUSES its own offer keys for the media transport; the server does not echo or rotate keys. Full answer schema is a documented revision gap (RFC md:762,839).
Client also extracts its own advertised SSRC from the offer (video field5->1, audio field3->1) because AVConference only accepts RTP/RTCP from the negotiated SSRC (offers.py:334-367).

=== 3. key1/key2 -> send/recv, and the RFC 3711 KDF ===
key1 = *_key_v = viewer->server = server-RECEIVE = client SEND (used only for the PT=101 keepalive SRTPEncryptor, srtp.py:229-271).
key2 = *_key_s = server->viewer = server-SEND = client RECEIVE (the video SRTPDecryptor). Confirmed: negotiation.py:818 `SRTPDecryptor.from_blob(keys.video_key_s)`; RFC R-C3 md:891 "use key2 for receive".
Video RTP arrives on UDP port P+1 (5901), PT=100 HEVC, 4 consecutive SSRCs (tiles); audio on P (5900) PT=101. RTCP is muxed on the same ports (RFC md:766-773).

RFC 3711 §4.3.1 KDF (srtp.py:45-65). From a 46B blob's (master_key[32], master_salt[14]):
 SRTP:  label 0 -> cipher key (32B), label 1 -> auth key (20B), label 2 -> session salt (14B).
 SRTCP: label 3 -> cipher key (32B), label 4 -> auth key (20B), label 5 -> session salt (14B).
Algorithm per (label, out_len):
  kid = 14 zero bytes; kid[7] = label.
  iv0[i] = kid[i] XOR master_salt[i]  for i in 0..13   (14 bytes)
  Treat block counter x = (iv0 << 16) as a 128-bit big-endian value (i.e. iv0 followed by 2 zero bytes), increment low 16 bits per AES block, AES-256-ECB(master_key) each block, concatenate, truncate to out_len.
Note it is AES-256 (32B master key) in counter mode, NOT AES-128.

Downstream SRTP receive path (context, srtp.py:83-205 — separate decode component):
  session_salt_int = int(session_salt || 0x0000, big)   // 16 bytes
  per packet: index=(ROC<<16)|seq; IV = session_salt_int XOR (SSRC<<64) XOR (index<<16), 16B big-endian.
  cipher = AES-256-CTR(cipher_key, IV) over payload.
  auth = HMAC-SHA1(auth_key, srtp_body || ROC_be32) truncated to 10 bytes (80-bit tag), compared constant-time. ROC tracked PER SSRC (RFC md:773,787).

=== 4. EXACT node:crypto KDF (VERIFIED byte-identical to the Python ECB loop for labels 0,1,2) ===
const crypto = require('node:crypto');
function srtpKdf(masterKey /*32B*/, masterSalt /*14B*/, label, outLen) {
  // iv0 = (kid ^ salt) with kid = zeros except kid[7]=label; pad to 16B counter block
  const iv = Buffer.alloc(16);                       // low 2 bytes = CTR block counter = 0
  for (let i = 0; i < 14; i++) iv[i] = ((i === 7 ? label : 0) ^ masterSalt[i]);
  const c = crypto.createCipheriv('aes-256-ctr', masterKey, iv);
  return Buffer.concat([c.update(Buffer.alloc(outLen)), c.final()]); // keystream = CTR of zeros
}
// Equivalence proof: AES-CTR(key, iv0||0000) encrypting zeros yields ECB(counter blocks); ran both
// implementations on random 32B/14B inputs for labels 0/1/2 -> identical hex (see citations).
// Literal alternative (matches srtp.py line-for-line): aes-256-ecb with setAutoPadding(false),
//   encrypting each 16B counter block iv0||0000 (+counter) manually. Same output; CTR form is preferred.

Build the receive keys from key2:
  const master = blob.subarray(0,32), salt = blob.subarray(32,46);
  const cipherKey = srtpKdf(master, salt, 0, 32);
  const authKey   = srtpKdf(master, salt, 1, 20);
  const sessSalt  = srtpKdf(master, salt, 2, 14);
Other node:crypto primitives on the media path: crypto.createDecipheriv('aes-256-ctr', cipherKey, iv) for payload; crypto.createHmac('sha1', authKey) then .digest().subarray(0,10) with crypto.timingSafeEqual for the tag; crypto.randomBytes for key/UUID generation. zlib.deflateSync/inflateSync (node:zlib) for the offer/answer MediaBlob.

Python->Node idiom map:
  os.urandom(n) -> crypto.randomBytes(n)
  struct.pack_into(">H",buf,off,v) -> buf.writeUInt16BE(v,off); ">I" -> writeUInt32BE
  int.from_bytes(b,"big") -> BigInt('0x'+b.toString('hex'))  (needed for the 128-bit IV XOR math)
  hashlib/hmac sha1 -> crypto.createHmac('sha1',key)
  Crypto.Cipher.AES MODE_ECB -> crypto.createCipheriv('aes-256-ecb',key,null).setAutoPadding(false)
  cryptography AES + modes.CTR -> crypto.createCipheriv/'aes-256-ctr'
  zlib.compress -> zlib.deflateSync ; zlib.decompress -> zlib.inflateSync
  plistlib.dumps(FMT_BINARY) -> a bplist encoder (bplist-parser/simple-plist or hand-rolled)

### Node crypto

KDF: crypto.createCipheriv('aes-256-ctr', masterKey(32B), iv(=iv0||0x0000, 16B)) encrypting Buffer.alloc(outLen) of zeros -> keystream = derived key (VERIFIED identical to Python AES-256-ECB counter loop for labels 0/1/2). Literal alt: crypto.createCipheriv('aes-256-ecb', masterKey, null).setAutoPadding(false) over each 16B counter block. Keys/UUID: crypto.randomBytes(46) per blob, randomBytes(16) for UUID. SRTP payload: crypto.createDecipheriv('aes-256-ctr', cipherKey, perPacketIV). Auth: crypto.createHmac('sha1', authKey).digest().subarray(0,10) + crypto.timingSafeEqual. 128-bit IV arithmetic: BigInt (salt<<16n) ^ (ssrc<<64n) ^ (index<<16n) -> 16B big-endian buffer. Framing: Buffer.writeUInt16BE/writeUInt32BE/writeUInt8. Offers: node:zlib deflateSync/inflateSync.

### Citations

negotiation.py:88-134 (NegotiationKeys akv/aks/vkv/vks semantics + random_negotiation_keys via os.urandom(46)); negotiation.py:137-216 (build_0x1c full byte layout, MS=AS+VS+0xD8, offsets 0x00/0x02/0x04/0x06/0x0a/0x0c/0x14/0x24/0x52/0x80 and vo/vo+0x2E/vo+0x5C); negotiation.py:194-205 (flags big-endian rationale, contradicts RFC); negotiation.py:818 (video_decryptor = SRTPDecryptor.from_blob(keys.video_key_s) => key2/server-send used for receive); srtp.py:27-42 (46B blob = 32B master||14B salt); srtp.py:45-65 (_srtp_kdf reference algorithm); srtp.py:83-87 (labels 0/1/2 -> cipher32/auth20/salt14); srtp.py:277-281,329-332 (labels 3/4/5 for SRTCP); srtp.py:200-205,260-271 (per-packet IV + HMAC-SHA1-80 tag over body||ROC); offers.py:334-367 (extract_offer_ssrc, video f5->1 / audio f3->1); offers.py:370-451 (extract_canvas_dims: answer[0]==0x00, bplist->zlib->protobuf F5.F4/F5/F6/F7); apple_vnc_rfc.md:735-762 (10.3 fixed-struct layout, three-stream/six-key form, flags note); apple_vnc_rfc.md:783-792 (10.5 SRTP: AES-256-CM, 46B=32+14, labels 0/1/2 & 3/4/5, IV formula, per-SSRC ROC); apple_vnc_rfc.md:890-894 (R-C2/C3/C4 'use key2 for receive'); apple_vnc_rfc.md:826-839,941 (re-offer key reuse/rotate, fresh-RNG requirement). Node KDF equivalence verified in-session: AES-256-CTR-of-zeros vs Python AES-256-ECB counter loop matched for labels 0/1/2 on random inputs.

### Unknowns

- FLAGS ENDIANNESS CONTRADICTION at +0x06: iShareScreen (the proven working impl) writes BIG-endian via struct.pack_into('>I', buf, 6, flags) -> bytes 00 00 00 07, with an emphatic comment (negotiation.py:194-205) that a double-byteswap across the MIG/NDR boundary makes this the value the agent honors. The RFC spec (md:741,749) says the OPPOSITE: host/little-endian, conforming client writes 07 00 00 00. These cannot both be right on the wire. Recommend following iShareScreen (writeUInt32BE) since it is empirically proven, but this MUST be validated against the live daemon; if cursor-strip / 60fps bits misbehave, flip to writeUInt32LE.
- message_type width: iSS writes a single byte buf[0]=0x1C leaving buf[1]=0 (so u16 BE 0x001C); RFC lists it as u16 at +0x00. Equivalent given buf[1]=0, but confirm no build writes a nonzero +0x01.
- 3rd video stream (video2, +0x0e len, extra 46B*2 keys, RFC md:759): iSS never emits it (video2_offer_len=0). Two-stream form is proven; six-key form is unexercised here.
- UUID format: iSS uses a real uuid4 (uuid.uuid4().bytes). crypto.randomBytes(16) is 16 random bytes without RFC4122 version/variant bits; unknown whether the daemon cares (treated as opaque 16B). Use a proper v4 to be safe.
- Full 0x1c ANSWER schema is a documented revision gap (RFC md:762,839): only F5.F4/F5/F6/F7 (canvas w/h/tiles/ltrp) are known. Parser must tolerate the answer arriving alongside unrelated decrypted msgs and treat zero canvas as 'retry'.
- Key lifecycle across mid-session re-offers (resolution change, RFC md:832): server accepts either reused or freshly-rotated key blobs; exact expectation unspecified. Native app rotates; iSS can reuse.

---

## HP-mode control messages (0x21 ViewerInfo, 0x1d SetDisplayConfiguration, 0x02 SetEncodings, 0x12 SetEncryption toggle, 0x03 FramebufferUpdateRequest, 0x09 AutoFrameBufferUpdate) + metadata burst parsing (0x451/0x453/0x455/0x456)

RFB-dialect control messages, sent inside the TCP record layer, that flip screensharingd into virtual-display HP mode and advertise the media-init/still-image encodings, plus parsers for the server metadata burst that follows. All wire fields are big-endian. display_type=4, display_flags=0x01, reserved=7, and the SetEncodings list (containing 0x3f2/0x3f3/0x3ea) must be exact — that is what makes the server accept the virtual display and later emit UDP HEVC after the 0x1c exchange. In Node these are fixed-offset Buffer writes; no crypto is needed here — the caller wraps them with the enc1103 StreamCipher once the record layer is active.

### Blueprint

Citations file:line. BIG-ENDIAN unless stated. Build each as Buffer.alloc(N) then writeXxxBE at fixed offsets.

ORDERING (record-layer-active to ready-for-MediaStreamOptions) - negotiation.py:500-548,612-666,798-806; spec 675-723. Reference and RFC DIVERGE on plaintext-vs-encrypted for 0x1d/0x02; FOLLOW REFERENCE.
Plaintext phase after ClientInit(0xC1)/ServerInit:
 1. 0x21 ViewerInfo glued in same write to 12-byte 0x12 followup (==SetEncryption cmd=1)
 2. sleep 0.1s (negotiation.py:57,522)
 3. 0x1d SetDisplayConfiguration (only if curtain=True)
 4. 0x02 SetEncodings — PLAINTEXT first copy
 5. Read until FramebufferUpdate rect encoding==1103; 36B body seeds enc1103 cipher (negotiation.py:825-888)
 6. 0x12 PostEncryptionToggle (==SetEncryption cmd=2, 8 fixed bytes) — activates record layer (negotiation.py:545)
 7. sleep 0.2s, drain+decrypt to align RX counter
RECORD LAYER ACTIVE (all below via cipher.encrypt_message):
 8. 0x02 SetEncodings — ENCRYPTED second copy (negotiation.py:629). "Ready to send MediaStreamOptions" is right after this.
 9. 0x1c (separate component)
 10. 0x03 FramebufferUpdateRequest(incremental=0,w=h=0xFFFF) ENCRYPTED (negotiation.py:639-644). Reference omits 0x09 on idle path (negotiation.py:583-609); spec says MUST. 0x03-only is proven for bring-up.
 11. Read+decrypt 0x1c answer; metadata burst (0x451/0x453/0x455/0x456/0x450) interleaves here as FramebufferUpdate rects.

0x21 ViewerInfo - rfb.py:200-225, apple.py:29-51. Total 66B, msgSize=0x3E(=total-4):
 +0x00 u8 0x21|+0x01 u8 0|+0x02 u16 0x003E|+0x04 u16 msgVersion=1|+0x06 u32 app_id=2|+0x0A u32 ver_maj=6|+0x0E u32 ver_min=1|+0x12 u32 ver_pat=0|+0x16 u32 os_maj=15|+0x1A u32 os_min=3|+0x1E u32 os_pat=0|+0x22 [32]command_mask|+0x42 extra(empty)
 command_mask 32B zero except [0]=0xB0,[2]=0x0C,[3]=0x03,[4]=0x90,[10]=0x40 (apple.py:29-36).

0x12 followup (SetEncryption cmd=1) - apple.py:70-72, glued after ViewerInfo negotiation.py:513-521. 12B: +0 0x12|+1 0|+2 u16=1|+4 u16=1|+6 u16=1|+8 u32=1. hex 12 00 0001 0001 0001 00000001. All load-bearing.

0x1d SetDisplayConfiguration - rfb.py:228-354. mode_count=5 -> di_size=0x9C+28*5=0x128(296); msg_size field=8+di_size=304(0x130); total wire=12+296=308.
 HEADER 12B: +0x00 u8 0x1D|+0x01 u8 0|+0x02 u16 0x0130|+0x04 u16=1|+0x06 u16=1|+0x08 u32=0.
 DI at wire+0x0C (di-relative offsets) rfb.py:289-350:
  di+0x00 u16 0x0128|di+0x02..0x79(max119) name UTF-8 NUL-pad|di+0x7A u32 display_flags=1(DYNAMIC_RESOLUTION,MANDATORY)|di+0x7E u32 display_type=4(virtual,MANDATORY)|di+0x82 f32 phys_w_mm=369.4545593261719(writeFloatBE)|di+0x86 f32 phys_h_mm=207.81817626953125|di+0x8A u32 max_w=3840|di+0x8E u32 max_h=2160|di+0x92 u16 cur_mode=0|di+0x94 u16 pref_mode=0|di+0x96 u32 reserved=7(MANDATORY)|di+0x9A u16 mode_count=5
  di+0x9C mode table 28B entries (m=di+0x9C+28*i): m+0x00 u32 pixel_w|m+0x04 u32 pixel_h|m+0x08 u32 scaled_w|m+0x0C u32 scaled_h|m+0x10 f64 refresh=60.0(writeDoubleBE)|m+0x18 u32 mode_flags=hdr?1:0
  template scaled dims rows i%5 (rfb.py:316-322): 1920x1080,1440x900,1920x1080,1440x810,1312x848; sx=pts_w/1920,sy=pts_h/1080; msw=round(base*sx); mw=round(msw*hidpi_scale).
 Spec C.4 (1063-1068) confirms 304/296/mode[0]/reserved=7.

0x02 SetEncodings - rfb.py:170-174, list 97-100. +0 u8 0x02|+1 u8 0|+2 u16 count=13|+4.. int32BE x13 (writeInt32BE; -223->0xFFFFFF21). Total 56B.
 order dec->hex: 1010->3F2,1011->3F3,1002->3EA,6->06,16->10,1104->450,1100->44C,-223->FFFFFF21,1101->44D,1105->451,1107->453,1109->455,1110->456. Advertising 0x451/0x453/0x455/0x456/0x450 makes the server emit those metadata records; 0x3f2 requests media-init (spec 575,597).

0x12 PostEncryptionToggle (SetEncryption cmd=2) - rfb.py:177-180. FIXED 8B: 12 00 00 02 00 01 00 00 = Buffer.from("1200000200010000","hex"). PLAINTEXT (last plaintext msg).

0x03 FramebufferUpdateRequest - negotiation.py:553-570. 10B: +0 u8 0x03|+1 u8 incremental(0=full)|+2 u16 x|+4 u16 y|+6 u16 w|+8 u16 h. Bring-up 0,0,0,0xFFFF,0xFFFF. ENCRYPTED after 0x1c.

0x09 AutoFrameBufferUpdate - negotiation.py:577-609, spec 633-648. 16B: +0 u8 0x09|+1 u8 0|+2 u16 version=1|+4 u32 selected_screen=0xFFFFFFFF|+8 u16 x=0|+0x0A u16 y=0|+0x0C u16 w=width|+0x0E u16 h=height. Re-arm: on every inbound 0x451 re-send 0x09 THEN non-incremental 0x03 (spec 508,650).

PARSING metadata burst. Envelope FramebufferUpdate: +0 u8 0x00|+1 u8 pad|+2 u16 num_rects|rects. Rect header 12B (negotiation.py:861-864): u16 x|u16 y|u16 w|u16 h|int32 encoding, then payload. Tolerate interleaved 0x14 (8B, negotiation.py:855) and 0x1f. Between the two SetEncodings, enc==1103 (36B->cipher); enc in {1010,1011} body=u16 size||size bytes, skip (negotiation.py:866-872).
 0x451 AppleDisplayLayout WORKING parser rfb.py:36-73: hdr20B: +0 u16 ver=5|+2 u16 scaled_w|+4 u16 scaled_h|+6 u16 backing_w|+8 u16 backing_h|+10 u32 0xffffffff|+14 u32 field|+18 u16 count; per-display 56B from +20: +0x00 f64 hscale|+0x08 f64 vscale|+0x10 u32 display_id|+0x14 point rect y0,x0,y1,x1(4xu16)|+0x1C pixel rect y0,x0,y1,x1(4xu16)|+0x24 20B ignored. Read pixel rect at off+28..36. Decode surface = backing_w x backing_h; window/input = scaled_* (spec 835). Spec §8.4 488-504 alternate model (version skew); treat live geometry authoritative.
 0x453 22B fixed (spec 511-523): +0 u16 0x0014|+2 u16 0x0001|+4 u16 4|+6 u32x4 1008FD00..03. parse-and-ignore.
 0x455 (S=len utf8 id) spec 527-539: +0 u16 prefix=S+8|+2 u16 marker=0x0001|+4 u32 kbd_flags(bit0=secure-input)|+8 u16 id_len=S|+10 u8[S] id(no NUL). payload=S+10. parse-and-cache.
 0x456 spec 541-557: +0 u16 msg_size=block+0x10|+2 u16 pair_count=2|+4 u32 struct_ver=1|+8 u32 enclosure_rgb=0|+12 u16 id_len(inclNUL)|+14 u16 color_len|+16 u16 enc_color_len|3 NUL-term UTF-8 strings|u32 housing_color(signed). parse-and-cache.
 0x450 CursorImage spec 469-477: rect hdr=hotspot x/y,w/h; payload u32 cache_id||u32 comp_len||zlib. comp_len>0 STORE(inflate lvl9 Z_SYNC_FLUSH -> w*h*4 BGRA + w*h alpha; cache by id); comp_len==0 SELECT(reapply id).

MINIMAL vs FIXED. MUST: 0x1d display_type=4 & display_flags=0x01 & reserved=7 & non-degenerate mode table; 0x02 list must include 0x3f2 + 0x450/0x451/0x453/0x455/0x456, count matches; 0x21 msgSize=0x3E + 5 command_mask bytes. FIXED-OK: 0x1d phys mm dims, max 3840x2160, name, mode indices=0; 0x21 app_id=2/ver(6,1,0)/os(15,3,0); 0x12 followup & toggle literals; 0x09 selected_screen=0xFFFFFFFF/version=1; 0x03 x=y=0/w=h=0xFFFF/incremental=0.

### Node crypto

No node:crypto in this component — every message is a fixed-offset Buffer build; the caller wraps them with enc1103 StreamCipher.encrypt_message() once the record layer is active (separate component). Python->Node: struct.pack(">B")=buf[o]=v; ">H"=writeUInt16BE(v,o); ">I"=writeUInt32BE(v,o); ">i"=writeInt32BE(v,o) (for -223->0xFFFFFF21); ">f"=writeFloatBE (two f32 mm fields in 0x1d); ">d"=writeDoubleBE (f64 60.0 refresh per mode entry, and f64 hscale/vscale when parsing 0x451). struct.pack_into on bytearray = Buffer.alloc(N) then writeXxxBE. int.from_bytes(x,'big')=readUInt16BE/readUInt32BE/readInt32BE. bytes.fromhex=Buffer.from(hex,'hex'). Glue in one sendall=Buffer.concat([a,b]). 0x450 cursor STORE decompression later: node:zlib inflateSync. No SHA/HMAC/AES/RSA here.

### Unknowns

- 0x1d/0x02 sent PLAINTEXT in the reference (negotiation.py:500-534) but RFC §9.2 lists them ENCRYPTED (spec 718-719). I followed the reference; confirm against a live capture which your host accepts.
- 0x451 has two conflicting field models: rfb.py:36-73 (20B header, backing at +6..10, count at +18) vs spec §8.4 488-504 (u16 payload_len prefix, u32 current_display, u32 flags, u16 flag_word). Spec flags version-skew (line 506). Implement rfb.py parser; keep spec model as fallback. Exact position of payload_len prefix unresolved.
- Reference omits 0x09 on the idle path (negotiation.py:583-609 'currently unused'), sending only non-incremental 0x03; RFC marks 0x09 MUST (§8.11, R-A16b line 868). 0x03-only is proven for bring-up; 0x09 needed for live cursor-shape updates across login/lock/agent transitions.
- PostEncryptionToggle 1200000200010000 read as SetEncryption cmd=2 from flow position; inner u16 fields (0x0002,0x0001,0x0000) are only a literal in the reference — treat the 8 bytes as an opaque constant.
- command_mask bit semantics beyond heartbeat/clipboard are partially documented (apple.py:14-28); the 5 documented non-zero bytes give byte-parity with Screen Sharing.app but full feature-gate meaning is a revision gap (spec 1109).

---
