# hp-protocol

Native Apple HP control transport. `HpConnection::connect` owns one TCP
connection and authenticated media key negotiation. It performs one preliminary
version-only connection and exactly one security-type-30 authentication attempt.
Passwords are never retried automatically or included in diagnostics.

The returned connection has nonblocking connected UDP sockets on local ports
5900 and 5901. Feed `video_socket` datagrams and `video_receive_key` to `hp-media`.
Send protected RTCP receiver reports and feedback using `video_send_key` through
`control_socket`. The caller must regularly call `poll_control` and send the
media receiver reports; neither operation starts a hidden background thread.
Apple additionally requires a 500ms SRTP heartbeat on the control socket even
with audio disabled: PT 101, payload `00 68 34 00`, protected using
`audio_send_key` and the matching `audio_ssrc`. Without it the Mac can stop
video after about 30 seconds despite valid RTCP receiver reports. The heartbeat
does not capture or transmit local microphone/audio content.

`connect` only succeeds after a bounded media answer supplies validated canvas
geometry. Read the actual tile count from `stream_config`. The offer selects
HEVC with one independently decodable full-screen picture, disables audio and
LTR acknowledgements, and requests 30 or 60 FPS. Asking for one tile preserves
the HP/SRTP transport while avoiding Apple's four-stream cross-tile references,
which can decode without reported errors yet composite into corrupted regions.
An encoder still warming after a session transition can answer with zero
geometry. The client re-queries media configuration on the same authenticated
connection, with the same media keys, up to 16 times within a 12-second deadline;
this never repeats the login handshake.
Apple omits the answer's tile-count field for a single full-picture stream.
An absent field therefore defaults to one; an explicit zero remains invalid.
Control input uses encrypted RFB key, pointer, and Latin-1 clipboard messages.

Apple's codec bank labels are misleading: bank 100 with AVC-labelled parameter
text produces HEVC; bank 123 with HEVC-labelled text produces H.264. This
inversion is documented by the upstream
[offer implementation](https://github.com/renegadelink/iShareScreen/blob/main/src/isharescreen/proxy/protocol/offers.py)
and protected by a test that decodes the serialized offer. Do not select a bank
based on the historical variable name.

`record` uses RustCrypto AES and SHA-1 with continuous CBC chaining in each
direction. A failed authentication hash terminates the connection instead of
guessing sequence counters. DH uses `num-bigint` modular exponentiation; it is
not constant-time and its internal allocations are not securely wiped. Password
and key byte buffers are cleared on drop where owned by this crate. Apple's
legacy DH/MD5 scheme is required for compatibility and does not authenticate a
server certificate.

Temporary authentication and media-key byte buffers use RAII zeroization, so
early network errors also clear them. The password is cleared immediately after
building its encrypted authentication response; RustCrypto AES key schedules
have their zeroization feature enabled. Control integrity failure permanently
disables that record-layer instance. Ciphertext sizes, protobuf field counts,
candidate compressed streams, and total decompressed bytes per answer are bounded
before further processing. These measures do not erase `num-bigint`'s internal
DH allocations or make its modular exponentiation constant-time.

Offline tests cover known AES and Node-crypto record fixtures, chaining,
tampering, length bounds, single-byte TCP fragmentation, credential layout,
protobuf truncation/overflow, and media geometry parsing. Live interoperability
is separate from these tests.

`network_rtt()` reads the existing TCP socket's operating-system estimate via
Windows [SIO_TCP_INFO](https://learn.microsoft.com/en-us/windows/win32/winsock/sio-tcp-info).
It returns the [TCP_INFO_v0 RttUs](https://learn.microsoft.com/en-us/windows/win32/api/mstcpip/ns-mstcpip-tcp_info_v0)
field as a `Duration`, preserving microsecond precision. This measures network
round trip rather than video decoding, rendering, or input-to-display latency;
the estimate may remain unchanged when TCP is idle. No probes or new connections
are sent, and unsupported systems or unavailable samples return `None`.

Display-layout (`0x451`) records include a two-byte payload length before the
layout header. Every complete layout update rearms a nonincremental framebuffer
request, including unchanged login/lock transitions; ordinary updates rearm a
full-region incremental request. Only one framebuffer request is outstanding, and the
client does not enable free-running AutoFrameBufferUpdate. Backing-size changes
coalesce a same-session media reoffer at most once every two seconds using the
original zeroizing offer and keys. `layout_events` and `media_reoffers` provide
numeric transition evidence without capturing desktop or key data. This follows
[upstream session handling](https://github.com/renegadelink/iShareScreen/blob/main/src/isharescreen/proxy/session.py);
it does not establish that every black frame is a geometry transition or wake a
sleeping Mac. Live transition recovery remains a separate validation step.
