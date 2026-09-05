//! Native Apple HP authentication and encrypted control transport.
//! No credentials or cryptographic material are logged or formatted with Debug.
pub mod metadata;
mod network_stats;
mod offer;
pub mod record;
use aes::{
    cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit},
    Aes128,
};
use anyhow::{bail, ensure, Context, Result};
use md5::{Digest, Md5};
use num_bigint::BigUint;
use rand::RngCore;
use record::RecordLayer;
use std::{
    io::{ErrorKind, Read, Write},
    net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket},
    time::{Duration, Instant},
};
use zeroize::{Zeroize, Zeroizing};

pub struct ConnectOptions {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub width: u16,
    pub height: u16,
    pub fps: u16,
}
impl Drop for ConnectOptions {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}
pub struct HpConnection {
    tcp: TcpStream,
    records: RecordLayer,
    pending: Vec<u8>,
    pub width: u16,
    pub height: u16,
    pub video_socket: UdpSocket,
    pub control_socket: UdpSocket,
    pub video_send_key: [u8; 46],
    pub video_receive_key: [u8; 46],
    pub video_ssrc: u32,
    pub audio_send_key: [u8; 46],
    pub audio_ssrc: u32,
    pub stream_config: Option<metadata::StreamConfig>,
    update_outstanding: bool,
}
impl Drop for HpConnection {
    fn drop(&mut self) {
        self.video_send_key.zeroize();
        self.video_receive_key.zeroize();
        self.audio_send_key.zeroize();
        let _ = self.tcp.shutdown(std::net::Shutdown::Both);
    }
}
impl HpConnection {
    /// Current OS-estimated network round-trip time of the HP TCP connection.
    /// Uses existing socket statistics only; does not measure video/input delay
    /// or send probes. Returns None on unsupported systems or before sampling.
    pub fn network_rtt(&self) -> Option<Duration> {
        network_stats::network_rtt(&self.tcp)
    }
    /// Performs exactly one authentication attempt. Errors never trigger retries.
    pub fn connect(mut options: ConnectOptions) -> Result<Self> {
        ensure!(!options.host.trim().is_empty(), "host is required");
        ensure!(options.port != 0, "invalid port");
        if options.width != 0 && options.height != 0 {
            validate_dimensions(options.width, options.height)?;
        }
        ensure!(
            [30, 60].contains(&options.fps),
            "HP supports a requested rate of 30 or 60 FPS"
        );
        ensure!(
            options.username.len() <= 63 && options.password.len() <= 63,
            "Apple authentication accepts at most 63 UTF-8 bytes per credential"
        );
        ensure!(
            !options.username.contains('\0') && !options.password.contains('\0'),
            "credentials cannot contain NUL"
        );
        let addr = (&*options.host, options.port)
            .to_socket_addrs()?
            .find(SocketAddr::is_ipv4)
            .context("host has no IPv4 address (HP media currently requires IPv4)")?;
        // Apple expects a preliminary version exchange; this is not a login attempt.
        let mut warm = TcpStream::connect_timeout(&addr, Duration::from_secs(6))?;
        configure(&warm)?;
        version(&mut warm)?;
        drop(warm);
        std::thread::sleep(Duration::from_millis(1400));
        let video_socket =
            UdpSocket::bind("0.0.0.0:5901").context("cannot bind HP video UDP port 5901")?;
        let control_socket =
            UdpSocket::bind("0.0.0.0:5900").context("cannot bind HP control UDP port 5900")?;
        // HP keyframes arrive in bursts, well above Windows' default buffer.
        socket2::SockRef::from(&video_socket).set_recv_buffer_size(4 * 1024 * 1024)?;
        socket2::SockRef::from(&control_socket).set_recv_buffer_size(1024 * 1024)?;
        video_socket.connect(SocketAddr::new(addr.ip(), 5901))?;
        control_socket.connect(SocketAddr::new(addr.ip(), 5900))?;
        video_socket.set_nonblocking(true)?;
        control_socket.set_nonblocking(true)?;
        video_socket.send(&[0])?;
        control_socket.send(&[0])?;
        let mut tcp = TcpStream::connect_timeout(&addr, Duration::from_secs(8))?;
        configure(&tcp)?;
        let types = version(&mut tcp)?;
        ensure!(
            types.contains(&30),
            "Mac did not offer Apple security type 30"
        );
        tcp.write_all(&[30])?;
        let generator = read16(&mut tcp)?;
        let key_len = read16(&mut tcp)? as usize;
        ensure!(
            (64..=512).contains(&key_len),
            "unsupported Apple DH key length"
        );
        let prime = read_n(&mut tcp, key_len)?;
        let public = read_n(&mut tcp, key_len)?;
        let (mut response, mut wrap_key) = authenticate(
            generator,
            &prime,
            &public,
            &options.username,
            &options.password,
        )
        .context("Apple authentication key exchange")?;
        options.password.zeroize();
        tcp.write_all(&response)?;
        response.zeroize();
        if read32(&mut tcp)? != 0 {
            wrap_key.zeroize();
            bail!("Mac rejected authentication; no retry was attempted");
        }
        tcp.write_all(&[1])?;
        let server_w = read16(&mut tcp)?;
        let server_h = read16(&mut tcp)?;
        read_n(&mut tcp, 16)?;
        let name_len = read32(&mut tcp)? as usize;
        ensure!(name_len <= 65536, "desktop name too large");
        read_n(&mut tcp, name_len)?;
        tcp.write_all(&offer::viewer_info())?;
        tcp.write_all(&[0x12, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1])?;
        std::thread::sleep(Duration::from_millis(120));
        tcp.write_all(&offer::encodings())?;
        let blob = find_rekey(&mut tcp).context("HP encryption setup")?;
        let key = Zeroizing::new(record::unwrap(&wrap_key, &blob[4..20])?);
        let iv = Zeroizing::new(record::unwrap(&wrap_key, &blob[20..36])?);
        wrap_key.zeroize();
        tcp.write_all(&[0x12, 0, 0, 2, 0, 1, 0, 0])?;
        let mut records = RecordLayer::new(*key, *iv);
        let n = read16(&mut tcp)? as usize;
        ensure!(
            n >= 32 && n.is_multiple_of(16),
            "bad initial control record length"
        );
        let first = records
            .decrypt(&read_n(&mut tcp, n)?)
            .context("first HP control record verification")?;
        let width = if options.width == 0 {
            server_w
        } else {
            options.width
        };
        let height = if options.height == 0 {
            server_h
        } else {
            options.height
        };
        validate_dimensions(width, height)?;
        for message in [
            offer::encodings(),
            offer::display_config(width, height, options.fps),
            vec![3, 0, 0, 0, 0, 0, 255, 255, 255, 255],
        ] {
            tcp.write_all(&records.encrypt(&message)?)?;
        }
        tcp.write_all(&records.encrypt(&offer::auto_fbu(width, height))?)?;
        let mut video_send_key = Zeroizing::new([0; 46]);
        let mut video_receive_key = Zeroizing::new([0; 46]);
        rand::rngs::OsRng.fill_bytes(&mut *video_send_key);
        rand::rngs::OsRng.fill_bytes(&mut *video_receive_key);
        let video_ssrc = rand::random();
        let audio_ssrc = rand::random();
        let mut audio_send_key = Zeroizing::new([0; 46]);
        rand::rngs::OsRng.fill_bytes(&mut *audio_send_key);
        // Leave the metadata records buffered in TCP: the persistent parser drains
        // them alongside media, so no fixed pre-stream delay loses the first IDR.
        video_socket.send(&[0])?;
        control_socket.send(&[0])?;
        let media_offer = Zeroizing::new(offer::media_options(
            video_ssrc,
            &video_send_key,
            &video_receive_key,
            options.fps,
            audio_ssrc,
            &audio_send_key,
        )?);
        tcp.write_all(&records.encrypt(&media_offer)?)?;
        tcp.set_read_timeout(None)?;
        tcp.set_nonblocking(true)?;
        let mut result = Self {
            tcp,
            records,
            pending: Vec::new(),
            width,
            height,
            video_socket,
            control_socket,
            video_send_key: *video_send_key,
            video_receive_key: *video_receive_key,
            video_ssrc,
            audio_ssrc,
            audio_send_key: *audio_send_key,
            stream_config: None,
            update_outstanding: true,
        };
        result.inspect_control(&first)?;
        let deadline = Instant::now() + Duration::from_secs(12);
        let mut last_offer = Instant::now();
        let (mut records_seen, mut plist_records, mut layout_records, mut requeries) =
            (1usize, 0usize, 0usize, 0usize);
        let mut answer_diagnostic = String::from("no_plist_received");
        while result.stream_config.is_none() {
            ensure!(
                Instant::now() < deadline,
                "Mac did not negotiate HP video geometry before timeout (control_records={records_seen}, plist_records={plist_records}, layout_records={layout_records}, media_requeries={requeries}, pending_bytes={}, last_answer=[{answer_diagnostic}])",result.pending.len()
            );
            for body in result.poll_control()? {
                records_seen += 1;
                if body.windows(8).any(|w| w == b"bplist00") {
                    plist_records += 1;
                    answer_diagnostic = metadata::diagnose_answer(&body);
                }
                if metadata::display_layout(&body).is_some() {
                    layout_records += 1;
                }
            }
            // A fresh screensharingd agent can answer with a zero-size canvas
            // while its encoder warms up. Upstream resends this exact offer on
            // the existing authenticated connection: never repeat credentials.
            if result.stream_config.is_none()
                && requeries < 16
                && last_offer.elapsed() >= Duration::from_millis(500)
            {
                result.send(&media_offer)?;
                requeries += 1;
                last_offer = Instant::now();
            }
            result.video_socket.send(&[0])?;
            result.control_socket.send(&[0])?;
            std::thread::sleep(Duration::from_millis(20));
        }
        Ok(result)
    }
    pub fn send_key(&mut self, down: bool, keysym: u32) -> Result<()> {
        let mut b = vec![4, down as u8, 0, 0];
        b.extend(keysym.to_be_bytes());
        self.send(&b)
    }
    pub fn send_pointer(&mut self, mask: u8, x: u16, y: u16) -> Result<()> {
        let mut b = vec![5, mask];
        b.extend(x.to_be_bytes());
        b.extend(y.to_be_bytes());
        self.send(&b)
    }
    pub fn send_clipboard(&mut self, text: &str) -> Result<()> {
        ensure!(text.len() <= 1_048_576, "clipboard too large");
        let bytes: Vec<u8> = text
            .chars()
            .map(|c| if c as u32 <= 255 { c as u8 } else { b'?' })
            .collect();
        let mut msg = vec![6, 0, 0, 0];
        msg.extend((bytes.len() as u32).to_be_bytes());
        msg.extend(bytes);
        ensure!(
            msg.len() <= 65498,
            "clipboard exceeds encrypted control record limit"
        );
        self.send(&msg)
    }
    fn send(&mut self, body: &[u8]) -> Result<()> {
        let wire = self.records.encrypt(body)?;
        self.tcp.set_nonblocking(false)?;
        self.tcp.set_write_timeout(Some(Duration::from_secs(3)))?;
        let r = self.tcp.write_all(&wire);
        let restore = self.tcp.set_nonblocking(true);
        r?;
        restore?;
        Ok(())
    }
    /// Drains available records without discarding partial TCP headers or bodies.
    pub fn poll_control(&mut self) -> Result<Vec<Vec<u8>>> {
        let mut chunk = [0u8; 8192];
        loop {
            match self.tcp.read(&mut chunk) {
                Ok(0) => bail!("Mac closed the HP control channel"),
                Ok(n) => {
                    self.pending.extend_from_slice(&chunk[..n]);
                    ensure!(
                        self.pending.len() <= 4 * 1024 * 1024,
                        "control backlog exceeded limit"
                    );
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            }
        }
        let result = record::drain_records(&mut self.records, &mut self.pending)?;
        for body in &result {
            self.inspect_control(body)?;
        }
        Ok(result)
    }
    fn inspect_control(&mut self, body: &[u8]) -> Result<()> {
        let layout = metadata::display_layout(body);
        if let Some((w, h)) = layout {
            self.send(&offer::auto_fbu(w, h))?;
        }
        if let Some(config) = metadata::parse_answer(body)? {
            ensure!(
                !config.ltr_enabled,
                "Mac selected unsupported long-term-reference acknowledgement mode"
            );
            self.width = config.width;
            self.height = config.height;
            self.stream_config = Some(config);
        }
        if metadata::complete_update(body) && self.update_outstanding {
            self.update_outstanding = false;
            self.send(&[
                3,
                u8::from(layout.is_none()),
                0,
                0,
                0,
                0,
                255,
                255,
                255,
                255,
            ])?;
            self.update_outstanding = true;
        }
        Ok(())
    }
}
fn configure(s: &TcpStream) -> Result<()> {
    s.set_nodelay(true)?;
    s.set_read_timeout(Some(Duration::from_secs(8)))?;
    s.set_write_timeout(Some(Duration::from_secs(8)))?;
    Ok(())
}
fn validate_dimensions(width: u16, height: u16) -> Result<()> {
    ensure!(
        width > 0
            && height > 0
            && width <= 16384
            && height <= 16384
            && u64::from(width) * u64::from(height) <= 67_108_864,
        "desktop dimensions exceed supported limits"
    );
    Ok(())
}
fn read_n(r: &mut impl Read, n: usize) -> Result<Vec<u8>> {
    let mut b = vec![0; n];
    read_exact_before(r, &mut b, Instant::now() + Duration::from_secs(8))?;
    Ok(b)
}
fn read_exact_before(r: &mut impl Read, mut output: &mut [u8], deadline: Instant) -> Result<()> {
    while !output.is_empty() {
        ensure!(Instant::now() < deadline, "handshake field read timed out");
        match r.read(output) {
            Ok(0) => bail!("connection closed in handshake field"),
            Ok(n) => output = &mut output[n..],
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
fn read16(r: &mut impl Read) -> Result<u16> {
    let mut b = [0; 2];
    read_exact_before(r, &mut b, Instant::now() + Duration::from_secs(8))?;
    Ok(u16::from_be_bytes(b))
}
fn read32(r: &mut impl Read) -> Result<u32> {
    let mut b = [0; 4];
    read_exact_before(r, &mut b, Instant::now() + Duration::from_secs(8))?;
    Ok(u32::from_be_bytes(b))
}
fn version(s: &mut TcpStream) -> Result<Vec<u8>> {
    let banner = read_n(s, 12)?;
    ensure!(
        &banner[..4] == b"RFB " && banner[11] == b'\n',
        "invalid RFB version banner"
    );
    s.write_all(b"RFB 003.008\n")?;
    let n = read_n(s, 1)?[0] as usize;
    ensure!(n > 0, "Mac refused the connection before authentication");
    read_n(s, n)
}
fn padded(n: BigUint, len: usize) -> Result<Vec<u8>> {
    let b = Zeroizing::new(n.to_bytes_be());
    ensure!(b.len() <= len, "DH value overflow");
    let mut out = vec![0; len];
    out[len - b.len()..].copy_from_slice(&b);
    Ok(out)
}
type AppleAuthResponse = (Zeroizing<Vec<u8>>, Zeroizing<[u8; 16]>);
fn authenticate(
    generator: u16,
    prime: &[u8],
    public: &[u8],
    user: &str,
    password: &str,
) -> Result<AppleAuthResponse> {
    ensure!(
        user.len() <= 63 && password.len() <= 63,
        "Apple credential exceeds 63 UTF-8 bytes"
    );
    ensure!(
        !user.contains('\0') && !password.contains('\0'),
        "credentials cannot contain NUL"
    );
    ensure!(
        !prime.is_empty() && prime.len() <= 512 && public.len() == prime.len(),
        "invalid DH parameter lengths"
    );
    let p = BigUint::from_bytes_be(prime);
    let g = BigUint::from(generator);
    let y = BigUint::from_bytes_be(public);
    let one = BigUint::from(1u8);
    ensure!(
        p > BigUint::from(5u8) && g > one && g < &p - &one && y > one && y < &p - &one,
        "invalid Apple DH parameters"
    );
    let mut random = Zeroizing::new(vec![0; prime.len()]);
    rand::rngs::OsRng.fill_bytes(&mut random);
    let x = BigUint::from_bytes_be(&random);
    random.zeroize();
    let ours = padded(g.modpow(&x, &p), prime.len())?;
    let mut secret = Zeroizing::new(padded(y.modpow(&x, &p), prime.len())?);
    let key = Zeroizing::new(<[u8; 16]>::from(Md5::digest(&*secret)));
    secret.zeroize();
    let mut plain = Zeroizing::new([0; 128]);
    rand::rngs::OsRng.fill_bytes(&mut *plain);
    plain[..user.len()].copy_from_slice(user.as_bytes());
    plain[user.len()] = 0;
    plain[64..64 + password.len()].copy_from_slice(password.as_bytes());
    plain[64 + password.len()] = 0;
    let cipher = Aes128::new(GenericArray::from_slice(&key[..]));
    for block in plain.as_chunks_mut::<16>().0 {
        cipher.encrypt_block(GenericArray::from_mut_slice(block));
    }
    let mut response = Zeroizing::new(plain.to_vec());
    plain.zeroize();
    response.extend(ours);
    Ok((response, key))
}
fn find_rekey(tcp: &mut TcpStream) -> Result<Vec<u8>> {
    let deadline = Instant::now() + Duration::from_secs(8);
    while Instant::now() < deadline {
        match read_n(tcp, 1)?[0] {
            0 => {
                read_n(tcp, 1)?;
                let n = read16(tcp)?;
                for _ in 0..n {
                    ensure!(
                        Instant::now() < deadline,
                        "HP encryption negotiation timed out"
                    );
                    let rh = read_n(tcp, 12)?;
                    let enc = i32::from_be_bytes(rh[8..12].try_into().unwrap());
                    match enc {
                        1103 => return read_n(tcp, 36),
                        1010 | 1011 => {
                            let n = read16(tcp)? as usize;
                            read_n(tcp, n)?;
                        }
                        -224 => break,
                        _ => bail!("unsupported pre-encryption metadata encoding {enc}"),
                    }
                }
            }
            0x14 => {
                // Upstream negotiation.py advances 8 bytes INCLUDING type.
                read_n(tcp, 7)?;
            }
            other => bail!("unexpected pre-encryption message {other}"),
        }
    }
    bail!("HP encryption negotiation timed out")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn handshake_deadline_and_eof_stop_partial_reads() {
        let mut reader = std::io::Cursor::new(vec![1, 2]);
        assert!(read_exact_before(
            &mut reader,
            &mut [0; 2],
            Instant::now() - Duration::from_secs(1)
        )
        .is_err());
        assert_eq!(reader.position(), 0);
        assert!(read_exact_before(
            &mut reader,
            &mut [0; 3],
            Instant::now() + Duration::from_secs(1)
        )
        .is_err());
    }
    #[test]
    fn invalid_credentials_and_peer_lengths_rejected_without_slicing() {
        assert!(authenticate(2, &[23], &[9], "u\0ser", "pass").is_err());
        assert!(authenticate(2, &[23], &[9], "user", &"é".repeat(32)).is_err());
        assert!(authenticate(2, &[23], &[], "user", "pass").is_err());
        assert!(authenticate(2, &vec![1; 513], &vec![2; 513], "user", "pass").is_err());
    }
    #[test]
    fn desktop_dimensions_bound_allocations_and_virtual_display_requests() {
        assert!(validate_dimensions(1920, 1080).is_ok());
        assert!(validate_dimensions(0, 1080).is_err());
        assert!(validate_dimensions(u16::MAX, 1080).is_err());
        assert!(validate_dimensions(16384, 16384).is_err());
    }
    #[test]
    fn credential_layout_and_shared_key_match_server() {
        use aes::cipher::BlockDecrypt;
        // Small synthetic DH group keeps this an offline framing fixture. The
        // production connection separately requires 64..=512 byte DH parameters.
        let (response, key) = authenticate(2, &[23], &[9], "alice", "example-only").unwrap();
        assert_eq!(response.len(), 129);
        let shared = (response[128] as u64).pow(5) % 23;
        let expected: [u8; 16] = Md5::digest([shared as u8]).into();
        assert_eq!(*key, expected);
        let mut plaintext = response[..128].to_vec();
        let cipher = Aes128::new(GenericArray::from_slice(&expected));
        for block in plaintext.as_chunks_mut::<16>().0 {
            cipher.decrypt_block(GenericArray::from_mut_slice(block));
        }
        assert_eq!(&plaintext[..6], b"alice\0");
        assert_eq!(&plaintext[64..77], b"example-only\0");
    }
    struct SingleByte(std::io::Cursor<Vec<u8>>);
    impl Read for SingleByte {
        fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
            let n = b.len().min(1);
            self.0.read(&mut b[..n])
        }
    }
    #[test]
    fn reads_single_byte_segments() {
        let mut r = SingleByte(std::io::Cursor::new(vec![
            0x12, 0x34, 0xff, 0xff, 0xff, 0x21,
        ]));
        assert_eq!(read16(&mut r).unwrap(), 0x1234);
        assert_eq!(read32(&mut r).unwrap(), 0xffffff21);
    }
    #[test]
    fn dh_rejects_degenerate_public() {
        assert!(authenticate(2, &[23], &[1], "u", "p").is_err());
    }
    #[test]
    fn left_padding() {
        assert_eq!(
            padded(BigUint::from(0x1234u32), 4).unwrap(),
            [0, 0, 0x12, 0x34]
        );
    }
}
