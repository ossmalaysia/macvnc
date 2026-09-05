use anyhow::{bail, Context, Result};
use hp_media::{
    build_empty_sr, build_fir, build_fir_legacy, build_pli, build_rr, is_rtcp, Compositor,
    Depacketizer, HevcDecoder, RgbaFrame, SrtcpSender, SrtpReceiver, SrtpSender,
};
use serde::Serialize;
use std::{
    io::ErrorKind,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, Sender, SyncSender},
        Arc, Mutex,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroize;

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
pub enum Command {
    Connect(ConnectOptions),
    Disconnect,
    Pointer { x: u16, y: u16, buttons: u8 },
    Key { keysym: u32, down: bool },
    Clipboard(String),
}
pub enum Event {
    Status(String),
    NetworkRtt(Option<Duration>),
    Connected { width: u32, height: u32 },
    Disconnected(String),
}
pub struct Backend {
    pub commands: CommandSender,
    pub events: Receiver<Event>,
    pub latest: Arc<Mutex<Option<RgbaFrame>>>,
}
pub struct CommandSender {
    sender: SyncSender<Command>,
    cancelled: Arc<AtomicBool>,
}
impl Drop for CommandSender {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Release);
    }
}
impl CommandSender {
    pub fn send(&self, command: Command) -> Result<(), mpsc::SendError<Command>> {
        if matches!(command, Command::Connect(_)) {
            self.cancelled.store(false, Ordering::Release);
        }
        if matches!(command, Command::Disconnect) {
            self.cancelled.store(true, Ordering::Release);
        }
        match self.sender.try_send(command) {
            Ok(()) => Ok(()),
            Err(mpsc::TrySendError::Full(command))
            | Err(mpsc::TrySendError::Disconnected(command)) => {
                // A dropped key release could latch remote input: close the session instead.
                self.cancelled.store(true, Ordering::Release);
                Err(mpsc::SendError(command))
            }
        }
    }
}
#[derive(Default, Serialize)]
pub struct ProbeReport {
    pub authenticated: bool,
    pub width: u32,
    pub height: u32,
    pub udp_packets: u64,
    pub control_udp_packets: u64,
    pub authenticated_packets: u64,
    pub media_sources: usize,
    pub rejected_packets: u64,
    pub access_units: u64,
    pub decoded_tiles: u64,
    pub decoded_width: u32,
    pub decoded_height: u32,
    pub composed_updates: u64,
    pub decode_errors: u64,
    pub reference_errors: u64,
    pub decoder_log_errors: u64,
    pub suppressed_pictures: u64,
    pub injected_packet_loss: u64,
    pub recovery_after_loss_seconds: Option<f64>,
    pub waiting_for_keyframe: bool,
    pub last_good_picture_age_seconds: f64,
    pub last_video_packet_age_seconds: f64,
    pub recovery_requests: u64,
    pub audio_heartbeats: u64,
    pub network_rtt_ms: Option<f64>,
    pub elapsed_seconds: f64,
    pub peak_frame_bytes: usize,
    pub media_diagnostics: String,
}
pub fn start(repaint: Arc<dyn Fn() + Send + Sync>) -> Backend {
    let (sender, rx) = mpsc::sync_channel(256);
    let cancelled = Arc::new(AtomicBool::new(false));
    let commands = CommandSender {
        sender,
        cancelled: cancelled.clone(),
    };
    let (tx, events) = mpsc::channel();
    let latest = Arc::new(Mutex::new(None));
    let output = latest.clone();
    std::thread::spawn(move || {
        while let Ok(command) = rx.recv() {
            if let Command::Connect(opts) = command {
                let _ = tx.send(Event::Status("Negotiating encrypted HP session…".into()));
                repaint();
                let result = run_session(opts, &rx, &tx, &output, &repaint, &cancelled, None);
                *output.lock().unwrap() = None;
                // No queued input or connection request survives a session boundary.
                while rx.try_recv().is_ok() {}
                let message = match result {
                    Ok(_) => "Disconnected".into(),
                    Err(e) => format!("{e:#}"),
                };
                let _ = tx.send(Event::Disconnected(message));
                repaint();
            }
        }
    });
    Backend {
        commands,
        events,
        latest,
    }
}

#[derive(Clone, Copy)]
struct ProbeOptions {
    duration: Duration,
    simulate_loss: bool,
}

pub fn probe(opts: ConnectOptions, seconds: u64, simulate_loss: bool) -> Result<ProbeReport> {
    let (_command_tx, rx) = mpsc::channel();
    let (tx, _events) = mpsc::channel();
    run_session(
        opts,
        &rx,
        &tx,
        &Arc::new(Mutex::new(None)),
        &(Arc::new(|| {}) as Arc<dyn Fn() + Send + Sync>),
        &AtomicBool::new(false),
        Some(ProbeOptions {
            duration: Duration::from_secs(seconds.clamp(5, 120)),
            simulate_loss,
        }),
    )
}

fn run_session(
    mut opts: ConnectOptions,
    commands: &Receiver<Command>,
    events: &Sender<Event>,
    latest: &Arc<Mutex<Option<RgbaFrame>>>,
    repaint: &Arc<dyn Fn() + Send + Sync>,
    cancelled: &AtomicBool,
    probe: Option<ProbeOptions>,
) -> Result<ProbeReport> {
    let limit = probe.map(|p| p.duration);
    if cancelled.load(Ordering::Acquire) {
        return Ok(ProbeReport::default());
    }
    // Check decoder availability before using a real account password.
    let mut decoder = HevcDecoder::new().context("Native HEVC decoder initialization failed")?;
    let mut connection = hp_protocol::HpConnection::connect(hp_protocol::ConnectOptions {
        host: std::mem::take(&mut opts.host),
        port: opts.port,
        username: std::mem::take(&mut opts.username),
        password: std::mem::take(&mut opts.password),
        width: opts.width,
        height: opts.height,
        fps: opts.fps,
    })?;
    // Negotiation is synchronous and uses protocol timeouts. Cancellation is
    // observed here after it returns; this is not immediate authentication abort.
    if cancelled.load(Ordering::Acquire) {
        return Ok(ProbeReport::default());
    }
    let width = connection.width as u32;
    let height = connection.height as u32;
    let tiles = connection
        .stream_config
        .as_ref()
        .map_or(1, |config| config.tile_count as usize);
    let mut compositor = Compositor::new(width, height, tiles)?;
    let mut receiver = SrtpReceiver::new(&connection.video_receive_key)?;
    let mut feedback = SrtcpSender::new(&connection.video_send_key)?;
    let mut heartbeat = SrtpSender::new(&connection.audio_send_key, connection.audio_ssrc)?;
    let mut depacketizer = Depacketizer::new(tiles);
    let mut report = ProbeReport {
        authenticated: true,
        width,
        height,
        ..Default::default()
    };
    let began = Instant::now();
    let mut last_feedback = began - Duration::from_secs(1);
    let mut last_latency = began - Duration::from_secs(1);
    let mut last_sender_report = began - Duration::from_secs(5);
    let mut last_fir = began - Duration::from_secs(3);
    let mut fir_sequence = 0u8;
    let mut last_frame = began;
    let mut last_video_packet = began;
    let mut dirty = false;
    let mut needs_keyframe = true;
    let mut generation = None;
    let mut loss_epoch = 0;
    let mut packet = [0u8; 65536];
    let mut connected = false;
    let mut loss_at = None;
    // Opt-in aggregate telemetry for authorized live validation, never media,
    // credentials, hostnames, usernames, keys or input contents.
    let diagnostics = std::env::var_os("MACVNC_DIAGNOSTICS_PATH").map(std::path::PathBuf::from);
    let mut last_diagnostics = began;
    loop {
        if cancelled.load(Ordering::Acquire) {
            report.elapsed_seconds = began.elapsed().as_secs_f64();
            return Ok(report);
        }
        for _ in 0..256 {
            match commands.try_recv() {
                Ok(Command::Disconnect) => {
                    report.elapsed_seconds = began.elapsed().as_secs_f64();
                    return Ok(report);
                }
                Ok(Command::Pointer { x, y, buttons }) => connection.send_pointer(buttons, x, y)?,
                Ok(Command::Key { keysym, down }) => connection.send_key(down, keysym)?,
                Ok(Command::Clipboard(text)) => connection.send_clipboard(&text)?,
                Ok(Command::Connect(_)) => (),
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => return Ok(report),
            }
        }
        connection.poll_control()?;
        // The control UDP pinhole is kept alive and its incoming datagrams drained.
        for _ in 0..256 {
            match connection.control_socket.recv(&mut packet) {
                Ok(_) => report.control_udp_packets += 1,
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) => return Err(e.into()),
            }
        }
        let mut units = Vec::new();
        for _ in 0..512 {
            match connection.video_socket.recv(&mut packet) {
                Ok(n) => {
                    report.udp_packets += 1;
                    if is_rtcp(&packet[..n]) {
                        continue;
                    }
                    if let Some(p) = receiver.unprotect(&packet[..n])? {
                        last_video_packet = Instant::now();
                        report.authenticated_packets += 1;
                        // Explicit diagnostic mode only: omit one authenticated
                        // middle FU fragment after playback has settled.
                        if probe.is_some_and(|p| p.simulate_loss)
                            && connected
                            && loss_at.is_none()
                            && began.elapsed() >= Duration::from_secs(15)
                            && p.payload.len() >= 3
                            && p.payload[0] >> 1 & 63 == 49
                            && p.payload[2] & 0xc0 == 0
                        {
                            loss_at = Some(Instant::now());
                            report.injected_packet_loss = 1;
                            continue;
                        }
                        units.extend(depacketizer.push(p, began.elapsed().as_millis() as u64));
                    } else {
                        report.rejected_packets += 1;
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) => return Err(e.into()),
            }
        }
        units.extend(depacketizer.poll(began.elapsed().as_millis() as u64));
        for au in units {
            if cancelled.load(Ordering::Acquire) {
                report.elapsed_seconds = began.elapsed().as_secs_f64();
                return Ok(report);
            }
            report.access_units += 1;
            if generation != Some(au.generation) || loss_epoch != au.loss_epoch {
                generation = Some(au.generation);
                loss_epoch = au.loss_epoch;
                needs_keyframe = true;
                dirty = false;
            }
            if needs_keyframe && !au.key {
                report.suppressed_pictures += 1;
                continue;
            }
            if needs_keyframe {
                // A new independently decodable picture starts a fresh reference
                // chain. Never feed new encoder generations into an old DPB.
                decoder = HevcDecoder::new()?;
                compositor = Compositor::new(width, height, tiles)?;
            }
            let decoded = decoder.decode(&au);
            let reference_errors = decoder.take_reference_errors();
            let log_errors = decoder.take_decode_errors();
            report.reference_errors += reference_errors;
            report.decoder_log_errors += log_errors;
            if decoded.is_err() || reference_errors > 0 || log_errors > 0 {
                report.decode_errors += u64::from(decoded.is_err());
                report.suppressed_pictures += 1;
                needs_keyframe = true;
                dirty = false;
                let _ = events.send(Event::Status(
                    "Recovering video… keeping the last good picture.".into(),
                ));
                repaint();
                continue;
            }
            match decoded {
                Ok(tiles) => {
                    if au.key && !tiles.is_empty() {
                        needs_keyframe = false;
                        if report.recovery_after_loss_seconds.is_none() {
                            report.recovery_after_loss_seconds =
                                loss_at.map(|at| at.elapsed().as_secs_f64());
                        }
                        if connected {
                            let _ = events.send(Event::Status("Connected · HP / HEVC".into()));
                        }
                    }
                    for tile in tiles {
                        report.decoded_tiles += 1;
                        report.decoded_width = tile.frame.width;
                        report.decoded_height = tile.frame.height;
                        if compositor.update(tile)? {
                            dirty = true;
                            last_frame = Instant::now();
                        }
                    }
                }
                Err(_) => unreachable!("decode errors handled before presentation"),
            }
        }
        // Loss after the last emitted picture must not be cleared by an earlier
        // keyframe in the same UDP batch. Stale duplicates do not change epochs.
        if loss_epoch != depacketizer.loss_epoch() {
            loss_epoch = depacketizer.loss_epoch();
            needs_keyframe = true;
            dirty = false;
        }
        if dirty && !needs_keyframe && !cancelled.load(Ordering::Acquire) {
            let frame = compositor.snapshot();
            report.composed_updates += 1;
            report.peak_frame_bytes = frame.pixels.len();
            // Publish once after the received batch. The replaceable slot drops
            // obsolete frames without a second timer that can halve presentation
            // rate when decode completion falls just before the timer deadline.
            *latest.lock().unwrap() = Some(frame);
            if !connected {
                connected = true;
                let _ = events.send(Event::Connected { width, height });
            }
            dirty = false;
            repaint();
        }
        if last_feedback.elapsed() >= Duration::from_millis(500) {
            let sources: Vec<_> = receiver
                .sources()
                .into_iter()
                .map(|s| (s, receiver.highest_sequence(s)))
                .collect();
            let mut rr = Vec::new();
            if last_sender_report.elapsed() >= Duration::from_secs(5) {
                rr.extend(build_empty_sr(
                    connection.video_ssrc,
                    SystemTime::now().duration_since(UNIX_EPOCH)?,
                ));
                last_sender_report = Instant::now();
            }
            rr.extend(build_rr(connection.video_ssrc, &sources));
            // AVConference receives all client reports on its control port.
            connection.control_socket.send(&feedback.protect(&rr)?)?;
            if last_fir.elapsed() >= Duration::from_secs(2)
                && (!connected || needs_keyframe || last_frame.elapsed() > Duration::from_secs(2))
            {
                let target = depacketizer.sources().first().copied().unwrap_or(0);
                let mut recovery = build_rr(connection.video_ssrc, &[]);
                recovery.extend(build_fir(connection.video_ssrc, target, fir_sequence));
                recovery.extend(build_pli(connection.video_ssrc, target));
                recovery.extend(build_fir_legacy(target));
                connection
                    .control_socket
                    .send(&feedback.protect(&recovery)?)?;
                fir_sequence = fir_sequence.wrapping_add(1);
                last_fir = Instant::now();
                report.recovery_requests += 1;
                if connected && needs_keyframe {
                    let _ = events.send(Event::Status(
                        if last_frame.elapsed() > Duration::from_secs(10) {
                            "Video recovery stalled · waiting for a new keyframe from the Mac"
                                .into()
                        } else {
                            "Recovering video… keeping the last good picture.".into()
                        },
                    ));
                    repaint();
                }
            }
            // Required even when audio playback is disabled.
            connection
                .control_socket
                .send(&heartbeat.audio_heartbeat()?)?;
            report.audio_heartbeats += 1;
            connection.control_socket.send(&[0])?;
            last_feedback = Instant::now();
        }
        if last_latency.elapsed() >= Duration::from_secs(1) {
            let rtt = connection.network_rtt();
            report.network_rtt_ms = rtt.map(|value| value.as_secs_f64() * 1000.0);
            let _ = events.send(Event::NetworkRtt(rtt));
            repaint();
            last_latency = Instant::now();
        }
        report.elapsed_seconds = began.elapsed().as_secs_f64();
        report.waiting_for_keyframe = needs_keyframe;
        report.last_good_picture_age_seconds = last_frame.elapsed().as_secs_f64();
        report.last_video_packet_age_seconds = last_video_packet.elapsed().as_secs_f64();
        if last_diagnostics.elapsed() >= Duration::from_secs(5) {
            if let Some(path) = &diagnostics {
                report.media_sources = receiver.sources().len();
                report.media_diagnostics = depacketizer.diagnostics();
                if let Ok(json) = serde_json::to_vec_pretty(&report) {
                    let temporary = path.with_extension("tmp");
                    if std::fs::write(&temporary, json).is_ok() {
                        let _ = std::fs::rename(temporary, path);
                    }
                }
            }
            last_diagnostics = Instant::now();
        }
        if limit.is_some_and(|limit| began.elapsed() >= limit) {
            report.media_sources = receiver.sources().len();
            report.media_diagnostics = depacketizer.diagnostics();
            return Ok(report);
        }
        if !connected && began.elapsed() > Duration::from_secs(25) {
            bail!("HP did not produce a complete screen (UDP {}, authenticated {}, access units {}, decoded tiles {}, errors {}).",report.udp_packets,report.authenticated_packets,report.access_units,report.decoded_tiles,report.decode_errors);
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn disconnect_cancels_even_when_input_queue_is_full() {
        let (sender, receiver) = mpsc::sync_channel(1);
        let cancelled = Arc::new(AtomicBool::new(false));
        let queue = CommandSender {
            sender,
            cancelled: cancelled.clone(),
        };
        assert!(queue
            .send(Command::Pointer {
                x: 1,
                y: 2,
                buttons: 0
            })
            .is_ok());
        assert!(queue.send(Command::Disconnect).is_err());
        assert!(cancelled.load(Ordering::Acquire));
        assert!(matches!(receiver.try_recv(), Ok(Command::Pointer { .. })));
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
    }
    #[test]
    fn lost_key_release_cancels_instead_of_latching_remote_keys() {
        let (sender, _receiver) = mpsc::sync_channel(1);
        let cancelled = Arc::new(AtomicBool::new(false));
        let queue = CommandSender {
            sender,
            cancelled: cancelled.clone(),
        };
        assert!(queue
            .send(Command::Key {
                keysym: 65,
                down: true
            })
            .is_ok());
        assert!(queue
            .send(Command::Key {
                keysym: 65,
                down: false
            })
            .is_err());
        assert!(cancelled.load(Ordering::Acquire));
    }
    #[test]
    fn dropping_ui_cancels_negotiation_when_it_next_yields() {
        let (sender, _receiver) = mpsc::sync_channel(1);
        let cancelled = Arc::new(AtomicBool::new(false));
        drop(CommandSender {
            sender,
            cancelled: cancelled.clone(),
        });
        assert!(cancelled.load(Ordering::Acquire));
    }
}
