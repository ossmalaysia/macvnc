#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]
mod backend;
mod input;
mod profile;

use backend::{Backend, Command, ConnectOptions, Event};
use eframe::egui::{self, Color32, Key, TextureHandle};
use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::{Duration, Instant},
};
use zeroize::Zeroize;

const APP_NAME: &str = "MacVNC";
const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

struct App {
    backend: Backend,
    profile: profile::Profile,
    remember: bool,
    port: String,
    status: String,
    connected: bool,
    connecting: bool,
    texture: Option<TextureHandle>,
    size: [u32; 2],
    full_screen: bool,
    pressed: HashMap<Key, u32>,
    modifiers: Vec<u32>,
    buttons: u8,
    pointer: (u16, u16),
    presented: VecDeque<Instant>,
    network_rtt: Option<Duration>,
    /// When the OS estimate last changed. It only moves when the Mac ACKs data
    /// we sent, so an unchanged value means no new sample, not a steady link.
    rtt_changed: Instant,
    pending_frame: bool,
    started: Instant,
    smoke: bool,
    smoke_duration: Duration,
    cancelling: bool,
    auto_pending: bool,
    window_drag_anchor: [Option<egui::Pos2>; 2],
    clipboard: ClipboardSync,
    pending_paste: VecDeque<Command>,
}
impl App {
    fn new(
        cc: &eframe::CreationContext<'_>,
        smoke: bool,
        smoke_duration: Duration,
        no_autoconnect: bool,
    ) -> Self {
        cc.egui_ctx.set_visuals(egui::Visuals::dark());
        let mut style = (*cc.egui_ctx.style()).clone();
        style.spacing.item_spacing = egui::vec2(10.0, 10.0);
        cc.egui_ctx.set_style(style);
        let ctx = cc.egui_ctx.clone();
        let (profile, remember, status) = if smoke {
            (
                profile::Profile::default(),
                false,
                "Synthetic UI validation · no connection".into(),
            )
        } else {
            match profile::load() {
                Ok(Some(p)) => {
                    let message = if p.legacy_password {
                        "Confirm the saved Mac address, then Connect to upgrade secure storage."
                    } else if !p.enc.is_empty() && p.password.is_empty() {
                        "Saved password unavailable. Enter it to connect."
                    } else {
                        "Ready to connect"
                    };
                    (p, true, message.into())
                }
                Ok(None) => (
                    profile::Profile::default(),
                    false,
                    "Ready to connect".into(),
                ),
                Err(e) => (profile::Profile::default(), false, e),
            }
        };
        let auto_pending = profile.auto_connect && !smoke && !no_autoconnect;
        let port = profile.port.to_string();
        Self {
            backend: backend::start(Arc::new(move || ctx.request_repaint())),
            profile,
            remember,
            port,
            status,
            connected: false,
            connecting: false,
            texture: None,
            size: [0, 0],
            full_screen: false,
            pressed: HashMap::new(),
            modifiers: Vec::new(),
            buttons: 0,
            pointer: (0, 0),
            presented: VecDeque::new(),
            network_rtt: None,
            rtt_changed: Instant::now(),
            pending_frame: false,
            started: Instant::now(),
            smoke,
            smoke_duration,
            cancelling: false,
            auto_pending,
            window_drag_anchor: [None; 2],
            clipboard: ClipboardSync::default(),
            pending_paste: VecDeque::new(),
        }
    }
    fn send(&self, command: Command) {
        let _ = self.backend.commands.send(command);
    }
    fn connect(&mut self) {
        if self.connecting || self.connected || self.cancelling || self.smoke {
            return;
        }
        let port = match self.port.parse::<u16>() {
            Ok(p) if p > 0 => p,
            _ => {
                self.status = "Enter a port from 1 to 65535.".into();
                return;
            }
        };
        if self.profile.password.is_empty() && self.remember {
            if let Ok(Some(mut saved)) = profile::load() {
                if saved.host.trim() == self.profile.host.trim()
                    && saved.port == port
                    && saved.username == self.profile.username
                {
                    self.profile.password = std::mem::take(&mut saved.password);
                }
            }
        }
        if self.profile.host.trim().is_empty()
            || self.profile.username.is_empty()
            || self.profile.password.is_empty()
        {
            self.status = "Enter the Mac address, account name, and password.".into();
            return;
        }
        self.profile.port = port;
        if self.remember {
            if let Err(e) = profile::save(&self.profile) {
                self.status = e;
                return;
            }
        }
        self.presented.clear();
        self.network_rtt = None;
        self.texture = None;
        self.pending_frame = false;
        self.size = [0, 0];
        self.connecting = true;
        self.status = "Connecting with High Performance…".into();
        self.send(Command::Connect(ConnectOptions {
            host: self.profile.host.trim().into(),
            port,
            username: self.profile.username.clone(),
            password: self.profile.password.clone(),
            width: 1920,
            height: 1080,
            fps: 60,
        }));
        // Remember also preserves the masked form value for explicit reconnects.
        // Profile::drop and Forget still clear it; persistence remains DPAPI-only.
        if !self.remember {
            self.profile.password.zeroize();
        }
    }
    /// Feeds a queued paste to the backend a few commands at a time.
    ///
    /// The command channel holds 256 entries and treats a full queue as fatal:
    /// `CommandSender::send` cancels the session rather than risk a dropped key
    /// release latching a key down on the Mac. A paste is two commands per
    /// character, so handing the whole thing over in one frame would disconnect
    /// the session outright. Stay well inside the channel's capacity instead.
    fn drain_pending_paste(&mut self, ctx: &egui::Context) {
        if self.pending_paste.is_empty() {
            return;
        }
        // A queue that outlives its session would type the tail of the old
        // clipboard into whatever connects next. Commands never cross a session.
        if !self.connected {
            self.pending_paste.clear();
            return;
        }
        for command in self
            .pending_paste
            .drain(..PASTE_COMMANDS_PER_FRAME.min(self.pending_paste.len()))
            .collect::<Vec<_>>()
        {
            self.send(command);
        }
        ctx.request_repaint();
    }
    fn release_input(&mut self) {
        for (_, keysym) in self.pressed.drain() {
            let _ = self.backend.commands.send(Command::Key {
                keysym,
                down: false,
            });
        }
        for keysym in self.modifiers.drain(..) {
            let _ = self.backend.commands.send(Command::Key {
                keysym,
                down: false,
            });
        }
        if self.buttons != 0 {
            self.buttons = 0;
            self.send(Command::Pointer {
                x: self.pointer.0,
                y: self.pointer.1,
                buttons: 0,
            });
        }
    }
    fn upload(&mut self, ctx: &egui::Context, width: u32, height: u32, rgba: Vec<u8>) {
        if width == 0
            || height == 0
            || width > 16384
            || height > 16384
            || (width as usize)
                .checked_mul(height as usize)
                .and_then(|n| n.checked_mul(4))
                != Some(rgba.len())
        {
            self.status = "Rejected malformed framebuffer.".into();
            return;
        }
        let image =
            egui::ColorImage::from_rgba_unmultiplied([width as usize, height as usize], &rgba);
        if let Some(texture) = &mut self.texture {
            texture.set(image, egui::TextureOptions::LINEAR);
        } else {
            self.texture =
                Some(ctx.load_texture("remote-frame", image, egui::TextureOptions::LINEAR));
        }
        self.size = [width, height];
        self.pending_frame = true;
    }
    fn remote_input(&mut self, ctx: &egui::Context, response: &egui::Response) {
        if response.hovered()
            || response.clicked()
            || response.drag_started()
            || (response.hovered() && ctx.input(|i| i.pointer.any_pressed()))
        {
            response.request_focus();
        }
        // egui uses Tab for local focus traversal and can clear the canvas focus
        // before delivering the event. Keep capturing keyboard input while the
        // pointer is over the remote view so Tab reaches the Mac as 0xff09.
        if !ctx.input(|i| i.focused) || (!response.has_focus() && !response.hovered()) {
            self.release_input();
            return;
        }
        let events = ctx.input(|i| i.events.clone());
        // On some Windows backends the frame-level modifier snapshot can lag
        // one frame behind a physical Ctrl press. Prefer the modifier state
        // attached to the key event when it is available.
        let frame_modifiers = ctx.input(|i| i.modifiers);
        let event_modifiers = events.iter().rev().find_map(|event| match event {
            egui::Event::Key { modifiers, .. } => Some(*modifiers),
            _ => None,
        });
        let modifiers = event_modifiers.unwrap_or(frame_modifiers);
        let next = input::modifiers(modifiers, self.profile.profile == "native");
        // A paste in flight spans several frames. Re-pressing Ctrl mid-paste would
        // latch Command on the Mac and turn the remaining characters into
        // shortcuts, so leave the modifier state alone until the queue drains.
        // Whatever is still physically held is re-sent on the first frame after.
        // Only the modifier diff pauses: key releases and pointer events must keep
        // flowing, or a key held when the paste began would stay down on the Mac.
        if self.pending_paste.is_empty() {
            for keysym in &self.modifiers {
                if !next.contains(keysym) {
                    self.send(Command::Key {
                        keysym: *keysym,
                        down: false,
                    });
                }
            }
            for keysym in &next {
                if !self.modifiers.contains(keysym) {
                    self.send(Command::Key {
                        keysym: *keysym,
                        down: true,
                    });
                }
            }
            self.modifiers = next;
        }
        let composed_text = events
            .iter()
            .any(|event| matches!(event, egui::Event::Text(text) if !text.is_ascii()));
        for event in events {
            match event {
                egui::Event::PointerMoved(pos)
                    if response.rect.contains(pos) || self.buttons != 0 =>
                {
                    self.pointer = input::position(pos, response.rect, self.size);
                    self.send(Command::Pointer {
                        x: self.pointer.0,
                        y: self.pointer.1,
                        buttons: self.buttons,
                    });
                }
                egui::Event::PointerButton {
                    pos,
                    button,
                    pressed,
                    ..
                } if response.rect.contains(pos) || self.buttons != 0 => {
                    let bit = match button {
                        egui::PointerButton::Primary => 1,
                        egui::PointerButton::Middle => 2,
                        egui::PointerButton::Secondary => 4,
                        _ => 0,
                    };
                    if pressed {
                        self.buttons |= bit;
                    } else {
                        self.buttons &= !bit;
                    }
                    self.pointer = input::position(pos, response.rect, self.size);
                    self.send(Command::Pointer {
                        x: self.pointer.0,
                        y: self.pointer.1,
                        buttons: self.buttons,
                    });
                }
                egui::Event::MouseWheel { delta, .. } if response.hovered() => {
                    let bit = if delta.y > 0.0 {
                        8
                    } else if delta.y < 0.0 {
                        16
                    } else if delta.x > 0.0 {
                        32
                    } else {
                        64
                    };
                    self.send(Command::Pointer {
                        x: self.pointer.0,
                        y: self.pointer.1,
                        buttons: self.buttons | bit,
                    });
                    self.send(Command::Pointer {
                        x: self.pointer.0,
                        y: self.pointer.1,
                        buttons: self.buttons,
                    });
                }
                egui::Event::Key {
                    key,
                    pressed,
                    repeat,
                    modifiers,
                    ..
                } if key != Key::F11 => {
                    if pressed {
                        if let Some(keysym) = self
                            .pressed
                            .get(&key)
                            .copied()
                            .or_else(|| input::keysym(key, modifiers.shift))
                        {
                            // A composed character is sent by Text; do not also send its base key.
                            if composed_text && keysym < 0xff00 && !modifiers.ctrl && !modifiers.alt
                            {
                                continue;
                            }
                            if !repeat {
                                self.pressed.insert(key, keysym);
                            }
                            self.send(Command::Key { keysym, down: true });
                        }
                    } else if let Some(keysym) = self.pressed.remove(&key) {
                        self.send(Command::Key {
                            keysym,
                            down: false,
                        });
                    }
                }
                event @ (egui::Event::Copy | egui::Event::Cut | egui::Event::Paste(_)) => {
                    if self.clipboard.will_type(&event) {
                        // Ctrl is still physically held at this point and is
                        // latched as Command on the Mac. Drop it before typing;
                        // the next frame re-presses it if it is still down.
                        for keysym in std::mem::take(&mut self.modifiers) {
                            self.send(Command::Key {
                                keysym,
                                down: false,
                            });
                        }
                    }
                    // Typing a very large clipboard would hold the session for
                    // minutes, so it is capped. Say so rather than silently
                    // dropping the tail; the pasteboard record still has it.
                    if let egui::Event::Paste(text) = &event {
                        let total = text.chars().count();
                        if self.clipboard.will_type(&event) && total > MAX_TYPED_PASTE_CHARS {
                            self.status = format!(
                                "Typed the first {MAX_TYPED_PASTE_CHARS} of {total} characters · press ⌘V on the Mac for the rest"
                            );
                        }
                    }
                    self.pending_paste.extend(self.clipboard.commands(event));
                }
                egui::Event::Text(text) if !text.is_ascii() => {
                    for c in text.chars() {
                        let keysym = if c as u32 <= 255 {
                            c as u32
                        } else {
                            0x01000000 | c as u32
                        };
                        self.send(Command::Key { keysym, down: true });
                        self.send(Command::Key {
                            keysym,
                            down: false,
                        });
                    }
                }
                _ => (),
            }
        }
    }
}
// egui turns Ctrl/Cmd+C, +X and +V into semantic clipboard events and swallows
// the letter key, so the shortcut itself never reaches the Mac. Rebuild what the
// remote needs for each one.
//
// Paste has two distinct cases. Text copied *inside* the session already lives in
// the Mac's own pasteboard, so replaying Command-V is exactly right. Text copied on
// Windows is not on that pasteboard: Apple's HP control channel does not apply our
// cut-text record to it, so a Command-V there pastes nothing at all. Type those
// characters instead, which also carries Unicode the Latin-1 cut-text record could
// not represent.
/// Typing is one round trip per character; a very large paste would otherwise
/// flood the control channel and appear to hang the session.
const MAX_TYPED_PASTE_CHARS: usize = 8192;
/// Commands handed to the backend per frame while a paste drains. Must stay well
/// below the command channel's 256-entry capacity, which a paste would otherwise
/// overrun. Half the channel leaves room for the pointer and key events the user
/// generates alongside it, and enters roughly 3800 characters per second at 60fps.
const PASTE_COMMANDS_PER_FRAME: usize = 128;
/// Characters the cut-text record may carry. `send_clipboard` encodes one byte
/// per character into a record capped at 65498 bytes including its 8-byte header,
/// and returns an error beyond that which would disconnect the session.
const CLIPBOARD_RECORD_CHAR_LIMIT: usize = 65_000;
// A paste is two commands per character; a frame's worth must never fill the
// channel, because a full channel cancels the session instead of dropping input.
const _: () = assert!(PASTE_COMMANDS_PER_FRAME < backend::COMMAND_QUEUE_CAPACITY);
#[derive(Default)]
struct ClipboardSync {
    remote_owns: bool,
}
impl ClipboardSync {
    /// True when this event will be typed out, which requires the caller to
    /// release held modifiers first: typing while Command is latched on the Mac
    /// fires shortcuts (Command-S, Command-W, Command-Q) instead of entering text.
    fn will_type(&self, event: &egui::Event) -> bool {
        matches!(event, egui::Event::Paste(_)) && !self.remote_owns
    }
    fn commands(&mut self, event: egui::Event) -> Vec<Command> {
        match event {
            egui::Event::Copy => {
                self.remote_owns = true;
                tap(b'c')
            }
            egui::Event::Cut => {
                self.remote_owns = true;
                tap(b'x')
            }
            egui::Event::Paste(text) => {
                // Consume the flag unconditionally so a Mac-side copy latches it
                // for exactly one paste.
                if std::mem::take(&mut self.remote_owns) {
                    tap(b'v')
                } else {
                    typed(&text)
                }
            }
            _ => Vec::new(),
        }
    }
}
/// Maps text to the same keysym scheme the direct typing path uses. The cut-text
/// record still goes out first so a later native Command-V on the Mac can recover
/// text too long to type, but nothing depends on the Mac honouring it.
///
/// The two carry different amounts on purpose. Typing costs a round trip per
/// character, so it stops at `MAX_TYPED_PASTE_CHARS`; the record is one message
/// and only has to stay under the protocol's limit, which `send_clipboard`
/// enforces by returning an error the session loop would turn into a disconnect.
fn typed(text: &str) -> Vec<Command> {
    let pasteboard: String = text.chars().take(CLIPBOARD_RECORD_CHAR_LIMIT).collect();
    let mut commands = vec![Command::Clipboard(pasteboard)];
    for c in text.chars().take(MAX_TYPED_PASTE_CHARS) {
        let keysym = match c {
            '\n' | '\r' => 0xff0d,
            '\t' => 0xff09,
            c if (c as u32) <= 0xff => c as u32,
            c => 0x01000000 | c as u32,
        };
        commands.push(Command::Key { keysym, down: true });
        commands.push(Command::Key {
            keysym,
            down: false,
        });
    }
    commands
}
/// Toolbar text for the network RTT. `unchanged_for` is how long the OS
/// estimate has held the same value; past a threshold it is an old sample
/// (for example a spike from a busy moment) rather than the current latency.
fn rtt_label(rtt: Option<Duration>, unchanged_for: Duration) -> String {
    let Some(rtt) = rtt else {
        return "RTT —".into();
    };
    let ms = rtt.as_secs_f64() * 1000.0;
    // A few 1-second reads with no change means no input has been ACKed since.
    if unchanged_for >= RTT_STALE_AFTER {
        format!("RTT {ms:.1} ms (stale)")
    } else {
        format!("RTT {ms:.1} ms")
    }
}
const RTT_STALE_AFTER: Duration = Duration::from_secs(5);
fn tap(letter: u8) -> Vec<Command> {
    vec![
        Command::Key {
            keysym: letter as u32,
            down: true,
        },
        Command::Key {
            keysym: letter as u32,
            down: false,
        },
    ]
}
impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.auto_pending {
            self.auto_pending = false;
            self.connect();
        }
        // Runs before the UI so a paste keeps draining even if the pointer leaves
        // the remote view part-way through.
        self.drain_pending_paste(ctx);
        let mut latest = None;
        while let Ok(event) = self.backend.events.try_recv() {
            match event {
                Event::Status(s) => self.status = s,
                Event::NetworkRtt(rtt) => {
                    if rtt != self.network_rtt {
                        self.rtt_changed = Instant::now();
                    }
                    self.network_rtt = rtt;
                }
                Event::Connected { width, height } => {
                    if self.cancelling {
                        continue;
                    }
                    self.connected = true;
                    self.connecting = false;
                    self.size = [width, height];
                    self.status = "Connected · HP / HEVC".into();
                }
                Event::Disconnected(reason) => {
                    self.network_rtt = None;
                    self.release_input();
                    self.connected = false;
                    self.connecting = false;
                    self.cancelling = false;
                    self.status = reason;
                    self.presented.clear();
                    self.texture = None;
                    self.size = [0, 0];
                    self.pending_frame = false;
                    latest = None;
                }
            }
        }
        // A frame can race the Disconnected event; never revive a closed/cancelled view.
        if self.cancelling {
            *self.backend.latest.lock().unwrap() = None;
        } else if self.connected {
            if let Some(frame) = self.backend.latest.lock().unwrap().take() {
                latest = Some((frame.width, frame.height, frame.pixels));
            }
        }
        if self.smoke && self.started.elapsed() < self.smoke_duration {
            let phase = (self.started.elapsed().as_millis() / 16) as u8;
            let mut rgba = vec![0; 640 * 360 * 4];
            for (i, p) in rgba.as_chunks_mut::<4>().0.iter_mut().enumerate() {
                p.copy_from_slice(&[((i % 640) / 3) as u8, ((i / 640) / 2) as u8, phase, 255]);
            }
            latest = Some((640, 360, rgba));
            ctx.request_repaint();
        }
        if let Some((w, h, rgba)) = latest {
            self.upload(ctx, w, h, rgba);
        }
        if ctx.input(|i| i.key_pressed(Key::F11)) {
            self.full_screen = !self.full_screen;
            ctx.send_viewport_cmd(egui::ViewportCommand::Fullscreen(self.full_screen));
        }
        let now = Instant::now();
        while self
            .presented
            .front()
            .is_some_and(|t| now.duration_since(*t) > Duration::from_secs(1))
        {
            self.presented.pop_front();
        }
        egui::TopBottomPanel::top("toolbar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.set_min_height(32.0);
                let brand = ui
                    .horizontal(|ui| {
                        ui.heading(APP_NAME);
                        ui.label(
                            egui::RichText::new(format!("v{APP_VERSION}"))
                                .small()
                                .weak(),
                        );
                        ui.label(
                            egui::RichText::new("HIGH PERFORMANCE")
                                .small()
                                .color(Color32::from_rgb(118, 202, 182)),
                        );
                    })
                    .response
                    .interact(egui::Sense::click_and_drag());
                window_drag(
                    ctx,
                    &brand,
                    self.full_screen,
                    &mut self.window_drag_anchor[0],
                );
                ui.separator();
                ui.label(format!("{} fps", self.presented.len()));
                ui.label(rtt_label(self.network_rtt, self.rtt_changed.elapsed()))
                .on_hover_text("Network latency: the OS-estimated TCP round-trip time, read every second. It only updates when the Mac acknowledges input you send, so it is marked stale while you are idle; move the mouse to refresh it. Excludes video decoding and display delay. — means unavailable.");
                if (self.connected || self.connecting)
                    && ui
                        .add_enabled(
                            !self.cancelling,
                            egui::Button::new(if self.cancelling {
                                "Disconnecting…"
                            } else {
                                "Disconnect"
                            }),
                        )
                        .clicked()
                {
                    self.release_input();
                    self.send(Command::Disconnect);
                    self.cancelling = true;
                    self.status =
                        "Disconnecting… negotiation may need to reach its timeout.".into();
                }
                if ui
                    .button(if self.full_screen {
                        "Exit fullscreen"
                    } else {
                        "Fullscreen · F11"
                    })
                    .clicked()
                {
                    self.full_screen = !self.full_screen;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Fullscreen(self.full_screen));
                }
                let space = ui.allocate_response(
                    egui::vec2(ui.available_width(), 32.0),
                    egui::Sense::click_and_drag(),
                );
                window_drag(
                    ctx,
                    &space,
                    self.full_screen,
                    &mut self.window_drag_anchor[1],
                );
            });
        });
        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(&self.status);
                if self.size[0] > 0 {
                    ui.separator();
                    ui.label(format!("{} × {}", self.size[0], self.size[1]));
                }
                ui.separator();
                ui.hyperlink_to("Developed by AnchorSprint", "https://anchorsprint.com");
            });
        });
        egui::CentralPanel::default().show(ctx, |ui| {
            if let Some(texture) = &self.texture {
                let avail = ui.available_size();
                let native = egui::vec2(self.size[0] as f32, self.size[1] as f32);
                let scale = (avail.x / native.x).min(avail.y / native.y);
                let size = native * scale;
                let (_, rect) = ui.allocate_space(avail);
                let image_rect = egui::Rect::from_center_size(rect.center(), size);
                let response = ui.put(
                    image_rect,
                    egui::Image::new((texture.id(), size)).sense(egui::Sense::click_and_drag()),
                );
                if self.pending_frame {
                    self.presented.push_back(now);
                    self.pending_frame = false;
                }
                if self.connected && !self.cancelling {
                    self.remote_input(ctx, &response);
                }
            } else {
                ui.vertical_centered(|ui| {
                    ui.add_space(38.0);
                    ui.label(
                        egui::RichText::new("MACVNC")
                            .size(13.0)
                            .strong()
                            .color(Color32::from_rgb(93, 205, 181)),
                    );
                    ui.add_space(8.0);
                    ui.heading("Connect to your Mac");
                    ui.label(
                        egui::RichText::new("Secure, high-performance screen sharing")
                            .color(Color32::from_gray(165)),
                    );
                    ui.add_space(24.0);
                    egui::Frame::group(ui.style()).show(ui, |ui| {
                        ui.set_width(430.0);
                        ui.vertical(|ui| {
                            ui.add_enabled_ui(!self.connecting, |ui| {
                                ui.label(
                                    egui::RichText::new("CONNECTION DETAILS")
                                        .small()
                                        .strong()
                                        .color(Color32::from_gray(145)),
                                );
                                ui.add_space(10.0);
                                ui.label("Mac address");
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.profile.host)
                                        .hint_text("192.168.1.10 or hostname")
                                        .desired_width(f32::INFINITY),
                                );
                                ui.add_space(10.0);
                                ui.horizontal(|ui| {
                                    ui.vertical(|ui| {
                                        ui.label("Port");
                                        ui.add(
                                            egui::TextEdit::singleline(&mut self.port)
                                                .desired_width(95.0),
                                        );
                                    });
                                    ui.add_space(16.0);
                                    ui.vertical(|ui| {
                                        ui.label("Account name");
                                        ui.add(
                                            egui::TextEdit::singleline(&mut self.profile.username)
                                                .desired_width(305.0),
                                        );
                                    });
                                });
                                ui.add_space(10.0);
                                ui.label("Password");
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.profile.password)
                                        .password(true)
                                        .desired_width(f32::INFINITY),
                                );
                                ui.add_space(10.0);
                                ui.horizontal(|ui| {
                                        ui.label("Shortcuts");
                                        egui::ComboBox::from_id_salt("keyboard-profile")
                                        .selected_text(if self.profile.profile == "native" {
                                            "Ctrl → Control"
                                        } else {
                                            "Ctrl → Command"
                                        })
                                        .show_ui(ui, |ui| {
                                            ui.selectable_value(
                                                &mut self.profile.profile,
                                                "ctrl-as-cmd".into(),
                                                "Ctrl → Command",
                                            );
                                            ui.selectable_value(
                                                &mut self.profile.profile,
                                                "native".into(),
                                                "Ctrl → Control",
                                            );
                                        });
                                });
                                ui.label(
                                    egui::RichText::new(
                                        "Use Ctrl → Control for Control-based Mac shortcuts; Ctrl → Command maps Windows Ctrl to ⌘.",
                                    )
                                    .small()
                                    .weak(),
                                );
                                ui.add_space(14.0);
                                ui.checkbox(&mut self.remember, "Remember securely");
                                ui.add_enabled(
                                    self.remember,
                                    egui::Checkbox::new(
                                        &mut self.profile.auto_connect,
                                        "Connect on launch",
                                    ),
                                );
                                if !self.remember {
                                    self.profile.auto_connect = false;
                                }
                                ui.add_space(16.0);
                                if ui
                                    .add_sized(
                                        [ui.available_width(), 42.0],
                                        egui::Button::new(
                                            egui::RichText::new("Connect securely").strong(),
                                        ),
                                    )
                                    .clicked()
                                {
                                    self.connect();
                                }
                                ui.add_space(8.0);
                                if ui.small_button("Forget saved connection").clicked() {
                                    match profile::forget() {
                                        Ok(()) => {
                                            self.profile.password.zeroize();
                                            self.profile = profile::Profile::default();
                                            self.port = "5900".into();
                                            self.remember = false;
                                            self.status = "Saved connection cleared.".into();
                                        }
                                        Err(e) => self.status = e,
                                    }
                                }
                            });
                        });
                    });
                    ui.add_space(16.0);
                    ui.label(
                        egui::RichText::new(
                            "HP mode is experimental · encrypted transport · HEVC video",
                        )
                        .small()
                        .weak(),
                    );
                });
            }
        });
        ctx.request_repaint_after(Duration::from_millis(100));
        if self.smoke && self.started.elapsed() > self.smoke_duration {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
    }
    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.release_input();
        self.send(Command::Disconnect);
        self.profile.password.zeroize();
    }
}
fn main() -> eframe::Result {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|arg| arg == "--live-smoke") {
        let result = live_smoke(&args);
        if let Err(error) = result {
            eprintln!("Live HP validation failed: {error:#}");
            std::process::exit(1);
        }
        return Ok(());
    }
    let smoke = args.iter().any(|arg| arg == "--smoke-ui");
    let smoke_seconds = option_value(&args, "--smoke-ui-seconds")
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(3)
        .clamp(1, 3600);
    let no_autoconnect = args.iter().any(|arg| arg == "--no-autoconnect");
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_decorations(true)
            .with_resizable(true)
            .with_icon(
                eframe::icon_data::from_png_bytes(include_bytes!("../assets/macvnc.png"))
                    .expect("embedded MacVNC icon"),
            )
            .with_inner_size([1120.0, 760.0])
            .with_min_inner_size([700.0, 500.0]),
        vsync: true,
        ..Default::default()
    };
    eframe::run_native(
        &format!("{APP_NAME} v{APP_VERSION}"),
        options,
        Box::new(move |cc| {
            Ok(Box::new(App::new(
                cc,
                smoke,
                Duration::from_secs(smoke_seconds),
                no_autoconnect,
            )))
        }),
    )
}

fn window_drag(
    ctx: &egui::Context,
    response: &egui::Response,
    fullscreen: bool,
    anchor: &mut Option<egui::Pos2>,
) {
    if fullscreen || !ctx.input(|i| i.focused) {
        *anchor = None;
        return;
    }
    response
        .clone()
        .on_hover_text("Drag to move · double-click to maximize")
        .on_hover_cursor(egui::CursorIcon::Grab);
    if response.double_clicked() {
        *anchor = None;
        let maximized = ctx.input(|i| i.viewport().maximized.unwrap_or(false));
        ctx.send_viewport_cmd(egui::ViewportCommand::Maximized(!maximized));
        return;
    }
    // Events can be delivered after release, too late for OS StartDrag.
    let (events, origin) =
        ctx.input(|i| (i.events.clone(), i.viewport().outer_rect.map(|r| r.min)));
    let mut delta = None;
    for event in events {
        match event {
            egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed: true,
                ..
            } if response.rect.contains(pos) => *anchor = Some(pos),
            egui::Event::PointerMoved(pos) => {
                if let Some(start) = *anchor {
                    delta = Some(pos - start);
                }
            }
            egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed: false,
                ..
            } => {
                if let Some(start) = anchor.take() {
                    delta = Some(pos - start);
                }
            }
            _ => {}
        }
    }
    if let (Some(origin), Some(delta)) = (origin, delta) {
        ctx.send_viewport_cmd(egui::ViewportCommand::OuterPosition(origin + delta));
    }
}

fn option_value<'a>(args: &'a [String], option: &str) -> Option<&'a str> {
    args.iter()
        .position(|arg| arg == option)
        .and_then(|index| args.get(index + 1))
        .filter(|value| !value.starts_with("--"))
        .map(String::as_str)
}

fn live_smoke(args: &[String]) -> anyhow::Result<()> {
    use anyhow::{bail, Context};
    let seconds = option_value(args, "--live-smoke")
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(15)
        .clamp(5, 120);
    let mut saved = profile::load()
        .map_err(anyhow::Error::msg)?
        .context("No saved app profile is available")?;
    if saved.host.is_empty() || saved.username.is_empty() || saved.password.is_empty() {
        bail!("Saved credentials are unavailable; no connection attempted");
    }
    let report = backend::probe(
        ConnectOptions {
            host: std::mem::take(&mut saved.host),
            port: saved.port,
            username: std::mem::take(&mut saved.username),
            password: std::mem::take(&mut saved.password),
            width: 1920,
            height: 1080,
            fps: 60,
        },
        seconds,
        args.iter().any(|arg| arg == "--simulate-video-loss"),
        args.iter().any(|arg| arg == "--wake-display-probe"),
    )?;
    let json = serde_json::to_string_pretty(&report)?;
    if let Some(path) = option_value(args, "--report") {
        std::fs::write(path, &json).context("Could not write aggregate validation report")?;
    }
    println!("{json}");
    if report.composed_updates == 0 {
        bail!("Authenticated session did not produce a composed screen");
    }
    if report.waiting_for_keyframe {
        bail!("Live session ended with video recovery still pending");
    }
    if args.iter().any(|arg| arg == "--simulate-video-loss")
        && (report.injected_packet_loss != 1
            || report.recovery_after_loss_seconds.is_none()
            || report.waiting_for_keyframe)
    {
        bail!("Video loss recovery was not demonstrated");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn describe(commands: &[Command]) -> Vec<String> {
        commands
            .iter()
            .map(|command| match command {
                Command::Clipboard(text) => format!("clipboard:{text}"),
                Command::Key { keysym, down } => format!("key:{keysym}:{down}"),
                _ => "other".to_string(),
            })
            .collect()
    }
    fn paste(sync: &mut ClipboardSync, local: &str) -> Vec<String> {
        describe(&sync.commands(egui::Event::Paste(local.to_string())))
    }
    const V_DOWN: &str = "key:118:true";
    const V_UP: &str = "key:118:false";
    #[test]
    fn paste_types_the_local_text_instead_of_relying_on_the_remote_pasteboard() {
        // Apple's HP control channel does not apply our cut-text record to the
        // Mac pasteboard, so a synthesized Command-V pastes nothing. Send the
        // characters themselves instead.
        let mut sync = ClipboardSync::default();
        assert_eq!(
            paste(&mut sync, "hi"),
            [
                "clipboard:hi",
                "key:104:true",
                "key:104:false",
                "key:105:true",
                "key:105:false"
            ],
            "each character must be typed as its own key press"
        );
    }
    #[test]
    fn rtt_label_marks_unchanged_estimate_stale() {
        let rtt = Some(Duration::from_micros(12_345));
        assert_eq!(rtt_label(None, Duration::ZERO), "RTT —");
        let fresh = rtt_label(rtt, Duration::ZERO);
        assert!(fresh.contains("12.3 ms"), "{fresh}");
        assert!(!fresh.contains("stale"), "{fresh}");
        let old = rtt_label(rtt, Duration::from_secs(60));
        assert!(old.contains("12.3 ms"), "{old}");
        assert!(old.contains("stale"), "{old}");
    }
    #[test]
    fn typed_paste_maps_non_latin1_characters_to_unicode_keysyms() {
        // The old cut-text path flattened anything above U+00FF to '?'.
        let mut sync = ClipboardSync::default();
        assert_eq!(
            paste(&mut sync, "\u{4e2d}"),
            [
                "clipboard:\u{4e2d}",
                "key:16797229:true",
                "key:16797229:false"
            ]
        );
    }
    #[test]
    fn typed_paste_sends_newlines_as_return() {
        let mut sync = ClipboardSync::default();
        assert_eq!(
            paste(&mut sync, "\n"),
            ["clipboard:\n", "key:65293:true", "key:65293:false"]
        );
    }
    #[test]
    fn oversized_paste_is_truncated_rather_than_flooding_the_remote() {
        let mut sync = ClipboardSync::default();
        let commands = paste(&mut sync, &"a".repeat(MAX_TYPED_PASTE_CHARS + 500));
        assert_eq!(
            commands.len(),
            MAX_TYPED_PASTE_CHARS * 2 + 1,
            "the cut-text record plus a press and release per capped character"
        );
    }
    #[test]
    fn oversized_paste_still_puts_the_whole_text_on_the_mac_pasteboard() {
        // Typing is capped because it costs a round trip per character, but the
        // record is one message: it should carry everything that fits so a native
        // Command-V on the Mac recovers the part we did not type.
        let mut sync = ClipboardSync::default();
        let text = "a".repeat(MAX_TYPED_PASTE_CHARS + 500);
        let commands = sync.commands(egui::Event::Paste(text));
        match &commands[0] {
            Command::Clipboard(sent) => assert_eq!(
                sent.chars().count(),
                MAX_TYPED_PASTE_CHARS + 500,
                "the record is not limited by the typing cap"
            ),
            _ => panic!("the pasteboard record must come first"),
        }
    }
    #[test]
    fn the_pasteboard_record_stays_inside_the_protocol_limit() {
        let mut sync = ClipboardSync::default();
        let text = "a".repeat(CLIPBOARD_RECORD_CHAR_LIMIT * 2);
        let commands = sync.commands(egui::Event::Paste(text));
        match &commands[0] {
            // One byte per character plus an 8-byte header must stay under the
            // 65498-byte record limit send_clipboard rejects beyond.
            Command::Clipboard(sent) => assert!(sent.len() + 8 <= 65498),
            _ => panic!("the pasteboard record must come first"),
        }
    }
    #[test]
    fn copy_and_cut_replay_their_letter_without_touching_the_pasteboard() {
        let mut sync = ClipboardSync::default();
        assert_eq!(
            describe(&sync.commands(egui::Event::Copy)),
            ["key:99:true", "key:99:false"]
        );
        assert_eq!(
            describe(&sync.commands(egui::Event::Cut)),
            ["key:120:true", "key:120:false"]
        );
    }
    #[test]
    fn paste_after_copying_on_the_mac_never_clobbers_the_remote_pasteboard() {
        // The regression this guards: egui hands us stale local text on the
        // first paste, which would otherwise overwrite what was just copied
        // inside the session.
        let mut sync = ClipboardSync::default();
        sync.commands(egui::Event::Copy);
        assert_eq!(paste(&mut sync, "stale windows text"), [V_DOWN, V_UP]);
    }
    #[test]
    fn repeated_local_pastes_each_type_their_text() {
        // Unlike the pasteboard path, typing has nothing to deduplicate: the
        // same text pasted twice must be entered twice.
        let mut sync = ClipboardSync::default();
        let expected = [
            "clipboard:hi",
            "key:104:true",
            "key:104:false",
            "key:105:true",
            "key:105:false",
        ];
        assert_eq!(paste(&mut sync, "hi"), expected);
        assert_eq!(paste(&mut sync, "hi"), expected);
    }
    #[test]
    fn a_mac_side_copy_latches_command_v_for_exactly_one_paste() {
        let mut sync = ClipboardSync::default();
        sync.commands(egui::Event::Copy);
        assert_eq!(
            paste(&mut sync, "windows text"),
            [V_DOWN, V_UP],
            "the paste right after a Mac-side copy must use the Mac's own pasteboard"
        );
        assert_eq!(
            paste(&mut sync, "hi"),
            [
                "clipboard:hi",
                "key:104:true",
                "key:104:false",
                "key:105:true",
                "key:105:false"
            ],
            "the following paste reverts to typing the Windows clipboard"
        );
    }
    #[test]
    fn will_type_reports_when_modifiers_must_be_released_first() {
        let mut sync = ClipboardSync::default();
        assert!(sync.will_type(&egui::Event::Paste("hi".into())));
        assert!(!sync.will_type(&egui::Event::Copy));
        sync.commands(egui::Event::Copy);
        assert!(
            !sync.will_type(&egui::Event::Paste("hi".into())),
            "a Command-V replay keeps the modifier held"
        );
    }
}
