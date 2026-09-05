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
    pending_frame: bool,
    started: Instant,
    smoke: bool,
    smoke_duration: Duration,
    cancelling: bool,
    auto_pending: bool,
    window_drag_anchor: [Option<egui::Pos2>; 2],
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
            pending_frame: false,
            started: Instant::now(),
            smoke,
            smoke_duration,
            cancelling: false,
            auto_pending,
            window_drag_anchor: [None; 2],
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
        if response.clicked()
            || response.drag_started()
            || (response.hovered() && ctx.input(|i| i.pointer.any_pressed()))
        {
            response.request_focus();
        }
        if !ctx.input(|i| i.focused) || !response.has_focus() {
            self.release_input();
            return;
        }
        let next = input::modifiers(ctx.input(|i| i.modifiers), self.profile.profile == "native");
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
        let events = ctx.input(|i| i.events.clone());
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
                egui::Event::Paste(text) => self.send(Command::Clipboard(text)),
                _ => (),
            }
        }
    }
}
impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.auto_pending {
            self.auto_pending = false;
            self.connect();
        }
        let mut latest = None;
        while let Ok(event) = self.backend.events.try_recv() {
            match event {
                Event::Status(s) => self.status = s,
                Event::NetworkRtt(rtt) => self.network_rtt = rtt,
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
                ui.label(self.network_rtt.map_or_else(
                    || "RTT —".into(),
                    |rtt| format!("RTT {:.1} ms", rtt.as_secs_f64() * 1000.0),
                ))
                .on_hover_text("Network latency: the OS-estimated TCP round-trip time, read every second. The estimate may stay unchanged while idle. Excludes video decoding and display delay. — means unavailable.");
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
        egui::CentralPanel::default().show(ctx,|ui| {
            if let Some(texture)=&self.texture {
                let avail=ui.available_size();let native=egui::vec2(self.size[0] as f32,self.size[1] as f32);let scale=(avail.x/native.x).min(avail.y/native.y);let size=native*scale;
                let (_,rect)=ui.allocate_space(avail);let image_rect=egui::Rect::from_center_size(rect.center(),size);
                let response=ui.put(image_rect,egui::Image::new((texture.id(),size)).sense(egui::Sense::click_and_drag()));
                if self.pending_frame {self.presented.push_back(now);self.pending_frame=false;}
                if self.connected && !self.cancelling {self.remote_input(ctx,&response);}
            } else {ui.vertical_centered(|ui| {
                ui.add_space(45.0);ui.heading("Connect to your Mac");ui.label("Native encrypted HP transport and HEVC playback");ui.add_space(18.0);
                ui.add_enabled_ui(!self.connecting,|ui| {egui::Grid::new("connection").num_columns(2).spacing([16.0,14.0]).show(ui,|ui| {
                    ui.label("Mac address");ui.add(egui::TextEdit::singleline(&mut self.profile.host).hint_text("IP address or hostname").desired_width(290.0));ui.end_row();
                    ui.label("Port");ui.add(egui::TextEdit::singleline(&mut self.port).desired_width(290.0));ui.end_row();
                    ui.label("Account name");ui.add(egui::TextEdit::singleline(&mut self.profile.username).desired_width(290.0));ui.end_row();
                    ui.label("Password");ui.add(egui::TextEdit::singleline(&mut self.profile.password).password(true).desired_width(290.0));ui.end_row();
                    ui.label("Keyboard");egui::ComboBox::from_id_salt("keyboard-profile").selected_text(if self.profile.profile=="native" {"Native"} else {"Ctrl → Command"}).show_ui(ui,|ui|{ui.selectable_value(&mut self.profile.profile,"ctrl-as-cmd".into(),"Ctrl → Command");ui.selectable_value(&mut self.profile.profile,"native".into(),"Native");});ui.end_row();
                });ui.add_space(12.0);ui.horizontal(|ui| {
                    ui.checkbox(&mut self.remember,"Remember securely");ui.add_enabled(self.remember,egui::Checkbox::new(&mut self.profile.auto_connect,"Connect on launch"));
                    if !self.remember {self.profile.auto_connect=false;}
                });ui.add_space(10.0);if ui.add_sized([290.0,38.0],egui::Button::new("Connect with HP")).clicked(){self.connect();}
                if ui.small_button("Forget saved connection").clicked(){match profile::forget(){Ok(())=>{self.profile.password.zeroize();self.profile=profile::Profile::default();self.port="5900".into();self.remember=false;self.status="Saved Rust connection cleared.".into();},Err(e)=>self.status=e}}
                });
                ui.add_space(18.0);ui.label(egui::RichText::new("HP is experimental. Frame assembly and compatibility are under active development.").small().weak());
            });}
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
