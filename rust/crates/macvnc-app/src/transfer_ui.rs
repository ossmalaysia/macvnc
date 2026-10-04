use crate::transfer::{Client, Request};
use eframe::egui;
use std::{path::PathBuf, time::Duration};

#[derive(Default)]
pub struct Files {
    pub open: bool,
    local_source: String,
    remote_directory: String,
    remote_source: String,
    local_destination: String,
    allow_replace: bool,
    error: String,
}
impl Files {
    pub fn session_ended(&mut self) {
        self.allow_replace = false;
    }
    /// Returns true only for the explicit Cancel-and-disconnect action.
    pub fn show(&mut self, ctx: &egui::Context, client: &Client, connected: bool) -> bool {
        let snapshot = client.snapshot();
        if snapshot.busy {
            ctx.request_repaint_after(Duration::from_millis(50));
        }
        if !self.open {
            return false;
        }
        let mut open = self.open;
        let mut cancel = false;
        egui::Window::new("Files")
            .open(&mut open).default_width(520.0).resizable(true)
            .show(ctx, |ui| {
                ui.label("Copy files through this screen-sharing session.");
                ui.label(egui::RichText::new("Experimental · macOS compatibility has not been validated.").small().weak());
                if !connected { ui.label("Connect to the Mac to send or receive files."); }
                ui.separator();
                ui.add_enabled_ui(connected && !snapshot.busy, |ui| {
                    ui.strong("Send to Mac");
                    ui.label("Drop one file into this window, or enter its full local path.");
                    ui.text_edit_singleline(&mut self.local_source);
                    let dropped = ctx.input(|i| i.raw.dropped_files.clone());
                    if !dropped.is_empty() {
                        if dropped.len() == 1 {
                            match dropped[0].path.as_ref().and_then(|p| p.to_str()) {
                                Some(path) => { self.local_source = path.into(); self.error.clear(); },
                                None => self.error = "The dropped file has no usable local path.".into(),
                            }
                        } else { self.error = "Send one regular file at a time.".into(); }
                    }
                    ui.label("Destination folder on Mac (for example /Users/name/Downloads)");
                    ui.text_edit_singleline(&mut self.remote_directory);
                    ui.checkbox(&mut self.allow_replace, "Allow replacing a file with the same name on the Mac");
                    if ui.add_enabled(self.allow_replace && !self.local_source.is_empty() && !self.remote_directory.is_empty(), egui::Button::new("Send file")).clicked() {
                        self.submit(client, Request::Upload {
                            local: PathBuf::from(&self.local_source), remote_directory: self.remote_directory.clone(), allow_replace: self.allow_replace,
                        });
                    }
                    ui.separator();
                    ui.strong("Receive from Mac");
                    ui.label("Full file path on Mac");
                    ui.text_edit_singleline(&mut self.remote_source);
                    ui.label("Save as (full local file path; existing files are preserved)");
                    ui.text_edit_singleline(&mut self.local_destination);
                    if ui.add_enabled(!self.remote_source.is_empty() && !self.local_destination.is_empty(), egui::Button::new("Receive file")).clicked() {
                        self.submit(client, Request::Download { remote: self.remote_source.clone(), local: PathBuf::from(&self.local_destination) });
                    }
                });
                ui.separator();
                ui.label(&snapshot.status);
                if snapshot.busy {
                    if let Some(total) = snapshot.total {
                        let fraction = if total == 0 { 0.0 } else { (snapshot.bytes as f64 / total as f64).clamp(0.0, 1.0) as f32 };
                        ui.add(egui::ProgressBar::new(fraction).text(format!("{} / {} bytes", snapshot.bytes, total)));
                    } else { ui.spinner(); ui.label(format!("{} bytes", snapshot.bytes)); }
                    if ui.button("Cancel and disconnect").clicked() { cancel = true; }
                    ui.label(egui::RichText::new("Stopping a transfer closes the session. A partial file may remain on the Mac.").small().weak());
                }
                if !self.error.is_empty() { ui.colored_label(egui::Color32::LIGHT_RED, &self.error); }
                ui.label(egui::RichText::new("Regular files below 4 GiB. Folder and clipboard file transfers are not supported yet.").small().weak());
            });
        self.open = open;
        cancel
    }
    fn submit(&mut self, client: &Client, request: Request) {
        self.error = client
            .submit(request)
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
    }
}
