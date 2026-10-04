use super::{State, Updater};
use eframe::egui;
use std::time::Duration;

impl Updater {
    pub fn button_label(&self) -> String {
        match self.state() {
            State::Available(r) => format!("Update · v{}", r.version),
            State::Downloading { .. } | State::Restarting => "Updating…".into(),
            _ => "Updates".into(),
        }
    }
    pub fn show(&mut self, ctx: &egui::Context, file_busy: bool, connected: bool) {
        self.tick();
        if !self.open {
            return;
        }
        let state = self.state();
        if state.busy() {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
        let mut open = self.open;
        egui::Window::new("MacVNC updates")
            .open(&mut open)
            .default_width(480.0)
            .show(ctx, |ui| {
                ui.label(format!("Installed version: v{}", env!("CARGO_PKG_VERSION")));
                match state {
                    State::Idle => {
                        ui.label("Check for the latest stable Windows release.");
                    }
                    State::Checking => {
                        ui.horizontal(|ui| {
                            ui.spinner();
                            ui.label("Checking for updates…");
                        });
                    }
                    State::Current => {
                        ui.label("No newer stable release is available.");
                    }
                    State::Available(ref release) => {
                        ui.heading(format!("v{} is available", release.version));
                        ui.hyperlink_to("View release on GitHub", &release.page);
                        if !release.notes.is_empty() {
                            ui.collapsing("What's new", |ui| {
                                egui::ScrollArea::vertical()
                                    .max_height(200.0)
                                    .show(ui, |ui| {
                                        ui.label(&release.notes);
                                    });
                            });
                        }
                        ui.separator();
                        ui.label("Download → close MacVNC → install → restart");
                        ui.label("MacVNC stays open until the download is verified.");
                        ui.label("Your saved connection is kept.");
                        if connected {
                            ui.label("Your Mac session will disconnect when installation begins.");
                        }
                        if file_busy {
                            ui.label("Finish or cancel the file transfer before updating.");
                        }
                        if ui
                            .add_enabled(
                                self.install_error.is_none() && !file_busy,
                                egui::Button::new("Download and restart"),
                            )
                            .clicked()
                        {
                            self.download(release.clone());
                        }
                    }
                    State::Downloading {
                        version,
                        bytes,
                        total,
                        detail,
                    } => {
                        ui.heading(format!("Updating to v{version}"));
                        ui.label(detail);
                        let fraction = if total == 0 {
                            0.0
                        } else {
                            (bytes as f64 / total as f64).clamp(0.0, 1.0) as f32
                        };
                        ui.add(egui::ProgressBar::new(fraction).text(format!(
                            "{:.1} / {:.1} MB",
                            bytes as f64 / 1048576.0,
                            total as f64 / 1048576.0,
                        )));
                        if ui.button("Cancel download").clicked() {
                            self.cancel();
                        }
                        if self
                            .shared
                            .lock()
                            .unwrap()
                            .cancelled
                            .load(std::sync::atomic::Ordering::Acquire)
                        {
                            ui.label("Cancelling download…");
                        }
                    }
                    State::Restarting => {
                        ui.spinner();
                        ui.label("Closing MacVNC to install the update.");
                        ui.label("It will restart automatically.");
                    }
                    State::Failed(ref error) => {
                        ui.colored_label(egui::Color32::LIGHT_RED, error);
                    }
                }
                if let Some(reason) = &self.install_error {
                    ui.label(reason);
                }
                if ui
                    .add_enabled(
                        self.enabled && !self.state().busy(),
                        egui::Button::new("Check for updates"),
                    )
                    .clicked()
                {
                    self.check();
                }
                ui.small("Updates come from ossmalaysia/macvnc on GitHub.");
                ui.small("Checks run at startup and once a day while open.");
            });
        self.open = open;
    }
}
