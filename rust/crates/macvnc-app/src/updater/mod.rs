//! Public stable-release updates for the portable Windows x64 package.
pub mod install;
mod package;
mod ui;

use anyhow::{ensure, Context, Result};
use eframe::egui;
use package::Release;
use reqwest::{redirect::Policy, Client, Url};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    future::Future,
    io::Write,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

const API: &str = "https://api.github.com/repos/ossmalaysia/macvnc/releases/latest";
#[derive(Clone)]
pub enum State {
    Idle,
    Checking,
    Current,
    Available(Release),
    Downloading {
        version: String,
        bytes: u64,
        total: u64,
        detail: String,
    },
    Restarting,
    Failed(String),
}
impl State {
    pub fn busy(&self) -> bool {
        matches!(
            self,
            Self::Checking | Self::Downloading { .. } | Self::Restarting
        )
    }
}
struct Shared {
    state: State,
    cancelled: Arc<AtomicBool>,
    exit: bool,
}
pub struct Updater {
    pub open: bool,
    shared: Arc<Mutex<Shared>>,
    ctx: egui::Context,
    last_check: Option<Instant>,
    enabled: bool,
    install_error: Option<String>,
}
impl Updater {
    pub fn new(ctx: egui::Context, smoke: bool) -> Self {
        let enabled = cfg!(all(windows, target_arch = "x86_64")) && !smoke;
        let state = if smoke {
            State::Available(Release {
                version: "0.1.10".into(),
                notes: "Synthetic update preview. No download or installation will run.".into(),
                page: format!("{}/releases", package::REPO),
                archive_url: String::new(),
                checksum_url: String::new(),
                size: 0,
            })
        } else {
            State::Idle
        };
        let install_error = if !enabled {
            Some("In-app installation requires the portable Windows x64 package.".into())
        } else {
            portable_install().err().map(|e| e.to_string())
        };
        let mut updater = Self {
            open: smoke,
            shared: Arc::new(Mutex::new(Shared {
                state,
                cancelled: Arc::new(AtomicBool::new(false)),
                exit: false,
            })),
            ctx,
            last_check: None,
            enabled,
            install_error,
        };
        if enabled {
            updater.check();
        }
        updater
    }
    pub fn state(&self) -> State {
        self.shared.lock().unwrap().state.clone()
    }
    pub fn install_busy(&self) -> bool {
        matches!(self.state(), State::Downloading { .. } | State::Restarting)
    }
    pub fn tick(&mut self) {
        if self.enabled
            && self
                .last_check
                .is_some_and(|t| t.elapsed() >= Duration::from_secs(24 * 60 * 60))
            && !self.state().busy()
        {
            self.check();
        }
    }
    pub fn should_exit(&self) -> bool {
        self.shared.lock().unwrap().exit
    }
    pub fn check(&mut self) {
        if !self.enabled || self.state().busy() {
            return;
        }
        self.last_check = Some(Instant::now());
        set_state(&self.shared, &self.ctx, State::Checking);
        let shared = self.shared.clone();
        let ctx = self.ctx.clone();
        thread::spawn(move || {
            let result = find_release();
            let state = match result {
                Ok(Some(release)) => State::Available(release),
                Ok(None) => State::Current,
                Err(e) => State::Failed(format!("Could not check for updates: {e:#}")),
            };
            set_state(&shared, &ctx, state);
        });
    }
    fn download(&mut self, release: Release) {
        if self.install_error.is_some() || self.state().busy() {
            return;
        }
        let cancel = Arc::new(AtomicBool::new(false));
        self.shared.lock().unwrap().cancelled = cancel.clone();
        set_state(
            &self.shared,
            &self.ctx,
            State::Downloading {
                version: release.version.clone(),
                bytes: 0,
                total: release.size,
                detail: "Downloading update…".into(),
            },
        );
        let shared = self.shared.clone();
        let ctx = self.ctx.clone();
        thread::spawn(move || {
            let result = prepare(&release, &cancel, |bytes, detail| {
                set_state(
                    &shared,
                    &ctx,
                    State::Downloading {
                        version: release.version.clone(),
                        bytes,
                        total: release.size,
                        detail: detail.into(),
                    },
                )
            });
            let result = result.and_then(|stage| {
                // No cancellation after helper handoff: the app is about to close.
                {
                    let mut state = shared.lock().unwrap();
                    ensure!(!cancel.load(Ordering::Acquire), "download cancelled");
                    state.state = State::Restarting;
                }
                ctx.request_repaint();
                install::launch(stage.path())?;
                let _ = stage.keep(); // The restarted app cleans up after the helper exits.
                shared.lock().unwrap().exit = true;
                ctx.request_repaint();
                Ok(())
            });
            if let Err(error) = result {
                set_state(
                    &shared,
                    &ctx,
                    State::Failed(format!("Update was not installed: {error:#}")),
                );
            }
        });
    }
    fn cancel(&self) {
        let shared = self.shared.lock().unwrap();
        if !matches!(shared.state, State::Restarting) {
            shared.cancelled.store(true, Ordering::Release);
        }
    }
}
impl Drop for Updater {
    fn drop(&mut self) {
        self.cancel();
    }
}
fn set_state(shared: &Mutex<Shared>, ctx: &egui::Context, state: State) {
    shared.lock().unwrap().state = state;
    ctx.request_repaint();
}

fn allowed_url(url: &Url) -> bool {
    url.scheme() == "https"
        && url.username().is_empty()
        && url.password().is_none()
        && url.port_or_known_default() == Some(443)
        && matches!(
            url.host_str(),
            Some(
                "api.github.com"
                    | "github.com"
                    | "release-assets.githubusercontent.com"
                    | "objects.githubusercontent.com"
            )
        )
}
fn http_client() -> Result<Client> {
    Client::builder()
        .user_agent(concat!("MacVNC/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(Duration::from_secs(15))
        .read_timeout(Duration::from_secs(20))
        .timeout(Duration::from_secs(600))
        .redirect(Policy::custom(|attempt| {
            if attempt.previous().len() >= 5 || !allowed_url(attempt.url()) {
                attempt.error("unexpected update redirect")
            } else {
                attempt.follow()
            }
        }))
        .build()
        .context("could not initialize update connection")
}
async fn read_bounded(mut response: reqwest::Response, limit: u64) -> Result<Vec<u8>> {
    let mut bytes = vec![];
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            bytes.len() as u64 + chunk.len() as u64 <= limit,
            "update response exceeds size limit"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
fn runtime() -> Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?)
}
async fn cancellable<T>(cancel: &AtomicBool, future: impl Future<Output = Result<T>>) -> Result<T> {
    let mut future = std::pin::pin!(future);
    loop {
        ensure!(!cancel.load(Ordering::Acquire), "download cancelled");
        tokio::select! {
            result = &mut future => return result,
            _ = tokio::time::sleep(Duration::from_millis(100)) => (),
        }
    }
}
fn find_release() -> Result<Option<Release>> {
    runtime()?.block_on(async {
        let response = http_client()?
            .get(API)
            .timeout(Duration::from_secs(30))
            .header("Accept", "application/vnd.github+json")
            .send()
            .await?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        package::parse_release(
            &read_bounded(response.error_for_status()?, 2 * 1024 * 1024).await?,
            env!("CARGO_PKG_VERSION"),
        )
    })
}
fn portable_install() -> Result<PathBuf> {
    ensure!(
        cfg!(all(windows, target_arch = "x86_64")),
        "in-app updates require Windows x64"
    );
    let exe = std::env::current_exe()?.canonicalize()?;
    ensure!(
        exe.file_name().is_some_and(|n| n == "macvnc-app.exe"),
        "use the portable MacVNC package for in-app updates"
    );
    let install = exe
        .parent()
        .context("missing application folder")?
        .to_owned();
    for name in ["README.txt", "LICENSE-AGPL-3.0.txt", "FFMPEG-LICENSE.txt"] {
        ensure!(
            install.join(name).is_file(),
            "use the extracted portable MacVNC package for in-app updates"
        );
    }
    Ok(install)
}

fn prepare(
    release: &Release,
    cancel: &AtomicBool,
    mut progress: impl FnMut(u64, &str),
) -> Result<tempfile::TempDir> {
    let check = || -> Result<()> {
        ensure!(!cancel.load(Ordering::Acquire), "download cancelled");
        Ok(())
    };
    let install = portable_install()?;
    let stage = tempfile::Builder::new()
        .prefix(".macvnc-update-")
        .tempdir_in(&install)
        .context(
            "application folder is not writable; move the portable app to a writable folder",
        )?;
    let archive = stage.path().join("download.zip");
    let bytes = runtime()?.block_on(cancellable(cancel, async {
        let client = http_client()?;
        let sums = read_bounded(
            client
                .get(&release.checksum_url)
                .timeout(Duration::from_secs(30))
                .send()
                .await?
                .error_for_status()?,
            64 * 1024,
        )
        .await?;
        let expected = package::checksum(&sums)?;
        check()?;
        let mut response = client
            .get(&release.archive_url)
            .send()
            .await?
            .error_for_status()?;
        ensure!(
            response.content_length().is_none_or(|n| n == release.size),
            "release package length changed"
        );
        let mut file = File::create(&archive)?;
        let mut hash = Sha256::new();
        let mut bytes = 0;
        let mut last = Instant::now();
        while let Some(chunk) = response.chunk().await? {
            check()?;
            bytes += chunk.len() as u64;
            ensure!(
                bytes <= release.size && bytes <= package::MAX_ARCHIVE,
                "download exceeds declared size"
            );
            file.write_all(&chunk)?;
            hash.update(&chunk);
            if last.elapsed() >= Duration::from_millis(100) {
                progress(bytes, "Downloading update…");
                last = Instant::now();
            }
        }
        file.sync_all()?;
        drop(file);
        ensure!(bytes == release.size, "download is incomplete");
        ensure!(
            format!("{:x}", hash.finalize()) == expected,
            "update checksum mismatch; app remains unchanged"
        );
        Ok(bytes)
    }))?;
    check()?;
    progress(bytes, "Verifying and preparing update…");
    let files = package::extract(
        &archive,
        &stage.path().join("package"),
        &release.version,
        check,
    )?;
    let plan = install::Plan {
        install,
        parent_pid: std::process::id(),
        version: release.version.clone(),
        files,
    };
    let mut file = File::create(stage.path().join("plan.json"))?;
    file.write_all(&serde_json::to_vec(&plan)?)?;
    file.sync_all()?;
    Ok(stage)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cancellation_interrupts_a_stalled_network_future() {
        let cancel = Arc::new(AtomicBool::new(false));
        let signal = cancel.clone();
        let worker = thread::spawn(move || {
            thread::sleep(Duration::from_millis(20));
            signal.store(true, Ordering::Release);
        });
        let began = Instant::now();
        let result: Result<()> = runtime()
            .unwrap()
            .block_on(cancellable(&cancel, std::future::pending()));
        worker.join().unwrap();
        assert!(result.unwrap_err().to_string().contains("cancelled"));
        assert!(began.elapsed() < Duration::from_secs(1));
    }
    #[test]
    fn redirects_cannot_leave_trusted_https_hosts() {
        for url in [
            "http://github.com/x",
            "https://github.com.evil.example/x",
            "https://user:pass@github.com/x",
            "https://github.com:444/x",
            "https://example.com/x",
        ] {
            assert!(!allowed_url(&Url::parse(url).unwrap()));
        }
        assert!(allowed_url(
            &Url::parse("https://release-assets.githubusercontent.com/x?token=synthetic").unwrap()
        ));
    }
}
