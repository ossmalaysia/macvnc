//! Same-volume replacement with a backup retained until the new UI starts.
#![cfg_attr(not(windows), allow(dead_code))]
use super::package::{self, FileEntry};
use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
    process::{Child, Command},
    thread,
    time::{Duration, Instant},
};

#[derive(Serialize, Deserialize)]
pub struct Plan {
    pub install: PathBuf,
    pub parent_pid: u32,
    pub version: String,
    pub files: Vec<FileEntry>,
}
#[derive(Serialize, Deserialize)]
struct Outcome {
    updated: bool,
    version: String,
    message: String,
}

pub fn plain(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        !metadata.file_type().is_symlink(),
        "update path contains a link"
    );
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        ensure!(
            metadata.file_attributes() & 0x400 == 0,
            "update path contains a reparse point"
        );
    }
    Ok(())
}

pub fn load_plan(stage: &Path) -> Result<Plan> {
    plain(stage)?;
    let plan: Plan =
        serde_json::from_reader(File::open(stage.join("plan.json"))?.take(64 * 1024 * 1024 + 1))?;
    ensure!(
        stage.is_absolute()
            && stage
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with(".macvnc-update-")),
        "invalid update staging directory"
    );
    ensure!(
        stage.parent() == Some(plan.install.as_path())
            && plan.install.canonicalize()? == plan.install
            && stage.canonicalize()? == stage,
        "update staging directory does not match installation"
    );
    plain(&plan.install)?;
    ensure!(
        plan.files.len() <= 100_000 && !plan.files.is_empty(),
        "invalid update file inventory"
    );
    semver::Version::parse(&plan.version)?;
    Ok(plan)
}

pub fn verify_files(stage: &Path, plan: &Plan) -> Result<()> {
    let package = stage.join("package");
    plain(&package)?;
    let mut seen = BTreeSet::new();
    for file in &plan.files {
        package::validate_relative(&file.path)?;
        ensure!(
            seen.insert(package::path_key(&file.path)),
            "duplicate update file"
        );
        let mut path = package.clone();
        for part in file.path.components() {
            path.push(part);
            plain(&path)?;
        }
        ensure!(
            fs::metadata(&path)?.is_file()
                && fs::metadata(&path)?.len() == file.size
                && package::hash_file(&path)? == file.sha256,
            "staged package changed after verification"
        );
    }
    // Ensure there are no extra files to move that were not verified.
    fn walk(
        root: &Path,
        relative: &Path,
        seen: &BTreeSet<String>,
        count: &mut usize,
    ) -> Result<()> {
        for entry in fs::read_dir(root.join(relative))? {
            let entry = entry?;
            plain(&entry.path())?;
            let path = relative.join(entry.file_name());
            package::validate_relative(&path)?;
            if entry.file_type()?.is_dir() {
                walk(root, &path, seen, count)?;
            } else {
                ensure!(
                    seen.contains(&package::path_key(&path)),
                    "unverified file in staged package"
                );
                *count += 1;
            }
        }
        Ok(())
    }
    let mut count = 0;
    walk(&package, Path::new(""), &seen, &mut count)?;
    ensure!(
        count == plan.files.len(),
        "staged package inventory changed"
    );
    Ok(())
}

fn remove_entry(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            plain(path)?;
            if metadata.is_dir() {
                fs::remove_dir_all(path)?;
            } else {
                fs::remove_file(path)?;
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

pub struct Transaction {
    install: PathBuf,
    stage: PathBuf,
    names: Vec<String>,
}
impl Transaction {
    pub fn new(stage: &Path, plan: &Plan) -> Result<Self> {
        verify_files(stage, plan)?;
        let mut names: Vec<_> = plan
            .files
            .iter()
            .map(|f| {
                f.path
                    .components()
                    .next()
                    .unwrap()
                    .as_os_str()
                    .to_str()
                    .unwrap()
                    .to_owned()
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        // Replace the main executable after its runtime and notices.
        names.sort_by_key(|n| (n == "macvnc-app.exe", n.clone()));
        for name in &names {
            let target = plan.install.join(name);
            match fs::symlink_metadata(&target) {
                Ok(_) => plain(&target)?,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                Err(e) => return Err(e.into()),
            }
        }
        fs::create_dir(stage.join("backup"))?;
        fs::write(stage.join("transaction.json"), serde_json::to_vec(&names)?)?;
        Ok(Self {
            install: plan.install.clone(),
            stage: stage.to_owned(),
            names,
        })
    }
    pub fn apply(&self) -> Result<()> {
        self.apply_with(|_, _, _| Ok(()))
    }
    fn apply_with(
        &self,
        mut before_move: impl FnMut(usize, &Path, &Path) -> Result<()>,
    ) -> Result<()> {
        for (index, name) in self.names.iter().enumerate() {
            let target = self.install.join(name);
            if fs::symlink_metadata(&target).is_ok() {
                fs::rename(&target, self.stage.join("backup").join(name))
                    .context("cannot back up installed files; close other MacVNC instances")?;
            }
            let source = self.stage.join("package").join(name);
            before_move(index, &source, &target)?;
            fs::rename(source, target).context("cannot replace installed files")?;
        }
        Ok(())
    }
    pub fn rollback(&self) -> Result<()> {
        let mut failures = vec![];
        for name in self.names.iter().rev() {
            let backup = self.stage.join("backup").join(name);
            let target = self.install.join(name);
            let result = if backup.exists() {
                remove_entry(&target)
                    .and_then(|()| fs::rename(&backup, &target).map_err(Into::into))
            } else if !self.stage.join("package").join(name).exists() {
                remove_entry(&target)
            } else {
                Ok(())
            };
            if let Err(error) = result {
                failures.push(format!("{name}: {error}"));
            }
        }
        ensure!(
            failures.is_empty(),
            "could not restore some files: {}; backups remain in {}",
            failures.join("; "),
            self.stage.join("backup").display()
        );
        Ok(())
    }
}

pub fn launch(stage: &Path) -> Result<()> {
    let helper = stage.join("updater-helper.exe");
    fs::copy(std::env::current_exe()?, &helper)?;
    let mut child = Command::new(helper)
        .arg("--apply-update")
        .arg(stage)
        .current_dir(stage)
        .spawn()
        .context("could not start updater")?;
    let began = Instant::now();
    while !stage.join("helper-ready").exists() {
        ensure!(
            child.try_wait()?.is_none(),
            "updater exited before it was ready"
        );
        if began.elapsed() > Duration::from_secs(10) {
            let _ = child.kill();
            let _ = child.wait();
            bail!("updater did not become ready; app remains open");
        }
        thread::sleep(Duration::from_millis(50));
    }
    Ok(())
}

fn restart(plan: &Plan, stage: &Path) -> Result<Child> {
    Command::new(plan.install.join("macvnc-app.exe"))
        .arg("--no-autoconnect")
        .arg("--finish-update")
        .arg(stage)
        .current_dir(&plan.install)
        .spawn()
        .context("could not restart MacVNC")
}
fn await_start(child: &mut Child, stage: &Path) -> Result<()> {
    let began = Instant::now();
    loop {
        if stage.join("restarted").exists() {
            return Ok(());
        }
        if child.try_wait()?.is_some() {
            bail!("MacVNC exited before its window started");
        }
        if began.elapsed() > Duration::from_secs(20) {
            let _ = child.kill();
            let _ = child.wait();
            bail!("MacVNC did not start its window in time");
        }
        thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(windows)]
pub fn run_helper(stage: &Path) -> Result<()> {
    use std::os::windows::fs::OpenOptionsExt;
    let plan = load_plan(stage)?;
    ensure!(
        std::env::current_exe()?.canonicalize()? == stage.join("updater-helper.exe"),
        "updater must run from its staging directory"
    );
    // Windows sharing mode prevents two helpers from updating the same folder.
    let _lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .share_mode(0)
        .open(plan.install.join(".macvnc-update.lock"))
        .context("another update is already running")?;
    let parent =
        windows::Process::open(plan.parent_pid, Some(&plan.install.join("macvnc-app.exe")))?;
    fs::write(stage.join("helper-ready"), std::process::id().to_string())?;
    parent.wait()?;
    let transaction = match Transaction::new(stage, &plan) {
        Ok(transaction) => transaction,
        Err(error) => {
            fs::write(
                stage.join("outcome.json"),
                serde_json::to_vec(&Outcome {
                    updated: false,
                    version: plan.version.clone(),
                    message: format!(
                        "Update was not installed. The previous version is unchanged: {error:#}"
                    ),
                })?,
            )?;
            let mut child = restart(&plan, stage)?;
            await_start(&mut child, stage)?;
            fs::write(stage.join("finished"), b"done")?;
            return Ok(());
        }
    };
    let result = transaction.apply().and_then(|()| {
        fs::write(
            stage.join("outcome.json"),
            serde_json::to_vec(&Outcome {
                updated: true,
                version: plan.version.clone(),
                message: String::new(),
            })?,
        )?;
        let mut child = restart(&plan, stage)?;
        await_start(&mut child, stage)
    });
    if let Err(error) = result {
        transaction
            .rollback()
            .context("update failed and rollback needs manual recovery")?;
        let _ = fs::remove_file(stage.join("restarted"));
        fs::write(
            stage.join("outcome.json"),
            serde_json::to_vec(&Outcome {
                updated: false,
                version: plan.version.clone(),
                message: format!(
                    "Update could not be installed. The previous version was restored: {error:#}"
                ),
            })?,
        )?;
        let mut child = restart(&plan, stage)?;
        await_start(&mut child, stage)?;
    }
    fs::write(stage.join("finished"), b"done")?;
    Ok(())
}
#[cfg(not(windows))]
pub fn run_helper(_: &Path) -> Result<()> {
    bail!("automatic installation is supported only on Windows")
}

pub fn finish_restart(stage: &Path) -> Result<String> {
    let plan = load_plan(stage)?;
    ensure!(
        std::env::current_exe()?.canonicalize()? == plan.install.join("macvnc-app.exe"),
        "restart does not match installed application"
    );
    let outcome: Outcome =
        serde_json::from_reader(File::open(stage.join("outcome.json"))?.take(8193))?;
    ensure!(
        !outcome.updated || outcome.version == env!("CARGO_PKG_VERSION"),
        "installed version does not match update"
    );
    let helper_pid: u32 = fs::read_to_string(stage.join("helper-ready"))?.parse()?;
    #[cfg(windows)]
    {
        // Open the helper handle before acknowledging startup, avoiding PID reuse.
        let helper = windows::Process::open(helper_pid, Some(&stage.join("updater-helper.exe")))?;
        let stage = stage.to_owned();
        thread::spawn(move || {
            if helper.wait().is_ok() && stage.join("finished").is_file() {
                let _ = fs::remove_dir_all(stage);
            }
        });
    }
    #[cfg(not(windows))]
    let _ = helper_pid;
    fs::write(stage.join("restarted"), b"window ready")?;
    Ok(if outcome.updated {
        format!("Updated to v{} · ready to connect", outcome.version)
    } else {
        outcome.message
    })
}

#[cfg(windows)]
mod windows {
    use super::*;
    use std::ffi::c_void;
    #[link(name = "kernel32")]
    extern "system" {
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut c_void;
        fn WaitForSingleObject(handle: *mut c_void, milliseconds: u32) -> u32;
        fn QueryFullProcessImageNameW(
            handle: *mut c_void,
            flags: u32,
            path: *mut u16,
            size: *mut u32,
        ) -> i32;
        fn CloseHandle(handle: *mut c_void) -> i32;
    }
    pub struct Process(*mut c_void);
    // A Windows process handle can be waited/closed from another thread.
    unsafe impl Send for Process {}
    impl Process {
        pub fn open(pid: u32, expected: Option<&Path>) -> Result<Self> {
            ensure!(
                pid != 0 && pid != std::process::id(),
                "invalid updater process ID"
            );
            let handle = unsafe { OpenProcess(0x00100000 | 0x1000, 0, pid) };
            ensure!(
                !handle.is_null(),
                "could not open updater process: {}",
                std::io::Error::last_os_error()
            );
            let process = Self(handle);
            if let Some(expected) = expected {
                let mut path = vec![0u16; 32768];
                let mut size = path.len() as u32;
                ensure!(
                    unsafe { QueryFullProcessImageNameW(handle, 0, path.as_mut_ptr(), &mut size) }
                        != 0,
                    "could not verify updater process"
                );
                use std::os::windows::ffi::OsStringExt;
                let actual = PathBuf::from(std::ffi::OsString::from_wide(&path[..size as usize]));
                ensure!(
                    actual.canonicalize()? == expected.canonicalize()?,
                    "updater process does not match application"
                );
            }
            Ok(process)
        }
        pub fn wait(&self) -> Result<()> {
            ensure!(
                unsafe { WaitForSingleObject(self.0, 120_000) } == 0,
                "timed out waiting for app/update process to exit"
            );
            Ok(())
        }
    }
    impl Drop for Process {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

pub fn show_error(message: &str) {
    #[cfg(windows)]
    {
        #[link(name = "user32")]
        extern "system" {
            fn MessageBoxW(
                window: *mut std::ffi::c_void,
                text: *const u16,
                title: *const u16,
                kind: u32,
            ) -> i32;
        }
        let text: Vec<_> = message.encode_utf16().chain(Some(0)).collect();
        let title: Vec<_> = "MacVNC update".encode_utf16().chain(Some(0)).collect();
        unsafe {
            MessageBoxW(std::ptr::null_mut(), text.as_ptr(), title.as_ptr(), 0x10);
        }
    }
    #[cfg(not(windows))]
    eprintln!("MacVNC update: {message}");
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(windows)]
    #[test]
    fn process_handle_tracks_the_actual_child_until_exit() {
        let dir = tempfile::tempdir().unwrap();
        let executable = std::env::current_exe().unwrap();
        let mut child = Command::new(&executable)
            .args([
                "--ignored",
                "--exact",
                "updater::install::tests::child_process_fixture",
                "--test-threads=1",
            ])
            .env("MACVNC_UPDATE_PROCESS_FIXTURE", dir.path())
            .spawn()
            .unwrap();
        let process = windows::Process::open(child.id(), Some(&executable)).unwrap();
        let began = Instant::now();
        let exit = dir.path().join("exit");
        let signal = thread::spawn(move || {
            thread::sleep(Duration::from_millis(150));
            fs::write(exit, b"exit").unwrap();
        });
        process.wait().unwrap();
        signal.join().unwrap();
        assert!(child.wait().unwrap().success());
        assert!(began.elapsed() >= Duration::from_millis(150));
    }
    #[cfg(windows)]
    #[test]
    #[ignore = "invoked as a child by process_handle_tracks_the_actual_child_until_exit"]
    fn child_process_fixture() {
        let folder = std::env::var_os("MACVNC_UPDATE_PROCESS_FIXTURE")
            .expect("fixture requires an isolated test directory");
        let began = Instant::now();
        while !Path::new(&folder).join("exit").exists() {
            assert!(began.elapsed() < Duration::from_secs(10));
            thread::sleep(Duration::from_millis(20));
        }
    }
    fn fixture() -> (tempfile::TempDir, PathBuf, Plan) {
        let root = tempfile::tempdir().unwrap();
        let stage = root.path().join(".macvnc-update-test");
        fs::create_dir(&stage).unwrap();
        fs::create_dir(stage.join("package")).unwrap();
        fs::create_dir_all(stage.join("package/source")).unwrap();
        fs::create_dir(root.path().join("source")).unwrap();
        fs::write(root.path().join("source/old.rs"), b"old source").unwrap();
        fs::write(root.path().join("macvnc-app.exe"), b"old app").unwrap();
        fs::write(root.path().join("personal.txt"), b"untouched").unwrap();
        let mut files = vec![];
        for (name, content) in [
            ("macvnc-app.exe", b"new app".as_slice()),
            ("source/new.rs", b"new source"),
            ("avcodec-61.dll", b"new dll"),
        ] {
            let path = stage.join("package").join(name);
            fs::write(&path, content).unwrap();
            files.push(FileEntry {
                path: name.into(),
                size: content.len() as u64,
                sha256: package::hash_file(&path).unwrap(),
            });
        }
        let plan = Plan {
            install: root.path().canonicalize().unwrap(),
            parent_pid: 1,
            version: "0.1.10".into(),
            files,
        };
        (root, stage, plan)
    }
    #[test]
    fn installs_full_source_tree_and_preserves_unmanaged_files() {
        let (root, stage, plan) = fixture();
        let transaction = Transaction::new(&stage, &plan).unwrap();
        transaction.apply().unwrap();
        assert_eq!(
            fs::read(root.path().join("macvnc-app.exe")).unwrap(),
            b"new app"
        );
        assert!(!root.path().join("source/old.rs").exists());
        assert_eq!(
            fs::read(root.path().join("personal.txt")).unwrap(),
            b"untouched"
        );
        transaction.rollback().unwrap();
        assert_eq!(
            fs::read(root.path().join("macvnc-app.exe")).unwrap(),
            b"old app"
        );
        assert!(root.path().join("source/old.rs").exists());
        assert!(!root.path().join("avcodec-61.dll").exists());
    }
    #[test]
    fn every_injected_replacement_failure_restores_the_previous_package() {
        for fail_at in 0..3 {
            let (root, stage, plan) = fixture();
            let transaction = Transaction::new(&stage, &plan).unwrap();
            assert!(transaction
                .apply_with(|index, _, _| {
                    if index == fail_at {
                        bail!("injected disk error");
                    }
                    Ok(())
                })
                .is_err());
            transaction.rollback().unwrap();
            assert_eq!(
                fs::read(root.path().join("macvnc-app.exe")).unwrap(),
                b"old app"
            );
            assert!(root.path().join("source/old.rs").exists());
            assert!(!root.path().join("avcodec-61.dll").exists());
        }
    }
    #[test]
    fn changed_or_uninventoried_staging_files_are_rejected_before_install() {
        let (root, stage, plan) = fixture();
        fs::write(stage.join("package/macvnc-app.exe"), b"tampered").unwrap();
        assert!(Transaction::new(&stage, &plan).is_err());
        assert_eq!(
            fs::read(root.path().join("macvnc-app.exe")).unwrap(),
            b"old app"
        );
        let (_root, stage, plan) = fixture();
        fs::write(stage.join("package/source/extra.rs"), b"unverified").unwrap();
        assert!(Transaction::new(&stage, &plan).is_err());
    }
}
