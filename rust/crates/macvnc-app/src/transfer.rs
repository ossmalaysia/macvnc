//! Local disk work is isolated from the HP session and its input queue.
use anyhow::{bail, ensure, Context, Result};
use hp_protocol::{
    file_transfer::{self as wire, Message},
    HpConnection,
};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU32, Ordering},
        mpsc::{self, Receiver, SyncSender, TrySendError},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

const RESPONSE_TIMEOUT: Duration = Duration::from_secs(15);

pub enum Request {
    Upload {
        local: PathBuf,
        remote_directory: String,
        allow_replace: bool,
    },
    Download {
        remote: String,
        local: PathBuf,
    },
}
struct Job {
    request: Request,
    cancel: Arc<AtomicBool>,
}

#[derive(Clone, Default)]
pub struct Snapshot {
    pub busy: bool,
    pub bytes: u64,
    pub total: Option<u64>,
    pub status: String,
}
#[derive(Default)]
struct Shared {
    generation: u64,
    route: Option<SyncSender<Job>>,
    cancel: Option<Arc<AtomicBool>>,
    snapshot: Snapshot,
}
#[derive(Clone, Default)]
pub struct Client {
    shared: Arc<Mutex<Shared>>,
}
impl Client {
    pub fn snapshot(&self) -> Snapshot {
        self.shared.lock().unwrap().snapshot.clone()
    }
    pub fn submit(&self, request: Request) -> Result<()> {
        let mut shared = self.shared.lock().unwrap();
        ensure!(!shared.snapshot.busy, "a file transfer is already active");
        let route = shared.route.as_ref().context("connect to the Mac first")?;
        let cancel = Arc::new(AtomicBool::new(false));
        route
            .try_send(Job {
                request,
                cancel: cancel.clone(),
            })
            .map_err(|_| anyhow::anyhow!("file worker is busy or unavailable"))?;
        shared.cancel = Some(cancel);
        shared.snapshot = Snapshot {
            busy: true,
            status: "Preparing file…".into(),
            ..Default::default()
        };
        Ok(())
    }
    /// Apple cancel framing is unverified: abort the owning session instead.
    pub fn cancel(&self) {
        if let Some(cancel) = &self.shared.lock().unwrap().cancel {
            cancel.store(true, Ordering::Release);
        }
    }
    fn update(&self, generation: u64, f: impl FnOnce(&mut Snapshot)) {
        let mut shared = self.shared.lock().unwrap();
        if shared.generation == generation {
            f(&mut shared.snapshot);
        }
    }
}

/// One per authenticated session; its worker can never write to the HP socket.
pub struct Session {
    client: Client,
    generation: u64,
    closed: Arc<AtomicBool>,
    disconnect: Arc<AtomicBool>,
    active_id: Arc<AtomicU32>,
    incoming: SyncSender<Message>,
    outgoing: Receiver<Vec<u8>>,
    pending: Option<Vec<u8>>,
    partial_since: Option<Instant>,
}
impl Session {
    pub fn new(client: Client) -> Self {
        let (jobs, job_rx) = mpsc::sync_channel(1);
        let (incoming, replies) = mpsc::sync_channel(8);
        let (outbound, outgoing) = mpsc::sync_channel(2);
        let closed = Arc::new(AtomicBool::new(false));
        let disconnect = Arc::new(AtomicBool::new(false));
        let active_id = Arc::new(AtomicU32::new(0));
        let generation = {
            let mut shared = client.shared.lock().unwrap();
            shared.generation += 1;
            shared.route = Some(jobs);
            shared.cancel = None;
            shared.snapshot = Snapshot {
                status: "Select a file to send or receive.".into(),
                ..Default::default()
            };
            shared.generation
        };
        let mut worker = Worker {
            client: client.clone(),
            generation,
            closed: closed.clone(),
            disconnect: disconnect.clone(),
            active_id: active_id.clone(),
            outgoing: outbound,
            incoming: replies,
        };
        thread::spawn(move || worker.run(job_rx));
        Self {
            client,
            generation,
            closed,
            disconnect,
            active_id,
            incoming,
            outgoing,
            pending: None,
            partial_since: None,
        }
    }
    pub fn pump(&mut self, connection: &mut HpConnection) -> Result<()> {
        ensure!(
            !self.disconnect.load(Ordering::Acquire),
            "file transfer stopped; reconnect before trying again"
        );
        for message in connection.take_file_messages() {
            self.reply(message);
        }
        ensure!(
            !self.disconnect.load(Ordering::Acquire),
            "file receiver stopped; reconnect before trying again"
        );
        if connection.file_message_pending() {
            let began = self.partial_since.get_or_insert_with(Instant::now);
            ensure!(
                began.elapsed() < RESPONSE_TIMEOUT,
                "incomplete file message timed out"
            );
        } else {
            self.partial_since = None;
        }
        // At most one bulk message per media iteration; keys/heartbeats keep flowing.
        if self.pending.is_none() {
            self.pending = self.outgoing.try_recv().ok();
        }
        if let Some(body) = &self.pending {
            if connection.try_send_file_message(body)? {
                self.pending = None;
            }
        }
        Ok(())
    }
    fn reply(&self, message: Message) {
        if message.session != self.active_id.load(Ordering::Acquire) || message.session == 0 {
            return;
        }
        if self.incoming.try_send(message).is_err() {
            self.client.update(self.generation, |view| {
                view.status = "File receiver could not keep up; disconnecting.".into()
            });
            self.disconnect.store(true, Ordering::Release);
            self.closed.store(true, Ordering::Release);
        }
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::Release);
        let mut shared = self.client.shared.lock().unwrap();
        if shared.generation == self.generation {
            shared.route = None;
            if let Some(cancel) = shared.cancel.take() {
                cancel.store(true, Ordering::Release);
            }
            if shared.snapshot.busy {
                shared.snapshot.busy = false;
                shared.snapshot.status = "Transfer stopped with the screen-sharing session. Partial Mac files may remain.".into();
            }
        }
    }
}

struct Worker {
    client: Client,
    generation: u64,
    closed: Arc<AtomicBool>,
    disconnect: Arc<AtomicBool>,
    active_id: Arc<AtomicU32>,
    outgoing: SyncSender<Vec<u8>>,
    incoming: Receiver<Message>,
}
impl Worker {
    fn check(&self, cancel: &AtomicBool) -> Result<()> {
        ensure!(
            !self.closed.load(Ordering::Acquire) && !cancel.load(Ordering::Acquire),
            "transfer cancelled"
        );
        Ok(())
    }
    fn send(&self, mut bytes: Vec<u8>, cancel: &AtomicBool) -> Result<()> {
        let began = Instant::now();
        loop {
            self.check(cancel)?;
            match self.outgoing.try_send(bytes) {
                Ok(()) => return Ok(()),
                Err(TrySendError::Full(value)) => bytes = value,
                Err(TrySendError::Disconnected(_)) => bail!("screen-sharing session closed"),
            }
            ensure!(began.elapsed() < RESPONSE_TIMEOUT, "file sender timed out");
            thread::sleep(Duration::from_millis(2));
        }
    }
    fn receive(&self, cancel: &AtomicBool) -> Result<Message> {
        let began = Instant::now();
        loop {
            self.check(cancel)?;
            ensure!(
                began.elapsed() < RESPONSE_TIMEOUT,
                "Mac did not confirm the transfer; authenticated file support may be unavailable"
            );
            match self.incoming.recv_timeout(Duration::from_millis(20)) {
                Ok(message) => return Ok(message),
                Err(mpsc::RecvTimeoutError::Timeout) => (),
                Err(mpsc::RecvTimeoutError::Disconnected) => bail!("screen-sharing session closed"),
            }
        }
    }
    fn run(&mut self, jobs: Receiver<Job>) {
        let mut id = 2u32;
        while !self.closed.load(Ordering::Acquire) {
            let job = match jobs.recv_timeout(Duration::from_millis(50)) {
                Ok(job) => job,
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            };
            while self.incoming.try_recv().is_ok() {}
            self.active_id.store(id, Ordering::Release);
            let mut started = false;
            let result = match job.request {
                Request::Upload {
                    local,
                    remote_directory,
                    allow_replace,
                } => self.upload(
                    id,
                    &local,
                    &remote_directory,
                    allow_replace,
                    &job.cancel,
                    &mut started,
                ),
                Request::Download { remote, local } => {
                    self.download(id, &remote, &local, &job.cancel, &mut started)
                }
            };
            self.active_id.store(0, Ordering::Release);
            match result {
                Ok(()) => self.client.update(self.generation, |view| {
                    view.busy = false;
                    view.status = "Transfer complete · Mac confirmed completion.".into();
                }),
                Err(error) => {
                    self.client.update(self.generation, |view| {
                        view.busy = false;
                        view.status = format!(
                            "Transfer stopped: {error:#}{}",
                            if started {
                                " · reconnect before retrying; partial Mac files may remain"
                            } else {
                                ""
                            }
                        );
                    });
                    if started {
                        self.disconnect.store(true, Ordering::Release);
                        break;
                    }
                }
            }
            match id.checked_add(1) {
                Some(next) => id = next,
                None => break,
            }
        }
    }
    fn progress(&self, bytes: u64, total: Option<u64>) {
        self.client.update(self.generation, |view| {
            view.bytes = bytes;
            view.total = total;
        });
    }
    fn upload(
        &self,
        id: u32,
        path: &Path,
        remote: &str,
        allow_replace: bool,
        cancel: &AtomicBool,
        started: &mut bool,
    ) -> Result<()> {
        ensure!(
            allow_replace,
            "confirm that replacement of the destination file is allowed"
        );
        let mut file = open_regular(path)?;
        let metadata = file.metadata()?;
        let size = metadata.len();
        ensure!(
            size <= wire::MAX_FILE_BYTES,
            "files must be smaller than 4 GiB"
        );
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .context("file name is not valid UTF-8")?;
        let request = wire::request(id, remote, true)?;
        let messages = wire::upload_metadata(id, name, size)?;
        self.check(cancel)?;
        self.client.update(self.generation, |view| {
            view.status = "Sending file…".into();
            view.total = Some(size);
        });
        *started = true;
        self.send(request, cancel)?;
        for message in messages {
            self.send(message, cancel)?;
        }
        let mut bytes = 0u64;
        let mut buffer = vec![0; wire::CHUNK_BYTES];
        while bytes < size {
            self.check(cancel)?;
            let limit = buffer.len().min((size - bytes) as usize);
            let n = file.read(&mut buffer[..limit])?;
            ensure!(n != 0, "source file became shorter");
            self.send(wire::data(id, &buffer[..n])?, cancel)?;
            bytes += n as u64;
            self.progress(bytes, Some(size));
        }
        let after = file.metadata()?;
        ensure!(
            after.len() == size && after.modified().ok() == metadata.modified().ok(),
            "source file changed during transfer"
        );
        self.send(wire::end(id)?, cancel)?;
        self.client.update(self.generation, |view| {
            view.status = "File sent · waiting for the Mac to confirm…".into()
        });
        // Transmission alone never establishes successful remote publication.
        let reply = self.receive(cancel)?;
        ensure!(
            reply.kind == wire::END && reply.argument == 0 && reply.payload.is_empty(),
            "unsupported or rejected Mac completion reply"
        );
        Ok(())
    }
    fn download(
        &self,
        id: u32,
        remote: &str,
        local: &Path,
        cancel: &AtomicBool,
        started: &mut bool,
    ) -> Result<()> {
        let request = wire::request(id, remote, false)?;
        let destination = download_destination(local)?;
        let parent = destination.parent().context("missing download directory")?;
        let mut temporary = tempfile::NamedTempFile::new_in(parent)
            .context("cannot create download staging file")?;
        self.check(cancel)?;
        self.client.update(self.generation, |view| {
            view.status = "Receiving file…".into()
        });
        *started = true;
        self.send(request, cancel)?;
        let mut bytes = 0u64;
        let mut total = None;
        let mut saw_item = false;
        loop {
            let message = self.receive(cancel)?;
            match message.kind {
                wire::ITEM_INFO | wire::NEW_ITEM => {
                    if message.kind == wire::NEW_ITEM {
                        ensure!(!saw_item && bytes == 0, "multiple files are unsupported");
                        saw_item = true;
                    }
                    let announced = message.announced_size()?.context("missing file size")?;
                    ensure!(
                        total.is_none_or(|old| old == announced) && bytes <= announced,
                        "Mac changed the file size"
                    );
                    total = Some(announced);
                }
                wire::DATA => {
                    ensure!(
                        message.argument as usize == message.payload.len(),
                        "file chunk length mismatch"
                    );
                    bytes = bytes
                        .checked_add(message.payload.len() as u64)
                        .context("download size overflow")?;
                    ensure!(
                        bytes <= wire::MAX_FILE_BYTES && total.is_none_or(|size| bytes <= size),
                        "download exceeds declared size or limit"
                    );
                    temporary
                        .write_all(&message.payload)
                        .context("cannot write download")?;
                }
                wire::END => {
                    ensure!(
                        message.argument == 0 && message.payload.is_empty(),
                        "Mac rejected file completion"
                    );
                    ensure!(
                        total.is_some_and(|size| bytes == size) && saw_item,
                        "Mac did not provide complete regular-file metadata/data"
                    );
                    break;
                }
                _ => bail!("unsupported Mac file response"),
            }
            self.progress(bytes, total);
        }
        self.check(cancel)?;
        temporary.as_file_mut().flush()?;
        temporary.as_file().sync_all()?;
        self.check(cancel)?;
        temporary.persist_noclobber(&destination).map_err(|_| {
            anyhow::anyhow!("cannot publish download; destination may already exist")
        })?;
        self.progress(bytes, total);
        Ok(())
    }
}

fn open_regular(path: &Path) -> Result<File> {
    ensure!(path.is_absolute(), "enter an absolute local file path");
    let before = fs::symlink_metadata(path).context("cannot inspect local file")?;
    ensure!(
        before.file_type().is_file(),
        "select a regular file, not a folder or link"
    );
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(0o400000 | 0o4000);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x00200000);
    }
    let file = options.open(path).context("cannot open local file")?;
    let metadata = file.metadata()?;
    ensure!(metadata.is_file(), "source is not a regular file");
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        ensure!(
            metadata.file_attributes() & 0x400 == 0,
            "reparse points are unsupported"
        );
    }
    Ok(file)
}
fn download_destination(path: &Path) -> Result<PathBuf> {
    ensure!(
        path.is_absolute(),
        "enter an absolute local destination path"
    );
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .context("invalid destination file name")?;
    wire::validate_name(name)?;
    let parent = path
        .parent()
        .context("missing destination folder")?
        .canonicalize()
        .context("destination folder must already exist")?;
    ensure!(parent.is_dir(), "destination parent is not a folder");
    let destination = parent.join(name);
    ensure!(
        fs::symlink_metadata(&destination).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "destination already exists or cannot be inspected; choose a new name"
    );
    Ok(destination)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn await_finished(client: &Client) -> Snapshot {
        let began = Instant::now();
        loop {
            let view = client.snapshot();
            if !view.busy {
                return view;
            }
            assert!(
                began.elapsed() < Duration::from_secs(3),
                "worker did not finish"
            );
            thread::sleep(Duration::from_millis(2));
        }
    }
    fn take_request(session: &Session) -> u32 {
        let bytes = session
            .outgoing
            .recv_timeout(Duration::from_secs(2))
            .unwrap();
        let (messages, _) = wire::Decoder::default().feed(&bytes).unwrap();
        messages[0].session
    }
    fn deliver(session: &Session, bytes: &[u8]) {
        let (messages, _) = wire::Decoder::default().feed(bytes).unwrap();
        for message in messages {
            session.reply(message);
        }
    }
    #[test]
    fn download_streams_binary_to_staging_and_publishes_only_on_end() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("received.bin");
        let client = Client::default();
        let session = Session::new(client.clone());
        client
            .submit(Request::Download {
                remote: "/tmp/synthetic.bin".into(),
                local: target.clone(),
            })
            .unwrap();
        let id = take_request(&session);
        let contents = vec![0xa5; wire::CHUNK_BYTES + 19];
        for metadata in wire::upload_metadata(id, "synthetic.bin", contents.len() as u64).unwrap() {
            deliver(&session, &metadata);
        }
        for chunk in contents.chunks(wire::CHUNK_BYTES) {
            deliver(&session, &wire::data(id, chunk).unwrap());
        }
        assert!(!target.exists());
        deliver(&session, &wire::end(id).unwrap());
        assert!(await_finished(&client)
            .status
            .starts_with("Transfer complete"));
        assert_eq!(fs::read(target).unwrap(), contents);
    }
    #[test]
    fn upload_streams_more_than_one_chunk_and_waits_for_confirmation() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("upload.bin");
        let contents = vec![42; wire::CHUNK_BYTES * 3 + 7];
        fs::write(&target, &contents).unwrap();
        let client = Client::default();
        let session = Session::new(client.clone());
        client
            .submit(Request::Upload {
                local: target,
                remote_directory: "/tmp".into(),
                allow_replace: true,
            })
            .unwrap();
        let id = take_request(&session);
        let mut observed: Vec<u8> = vec![];
        loop {
            let packet = session
                .outgoing
                .recv_timeout(Duration::from_secs(2))
                .unwrap();
            let (messages, _) = wire::Decoder::default().feed(&packet).unwrap();
            let m = &messages[0];
            if m.kind == wire::DATA {
                observed.extend(&m.payload);
            }
            if m.kind == wire::END {
                break;
            }
        }
        assert_eq!(observed, contents);
        assert!(client.snapshot().busy);
        deliver(&session, &wire::end(id).unwrap());
        assert!(await_finished(&client)
            .status
            .starts_with("Transfer complete"));
    }
    #[test]
    fn failed_download_never_publishes_or_leaves_local_partials() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("received.bin");
        let client = Client::default();
        let session = Session::new(client.clone());
        client
            .submit(Request::Download {
                remote: "/tmp/test".into(),
                local: target.clone(),
            })
            .unwrap();
        let id = take_request(&session);
        for m in wire::upload_metadata(id, "test", 99).unwrap() {
            deliver(&session, &m);
        }
        deliver(&session, &wire::data(id, &[1, 2]).unwrap());
        deliver(&session, &wire::end(id).unwrap());
        assert!(await_finished(&client)
            .status
            .starts_with("Transfer stopped"));
        assert!(!target.exists());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
        assert!(session.disconnect.load(Ordering::Acquire));
    }
    #[test]
    fn existing_destination_survives_and_sessions_do_not_share_jobs() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("existing.bin");
        fs::write(&target, b"keep").unwrap();
        let client = Client::default();
        let old = Session::new(client.clone());
        client
            .submit(Request::Download {
                remote: "/tmp/test".into(),
                local: target.clone(),
            })
            .unwrap();
        assert!(await_finished(&client)
            .status
            .starts_with("Transfer stopped"));
        assert_eq!(fs::read(&target).unwrap(), b"keep");
        let new = Session::new(client.clone());
        old.client
            .update(old.generation, |view| view.status = "stale".into());
        drop(old);
        assert_ne!(client.snapshot().status, "stale");
        assert!(client.shared.lock().unwrap().route.is_some());
        drop(new);
        assert!(client
            .submit(Request::Download {
                remote: "/tmp/test".into(),
                local: target
            })
            .is_err());
    }
    #[test]
    fn cancellation_interrupts_reply_wait_and_cleans_download() {
        let dir = tempfile::tempdir().unwrap();
        let client = Client::default();
        let session = Session::new(client.clone());
        client
            .submit(Request::Download {
                remote: "/tmp/test".into(),
                local: dir.path().join("cancel.bin"),
            })
            .unwrap();
        let _ = take_request(&session);
        client.cancel();
        assert!(await_finished(&client).status.contains("cancelled"));
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    }
    #[test]
    fn cancellation_interrupts_full_upload_queue() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("upload.bin");
        fs::write(&source, vec![42; wire::CHUNK_BYTES * 4]).unwrap();
        let client = Client::default();
        let session = Session::new(client.clone());
        client
            .submit(Request::Upload {
                local: source,
                remote_directory: "/tmp".into(),
                allow_replace: true,
            })
            .unwrap();
        let _ = take_request(&session);
        // Drain metadata, then leave bulk chunks queued until the sender stalls.
        for _ in 0..2 {
            session
                .outgoing
                .recv_timeout(Duration::from_secs(2))
                .unwrap();
        }
        let began = Instant::now();
        while client.snapshot().bytes < (wire::CHUNK_BYTES * 2) as u64 {
            assert!(began.elapsed() < Duration::from_secs(2));
            thread::sleep(Duration::from_millis(2));
        }
        assert!(client.snapshot().busy);
        client.cancel();
        assert!(await_finished(&client).status.contains("cancelled"));
        assert!(session.disconnect.load(Ordering::Acquire));
    }
    #[test]
    fn stale_transfer_replies_cannot_complete_a_download() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("received.bin");
        let client = Client::default();
        let session = Session::new(client.clone());
        client
            .submit(Request::Download {
                remote: "/tmp/test".into(),
                local: target.clone(),
            })
            .unwrap();
        let id = take_request(&session);
        deliver(&session, &wire::end(id + 1).unwrap());
        assert!(client.snapshot().busy);
        assert!(!target.exists());
        for metadata in wire::upload_metadata(id, "test", 0).unwrap() {
            deliver(&session, &metadata);
        }
        deliver(&session, &wire::end(id).unwrap());
        assert!(await_finished(&client)
            .status
            .starts_with("Transfer complete"));
        assert_eq!(fs::read(target).unwrap(), b"");
    }
    #[test]
    fn destination_created_during_download_survives_publication() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("received.bin");
        let client = Client::default();
        let session = Session::new(client.clone());
        client
            .submit(Request::Download {
                remote: "/tmp/test".into(),
                local: target.clone(),
            })
            .unwrap();
        let id = take_request(&session);
        for metadata in wire::upload_metadata(id, "test", 3).unwrap() {
            deliver(&session, &metadata);
        }
        deliver(&session, &wire::data(id, b"new").unwrap());
        // A competing process creates the final name after initial validation.
        fs::write(&target, b"preserve this").unwrap();
        deliver(&session, &wire::end(id).unwrap());
        assert!(await_finished(&client)
            .status
            .contains("cannot publish download"));
        assert_eq!(fs::read(&target).unwrap(), b"preserve this");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }
    #[test]
    fn upload_without_replacement_consent_sends_no_request() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("upload.bin");
        fs::write(&target, b"content").unwrap();
        let client = Client::default();
        let session = Session::new(client.clone());
        client
            .submit(Request::Upload {
                local: target,
                remote_directory: "/tmp".into(),
                allow_replace: false,
            })
            .unwrap();
        assert!(await_finished(&client)
            .status
            .contains("confirm that replacement"));
        assert!(session.outgoing.try_recv().is_err());
        assert!(!session.disconnect.load(Ordering::Acquire));
    }
}
