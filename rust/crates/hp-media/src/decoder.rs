//! FFmpeg 7 ABI adapter. Only stable public struct prefixes are accessed;
//! runtime major versions are checked before any structure access.
use crate::{allocate_rgba, rgba_len, AccessUnit, RgbaFrame};
use anyhow::{anyhow, bail, Context, Result};
use libloading::Library;
use std::{
    collections::BTreeMap,
    ffi::{c_char, c_int, c_void, CStr},
    path::{Path, PathBuf},
    ptr,
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
};
fn decoder_directory(path: &Path) -> Result<PathBuf> {
    // A drive-relative or CWD-relative environment setting can resolve to an
    // attacker-controlled directory after a launcher changes working directory.
    if !path.is_absolute() {
        bail!("MACVNC_FFMPEG_DIR must be an absolute directory")
    }
    let directory = path
        .canonicalize()
        .context("Decoder directory is unavailable")?;
    if !directory.is_dir() {
        bail!("Decoder path is not a directory")
    }
    Ok(directory)
}
unsafe fn load_decoder_library(path: &Path) -> Result<Library> {
    #[cfg(windows)]
    {
        use libloading::os::windows::{
            Library as WindowsLibrary, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR,
            LOAD_LIBRARY_SEARCH_SYSTEM32,
        };
        // Absolute main DLL plus its sibling directory and System32 only. The
        // default dependency search would additionally consult CWD and PATH.
        Ok(WindowsLibrary::load_with_flags(
            path,
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32,
        )?
        .into())
    }
    #[cfg(not(windows))]
    {
        Ok(Library::new(path)?)
    }
}
struct ReferenceCounter {
    context: AtomicUsize,
    count: AtomicU64,
    decode_errors: AtomicU64,
}
// Fixed capacity, no allocations/locks/panics in FFmpeg's slice-worker callback.
static REFERENCE_COUNTERS: [ReferenceCounter; 16] = [const {
    ReferenceCounter {
        context: AtomicUsize::new(0),
        count: AtomicU64::new(0),
        decode_errors: AtomicU64::new(0),
    }
}; 16];
type LogCallback = unsafe extern "C" fn(*mut c_void, c_int, *const c_char, *mut c_void);
unsafe extern "C" fn count_reference_error(
    context: *mut c_void,
    level: c_int,
    format: *const c_char,
    _arguments: *mut c_void,
) {
    if context.is_null() || format.is_null() || level > 24 {
        return;
    }
    // Inspect only the trusted static format string. Never format varargs or
    // write FFmpeg log output: arguments may contain untrusted stream content.
    let missing_reference = CStr::from_ptr(format)
        .to_bytes()
        .starts_with(b"Could not find ref with POC");
    if !missing_reference && level > 16 {
        return;
    }
    for slot in &REFERENCE_COUNTERS {
        if slot.context.load(Ordering::Acquire) == context as usize {
            let counter = if missing_reference {
                &slot.count
            } else {
                &slot.decode_errors
            };
            let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(n.saturating_add(1))
            });
            break;
        }
    }
}
#[repr(C)]
struct Packet {
    buf: *mut c_void,
    pts: i64,
    dts: i64,
    data: *mut u8,
    size: c_int,
}
#[repr(C)]
struct Frame {
    data: [*mut u8; 8],
    linesize: [c_int; 8],
    extended_data: *mut *mut u8,
    width: c_int,
    height: c_int,
    nb_samples: c_int,
    format: c_int,
    key_frame: c_int,
    pict_type: c_int,
    sar: [c_int; 2],
    pts: i64,
}
type Ctx = *mut c_void;
struct Api {
    _libs: Vec<Library>,
    find: unsafe extern "C" fn(*const c_char) -> *const c_void,
    alloc: unsafe extern "C" fn(*const c_void) -> Ctx,
    open: unsafe extern "C" fn(Ctx, *const c_void, *mut Ctx) -> c_int,
    free: unsafe extern "C" fn(*mut Ctx),
    send: unsafe extern "C" fn(Ctx, *const Packet) -> c_int,
    receive: unsafe extern "C" fn(Ctx, *mut Frame) -> c_int,
    packet_alloc: unsafe extern "C" fn() -> *mut Packet,
    packet_new: unsafe extern "C" fn(*mut Packet, c_int) -> c_int,
    packet_free: unsafe extern "C" fn(*mut *mut Packet),
    frame_alloc: unsafe extern "C" fn() -> *mut Frame,
    frame_free: unsafe extern "C" fn(*mut *mut Frame),
    frame_unref: unsafe extern "C" fn(*mut Frame),
    opt: unsafe extern "C" fn(Ctx, *const c_char, i64, c_int) -> c_int,
    sws_get: unsafe extern "C" fn(
        Ctx,
        c_int,
        c_int,
        c_int,
        c_int,
        c_int,
        c_int,
        c_int,
        Ctx,
        Ctx,
        *const f64,
    ) -> Ctx,
    sws_scale: unsafe extern "C" fn(
        Ctx,
        *const *const u8,
        *const c_int,
        c_int,
        c_int,
        *const *mut u8,
        *const c_int,
    ) -> c_int,
    sws_free: unsafe extern "C" fn(Ctx),
}
impl Api {
    unsafe fn load() -> Result<Self> {
        let dir = std::env::var_os("MACVNC_FFMPEG_DIR")
            .map(PathBuf::from)
            .or_else(|| std::env::current_exe().ok()?.parent().map(PathBuf::from))
            .ok_or_else(|| anyhow!("Cannot locate decoder directory"))?;
        let dir = decoder_directory(&dir)?;
        let names = if cfg!(target_os = "windows") {
            [
                "avutil-59.dll",
                "swresample-5.dll",
                "avcodec-61.dll",
                "swscale-8.dll",
            ]
        } else {
            [
                "libavutil.so.59",
                "libswresample.so.5",
                "libavcodec.so.61",
                "libswscale.so.8",
            ]
        };
        let mut libs = vec![];
        for n in names {
            libs.push(load_decoder_library(&dir.join(n)).with_context(|| {
                format!("FFmpeg 7 library {n} unavailable; set MACVNC_FFMPEG_DIR")
            })?);
        }
        let u = &libs[0];
        let c = &libs[2];
        let s = &libs[3];
        for (lib, symbol, major) in [
            (u, b"avutil_version\0".as_slice(), 59),
            (&libs[1], b"swresample_version\0".as_slice(), 5),
            (c, b"avcodec_version\0".as_slice(), 61),
            (s, b"swscale_version\0".as_slice(), 8),
        ] {
            let f = lib.get::<unsafe extern "C" fn() -> u32>(symbol)?;
            if f() >> 16 != major {
                bail!("Unsupported FFmpeg ABI")
            }
        }
        // Silent callback counts concealed missing-reference events. A decoded
        // grey frame can otherwise look successful because receive_frame=0.
        let callback =
            u.get::<unsafe extern "C" fn(Option<LogCallback>)>(b"av_log_set_callback\0")?;
        callback(Some(count_reference_error));
        let log = u.get::<unsafe extern "C" fn(c_int)>(b"av_log_set_level\0")?;
        log(24);
        macro_rules! sym {
            ($l:ident,$n:literal) => {
                *$l.get(concat!($n, "\0").as_bytes())?
            };
        }
        Ok(Self {
            find: sym!(c, "avcodec_find_decoder_by_name"),
            alloc: sym!(c, "avcodec_alloc_context3"),
            open: sym!(c, "avcodec_open2"),
            free: sym!(c, "avcodec_free_context"),
            send: sym!(c, "avcodec_send_packet"),
            receive: sym!(c, "avcodec_receive_frame"),
            packet_alloc: sym!(c, "av_packet_alloc"),
            packet_new: sym!(c, "av_new_packet"),
            packet_free: sym!(c, "av_packet_free"),
            frame_alloc: sym!(u, "av_frame_alloc"),
            frame_free: sym!(u, "av_frame_free"),
            frame_unref: sym!(u, "av_frame_unref"),
            opt: sym!(u, "av_opt_set_int"),
            sws_get: sym!(s, "sws_getCachedContext"),
            sws_scale: sym!(s, "sws_scale"),
            sws_free: sym!(s, "sws_freeContext"),
            _libs: libs,
        })
    }
}
pub struct DecodedTile {
    pub tile: usize,
    pub pts: i64,
    pub frame: RgbaFrame,
}
pub struct HevcDecoder {
    api: Api,
    ctx: Ctx,
    frame: *mut Frame,
    sws: Ctx,
    routes: BTreeMap<i64, usize>,
    reference_slot: usize,
}
impl HevcDecoder {
    pub fn new() -> Result<Self> {
        unsafe {
            let api = Api::load()?;
            let codec = (api.find)(c"hevc".as_ptr());
            if codec.is_null() {
                bail!("FFmpeg HEVC decoder unavailable")
            }
            let mut ctx = (api.alloc)(codec);
            if ctx.is_null() {
                bail!("HEVC context allocation failed")
            }
            // SLICE threads preserve one shared DPB and add no frame-thread latency.
            for (key, value) in [
                (c"threads", 0),
                (c"thread_type", 2),
                (c"flags", 1 << 19),
                (c"max_pixels", 32 * 1024 * 1024),
            ] {
                if (api.opt)(ctx, key.as_ptr(), value, 0) < 0 {
                    (api.free)(&mut ctx);
                    bail!("HEVC configuration failed")
                }
            }
            if (api.open)(ctx, codec, ptr::null_mut()) < 0 {
                (api.free)(&mut ctx);
                bail!("HEVC decoder could not open")
            }
            let frame = (api.frame_alloc)();
            if frame.is_null() {
                (api.free)(&mut ctx);
                bail!("Frame allocation failed")
            }
            let reference_slot = REFERENCE_COUNTERS.iter().position(|slot| {
                slot.context
                    .compare_exchange(0, ctx as usize, Ordering::AcqRel, Ordering::Relaxed)
                    .is_ok()
            });
            let Some(reference_slot) = reference_slot else {
                let mut frame = frame;
                (api.frame_free)(&mut frame);
                (api.free)(&mut ctx);
                bail!("Too many simultaneous native decoders")
            };
            REFERENCE_COUNTERS[reference_slot]
                .count
                .store(0, Ordering::Relaxed);
            REFERENCE_COUNTERS[reference_slot]
                .decode_errors
                .store(0, Ordering::Relaxed);
            Ok(Self {
                api,
                ctx,
                frame,
                sws: ptr::null_mut(),
                routes: BTreeMap::new(),
                reference_slot,
            })
        }
    }
    /// Missing-reference concealment can emit grey pixels without a decode
    /// failure. Request a rate-limited FIR when this rises; do not flush the
    /// shared DPB or request a keyframe for every individual missing reference.
    pub fn take_reference_errors(&mut self) -> u64 {
        REFERENCE_COUNTERS[self.reference_slot]
            .count
            .swap(0, Ordering::AcqRel)
    }
    /// Other AV_LOG_ERROR-or-worse decoder events, excluding missing references.
    /// Some are concealed while receive_frame succeeds; suppress that output
    /// and request rate-limited recovery rather than publishing damaged pixels.
    pub fn take_decode_errors(&mut self) -> u64 {
        REFERENCE_COUNTERS[self.reference_slot]
            .decode_errors
            .swap(0, Ordering::AcqRel)
    }
    pub fn decode(&mut self, au: &AccessUnit) -> Result<Vec<DecodedTile>> {
        unsafe {
            if au.data.is_empty() || au.data.len() > 8 * 1024 * 1024 {
                bail!("HEVC access unit exceeds limit")
            }
            let mut packet = (self.api.packet_alloc)();
            if packet.is_null() {
                bail!("Packet allocation failed")
            }
            if (self.api.packet_new)(packet, au.data.len() as c_int) < 0 {
                (self.api.packet_free)(&mut packet);
                bail!("Packet buffer allocation failed")
            }
            if (*packet).data.is_null() {
                (self.api.packet_free)(&mut packet);
                bail!("Packet buffer allocation failed")
            }
            ptr::copy_nonoverlapping(au.data.as_ptr(), (*packet).data, au.data.len());
            (*packet).pts = au.pts;
            (*packet).dts = au.pts;
            let mut out = vec![];
            let mut code = (self.api.send)(self.ctx, packet);
            if code == -11 {
                match self.drain() {
                    Ok(v) => out.extend(v),
                    Err(e) => {
                        (self.api.packet_free)(&mut packet);
                        return Err(e);
                    }
                }
                code = (self.api.send)(self.ctx, packet);
            }
            (self.api.packet_free)(&mut packet);
            if code < 0 {
                bail!("HEVC packet rejected ({code})")
            }
            self.routes.insert(au.pts, au.tile);
            while self.routes.len() > 1024 {
                self.routes.pop_first();
            }
            out.extend(self.drain()?);
            Ok(out)
        }
    }
    unsafe fn drain(&mut self) -> Result<Vec<DecodedTile>> {
        let mut out = vec![];
        loop {
            let code = (self.api.receive)(self.ctx, self.frame);
            if code == -11 || code == -541478725 {
                break;
            }
            if code < 0 {
                bail!("HEVC frame rejected ({code})")
            }
            let result = self.convert();
            (self.api.frame_unref)(self.frame);
            if let Some(tile) = result? {
                out.push(tile)
            }
        }
        Ok(out)
    }
    unsafe fn convert(&mut self) -> Result<Option<DecodedTile>> {
        let f = &*self.frame;
        let Some(tile) = self.routes.remove(&f.pts) else {
            return Ok(None);
        };
        rgba_len(
            f.width.try_into().context("Invalid HEVC width")?,
            f.height.try_into().context("Invalid HEVC height")?,
        )?;
        // AV_PIX_FMT_RGBA = 26 in the pinned FFmpeg 7 public enum.
        self.sws = (self.api.sws_get)(
            self.sws,
            f.width,
            f.height,
            f.format,
            f.width,
            f.height,
            26,
            2,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null(),
        );
        if self.sws.is_null() {
            bail!("Unsupported HEVC pixel format")
        }
        let mut pixels = allocate_rgba(f.width as u32, f.height as u32)?;
        let dst = [
            pixels.as_mut_ptr(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        ];
        let stride = [f.width * 4, 0, 0, 0];
        let rows = (self.api.sws_scale)(
            self.sws,
            f.data.as_ptr().cast(),
            f.linesize.as_ptr(),
            0,
            f.height,
            dst.as_ptr(),
            stride.as_ptr(),
        );
        if rows != f.height {
            bail!("Incomplete HEVC color conversion")
        }
        Ok(Some(DecodedTile {
            tile,
            pts: f.pts,
            frame: RgbaFrame {
                width: f.width as u32,
                height: f.height as u32,
                pixels,
            },
        }))
    }
}
impl Drop for HevcDecoder {
    fn drop(&mut self) {
        unsafe {
            (self.api.frame_free)(&mut self.frame);
            (self.api.free)(&mut self.ctx);
            if !self.sws.is_null() {
                (self.api.sws_free)(self.sws);
            }
            REFERENCE_COUNTERS[self.reference_slot]
                .context
                .store(0, Ordering::Release);
        }
    }
}

#[cfg(test)]
mod security_tests {
    use super::*;
    #[test]
    fn library_directory_rejects_cwd_relative_and_file_paths() {
        for name in [".", "relative/ffmpeg", ""] {
            assert!(decoder_directory(Path::new(name)).is_err());
        }
        #[cfg(windows)]
        assert!(decoder_directory(Path::new("C:ffmpeg")).is_err());
        let exe = std::env::current_exe().unwrap();
        assert!(decoder_directory(&exe).is_err());
        let parent = exe.parent().unwrap();
        assert_eq!(
            decoder_directory(parent).unwrap(),
            parent.canonicalize().unwrap()
        );
    }
}
