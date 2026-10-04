//! Release and archive validation; no network or process management here.
use anyhow::{bail, ensure, Context, Result};
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

pub const ARCHIVE: &str = "macvnc-rust-windows-x64.zip";
pub const MAX_ARCHIVE: u64 = 512 * 1024 * 1024;
const MAX_EXPANDED: u64 = 2 * 1024 * 1024 * 1024;
pub const REPO: &str = "https://github.com/ossmalaysia/macvnc";

#[derive(Clone)]
pub struct Release {
    pub version: String,
    pub notes: String,
    pub page: String,
    pub archive_url: String,
    pub checksum_url: String,
    pub size: u64,
}
#[derive(Deserialize)]
struct ApiRelease {
    tag_name: String,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
    #[serde(default)]
    body: Option<String>,
    assets: Vec<Asset>,
}
#[derive(Deserialize)]
struct Asset {
    name: String,
    browser_download_url: String,
    size: u64,
}

pub fn parse_release(bytes: &[u8], current: &str) -> Result<Option<Release>> {
    let release: ApiRelease = serde_json::from_slice(bytes).context("invalid release response")?;
    if release.draft || release.prerelease {
        return Ok(None);
    }
    let version = Version::parse(
        release
            .tag_name
            .strip_prefix('v')
            .context("unsupported release tag")?,
    )?;
    if !version.pre.is_empty() || !version.build.is_empty() || version <= Version::parse(current)? {
        return Ok(None);
    }
    ensure!(release.assets.len() <= 64, "release has too many assets");
    let asset = |name: &str, limit: u64| -> Result<&Asset> {
        let mut matching = release.assets.iter().filter(|a| a.name == name);
        let a = matching
            .next()
            .context("release is missing its Windows package or checksum")?;
        ensure!(matching.next().is_none(), "ambiguous release asset");
        ensure!(
            a.size > 0 && a.size <= limit,
            "release asset exceeds size limit"
        );
        ensure!(
            a.browser_download_url
                == format!("{REPO}/releases/download/{}/{name}", release.tag_name),
            "unexpected release download URL"
        );
        Ok(a)
    };
    let archive = asset(ARCHIVE, MAX_ARCHIVE)?;
    let checksum = asset("SHA256SUMS.txt", 64 * 1024)?;
    Ok(Some(Release {
        version: version.to_string(),
        notes: release
            .body
            .as_deref()
            .unwrap_or_default()
            .chars()
            .take(8000)
            .collect(),
        page: format!("{REPO}/releases/tag/{}", release.tag_name),
        archive_url: archive.browser_download_url.clone(),
        checksum_url: checksum.browser_download_url.clone(),
        size: archive.size,
    }))
}

pub fn checksum(bytes: &[u8]) -> Result<String> {
    let text = std::str::from_utf8(bytes)?.trim_start_matches('\u{feff}');
    let mut found = None;
    for line in text.lines().filter(|s| !s.trim().is_empty()) {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() == 2 && fields[1].trim_start_matches('*') == ARCHIVE {
            ensure!(found.is_none(), "duplicate package checksum");
            ensure!(
                fields[0].len() == 64 && fields[0].bytes().all(|b| b.is_ascii_hexdigit()),
                "invalid SHA-256 checksum"
            );
            found = Some(fields[0].to_ascii_lowercase());
        }
    }
    found.context("release checksum does not name the Windows package")
}

pub fn hash_file(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

pub fn safe_component(name: &str) -> bool {
    if name.is_empty()
        || name.len() > 255
        || name == "."
        || name == ".."
        || name.ends_with([' ', '.'])
        || name
            .chars()
            .any(|c| c.is_control() || "/\\:<>\"|?*".contains(c))
    {
        return false;
    }
    let stem = name
        .split('.')
        .next()
        .unwrap_or_default()
        .trim_end()
        .to_ascii_uppercase();
    !["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"].contains(&stem.as_str())
        && !["1", "2", "3", "4", "5", "6", "7", "8", "9", "¹", "²", "³"]
            .iter()
            .any(|n| stem == format!("COM{n}") || stem == format!("LPT{n}"))
}

pub fn managed_entry(name: &str) -> bool {
    safe_component(name)
        && (name == "source"
            || name == "macvnc-app.exe"
            || name.ends_with(".dll")
            || [
                "UPDATE.json",
                "README.txt",
                "LICENSE.txt",
                "LICENSE-AGPL-3.0.txt",
                "FFMPEG-LICENSE.txt",
                "FFMPEG-GPL-3.0.txt",
                "THIRD_PARTY.md",
            ]
            .contains(&name))
}

#[derive(Serialize, Deserialize)]
pub struct PackageIdentity {
    pub schema: u32,
    pub version: String,
    pub target: String,
    pub runtime: Vec<String>,
}
#[derive(Serialize, Deserialize)]
pub struct FileEntry {
    pub path: PathBuf,
    pub sha256: String,
    pub size: u64,
}

pub fn validate_relative(path: &Path) -> Result<()> {
    ensure!(
        !path.as_os_str().is_empty() && !path.is_absolute(),
        "invalid package path"
    );
    let parts: Vec<_> = path.components().collect();
    ensure!(parts.len() <= 32, "package path nesting exceeds limit");
    for part in &parts {
        match part {
            std::path::Component::Normal(s) => ensure!(
                s.to_str().is_some_and(safe_component),
                "unsafe package path"
            ),
            _ => bail!("unsafe package path"),
        }
    }
    let first = parts[0]
        .as_os_str()
        .to_str()
        .context("invalid package path")?;
    ensure!(
        managed_entry(first) && (parts.len() == 1 || first == "source"),
        "unsupported package entry"
    );
    Ok(())
}
pub fn path_key(path: &Path) -> String {
    path.components()
        .map(|c| c.as_os_str().to_string_lossy().to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join("/")
}

pub fn extract(
    archive: &Path,
    destination: &Path,
    version: &str,
    mut cancelled: impl FnMut() -> Result<()>,
) -> Result<Vec<FileEntry>> {
    ensure!(
        fs::metadata(archive)?.len() <= MAX_ARCHIVE,
        "archive exceeds size limit"
    );
    let mut zip = zip::ZipArchive::new(File::open(archive)?)?;
    ensure!(zip.len() <= 100_000, "package has too many entries");
    fs::create_dir(destination)?;
    let mut total = 0u64;
    let mut seen = HashSet::new();
    let mut files = vec![];
    for index in 0..zip.len() {
        cancelled()?;
        let mut entry = zip.by_index(index)?;
        let name = entry.name().trim_end_matches('/');
        if name == "macvnc-rust" && entry.is_dir() {
            continue;
        }
        let relative = name
            .strip_prefix("macvnc-rust/")
            .context("unexpected package root")?;
        ensure!(!relative.contains('\\'), "unsafe archive path");
        let path = PathBuf::from(relative);
        validate_relative(&path)?;
        ensure!(seen.insert(path_key(&path)), "duplicate package path");
        let kind = entry.unix_mode().unwrap_or(0) & 0o170000;
        ensure!(
            kind == 0
                || (entry.is_dir() && kind == 0o040000)
                || (!entry.is_dir() && kind == 0o100000),
            "links and special files are unsupported"
        );
        let target = destination.join(&path);
        if entry.is_dir() {
            fs::create_dir_all(target)?;
            continue;
        }
        total = total
            .checked_add(entry.size())
            .context("package size overflow")?;
        ensure!(
            entry.size() <= MAX_ARCHIVE && total <= MAX_EXPANDED,
            "expanded package exceeds size limit"
        );
        fs::create_dir_all(target.parent().context("missing package parent")?)?;
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&target)?;
        let mut hash = Sha256::new();
        let mut copied = 0u64;
        let mut buffer = [0; 64 * 1024];
        loop {
            cancelled()?;
            let n = entry.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            copied += n as u64;
            ensure!(
                copied <= entry.size(),
                "archive entry exceeds declared size"
            );
            output.write_all(&buffer[..n])?;
            hash.update(&buffer[..n]);
        }
        ensure!(copied == entry.size(), "truncated package entry");
        if path.components().count() == 1 {
            output.sync_all()?;
        }
        files.push(FileEntry {
            path,
            sha256: format!("{:x}", hash.finalize()),
            size: copied,
        });
    }
    for required in [
        "macvnc-app.exe",
        "UPDATE.json",
        "LICENSE-AGPL-3.0.txt",
        "LICENSE.txt",
        "FFMPEG-LICENSE.txt",
        "THIRD_PARTY.md",
        "source/Cargo.toml",
    ] {
        ensure!(
            files.iter().any(|f| f.path == Path::new(required)),
            "package is missing required files"
        );
    }
    ensure!(
        files
            .iter()
            .any(|f| f.path.extension().is_some_and(|s| s == "dll")),
        "package has no runtime DLLs"
    );
    let identity: PackageIdentity =
        serde_json::from_reader(File::open(destination.join("UPDATE.json"))?.take(4097))?;
    ensure!(
        identity.schema == 1 && identity.version == version && identity.target == "windows-x64",
        "package version or platform does not match the release"
    );
    ensure!(
        identity.runtime.len() <= 128,
        "runtime inventory exceeds limit"
    );
    let mut runtime = HashSet::new();
    for name in &identity.runtime {
        ensure!(
            safe_component(name)
                && name.ends_with(".dll")
                && runtime.insert(name.to_ascii_lowercase()),
            "invalid runtime inventory"
        );
        ensure!(
            files.iter().any(|f| f.path == Path::new(name)),
            "package is missing a declared runtime DLL"
        );
    }
    for prefix in ["avcodec-", "avutil-", "swresample-", "swscale-"] {
        ensure!(
            identity.runtime.iter().any(|n| n.starts_with(prefix)),
            "package is missing a required FFmpeg runtime library"
        );
    }
    let mut exe = File::open(destination.join("macvnc-app.exe"))?;
    let mut header = vec![];
    Read::by_ref(&mut exe).take(4096).read_to_end(&mut header)?;
    ensure!(
        header.starts_with(b"MZ") && header.len() >= 64,
        "invalid Windows executable"
    );
    let pe = u32::from_le_bytes(header[60..64].try_into()?) as usize;
    ensure!(
        pe <= header.len().saturating_sub(6)
            && &header[pe..pe + 4] == b"PE\0\0"
            && header[pe + 4..pe + 6] == [0x64, 0x86],
        "package executable is not Windows x64"
    );
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture_zip(path: &Path, version: &str) {
        let mut zip = zip::ZipWriter::new(File::create(path).unwrap());
        let mut exe = vec![0u8; 128];
        exe[..2].copy_from_slice(b"MZ");
        exe[60..64].copy_from_slice(&64u32.to_le_bytes());
        exe[64..70].copy_from_slice(b"PE\0\0\x64\x86");
        let identity = serde_json::to_vec(&PackageIdentity {
            schema: 1,
            version: version.into(),
            target: "windows-x64".into(),
            runtime: [
                "avcodec-61.dll",
                "avutil-59.dll",
                "swresample-5.dll",
                "swscale-8.dll",
            ]
            .map(String::from)
            .to_vec(),
        })
        .unwrap();
        for (name, bytes) in [
            ("macvnc-app.exe", exe.as_slice()),
            ("UPDATE.json", &identity),
            ("avcodec-61.dll", b"synthetic DLL"),
            ("avutil-59.dll", b"synthetic DLL"),
            ("swresample-5.dll", b"synthetic DLL"),
            ("swscale-8.dll", b"synthetic DLL"),
            ("LICENSE-AGPL-3.0.txt", b"synthetic license"),
            ("LICENSE.txt", b"synthetic license"),
            ("FFMPEG-LICENSE.txt", b"synthetic license"),
            ("THIRD_PARTY.md", b"synthetic notices"),
            ("source/Cargo.toml", b"synthetic source"),
        ] {
            zip.start_file(
                format!("macvnc-rust/{name}"),
                zip::write::SimpleFileOptions::default(),
            )
            .unwrap();
            zip.write_all(bytes).unwrap();
        }
        zip.finish().unwrap();
    }
    #[test]
    fn valid_package_is_extracted_and_bound_to_its_release_version() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("fixture.zip");
        fixture_zip(&archive, "0.1.10");
        let files = extract(&archive, &dir.path().join("package"), "0.1.10", || Ok(())).unwrap();
        assert_eq!(files.len(), 11);
        for file in files {
            assert_eq!(
                hash_file(&dir.path().join("package").join(file.path)).unwrap(),
                file.sha256
            );
        }
        assert!(extract(
            &archive,
            &dir.path().join("wrong-version"),
            "0.1.11",
            || Ok(())
        )
        .is_err());
    }
    #[test]
    fn malicious_archive_paths_and_links_never_escape_staging() {
        for name in [
            "macvnc-rust/../../escaped.txt",
            "macvnc-rust/source/../../escaped.txt",
            "macvnc-rust/source/NUL.txt",
            "macvnc-rust/source/x:ads",
            "macvnc-rust/source/escape-link",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let archive = dir.path().join("fixture.zip");
            let mut zip = zip::ZipWriter::new(File::create(&archive).unwrap());
            if name.ends_with("escape-link") {
                zip.add_symlink(
                    name,
                    "../../escaped.txt",
                    zip::write::SimpleFileOptions::default(),
                )
                .unwrap();
            } else {
                zip.start_file(name, zip::write::SimpleFileOptions::default())
                    .unwrap();
                zip.write_all(b"untrusted").unwrap();
            }
            zip.finish().unwrap();
            assert!(extract(&archive, &dir.path().join("package"), "0.1.10", || Ok(())).is_err());
            assert!(!dir.path().join("escaped.txt").exists());
        }
    }
    #[test]
    fn extraction_cancellation_leaves_installed_files_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("fixture.zip");
        fixture_zip(&archive, "0.1.10");
        let installed = dir.path().join("macvnc-app.exe");
        fs::write(&installed, b"keep installed app").unwrap();
        let mut calls = 0;
        assert!(
            extract(&archive, &dir.path().join("package"), "0.1.10", || {
                calls += 1;
                ensure!(calls < 5, "cancelled");
                Ok(())
            })
            .is_err()
        );
        assert_eq!(fs::read(installed).unwrap(), b"keep installed app");
    }
    #[test]
    fn stable_versions_and_exact_release_assets_only() {
        let json = |tag: &str| {
            serde_json::json!({"tag_name":tag, "assets":[
                {"name":ARCHIVE,"size":10,"browser_download_url":format!("{REPO}/releases/download/{tag}/{ARCHIVE}")},
                {"name":"SHA256SUMS.txt","size":100,"browser_download_url":format!("{REPO}/releases/download/{tag}/SHA256SUMS.txt")}
            ]})
        };
        assert_eq!(
            parse_release(&serde_json::to_vec(&json("v0.1.10")).unwrap(), "0.1.9")
                .unwrap()
                .unwrap()
                .version,
            "0.1.10"
        );
        for tag in ["v0.1.9", "v0.1.8", "v0.1.10-rc.1"] {
            assert!(
                parse_release(&serde_json::to_vec(&json(tag)).unwrap(), "0.1.9")
                    .unwrap()
                    .is_none()
            );
        }
        let mut evil = json("v0.1.10");
        evil["assets"][0]["browser_download_url"] = "https://example.com/app.zip".into();
        assert!(parse_release(&serde_json::to_vec(&evil).unwrap(), "0.1.9").is_err());
        let mut duplicate = json("v0.1.10");
        let a = duplicate["assets"][0].clone();
        duplicate["assets"].as_array_mut().unwrap().push(a);
        assert!(parse_release(&serde_json::to_vec(&duplicate).unwrap(), "0.1.9").is_err());
    }
    #[test]
    fn checksum_requires_one_exact_asset_and_valid_hash() {
        let line = format!("{}  {ARCHIVE}\r\n", "AB".repeat(32));
        assert_eq!(checksum(line.as_bytes()).unwrap(), "ab".repeat(32));
        assert!(checksum(format!("{line}{line}").as_bytes()).is_err());
        assert!(checksum(b"bad  macvnc-rust-windows-x64.zip").is_err());
        assert!(checksum(format!("{}  other.zip", "ab".repeat(32)).as_bytes()).is_err());
    }
    #[test]
    fn unsafe_paths_and_windows_aliases_are_rejected() {
        for name in [
            "../macvnc-app.exe",
            "/macvnc-app.exe",
            "source/../profile.json",
            "source/NUL.txt",
            "source/COM¹.txt",
            "source/CON .txt",
            "source/x:ads",
            "other.exe",
            "macvnc-app.exe/child",
            "source/x.",
        ] {
            assert!(validate_relative(Path::new(name)).is_err(), "{name}");
        }
        assert!(validate_relative(Path::new("source/vendor/a/src/lib.rs")).is_ok());
    }
}
