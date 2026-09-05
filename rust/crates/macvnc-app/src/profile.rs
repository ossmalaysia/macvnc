//! Only this application's profile is read. Never enumerate other applications' secrets.
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};
use zeroize::{Zeroize, Zeroizing};

const MAX_PROFILE_BYTES: u64 = 64 * 1024;
const MAX_STATE_BYTES: u64 = 1024 * 1024;
const BOUND_PREFIX: &[u8] = b"MACVNC1\0";

#[derive(Serialize, Deserialize)]
struct BoundSecret {
    host: String,
    port: u16,
    username: String,
    password: String,
}
impl Drop for BoundSecret {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

fn read_bounded(path: &Path, limit: u64) -> std::io::Result<Vec<u8>> {
    let file = fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Saved file exceeds size limit",
        ));
    }
    Ok(bytes)
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Profile {
    #[serde(default)]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default)]
    pub username: String,
    #[serde(default = "default_keyboard")]
    pub profile: String,
    #[serde(default)]
    pub auto_connect: bool,
    #[serde(default)]
    pub enc: String,
    #[serde(skip)]
    pub password: String,
    #[serde(skip)]
    pub legacy_password: bool,
}
fn default_port() -> u16 {
    5900
}
fn default_keyboard() -> String {
    "ctrl-as-cmd".into()
}
impl Default for Profile {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: 5900,
            username: String::new(),
            profile: "ctrl-as-cmd".into(),
            auto_connect: false,
            enc: String::new(),
            password: String::new(),
            legacy_password: false,
        }
    }
}
impl Drop for Profile {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

pub fn paths() -> Vec<PathBuf> {
    let base = std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_default()
                .join(".config")
        });
    vec![
        base.join("macvnc").join("rust-profile.json"),
        base.join("macvnc").join("vnc-creds.json"),
        base.join("vnc-client").join("vnc-creds.json"),
    ]
}
pub fn load() -> Result<Option<Profile>, String> {
    load_from(&paths())
}
fn load_from(paths: &[PathBuf]) -> Result<Option<Profile>, String> {
    for path in paths {
        let bytes = match read_bounded(path, MAX_PROFILE_BYTES) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err("Saved connection cannot be read.".into()),
        };
        let mut p: Profile = serde_json::from_slice(&bytes)
            .map_err(|_| "Saved connection is invalid.".to_string())?;
        if !p.enc.is_empty() {
            if let Ok(bytes) = STANDARD.decode(&p.enc) {
                if let Some(encrypted) = bytes.strip_prefix(BOUND_PREFIX) {
                    p.password = decrypt_bound(encrypted, &p).unwrap_or_default();
                } else {
                    // Older formats cannot authenticate the destination fields.
                    // Keep the remembered password, but require an explicit Connect
                    // before migrating it to a destination-bound saved profile.
                    p.auto_connect = false;
                    if let Ok(plain) =
                        decrypt_saved(&bytes, path.parent().unwrap_or(Path::new(".")))
                    {
                        let plain = Zeroizing::new(plain);
                        p.password = std::str::from_utf8(&plain).unwrap_or_default().to_owned();
                        p.legacy_password = !p.password.is_empty();
                    }
                }
            }
        }
        p.auto_connect &= !p.password.is_empty() && !p.host.is_empty() && !p.username.is_empty();
        return Ok(Some(p));
    }
    Ok(None)
}
pub fn save(p: &Profile) -> Result<(), String> {
    save_to(p, &paths().remove(0))
}
fn save_to(p: &Profile, path: &Path) -> Result<(), String> {
    let mut saved = Profile {
        host: p.host.clone(),
        port: p.port,
        username: p.username.clone(),
        profile: p.profile.clone(),
        auto_connect: p.auto_connect && !p.password.is_empty(),
        enc: String::new(),
        password: String::new(),
        legacy_password: false,
    };
    if !p.password.is_empty() {
        let secret = BoundSecret {
            host: p.host.clone(),
            port: p.port,
            username: p.username.clone(),
            password: p.password.clone(),
        };
        let plain = Zeroizing::new(
            serde_json::to_vec(&secret).map_err(|_| "Could not encode secret.".to_string())?,
        );
        if plain.len() > MAX_PROFILE_BYTES as usize / 2 {
            return Err("Saved connection exceeds size limit.".into());
        }
        let mut encrypted = BOUND_PREFIX.to_vec();
        encrypted.extend(protect(&plain)?);
        saved.enc = STANDARD.encode(encrypted);
    }
    let bytes = serde_json::to_vec(&saved).map_err(|_| "Could not encode profile.".to_string())?;
    if bytes.len() as u64 > MAX_PROFILE_BYTES {
        return Err("Saved connection exceeds size limit.".into());
    }
    let parent = path.parent().ok_or("Invalid profile directory.")?;
    fs::create_dir_all(parent).map_err(|_| "Could not create profile directory.".to_string())?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .map_err(|_| "Could not create profile file.".to_string())?;
    temporary
        .write_all(&bytes)
        .and_then(|_| temporary.as_file().sync_all())
        .map_err(|_| "Could not save connection.".to_string())?;
    temporary
        .persist(path)
        .map_err(|_| "Could not replace saved connection.".to_string())?;
    Ok(())
}
fn decrypt_bound(encrypted: &[u8], profile: &Profile) -> Result<String, String> {
    let plain = Zeroizing::new(unprotect(encrypted)?);
    let mut secret: BoundSecret =
        serde_json::from_slice(&plain).map_err(|_| "Invalid saved secret.".to_string())?;
    if secret.host != profile.host
        || secret.port != profile.port
        || secret.username != profile.username
    {
        return Err("Saved connection identity changed.".into());
    }
    Ok(std::mem::take(&mut secret.password))
}
pub fn forget() -> Result<(), String> {
    // A tombstone prevents importing the previous Electron profile again.
    save(&Profile::default())
}
fn decrypt_saved(bytes: &[u8], directory: &Path) -> Result<Vec<u8>, String> {
    if bytes.starts_with(b"v10") {
        // Chromium OSCrypt: v10 + 12-byte GCM nonce + ciphertext + 16-byte tag.
        use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
        if bytes.len() < 31 {
            return Err("Invalid encrypted password.".into());
        }
        let state: serde_json::Value = serde_json::from_slice(
            &read_bounded(&directory.join("Local State"), MAX_STATE_BYTES)
                .map_err(|_| "Saved encryption key is unavailable.".to_string())?,
        )
        .map_err(|_| "Invalid saved encryption state.".to_string())?;
        let encrypted = STANDARD
            .decode(
                state["os_crypt"]["encrypted_key"]
                    .as_str()
                    .ok_or("Saved encryption key is unavailable.")?,
            )
            .map_err(|_| "Invalid saved encryption key.".to_string())?;
        let key = Zeroizing::new(unprotect(
            encrypted
                .strip_prefix(b"DPAPI")
                .ok_or("Unknown saved encryption provider.")?,
        )?);
        let result = Aes256Gcm::new_from_slice(&key)
            .map_err(|_| "Invalid saved encryption key.".to_string())
            .and_then(|cipher| {
                cipher
                    .decrypt(Nonce::from_slice(&bytes[3..15]), &bytes[15..])
                    .map_err(|_| "Cannot decrypt saved password.".to_string())
            });
        result
    } else {
        unprotect(bytes.strip_prefix(b"DPAPI").unwrap_or(bytes))
    }
}

#[cfg(windows)]
mod dpapi {
    use std::{ffi::c_void, ptr};
    #[repr(C)]
    struct Blob {
        len: u32,
        data: *mut u8,
    }
    #[link(name = "crypt32")]
    extern "system" {
        fn CryptProtectData(
            input: *const Blob,
            description: *const u16,
            entropy: *const Blob,
            reserved: *mut c_void,
            prompt: *mut c_void,
            flags: u32,
            output: *mut Blob,
        ) -> i32;
        fn CryptUnprotectData(
            input: *const Blob,
            description: *mut *mut u16,
            entropy: *const Blob,
            reserved: *mut c_void,
            prompt: *mut c_void,
            flags: u32,
            output: *mut Blob,
        ) -> i32;
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn LocalFree(memory: *mut c_void) -> *mut c_void;
    }
    pub fn run(bytes: &[u8], encrypt: bool) -> Result<Vec<u8>, String> {
        let len =
            u32::try_from(bytes.len()).map_err(|_| "Secret exceeds storage limit.".to_string())?;
        let input = Blob {
            len,
            data: bytes.as_ptr() as *mut u8,
        };
        let mut output = Blob {
            len: 0,
            data: ptr::null_mut(),
        };
        // DPAPI allocates output with LocalAlloc; UI_FORBIDDEN prevents modal system prompts.
        unsafe {
            let ok = if encrypt {
                CryptProtectData(
                    &input,
                    ptr::null(),
                    ptr::null(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    1,
                    &mut output,
                )
            } else {
                CryptUnprotectData(
                    &input,
                    ptr::null_mut(),
                    ptr::null(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    1,
                    &mut output,
                )
            };
            if ok == 0 {
                return Err("Windows secure password storage is unavailable.".into());
            }
            if output.len > 0 && output.data.is_null() {
                return Err("Windows returned invalid secure storage data.".into());
            }
            let result = if output.len == 0 {
                Vec::new()
            } else {
                std::slice::from_raw_parts(output.data, output.len as usize).to_vec()
            };
            if !encrypt && output.len > 0 {
                use zeroize::Zeroize;
                std::slice::from_raw_parts_mut(output.data, output.len as usize).zeroize();
            }
            LocalFree(output.data.cast());
            Ok(result)
        }
    }
}
#[cfg(windows)]
fn protect(bytes: &[u8]) -> Result<Vec<u8>, String> {
    dpapi::run(bytes, true)
}
#[cfg(windows)]
fn unprotect(bytes: &[u8]) -> Result<Vec<u8>, String> {
    dpapi::run(bytes, false)
}
#[cfg(not(windows))]
fn protect(_: &[u8]) -> Result<Vec<u8>, String> {
    Err("Secure password storage is currently supported only on Windows.".into())
}
#[cfg(not(windows))]
fn unprotect(_: &[u8]) -> Result<Vec<u8>, String> {
    Err("Secure password storage is currently supported only on Windows.".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(windows)]
    #[test]
    fn saved_secret_is_bound_to_destination_and_replaces_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("profile.json");
        let mut p = Profile::default();
        p.host = "mac.example.invalid".into();
        p.username = "test".into();
        p.password = "synthetic-password".into();
        p.auto_connect = true;
        save_to(&p, &path).unwrap();
        assert!(!String::from_utf8(fs::read(&path).unwrap())
            .unwrap()
            .contains("synthetic-password"));
        let loaded = load_from(std::slice::from_ref(&path)).unwrap().unwrap();
        assert_eq!(loaded.password, p.password);
        assert!(loaded.auto_connect);
        let original: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        for (field, value) in [
            ("host", serde_json::json!("other.invalid")),
            ("port", serde_json::json!(5902)),
            ("username", serde_json::json!("other")),
        ] {
            let mut changed = original.clone();
            changed[field] = value;
            fs::write(&path, serde_json::to_vec(&changed).unwrap()).unwrap();
            let loaded = load_from(std::slice::from_ref(&path)).unwrap().unwrap();
            assert!(loaded.password.is_empty());
            assert!(!loaded.auto_connect);
        }
        p.password.zeroize();
        save_to(&p, &path).unwrap();
        assert!(load_from(&[path]).unwrap().unwrap().password.is_empty());
    }
    #[cfg(windows)]
    #[test]
    fn legacy_password_remains_available_but_never_autoconnects() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("profile.json");
        let data = serde_json::json!({"host":"mac.invalid","username":"test","autoConnect":true,"enc":STANDARD.encode(protect(b"synthetic-password").unwrap())});
        fs::write(&path, serde_json::to_vec(&data).unwrap()).unwrap();
        let loaded = load_from(&[path]).unwrap().unwrap();
        assert_eq!(loaded.password, "synthetic-password");
        assert!(loaded.legacy_password);
        assert!(!loaded.auto_connect);
    }
    #[test]
    fn oversized_saved_profile_is_rejected_before_parsing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("profile.json");
        fs::write(&path, vec![b' '; MAX_PROFILE_BYTES as usize + 1]).unwrap();
        assert!(load_from(&[path]).is_err());
    }
    #[test]
    fn serialization_never_contains_password() {
        let mut p = Profile::default();
        p.password = "synthetic-secret-do-not-save".into();
        assert!(!serde_json::to_string(&p)
            .unwrap()
            .contains("synthetic-secret"));
    }
    #[test]
    fn default_host_is_blank() {
        assert!(Profile::default().host.is_empty());
    }
    #[test]
    fn corrupt_current_profile_never_restores_legacy_account() {
        let dir = std::env::temp_dir().join(format!(
            "macvnc-corrupt-profile-test-{}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        let current = dir.join("current.json");
        let legacy = dir.join("legacy.json");
        fs::write(&current, b"invalid json").unwrap();
        fs::write(
            &legacy,
            br#"{"host":"legacy.invalid","username":"old-account"}"#,
        )
        .unwrap();
        assert!(load_from(&[current.clone(), legacy.clone()]).is_err());
        fs::remove_file(current).unwrap();
        fs::remove_file(legacy).unwrap();
        fs::remove_dir(dir).unwrap();
    }
    #[test]
    fn unavailable_password_disables_autoconnect() {
        let dir = std::env::temp_dir().join(format!("macvnc-profile-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("profile.json");
        fs::write(
            &path,
            br#"{"host":"example.invalid","username":"test","autoConnect":true,"enc":"invalid"}"#,
        )
        .unwrap();
        let p = load_from(std::slice::from_ref(&path)).unwrap().unwrap();
        assert!(!p.auto_connect);
        assert!(p.password.is_empty());
        fs::remove_file(path).unwrap();
        fs::remove_dir(dir).unwrap();
    }
    #[cfg(windows)]
    #[test]
    fn dpapi_roundtrip_and_rejects_modified_blob() {
        let bytes = protect(b"synthetic-password").unwrap();
        assert_eq!(unprotect(&bytes).unwrap(), b"synthetic-password");
        let mut bad = bytes;
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(unprotect(&bad).is_err());
    }
}
