//! Keeps the installer's Windows "Installed apps" entry in step with in-app
//! updates. The installer (scripts/installer/macvnc.nsi) writes a per-user
//! uninstall key; the in-app updater replaces files in place and would otherwise
//! leave the old DisplayVersion behind. Portable copies are left alone: the key
//! is only touched when its InstallLocation is this executable's folder.

#[cfg(windows)]
pub fn sync_version() {
    let _ = windows::sync(env!("CARGO_PKG_VERSION"));
}
#[cfg(not(windows))]
pub fn sync_version() {}

/// Windows paths compare case-insensitively and may carry a trailing separator.
#[cfg_attr(not(windows), allow(dead_code))]
fn same_folder(a: &str, b: &str) -> bool {
    let trim = |s: &str| s.trim_end_matches(['\\', '/']).to_lowercase();
    !a.is_empty() && trim(a) == trim(b)
}

#[cfg(windows)]
mod windows {
    use std::{ffi::c_void, os::windows::ffi::OsStrExt};
    type Hkey = *mut c_void;
    const HKEY_CURRENT_USER: Hkey = 0x8000_0001u32 as i32 as isize as Hkey;
    const KEY_QUERY_VALUE: u32 = 0x0001;
    const KEY_SET_VALUE: u32 = 0x0002;
    const REG_SZ: u32 = 1;
    #[link(name = "advapi32")]
    extern "system" {
        fn RegOpenKeyExW(key: Hkey, sub: *const u16, options: u32, sam: u32, out: *mut Hkey)
            -> i32;
        fn RegQueryValueExW(
            key: Hkey,
            name: *const u16,
            reserved: *mut u32,
            kind: *mut u32,
            data: *mut u8,
            len: *mut u32,
        ) -> i32;
        fn RegSetValueExW(
            key: Hkey,
            name: *const u16,
            reserved: u32,
            kind: u32,
            data: *const u8,
            len: u32,
        ) -> i32;
        fn RegCloseKey(key: Hkey) -> i32;
    }
    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }
    struct Key(Hkey);
    impl Drop for Key {
        fn drop(&mut self) {
            // SAFETY: the handle came from a successful RegOpenKeyExW.
            unsafe { RegCloseKey(self.0) };
        }
    }
    pub fn sync(version: &str) -> Option<()> {
        let folder = std::env::current_exe().ok()?.parent()?.to_owned();
        let folder: Vec<u16> = folder.as_os_str().encode_wide().collect();
        let folder = String::from_utf16(&folder).ok()?;
        let path = wide(r"Software\Microsoft\Windows\CurrentVersion\Uninstall\MacVNC");
        let mut raw = std::ptr::null_mut();
        // SAFETY: valid NUL-terminated path and out-pointer.
        let status = unsafe {
            RegOpenKeyExW(
                HKEY_CURRENT_USER,
                path.as_ptr(),
                0,
                KEY_QUERY_VALUE | KEY_SET_VALUE,
                &mut raw,
            )
        };
        if status != 0 {
            return None; // Not installed with the installer.
        }
        let key = Key(raw);
        let mut buffer = [0u16; 1024];
        let mut len = (buffer.len() * 2) as u32;
        let mut kind = 0;
        let name = wide("InstallLocation");
        // SAFETY: buffer and len describe writable memory of len bytes.
        let status = unsafe {
            RegQueryValueExW(
                key.0,
                name.as_ptr(),
                std::ptr::null_mut(),
                &mut kind,
                buffer.as_mut_ptr().cast(),
                &mut len,
            )
        };
        if status != 0 || kind != REG_SZ {
            return None;
        }
        let chars = (len as usize / 2).min(buffer.len());
        let location = String::from_utf16_lossy(&buffer[..chars]);
        if !super::same_folder(location.trim_end_matches('\0'), &folder) {
            return None; // A portable copy elsewhere must not rewrite the installed entry.
        }
        let value = wide(version);
        let name = wide("DisplayVersion");
        // SAFETY: value is a NUL-terminated UTF-16 string of the given byte length.
        let status = unsafe {
            RegSetValueExW(
                key.0,
                name.as_ptr(),
                0,
                REG_SZ,
                value.as_ptr().cast(),
                (value.len() * 2) as u32,
            )
        };
        (status == 0).then_some(())
    }
}

#[cfg(test)]
mod tests {
    use super::same_folder;
    #[test]
    fn install_location_matches_case_and_trailing_separator_insensitively() {
        assert!(same_folder(
            r"C:\Users\A\AppData\Local\Programs\MacVNC\",
            r"c:\users\a\appdata\local\programs\macvnc"
        ));
        assert!(!same_folder(r"C:\Tools\MacVNC", r"C:\Users\A\MacVNC"));
        assert!(!same_folder("", r"C:\MacVNC"));
    }
}
