//! Volume discovery and process elevation (Windows).

use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation};
use windows::Win32::Storage::FileSystem::{GetDiskFreeSpaceExW, GetVolumeInformationW, GetVolumePathNameW};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::core::PCWSTR;

use crate::scan::ScanError;

fn wide(s: &std::ffi::OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

fn from_wide(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

/// Whether the current process is elevated.
pub fn is_elevated() -> bool {
    // SAFETY: Standard token query; the output buffer has the correct size and handles are closed.
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut e = TOKEN_ELEVATION::default();
        let mut len = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut e as *mut _ as *mut _),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        )
        .is_ok();
        let _ = CloseHandle(token);
        ok && e.TokenIsElevated != 0
    }
}

/// Mount point of the volume containing `path`.
pub fn volume_root_of(path: &Path) -> Result<String, ScanError> {
    let mut p = path.as_os_str().to_owned();
    // Treat a bare drive letter as its volume root.
    if p.len() == 2 && p.to_string_lossy().ends_with(':') {
        p.push("\\");
    }
    let w = wide(&p);
    let mut buf = vec![0u16; w.len() + 64];
    // SAFETY: The input is NUL-terminated and the output buffer is valid.
    unsafe { GetVolumePathNameW(PCWSTR(w.as_ptr()), &mut buf) }
        .map_err(|e| ScanError::Io(format!("volume of {}: {e}", path.display())))?;
    Ok(from_wide(&buf))
}

/// Whether `path` is the volume root itself.
pub fn is_volume_root(path: &Path, mount: &str) -> bool {
    let a = path.to_string_lossy();
    let a = a.trim_end_matches(['\\', '/']);
    let b = mount.trim_end_matches('\\');
    a.eq_ignore_ascii_case(b)
}

/// Filesystem name, such as NTFS, ReFS, or exFAT.
pub fn filesystem_name(mount: &str) -> Result<String, ScanError> {
    let w = wide(std::ffi::OsStr::new(mount));
    let mut fs = [0u16; 64];
    // SAFETY: The root path is NUL-terminated and the output buffer is valid.
    unsafe { GetVolumeInformationW(PCWSTR(w.as_ptr()), None, None, None, None, Some(&mut fs)) }
        .map_err(|e| ScanError::Io(format!("volume information for {mount}: {e}")))?;
    Ok(from_wide(&fs))
}

/// Volume capacity and free space in bytes: `(total, free)`.
pub fn disk_space(mount: &str) -> Result<(u64, u64), ScanError> {
    let w = wide(std::ffi::OsStr::new(mount));
    let mut free_to_caller = 0u64;
    let mut total = 0u64;
    let mut free = 0u64;
    // SAFETY: All output pointers are valid.
    unsafe {
        GetDiskFreeSpaceExW(
            PCWSTR(w.as_ptr()),
            Some(&mut free_to_caller),
            Some(&mut total),
            Some(&mut free),
        )
    }
    .map_err(|e| ScanError::Io(format!("disk space for {mount}: {e}")))?;
    Ok((total, free))
}

/// A local drive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DriveInfo {
    /// Mount point, such as a drive-letter root.
    pub mount: String,
    /// Volume label, which may be empty.
    pub label: String,
    /// Filesystem name.
    pub filesystem: String,
    /// Total capacity in bytes.
    pub total: u64,
    /// Free space in bytes.
    pub free: u64,
    /// Whether the drive is removable.
    pub removable: bool,
}

impl DriveInfo {
    /// Used bytes.
    pub fn used(&self) -> u64 {
        self.total.saturating_sub(self.free)
    }
}

/// Local fixed and removable drives with drive letters, sorted by mount point.
/// Uses sysinfo for volume enumeration, labels, filesystem names, and capacity.
pub fn list_drives() -> Vec<DriveInfo> {
    let disks = sysinfo::Disks::new_with_refreshed_list();
    let mut out: Vec<DriveInfo> = disks
        .list()
        .iter()
        .filter_map(|d| {
            let mount = d.mount_point().to_string_lossy().into_owned();
            // Keep only drive-letter mount points to avoid listing folder-mounted volumes twice.
            let b = mount.as_bytes();
            if !(b.len() == 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\') {
                return None;
            }
            Some(DriveInfo {
                mount: mount.to_ascii_uppercase(),
                label: d.name().to_string_lossy().into_owned(),
                filesystem: d.file_system().to_string_lossy().into_owned(),
                total: d.total_space(),
                free: d.available_space(),
                removable: d.is_removable(),
            })
        })
        .collect();
    out.sort_by(|a, b| a.mount.cmp(&b.mount));
    out.dedup_by(|a, b| a.mount == b.mount);
    out
}

/// Whether the user has an unelevated administrator token. Elevation then requires consent
/// rather than another account password. Standard users return false to avoid a credential prompt.
pub fn can_elevate() -> bool {
    use windows::Win32::Security::{TOKEN_ELEVATION_TYPE, TokenElevationType, TokenElevationTypeLimited};
    // SAFETY: Standard token query; the output buffer has the correct size and handles are closed.
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut t = TOKEN_ELEVATION_TYPE::default();
        let mut len = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevationType,
            Some(&mut t as *mut _ as *mut _),
            size_of::<TOKEN_ELEVATION_TYPE>() as u32,
            &mut len,
        )
        .is_ok();
        let _ = CloseHandle(token);
        ok && t == TokenElevationTypeLimited
    }
}

/// Launch `exe args` elevated through Shell runas. Return after launch without waiting for exit.
/// If consent is declined or elevation is unavailable, return an error so the caller can continue.
///
/// A direct Shell call avoids wrappers that wait for the elevated child process to exit.
pub fn relaunch_elevated(exe: &Path, args: &[String]) -> Result<(), String> {
    use windows::Win32::UI::Shell::{SEE_MASK_FLAG_NO_UI, SEE_MASK_NOASYNC, SHELLEXECUTEINFOW, ShellExecuteExW};
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
    let file = wide(exe.as_os_str());
    let params: Vec<String> = args.iter().map(|a| quote_arg(a)).collect();
    let params = wide(std::ffi::OsStr::new(&params.join(" ")));
    let verb = wide(std::ffi::OsStr::new("runas"));
    let cwd = std::env::current_dir().ok().map(|d| wide(d.as_os_str()));
    let mut info = SHELLEXECUTEINFOW {
        cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI,
        lpVerb: PCWSTR(verb.as_ptr()),
        lpFile: PCWSTR(file.as_ptr()),
        lpParameters: PCWSTR(params.as_ptr()),
        lpDirectory: cwd.as_ref().map_or(PCWSTR::null(), |d| PCWSTR(d.as_ptr())),
        nShow: SW_SHOWNORMAL.0,
        ..Default::default()
    };
    // SAFETY: Strings in the structure are NUL-terminated and remain alive during the call.
    unsafe { ShellExecuteExW(&mut info) }.map_err(|e| format!("Failed to launch with administrator privileges: {e}"))
}

/// Quote a Windows command-line argument using CommandLineToArgvW rules.
fn quote_arg(a: &str) -> String {
    if !a.is_empty() && !a.contains([' ', '\t', '"']) {
        return a.to_string();
    }
    let mut out = String::from("\"");
    let mut backslashes = 0;
    for ch in a.chars() {
        match ch {
            '\\' => backslashes += 1,
            '"' => {
                out.push_str(&"\\".repeat(backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            }
            c => {
                out.push_str(&"\\".repeat(backslashes));
                out.push(c);
                backslashes = 0;
            }
        }
    }
    out.push_str(&"\\".repeat(backslashes * 2));
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_the_system_drive() {
        let drives = list_drives();
        let sys = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into()).to_ascii_uppercase();
        let c = drives.iter().find(|d| d.mount.starts_with(&sys)).expect("system drive listed");
        assert!(c.total > 0 && c.used() > 0 && c.used() <= c.total);
        assert_eq!(c.filesystem, filesystem_name(&c.mount).unwrap());
        let (total, free) = disk_space(&c.mount).unwrap();
        assert_eq!(total, c.total);
        // Free space changes continuously; only require values to be in the same range.
        assert!(free.abs_diff(c.free) < 1 << 30);
    }

    #[test]
    fn elevation_queries_do_not_panic() {
        // The account determines elevation; an already elevated process cannot be elevatable.
        if is_elevated() {
            assert!(!can_elevate());
        }
    }

    #[test]
    fn command_line_quoting() {
        assert_eq!(quote_arg("--elevated"), "--elevated");
        assert_eq!(quote_arg("C:\\Program Files\\x"), "\"C:\\Program Files\\x\"");
        assert_eq!(quote_arg("D:\\a b\\"), "\"D:\\a b\\\\\"");
        assert_eq!(quote_arg("say \"hi\""), "\"say \\\"hi\\\"\"");
        assert_eq!(quote_arg(""), "\"\"");
    }
}
