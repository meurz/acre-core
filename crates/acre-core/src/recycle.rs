//! Move files and directories to the recycle bin (Windows).
//!
//! Uses the trash crate (IFileOperation, with undo support and no system UI). On failure,
//! probes individual entries to distinguish files in use, access denial, and missing paths.

use std::fmt;
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

/// Structured deletion failure reason. UI clients can localize these variants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeleteFailure {
    /// Another process holds a handle that prevents deletion.
    InUse,
    /// The caller lacks permission.
    AccessDenied,
    /// The path no longer exists.
    NotFound,
    /// Another failure, such as an unavailable recycle bin; see `detail`.
    Other,
}

impl DeleteFailure {
    /// A short English description. Localized clients should match the enum variants.
    pub fn label(self) -> &'static str {
        match self {
            DeleteFailure::InUse => "In use by another program",
            DeleteFailure::AccessDenied => "Access denied",
            DeleteFailure::NotFound => "No longer exists",
            DeleteFailure::Other => "Other error",
        }
    }
}

/// Classify a Windows error code; return `None` for unrecognized codes.
pub(crate) fn failure_kind(code: Option<i32>) -> Option<DeleteFailure> {
    match code {
        Some(32 | 33) => Some(DeleteFailure::InUse),
        Some(5) => Some(DeleteFailure::AccessDenied),
        Some(2 | 3) => Some(DeleteFailure::NotFound),
        _ => None,
    }
}

/// A deletion failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeleteError {
    /// Structured reason.
    pub kind: DeleteFailure,
    /// The blocking entry, which may be a child of the requested directory.
    pub path: PathBuf,
    /// Original system or library diagnostic; its language may follow the operating system.
    pub detail: String,
}

impl fmt::Display for DeleteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let p = self.path.display();
        match self.kind {
            DeleteFailure::InUse => write!(f, "In use by another program: {p}"),
            DeleteFailure::AccessDenied => write!(f, "Permission denied deleting: {p}"),
            DeleteFailure::NotFound => write!(f, "Path no longer exists: {p}"),
            DeleteFailure::Other => write!(f, "Could not delete: {}", self.detail),
        }
    }
}

impl std::error::Error for DeleteError {}

/// Move a file or directory to the recycle bin. Success means the original path is gone.
pub fn move_to_recycle_bin(path: &Path) -> Result<(), DeleteError> {
    if std::fs::symlink_metadata(path).is_err() {
        return Err(DeleteError {
            kind: DeleteFailure::NotFound,
            path: path.to_path_buf(),
            detail: String::new(),
        });
    }
    let detail = match trash::delete(path) {
        Ok(()) if std::fs::symlink_metadata(path).is_err() => return Ok(()),
        Ok(()) => "The operation was aborted".to_string(),
        Err(e) => e.to_string(),
    };
    if std::fs::symlink_metadata(path).is_err() {
        // The operation reported an error after moving the item successfully.
        return Ok(());
    }
    Err(match probe(path) {
        Some((kind, p)) => DeleteError { kind, path: p, detail },
        None => DeleteError {
            kind: DeleteFailure::Other,
            path: path.to_path_buf(),
            detail,
        },
    })
}

/// Bound failure probing so a failed delete does not require traversing a large tree.
const PROBE_LIMIT: usize = 200_000;

/// Find the first blocking entry, starting with the requested path and then its children.
fn probe(path: &Path) -> Option<(DeleteFailure, PathBuf)> {
    if let Some(k) = check_one(path) {
        return Some((k, path.to_path_buf()));
    }
    let meta = std::fs::symlink_metadata(path).ok()?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return None;
    }
    let mut stack = vec![path.to_path_buf()];
    let mut seen = 0usize;
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            return Some((DeleteFailure::AccessDenied, dir));
        };
        for e in rd.flatten() {
            seen += 1;
            if seen > PROBE_LIMIT {
                return None;
            }
            let p = e.path();
            if let Some(k) = check_one(&p) {
                return Some((k, p));
            }
            if let Ok(ft) = e.file_type()
                && ft.is_dir()
                && !ft.is_symlink()
            {
                stack.push(p);
            }
        }
    }
    None
}

/// Open with delete access and full sharing to detect handles that deny delete sharing.
fn check_one(path: &Path) -> Option<DeleteFailure> {
    const DELETE: u32 = 0x0001_0000;
    const SHARE_ALL: u32 = 0x1 | 0x2 | 0x4;
    const BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    match std::fs::OpenOptions::new()
        .access_mode(DELETE)
        .share_mode(SHARE_ALL)
        .custom_flags(BACKUP_SEMANTICS | OPEN_REPARSE_POINT)
        .open(path)
    {
        Ok(_) => None,
        Err(e) => failure_kind(e.raw_os_error()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Delete only test-created items, then purge those specific items from the recycle bin.
    #[test]
    fn recycles_own_files_and_explains_failures() {
        // A runner can redirect TEMP to a scratch volume without a recycle bin.
        // Keep the fixture on the user profile's local volume instead.
        let local = std::env::var_os("LOCALAPPDATA").expect("LOCALAPPDATA is required for the recycle-bin test");
        let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let dir = PathBuf::from(local).join(format!("acre-recycle-test-{}-{nonce}", std::process::id()));
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        let canonical_dir = dir.canonicalize().unwrap();
        std::fs::write(dir.join("a.txt"), b"acre recycle test").unwrap();
        std::fs::write(dir.join("sub/b.txt"), b"acre recycle test").unwrap();
        std::fs::write(dir.join("locked.txt"), b"acre recycle test").unwrap();
        std::fs::create_dir_all(dir.join("busy")).unwrap();
        std::fs::write(dir.join("busy/held.txt"), b"acre recycle test").unwrap();

        let result = std::panic::catch_unwind(|| {
            move_to_recycle_bin(&dir.join("a.txt")).unwrap();
            assert!(!dir.join("a.txt").exists());
            move_to_recycle_bin(&dir.join("sub")).unwrap();
            assert!(!dir.join("sub").exists());

            // A handle that disallows delete sharing must be reported as an in-use file.
            let held = std::fs::OpenOptions::new().read(true).share_mode(0).open(dir.join("locked.txt")).unwrap();
            let e = move_to_recycle_bin(&dir.join("locked.txt")).unwrap_err();
            assert_eq!(e.kind, DeleteFailure::InUse, "{e}");
            assert!(dir.join("locked.txt").exists());
            drop(held);

            // Identify the specific blocking file inside a directory.
            let held = std::fs::OpenOptions::new().read(true).share_mode(0).open(dir.join("busy/held.txt")).unwrap();
            let e = move_to_recycle_bin(&dir.join("busy")).unwrap_err();
            assert_eq!(e.kind, DeleteFailure::InUse, "{e}");
            assert!(e.path.ends_with("held.txt"), "{e}");
            drop(held);

            let e = move_to_recycle_bin(&dir.join("gone.txt")).unwrap_err();
            assert_eq!(e.kind, DeleteFailure::NotFound);
        });

        // Purge only items recycled by this test, then remove its temporary directory.
        let items = trash::os_limited::list().expect("Could not enumerate the recycle bin");
        let ours: Vec<_> = items
            .into_iter()
            // The shell resolves short paths and casing before recording the original parent.
            .filter(|i| i.original_parent.canonicalize().is_ok_and(|parent| parent.starts_with(&canonical_dir)))
            .collect();
        let n = ours.len();
        if n > 0 {
            trash::os_limited::purge_all(ours).unwrap();
        }
        let _ = std::fs::remove_dir_all(&dir);
        result.unwrap();
        assert_eq!(n, 2, "a.txt and sub must be present in the recycle bin (fixture: {})", dir.display());
    }
}
