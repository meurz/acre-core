//! Permanent deletion with progress and partial-failure reporting (Windows).
//!
//! The standard library and remove_dir_all stop at the first failure and do not expose
//! progress. This module traverses directories by level, deletes everything it can,
//! and reports each blocking entry while delegating individual removals to std::fs.
//!
//! - Files use `std::fs::remove_file`: DeleteFileW first, then POSIX semantics with
//!   read-only handling on access denial, without changing file attributes first.
//! - The standard library adds the extended-length path prefix when required.
//! - Directories use `std::fs::remove_dir`; read-only attributes are temporarily cleared
//!   on access denial and restored on failure. Transient nonempty errors are retried.
//! - Symbolic links and junctions are removed without following their targets.
//!
//! Directories at each depth are read in parallel, and files are deleted in a dedicated
//! Rayon pool. Directories are then removed from the deepest level upward. Ancestors
//! of failed items are skipped to avoid redundant directory-not-empty diagnostics.

use std::collections::HashSet;
use std::fs;
use std::io;
use std::os::windows::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use rayon::prelude::*;

use crate::recycle::{DeleteError, DeleteFailure, failure_kind};

/// Maximum number of listed failures; the total failure count is tracked separately.
pub const MAX_LISTED_FAILURES: usize = 1000;

/// Deletion progress, written by worker threads and read by the UI.
#[derive(Debug, Default)]
pub struct DeleteProgress {
    files: AtomicU64,
    dirs: AtomicU64,
    bytes: AtomicU64,
    failed: AtomicU64,
}

impl DeleteProgress {
    /// Deleted file count, including symbolic links.
    pub fn files(&self) -> u64 {
        self.files.load(Ordering::Relaxed)
    }
    /// Deleted directory count.
    pub fn dirs(&self) -> u64 {
        self.dirs.load(Ordering::Relaxed)
    }
    /// Total logical bytes of deleted files.
    pub fn bytes(&self) -> u64 {
        self.bytes.load(Ordering::Relaxed)
    }
    /// Number of entries that could not be deleted.
    pub fn failed(&self) -> u64 {
        self.failed.load(Ordering::Relaxed)
    }
}

/// The outcome of one permanent deletion.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeleteReport {
    /// The requested path is gone, either deleted successfully or already absent.
    pub removed: bool,
    /// Deleted file count, including symbolic links.
    pub files: u64,
    /// Deleted directory count, including the requested directory.
    pub dirs: u64,
    /// Total logical bytes of deleted files.
    pub bytes: u64,
    /// Total number of failed entries.
    pub failed: u64,
    /// Failed entries sorted by path, capped at [`MAX_LISTED_FAILURES`]. Blocked ancestors are omitted.
    pub failures: Vec<DeleteError>,
}

/// Permanently delete a file or directory tree, reporting failures while continuing other removals.
///
/// Volume roots and paths without a parent are rejected.
pub fn delete_permanently(path: &Path, progress: &DeleteProgress) -> DeleteReport {
    let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4).clamp(2, 16);
    delete_permanently_with_threads(path, progress, threads)
}

/// Like [`delete_permanently`], with an explicit thread count (1 for sequential deletion).
pub fn delete_permanently_with_threads(path: &Path, progress: &DeleteProgress, threads: usize) -> DeleteReport {
    let ctx = Ctx {
        progress,
        failures: Mutex::new(Vec::new()),
        blocked: Mutex::new(HashSet::new()),
    };
    let removed = if path.parent().is_none_or(|p| p.as_os_str().is_empty()) {
        ctx.fail_with(path, DeleteFailure::Other, "Cannot delete a volume root".into());
        false
    } else {
        match fs::symlink_metadata(path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => true,
            Err(e) => {
                ctx.fail(path, &e);
                false
            }
            Ok(meta) => {
                let ft = meta.file_type();
                if ft.is_dir() && !ft.is_symlink() {
                    match rayon::ThreadPoolBuilder::new()
                        .num_threads(threads.max(1))
                        .thread_name(|i| format!("acre-delete-{i}"))
                        .build()
                    {
                        Ok(pool) => pool.install(|| ctx.delete_tree(path)),
                        Err(e) => {
                            ctx.fail_with(path, DeleteFailure::Other, e.to_string());
                            false
                        }
                    }
                } else {
                    ctx.delete_leaf(path, ft.is_symlink_dir(), meta.len())
                }
            }
        }
    };
    let mut failures = ctx.failures.into_inner().unwrap_or_else(|e| e.into_inner());
    failures.sort_by(|a, b| a.path.cmp(&b.path));
    DeleteReport {
        removed,
        files: progress.files(),
        dirs: progress.dirs(),
        bytes: progress.bytes(),
        failed: progress.failed(),
        failures,
    }
}

struct Ctx<'a> {
    progress: &'a DeleteProgress,
    failures: Mutex<Vec<DeleteError>>,
    /// Directories containing entries that could not be deleted.
    blocked: Mutex<HashSet<PathBuf>>,
}

/// An entry discovered while reading a directory.
enum Entry {
    Dir(PathBuf),
    Leaf { path: PathBuf, link_dir: bool, len: u64 },
}

impl Ctx<'_> {
    fn fail(&self, path: &Path, e: &io::Error) {
        let kind = failure_kind(e.raw_os_error()).unwrap_or(DeleteFailure::Other);
        self.fail_with(path, kind, e.to_string());
    }

    fn fail_with(&self, path: &Path, kind: DeleteFailure, detail: String) {
        self.progress.failed.fetch_add(1, Ordering::Relaxed);
        if let Some(parent) = path.parent() {
            self.blocked.lock().unwrap().insert(parent.to_path_buf());
        }
        let mut f = self.failures.lock().unwrap();
        if f.len() < MAX_LISTED_FAILURES {
            f.push(DeleteError { kind, path: path.to_path_buf(), detail });
        }
    }

    fn is_blocked(&self, dir: &Path) -> bool {
        self.blocked.lock().unwrap().contains(dir)
    }

    /// Delete a file or link and return whether its path is gone.
    fn delete_leaf(&self, path: &Path, link_dir: bool, len: u64) -> bool {
        let r = if link_dir { remove_dir_retry(path, false) } else { remove_file_retry(path) };
        match r {
            Ok(()) => {
                self.progress.files.fetch_add(1, Ordering::Relaxed);
                self.progress.bytes.fetch_add(len, Ordering::Relaxed);
                true
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => true,
            Err(e) => {
                self.fail(path, &e);
                false
            }
        }
    }

    /// Read directory entries; report read failures and mark the directory as blocked.
    fn read_dir(&self, dir: &Path) -> Vec<Entry> {
        let rd = match fs::read_dir(dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Vec::new(),
            Err(e) => {
                self.fail(dir, &e);
                self.blocked.lock().unwrap().insert(dir.to_path_buf());
                return Vec::new();
            }
        };
        let mut out = Vec::new();
        for item in rd {
            let item = match item {
                Ok(i) => i,
                Err(e) => {
                    self.fail(dir, &e);
                    self.blocked.lock().unwrap().insert(dir.to_path_buf());
                    continue;
                }
            };
            let path = item.path();
            // Windows obtains DirEntry type and size during enumeration without additional system calls.
            let Ok(ft) = item.file_type() else {
                out.push(Entry::Leaf { path, link_dir: false, len: 0 });
                continue;
            };
            if ft.is_dir() && !ft.is_symlink() {
                out.push(Entry::Dir(path));
            } else {
                let len = if ft.is_symlink() { 0 } else { item.metadata().map(|m| m.len()).unwrap_or(0) };
                out.push(Entry::Leaf { path, link_dir: ft.is_symlink_dir(), len });
            }
        }
        out
    }

    /// Delete a directory tree and return whether its root is gone.
    fn delete_tree(&self, root: &Path) -> bool {
        let mut levels: Vec<Vec<PathBuf>> = Vec::new();
        let mut level = vec![root.to_path_buf()];
        while !level.is_empty() {
            let next: Vec<PathBuf> = level
                .par_iter()
                .flat_map_iter(|dir| {
                    let entries = self.read_dir(dir);
                    entries.par_iter().for_each(|e| {
                        if let Entry::Leaf { path, link_dir, len } = e {
                            self.delete_leaf(path, *link_dir, *len);
                        }
                    });
                    entries.into_iter().filter_map(|e| match e {
                        Entry::Dir(p) => Some(p),
                        Entry::Leaf { .. } => None,
                    })
                })
                .collect();
            levels.push(level);
            level = next;
        }
        // Remove directories from the deepest level upward; peers can be processed in parallel.
        for level in levels.iter().rev() {
            level.par_iter().for_each(|dir| self.delete_dir(dir));
        }
        fs::symlink_metadata(root).is_err()
    }

    fn delete_dir(&self, dir: &Path) {
        if self.is_blocked(dir) {
            if let Some(parent) = dir.parent() {
                self.blocked.lock().unwrap().insert(parent.to_path_buf());
            }
            return;
        }
        match remove_dir_retry(dir, true) {
            Ok(()) => {
                self.progress.dirs.fetch_add(1, Ordering::Relaxed);
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) if e.raw_os_error() == Some(ERROR_DIR_NOT_EMPTY) => {
                // Another process may have created entries after the original children were removed.
                self.fail_with(dir, DeleteFailure::Other, format!("New entries appeared in the directory during deletion ({e})"));
            }
            Err(e) => self.fail(dir, &e),
        }
    }
}

const ERROR_ACCESS_DENIED: i32 = 5;
const ERROR_SHARING_VIOLATION: i32 = 32;
const ERROR_DIR_NOT_EMPTY: i32 = 145;

/// Delete a file, retrying sharing violations twice for short-lived antivirus or indexer handles.
fn remove_file_retry(path: &Path) -> io::Result<()> {
    let mut tries = 0;
    loop {
        match fs::remove_file(path) {
            Err(e) if e.raw_os_error() == Some(ERROR_SHARING_VIOLATION) && tries < 2 => {
                tries += 1;
                std::thread::sleep(Duration::from_millis(5));
            }
            r => return r,
        }
    }
}

/// Delete an empty directory or link; for real directories, temporarily clear read-only on denial.
// Windows-only: set_readonly(false) clears the attribute and does not modify Unix permission bits.
#[allow(clippy::permissions_set_readonly_false)]
fn remove_dir_retry(path: &Path, real_dir: bool) -> io::Result<()> {
    let mut not_empty_tries = 0u64;
    let mut cleared: Option<fs::Permissions> = None;
    loop {
        match fs::remove_dir(path) {
            Ok(()) => return Ok(()),
            // A removed child can remain visible while another process holds a handle with delete sharing.
            Err(e) if e.raw_os_error() == Some(ERROR_DIR_NOT_EMPTY) && not_empty_tries < 10 => {
                not_empty_tries += 1;
                std::thread::sleep(Duration::from_millis(not_empty_tries));
            }
            Err(e) if e.raw_os_error() == Some(ERROR_ACCESS_DENIED) && real_dir && cleared.is_none() => {
                let Ok(meta) = fs::symlink_metadata(path) else { return Err(e) };
                let original = meta.permissions();
                if !original.readonly() {
                    return Err(e);
                }
                let mut writable = original.clone();
                writable.set_readonly(false);
                if fs::set_permissions(path, writable).is_err() {
                    return Err(e);
                }
                cleared = Some(original);
            }
            Err(e) => {
                if let Some(original) = cleared {
                    let _ = fs::set_permissions(path, original);
                }
                return Err(e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::fs::OpenOptionsExt;
    use std::time::Instant;

    /// A private temporary directory for each test, removed on drop.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!("acre-delete-test-{tag}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(&p).unwrap();
            TempDir(p)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            clear_readonly(&self.0);
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[allow(clippy::permissions_set_readonly_false)]
    fn clear_readonly(p: &Path) {
        if let Ok(m) = fs::symlink_metadata(p) {
            let mut perm = m.permissions();
            if perm.readonly() {
                perm.set_readonly(false);
                let _ = fs::set_permissions(p, perm);
            }
            if m.is_dir()
                && let Ok(rd) = fs::read_dir(p)
            {
                for e in rd.flatten() {
                    clear_readonly(&e.path());
                }
            }
        }
    }

    fn set_readonly(p: &Path) {
        let mut perm = fs::metadata(p).unwrap().permissions();
        perm.set_readonly(true);
        fs::set_permissions(p, perm).unwrap();
    }

    fn make_junction(link: &Path, target: &Path) {
        // mklink treats forward slashes as option prefixes.
        let win = |p: &Path| p.to_string_lossy().replace('/', "\\");
        let out = std::process::Command::new("cmd")
            .arg("/C")
            .arg("mklink")
            .arg("/J")
            .arg(win(link))
            .arg(win(target))
            .output()
            .unwrap();
        assert!(out.status.success(), "mklink /J failed: {}", String::from_utf8_lossy(&out.stderr));
    }

    #[test]
    fn deletes_tree_with_readonly_long_paths_and_links() {
        let tmp = TempDir::new("tree");
        let victim = tmp.0.join("victim");
        let outside = tmp.0.join("outside");
        fs::create_dir_all(victim.join("a/b/c")).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("keep.txt"), b"must survive").unwrap();

        let mut files = 0u64;
        let mut bytes = 0u64;
        let mut put = |p: PathBuf, n: usize| {
            fs::write(&p, vec![b'x'; n]).unwrap();
            files += 1;
            bytes += n as u64;
            p
        };
        put(victim.join("top.txt"), 10);
        put(victim.join("a/one.bin"), 100);
        for i in 0..50 {
            put(victim.join(format!("a/b/f{i}.txt")), i);
        }
        // Read-only files and directories.
        let ro = put(victim.join("a/b/c/readonly.txt"), 7);
        set_readonly(&ro);
        fs::create_dir_all(victim.join("ro-dir")).unwrap();
        put(victim.join("ro-dir/inside.txt"), 3);
        set_readonly(&victim.join("ro-dir"));
        // Paths longer than MAX_PATH.
        let mut deep = victim.join("long");
        while deep.as_os_str().len() < 400 {
            deep = deep.join("a-fairly-long-directory-name-for-max-path");
        }
        fs::create_dir_all(&deep).unwrap();
        let long_file = put(deep.join("deep-file.txt"), 5);
        assert!(long_file.as_os_str().len() > 260);
        // An external junction: remove the link while preserving files in its target.
        make_junction(&victim.join("a/junction-to-outside"), &outside);
        let dirs_expected = {
            let mut n = 0u64;
            let mut stack = vec![victim.clone()];
            while let Some(d) = stack.pop() {
                n += 1;
                for e in fs::read_dir(&d).unwrap().flatten() {
                    let ft = e.file_type().unwrap();
                    if ft.is_dir() && !ft.is_symlink() {
                        stack.push(e.path());
                    }
                }
            }
            n
        };

        let progress = DeleteProgress::default();
        let r = delete_permanently(&victim, &progress);
        assert!(r.failures.is_empty(), "{:?}", r.failures);
        assert!(r.removed);
        assert!(!victim.exists());
        assert_eq!(r.files, files + 1, "files + junction");
        assert_eq!(r.bytes, bytes);
        assert_eq!(r.dirs, dirs_expected);
        assert_eq!(r.failed, 0);
        assert_eq!(progress.files(), r.files);
        assert_eq!(fs::read(outside.join("keep.txt")).unwrap(), b"must survive");
    }

    #[test]
    fn deletes_single_files_and_tolerates_missing() {
        let tmp = TempDir::new("single");
        let f = tmp.0.join("plain.txt");
        fs::write(&f, b"12345").unwrap();
        let r = delete_permanently(&f, &DeleteProgress::default());
        assert!(r.removed && r.files == 1 && r.bytes == 5 && r.failures.is_empty(), "{r:?}");
        assert!(!f.exists());

        let ro = tmp.0.join("readonly.txt");
        fs::write(&ro, b"ro").unwrap();
        set_readonly(&ro);
        let r = delete_permanently(&ro, &DeleteProgress::default());
        assert!(r.removed && r.files == 1, "{r:?}");
        assert!(!ro.exists());

        let r = delete_permanently(&tmp.0.join("never-existed"), &DeleteProgress::default());
        assert!(r.removed && r.files == 0 && r.failed == 0, "{r:?}");

        let r = delete_permanently(Path::new("C:\\"), &DeleteProgress::default());
        assert!(!r.removed && r.failed == 1, "{r:?}");
    }

    #[test]
    fn keeps_going_past_files_in_use_and_reports_them() {
        let tmp = TempDir::new("busy");
        let root = tmp.0.join("busy");
        fs::create_dir_all(root.join("sub/deeper")).unwrap();
        fs::create_dir_all(root.join("clean")).unwrap();
        for i in 0..20 {
            fs::write(root.join(format!("f{i}.txt")), b"x").unwrap();
            fs::write(root.join(format!("clean/f{i}.txt")), b"x").unwrap();
        }
        fs::write(root.join("sub/deeper/held.txt"), b"held").unwrap();
        fs::write(root.join("sub/free.txt"), b"free").unwrap();
        let held = fs::OpenOptions::new().read(true).share_mode(0).open(root.join("sub/deeper/held.txt")).unwrap();

        let single = delete_permanently(&root.join("sub/deeper/held.txt"), &DeleteProgress::default());
        assert!(!single.removed);
        assert_eq!(single.failures.len(), 1);
        assert_eq!(single.failures[0].kind, DeleteFailure::InUse);

        let progress = DeleteProgress::default();
        let r = delete_permanently(&root, &progress);
        drop(held);
        assert!(!r.removed);
        // Report only the held file, without duplicate failures for deeper, sub, and busy.
        assert_eq!(r.failed, 1, "{:?}", r.failures);
        assert_eq!(r.failures.len(), 1);
        assert_eq!(r.failures[0].kind, DeleteFailure::InUse);
        assert!(r.failures[0].path.ends_with("held.txt"));
        assert_eq!(r.files, 41);
        assert_eq!(r.dirs, 1, "clean");
        assert_eq!(progress.failed(), 1);
        // Everything removable is gone; only the held file and its ancestors remain.
        assert!(root.join("sub/deeper/held.txt").exists());
        assert!(!root.join("sub/free.txt").exists());
        assert!(!root.join("clean").exists());
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
    }

    /// Benchmark 10,000 small files. Run with `cargo test --release -- --ignored --nocapture delete_speed`.
    #[test]
    #[ignore]
    fn delete_speed() {
        let tmp = TempDir::new("speed");
        for threads in [1usize, 4, 8, 16] {
            let root = tmp.0.join(format!("t{threads}"));
            for d in 0..10 {
                fs::create_dir_all(root.join(format!("d{d}"))).unwrap();
                for i in 0..1000 {
                    fs::write(root.join(format!("d{d}/file-{i}.txt")), b"acre").unwrap();
                }
            }
            let t = Instant::now();
            let r = delete_permanently_with_threads(&root, &DeleteProgress::default(), threads);
            let secs = t.elapsed().as_secs_f64();
            assert!(r.removed, "{r:?}");
            println!("threads={threads}: {} files in {secs:.3}s ({:.0} files/s)", r.files, r.files as f64 / secs);
        }
    }
}
