//! Background scanning, progress, cancellation, and incremental result batches.
//!
//! ```no_run
//! use acre_core::scan::{ScanOptions, start};
//! let handle = start(ScanOptions::new("C:\\"));
//! while !handle.is_finished() {
//!     let p = handle.progress();          // Poll every 100-250 ms from the UI.
//!     for batch in handle.take_batches() { /* New nodes, parents before children. */ }
//!     std::thread::sleep(std::time::Duration::from_millis(200));
//! }
//! let outcome = handle.join().unwrap();
//! println!("{} files", outcome.tree.summary().files);
//! ```

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::tree::{Batch, DiskTree};

/// Scanning phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Phase {
    /// Preparing volume information and permissions.
    Starting = 0,
    /// Reading MFT records or traversing directories.
    Reading = 1,
    /// Linking nodes and aggregating totals.
    Linking = 2,
    /// Complete.
    Done = 3,
    /// Cancelled.
    Cancelled = 4,
    /// Failed.
    Failed = 5,
}

impl Phase {
    fn from_u8(v: u8) -> Phase {
        match v {
            1 => Phase::Reading,
            2 => Phase::Linking,
            3 => Phase::Done,
            4 => Phase::Cancelled,
            5 => Phase::Failed,
            _ => Phase::Starting,
        }
    }
}

/// Lock-free counters written by the scanner and read by the UI.
#[derive(Debug, Default)]
pub struct Progress {
    phase: AtomicU8,
    items: AtomicU64,
    bytes: AtomicU64,
    units_done: AtomicU64,
    units_total: AtomicU64,
}

impl Progress {
    /// Add discovered entries.
    pub fn add_items(&self, n: u64) {
        self.items.fetch_add(n, Ordering::Relaxed);
    }
    /// Add discovered allocated bytes.
    pub fn add_bytes(&self, n: u64) {
        self.bytes.fetch_add(n, Ordering::Relaxed);
    }
    /// Set completed work units (records read for MFT).
    pub fn set_units_done(&self, n: u64) {
        self.units_done.store(n, Ordering::Relaxed);
    }
    /// Set total work units (MFT record count, or 0 if unknown during traversal).
    pub fn set_units_total(&self, n: u64) {
        self.units_total.store(n, Ordering::Relaxed);
    }
}

/// A snapshot of scan progress.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProgressSnapshot {
    /// Current phase.
    pub phase: Phase,
    /// Discovered files and directories.
    pub items: u64,
    /// Discovered allocated bytes.
    pub bytes: u64,
    /// Completed work units.
    pub units_done: u64,
    /// Total work units (0 if unknown).
    pub units_total: u64,
}

/// Control state shared between the scanner and UI.
#[derive(Debug)]
pub struct ScanControl {
    cancel: Arc<AtomicBool>,
    progress: Progress,
    want_batches: bool,
    batches: Mutex<Vec<Batch>>,
}

impl ScanControl {
    /// Create control state; `want_batches` enables incremental result delivery.
    pub fn new(want_batches: bool) -> Self {
        ScanControl {
            cancel: Arc::new(AtomicBool::new(false)),
            progress: Progress::default(),
            want_batches,
            batches: Mutex::new(Vec::new()),
        }
    }
    /// Request cancellation.
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }
    /// Whether cancellation has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }
    /// The cancellation flag for the reader thread.
    pub fn cancel_flag(&self) -> &AtomicBool {
        &self.cancel
    }
    pub(crate) fn cancel_token(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.cancel)
    }
    /// Progress counters.
    pub fn progress(&self) -> &Progress {
        &self.progress
    }
    /// Set the phase.
    pub fn set_phase(&self, p: Phase) {
        self.progress.phase.store(p as u8, Ordering::Relaxed);
    }
    /// Read current progress.
    pub fn snapshot(&self) -> ProgressSnapshot {
        let p = &self.progress;
        ProgressSnapshot {
            phase: Phase::from_u8(p.phase.load(Ordering::Relaxed)),
            items: p.items.load(Ordering::Relaxed),
            bytes: p.bytes.load(Ordering::Relaxed),
            units_done: p.units_done.load(Ordering::Relaxed),
            units_total: p.units_total.load(Ordering::Relaxed),
        }
    }
    /// Whether incremental batches are requested.
    pub fn wants_batches(&self) -> bool {
        self.want_batches
    }
    /// Push a result batch.
    pub fn push_batch(&self, b: Batch) {
        if self.want_batches && !b.is_empty() {
            self.batches.lock().unwrap_or_else(|e| e.into_inner()).push(b);
        }
    }
    /// Drain all currently available batches.
    pub fn take_batches(&self) -> Vec<Batch> {
        std::mem::take(&mut *self.batches.lock().unwrap_or_else(|e| e.into_inner()))
    }
}

/// Requested scan backend.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backend {
    /// Use MFT when available (NTFS with elevation); otherwise traverse directories.
    Auto,
    /// Use only MFT, returning an error on failure.
    Mft,
    /// Use only directory traversal (dua-core).
    Walk,
    /// Read a WSL VHDX image containing an ext4 filesystem, without mounting it.
    Vhdx,
}

/// The backend actually used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackendUsed {
    /// Direct MFT scan.
    Mft,
    /// Directory traversal.
    Walk,
    /// Read a WSL VHDX image containing an ext4 filesystem, without mounting it.
    Vhdx,
}

/// Scan options.
#[derive(Clone, Debug)]
pub struct ScanOptions {
    /// A volume root, directory, or WSL VHDX image to scan.
    pub root: PathBuf,
    /// Requested backend.
    pub backend: Backend,
    /// Traversal thread count (0 for the logical processor count).
    pub threads: usize,
    /// Deliver incremental batches during directory traversal. MFT requires the whole table
    /// before linking parents; split its final result with [`DiskTree::batches`] if needed.
    pub batches: bool,
    /// Number of entries per batch.
    pub batch_size: usize,
    /// Include directory index allocation in directory sizes (MFT and VHDX).
    pub count_directory_index: bool,
    /// For an elevated NTFS folder scan, read the volume MFT and extract the requested subtree.
    /// This preserves whole-volume hard-link and directory-index accounting and benefits large
    /// folders. Small folders still require reading the full table. Disable to force traversal.
    pub folder_via_mft: bool,
}

impl ScanOptions {
    /// Default options.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        ScanOptions {
            root: root.into(),
            backend: Backend::Auto,
            threads: 0,
            batches: false,
            batch_size: 50_000,
            count_directory_index: true,
            folder_via_mft: true,
        }
    }
}

/// Scan failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanError {
    /// Cancelled.
    Cancelled,
    /// The caller cannot open the raw volume with administrator access.
    AccessDenied(String),
    /// An unsupported filesystem or scan root.
    NotSupported(String),
    /// Another I/O or parsing error.
    Io(String),
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanError::Cancelled => f.write_str("Cancelled"),
            ScanError::AccessDenied(e) => write!(f, "Access denied: {e}"),
            ScanError::NotSupported(e) => write!(f, "Not supported: {e}"),
            ScanError::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ScanError {}

/// Time spent in each phase.
#[derive(Clone, Copy, Debug, Default)]
pub struct Timings {
    /// Total time.
    pub total: Duration,
    /// Preparation (open the volume and locate $MFT).
    pub prepare: Duration,
    /// MFT reading and parsing, or the complete directory traversal.
    pub read: Duration,
    /// Linking and aggregation, including extension totals.
    pub finish: Duration,
}

/// Completed scan result.
pub struct ScanOutcome {
    /// Directory tree.
    pub tree: DiskTree,
    /// Backend used.
    pub backend: BackendUsed,
    /// Phase timings.
    pub timings: Timings,
    /// Diagnostics such as MFT fallback reasons and torn-record counts.
    pub notes: Vec<String>,
}

/// Handle for a background scan.
pub struct ScanHandle {
    ctl: Arc<ScanControl>,
    thread: Option<JoinHandle<Result<ScanOutcome, ScanError>>>,
}

impl ScanHandle {
    /// Current progress.
    pub fn progress(&self) -> ProgressSnapshot {
        self.ctl.snapshot()
    }
    /// Request cancellation, returning [`ScanError::Cancelled`] as soon as possible.
    pub fn cancel(&self) {
        self.ctl.cancel();
    }
    /// Drain available incremental batches without blocking.
    pub fn take_batches(&self) -> Vec<Batch> {
        self.ctl.take_batches()
    }
    /// Whether the worker has finished.
    pub fn is_finished(&self) -> bool {
        self.thread.as_ref().is_none_or(|t| t.is_finished())
    }
    /// Wait for completion and return the result.
    pub fn join(mut self) -> Result<ScanOutcome, ScanError> {
        match self.thread.take() {
            Some(t) => t.join().unwrap_or_else(|_| Err(ScanError::Io("scan thread panicked".into()))),
            None => Err(ScanError::Io("already joined".into())),
        }
    }
}

impl Drop for ScanHandle {
    fn drop(&mut self) {
        if let Some(t) = self.thread.take() {
            self.ctl.cancel();
            let _ = t.join();
        }
    }
}

/// Start scanning in a background thread.
pub fn start(opts: ScanOptions) -> ScanHandle {
    let ctl = Arc::new(ScanControl::new(opts.batches));
    let c = Arc::clone(&ctl);
    let thread = std::thread::Builder::new()
        .name("acre-scan".into())
        .spawn(move || {
            let r = scan_blocking(&opts, &c);
            c.set_phase(match &r {
                Ok(_) => Phase::Done,
                Err(ScanError::Cancelled) => Phase::Cancelled,
                Err(_) => Phase::Failed,
            });
            r
        })
        .expect("spawn scan thread");
    ScanHandle {
        ctl,
        thread: Some(thread),
    }
}

/// Scan on the calling thread (useful for benchmarks).
pub fn scan_blocking(opts: &ScanOptions, ctl: &ScanControl) -> Result<ScanOutcome, ScanError> {
    let t0 = Instant::now();
    ctl.set_phase(Phase::Starting);
    let mut notes = Vec::new();
    if ctl.is_cancelled() {
        return Err(ScanError::Cancelled);
    }
    if opts.backend == Backend::Vhdx
        || (opts.backend == Backend::Auto && crate::vhdx::is_image_path(&opts.root) && !opts.root.is_dir())
    {
        return crate::vhdx::scan(opts, ctl);
    }

    if matches!(opts.backend, Backend::Auto | Backend::Mft) {
        match try_mft(opts, ctl) {
            Ok((tree, timings)) => {
                let total = t0.elapsed();
                let mut out = ScanOutcome {
                    tree,
                    backend: BackendUsed::Mft,
                    timings: Timings {
                        total,
                        prepare: timings.0,
                        read: timings.1,
                        finish: timings.2,
                    },
                    notes: timings.3,
                };
                // MFT returns a complete tree after linking. Automatically splitting millions of nodes
                // would add extra work; use DiskTree::batches explicitly for clients that require batches.
                out.timings.total = t0.elapsed();
                return Ok(out);
            }
            Err(ScanError::Cancelled) => return Err(ScanError::Cancelled),
            Err(e) if opts.backend == Backend::Mft => return Err(e),
            Err(e) => notes.push(format!("MFT scan unavailable; using directory traversal: {e}")),
        }
    }

    let t1 = Instant::now();
    ctl.set_phase(Phase::Reading);
    let walk = crate::walk::scan_dir(&opts.root, opts, ctl)?;
    let mut out = ScanOutcome {
        tree: walk.tree,
        backend: BackendUsed::Walk,
        timings: Timings {
            total: Duration::ZERO,
            prepare: t1 - t0,
            read: walk.read,
            finish: walk.finish,
        },
        notes,
    };
    out.notes.extend(walk.notes);
    out.timings.total = t0.elapsed();
    Ok(out)
}

type MftParts = (DiskTree, (Duration, Duration, Duration, Vec<String>));

#[cfg(windows)]
fn try_mft(opts: &ScanOptions, ctl: &ScanControl) -> Result<MftParts, ScanError> {
    let t = Instant::now();
    let mount = crate::volume::volume_root_of(&opts.root)?;
    let whole_volume = crate::volume::is_volume_root(&opts.root, &mount);
    if !whole_volume && !opts.folder_via_mft {
        return Err(ScanError::NotSupported(format!("{} is not a volume root", opts.root.display())));
    }
    let fs = crate::volume::filesystem_name(&mount)?;
    if fs != "NTFS" {
        return Err(ScanError::NotSupported(format!("{mount} uses {fs}, not NTFS")));
    }
    if std::env::var_os("ACRE_MFT_TRACE").is_some() {
        eprintln!("mft trace: volume checks={:?}", t.elapsed());
    }
    let table_opts = crate::mft::table::TableOptions {
        count_directory_index: opts.count_directory_index,
    };
    let (tree, t) = crate::mft::scan_volume(&mount, table_opts, ctl)?;
    let mut notes = Vec::new();
    let tree = if whole_volume {
        tree
    } else {
        // For folder scans, extract the requested subtree from the volume tree. Paths through
        // junctions or symbolic links may be absent because MFT does not expand those links.
        let rel = opts.root.to_string_lossy();
        let rel = rel.get(mount.len()..).unwrap_or("");
        let full = format!("{}{}", tree.name(tree.root()), rel);
        let id = tree
            .find_path(&full)
            .filter(|&id| tree.node(id).flags.is_dir())
            .ok_or_else(|| ScanError::NotSupported(format!("{} was not found in the MFT (the path may cross a junction)", opts.root.display())))?;
        let t0 = Instant::now();
        let sub = tree.subtree(id, &root_display_name(&opts.root));
        notes.push(format!("Extracted {} from the volume MFT (subtree extraction: {:?})", opts.root.display(), t0.elapsed()));
        sub
    };
    let s = t.table;
    notes.push(format!(
        "MFT {} MiB, {} record slots, {} extension records, {} torn records, {} discarded patches, {} bytes of directory indexes",
        t.mft_bytes >> 20,
        s.records,
        s.extension_records,
        s.torn,
        s.dropped_patches,
        s.index_alloc
    ));
    Ok((tree, (t.map, t.read_parse, t.link_finish, notes)))
}

#[cfg(not(windows))]
fn try_mft(_opts: &ScanOptions, _ctl: &ScanControl) -> Result<MftParts, ScanError> {
    Err(ScanError::NotSupported("MFT scanning is supported only on Windows".into()))
}

/// Display name for a scan root: trim folder separators while preserving volume roots.
pub fn root_display_name(root: &Path) -> String {
    let s = root.to_string_lossy();
    if looks_like_volume_root(root) {
        let t = s.trim_end_matches(['\\', '/']);
        format!("{t}\\")
    } else {
        s.trim_end_matches(['\\', '/']).to_string()
    }
}

/// Whether a path denotes a volume root, including drive letters and volume GUID paths.
pub fn looks_like_volume_root(p: &Path) -> bool {
    let s = p.to_string_lossy();
    let s = s.trim_end_matches(['\\', '/']);
    (s.len() == 2 && s.as_bytes()[1] == b':') || (s.starts_with(r"\\?\Volume{") && s.ends_with('}'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn walk_scan_with_progress_batches_and_cancel() {
        let dir = std::env::temp_dir().join(format!("acre-scan-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("a/b")).unwrap();
        std::fs::write(dir.join("a/one.txt"), vec![1u8; 10_000]).unwrap();
        std::fs::write(dir.join("a/b/two.bin"), vec![2u8; 50_000]).unwrap();
        std::fs::write(dir.join("three.log"), b"x").unwrap();

        let mut opts = ScanOptions::new(&dir);
        opts.backend = Backend::Walk;
        opts.batches = true;
        opts.batch_size = 2;
        let h = start(opts.clone());
        let mut got = Vec::new();
        while !h.is_finished() {
            got.extend(h.take_batches());
            std::thread::sleep(Duration::from_millis(5));
        }
        let out = h.join().unwrap();
        // The final batch may remain after join; joining consumes the handle, so check the tree.
        assert_eq!(out.backend, BackendUsed::Walk);
        let t = &out.tree;
        assert_eq!(t.summary().files, 3);
        assert_eq!(t.summary().dirs, 3);
        assert_eq!(t.node(t.root()).logical, 60_001);
        let a = t.child_by_name(t.root(), "a").unwrap();
        assert_eq!(t.node(a).logical, 60_000);

        // Cancellation requested before scanning should return Cancelled immediately.
        let ctl = ScanControl::new(false);
        ctl.cancel();
        assert_eq!(scan_blocking(&opts, &ctl).err(), Some(ScanError::Cancelled));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn volume_root_detection() {
        assert!(looks_like_volume_root(Path::new("C:\\")));
        assert!(looks_like_volume_root(Path::new("D:")));
        assert!(!looks_like_volume_root(Path::new("C:\\Windows")));
    }
}
