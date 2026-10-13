//! Acre disk usage scanning core.
//!
//! - [`tree`]: compact directory trees, on-demand child sorting, and extension totals.
//! - [`scan`]: background scanning, progress, cancellation, batches, and automatic backend selection.
//! - [`mft`]: direct NTFS $MFT scanning (requires elevation), adapted from mathom (MIT).
//! - [`walk`]: directory traversal fallback based on dua-core.
//! - `volume`: drive discovery, elevation checks, and elevated relaunch (Windows).
//! - `recycle`: recycling with structured failure reasons (Windows).
//! - `delete`: permanent deletion with progress and per-item failures (Windows).
//!
//! Uses allocated disk space by default and counts hard-linked file contents once.

#![warn(missing_docs)]

pub mod mft;
pub mod scan;
pub mod tree;
pub mod walk;
pub mod vhdx;

#[cfg(windows)]
pub mod delete;
#[cfg(windows)]
pub mod recycle;
#[cfg(windows)]
pub mod volume;

pub use scan::{Backend, BackendUsed, ScanError, ScanHandle, ScanOptions, ScanOutcome, start};
pub use tree::{DiskTree, Flags, Node, NodeId, Removed, SortKey};
