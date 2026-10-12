//! Directory traversal fallback for scans without raw NTFS access.
//!
//! Uses dua-core and its work-stealing directory enumeration. On Windows,
//! FileIdBothDirectoryInfo returns batches of entries with sizes and file identifiers
//! without opening each file or triggering cloud downloads. Links are not followed.
//!
//! Hard links are deduplicated by file identifier. Select the retained name using the
//! little-endian byte order of the parent file identifier, then UTF-16 name ordering,
//! to approximate the attribute order used by NTFS and WizTree. Traversal cannot read
//! the original file records, so files whose names span extension records can be assigned
//! to a different directory than they would be by the MFT backend.

use std::path::Path;
use std::time::{Duration, Instant};

use dua_core::{Options, Order};

use crate::scan::{ScanControl, ScanError, ScanOptions};
use crate::tree::{DiskTree, Flags, NodeId, TreeBuilder};

/// Traversal result.
pub struct WalkOutput {
    /// Directory tree.
    pub tree: DiskTree,
    /// Traversal time.
    pub read: Duration,
    /// Hard-link deduplication and aggregation time.
    pub finish: Duration,
    /// Diagnostics such as unreadable directory counts.
    pub notes: Vec<String>,
}

/// Interval between result batches.
const BATCH_INTERVAL: Duration = Duration::from_millis(200);

/// Traverse `root`.
pub fn scan_dir(root: &Path, opts: &ScanOptions, ctl: &ScanControl) -> Result<WalkOutput, ScanError> {
    if ctl.is_cancelled() {
        return Err(ScanError::Cancelled);
    }
    let threads = if opts.threads == 0 {
        std::thread::available_parallelism().map_or(4, |n| n.get())
    } else {
        opts.threads
    };
    let t0 = Instant::now();
    let root_name = crate::scan::root_display_name(root);
    let mut b = TreeBuilder::with_capacity(&root_name, 1 << 16, 1 << 20);
    let root_id = b.root();
    // dua-core uses dense directory identifiers starting at 0, suitable for a direct array map.
    let mut dir_map: Vec<NodeId> = Vec::new();
    let mut file_ids: Vec<(u64, NodeId)> = Vec::new();
    // Directory node to file identifier, used to choose the retained hard-link name.
    let mut dir_fids: Vec<(NodeId, u64)> = Vec::new();
    let mut errors = 0u64;
    let mut error_samples: Vec<String> = Vec::new();
    let mut seen = 0u64;
    let mut batch_mark: NodeId = b.len() as NodeId;
    let mut last_batch = Instant::now();

    let mut walk = dua_core::walk(root, threads, Order::ParentFirst, Options::default(), |_| true);
    while let Some(item) = walk.next_cancellable(ctl.cancel_flag()) {
        let entry = match item {
            Ok(e) => e,
            Err(e) => {
                errors += 1;
                if error_samples.len() < 8 {
                    error_samples.push(e.to_string());
                }
                continue;
            }
        };
        if entry.depth == 0 {
            if let Some(d) = entry.directory_id {
                map_set(&mut dir_map, d.index(), root_id);
            }
            if let Some(Ok(m)) = &entry.metadata
                && let Some((_, fid)) = m.hard_link_id()
            {
                dir_fids.push((root_id, fid));
            }
            continue;
        }
        let parent = entry
            .parent_directory_id
            .and_then(|d| dir_map.get(d.index()).copied())
            .unwrap_or(root_id);
        let ft = entry.file_type;
        let mut flags = Flags::default();
        if ft.is_dir() {
            flags.insert(Flags::DIR);
        }
        if ft.is_symlink() {
            flags.insert(Flags::REPARSE);
        }
        let (len, alloc, fid) = match &entry.metadata {
            Some(Ok(m)) => (m.len(), m.allocated_size(), m.hard_link_id()),
            Some(Err(_)) => {
                errors += 1;
                (0, 0, None)
            }
            None => (0, 0, None),
        };
        let name = entry.file_name.to_string_lossy();
        let (logical, alloc) = if ft.is_dir() { (0, 0) } else { (len, alloc) };
        let id = b.add(parent, &name, flags, logical, alloc);
        if ft.is_dir() {
            if let Some(d) = entry.directory_id {
                map_set(&mut dir_map, d.index(), id);
            }
            if let Some((_, file_id)) = fid {
                dir_fids.push((id, file_id));
            }
        } else if let Some((_, file_id)) = fid {
            file_ids.push((file_id, id));
        }

        seen += 1;
        if seen.is_multiple_of(4096) {
            let p = ctl.progress();
            p.add_items(4096);
            if ctl.wants_batches() && last_batch.elapsed() >= BATCH_INTERVAL {
                ctl.push_batch(b.batch_since(batch_mark));
                batch_mark = b.len() as NodeId;
                last_batch = Instant::now();
            }
        }
        if alloc != 0 {
            ctl.progress().add_bytes(alloc);
        }
    }
    drop(walk);
    if ctl.is_cancelled() {
        return Err(ScanError::Cancelled);
    }
    if ctl.wants_batches() {
        ctl.push_batch(b.batch_since(batch_mark));
    }
    let read = t0.elapsed();

    let t1 = Instant::now();
    ctl.set_phase(crate::scan::Phase::Linking);
    dir_fids.sort_unstable();
    let extra = dedup_hardlinks(&mut b, &mut file_ids, &dir_fids);
    drop(file_ids);
    drop(dir_fids);
    drop(dir_map);
    {
        let s = b.summary_mut();
        s.extra_link_names = extra;
        s.unreadable_dirs = errors;
    }
    let tree = b.finish();
    let finish = t1.elapsed();

    let mut notes = Vec::new();
    if errors > 0 {
        notes.push(format!("Failed to read {errors} directories or entries (often access denied); examples: {}", error_samples.join("; ")));
    }
    Ok(WalkOutput {
        tree,
        read,
        finish,
        notes,
    })
}

fn map_set(map: &mut Vec<NodeId>, idx: usize, id: NodeId) {
    if map.len() <= idx {
        map.resize(idx + 1, crate::tree::NONE);
    }
    map[idx] = id;
}

/// Retain sizes under one name per file identifier, zero and mark duplicates, and count them.
///
/// Selection uses the little-endian parent file identifier, then UTF-16 name ordering.
/// `dir_fids` contains `(directory node, file identifier)` pairs sorted by node identifier.
fn dedup_hardlinks(b: &mut TreeBuilder, ids: &mut [(u64, NodeId)], dir_fids: &[(NodeId, u64)]) -> u64 {
    ids.sort_unstable();
    let parent_key = |b: &TreeBuilder, id: NodeId| -> [u8; 8] {
        let p = b.node(id).parent;
        let fid = dir_fids
            .binary_search_by_key(&p, |&(n, _)| n)
            .map(|i| dir_fids[i].1)
            .unwrap_or(u64::MAX);
        fid.to_le_bytes()
    };
    let mut extra = 0u64;
    let mut i = 0;
    while i < ids.len() {
        let mut j = i + 1;
        while j < ids.len() && ids[j].0 == ids[i].0 {
            j += 1;
        }
        if j - i > 1 {
            extra += (j - i - 1) as u64;
            let keep = ids[i..j]
                .iter()
                .map(|&(_, id)| id)
                .min_by(|&x, &y| {
                    parent_key(b, x)
                        .cmp(&parent_key(b, y))
                        .then_with(|| b.name(x).encode_utf16().cmp(b.name(y).encode_utf16()))
                        .then(x.cmp(&y))
                })
                .expect("non-empty group");
            for &(_, id) in &ids[i..j] {
                let n = b.node_mut(id);
                n.flags.insert(Flags::HARDLINK);
                if id != keep {
                    n.logical = 0;
                    n.alloc = 0;
                }
            }
        }
        i = j;
    }
    extra
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedup_keeps_one_name_by_parent_id_then_name() {
        let mut b = TreeBuilder::new("R");
        let r = b.root();
        // Directory x has ID 0x0201 (bytes 01 02), while y has 0x0102 (02 01): x sorts first.
        let x = b.add(r, "x", Flags::DIR, 0, 0);
        let y = b.add(r, "y", Flags::DIR, 0, 0);
        let in_y = b.add(y, "a", Flags::default(), 100, 4096);
        let in_x = b.add(x, "b", Flags::default(), 100, 4096);
        // Within one directory, UTF-16 ordering places uppercase Zeta before lowercase alpha.
        let zeta = b.add(r, "Zeta", Flags::default(), 7, 4096);
        let alpha = b.add(r, "alpha", Flags::default(), 7, 4096);
        let d = b.add(r, "d", Flags::default(), 5, 4096);
        let mut dir_fids = vec![(r, 5u64), (x, 0x0201), (y, 0x0102)];
        dir_fids.sort_unstable();
        let mut ids = vec![(7, in_y), (7, in_x), (8, alpha), (8, zeta), (9, d)];
        assert_eq!(dedup_hardlinks(&mut b, &mut ids, &dir_fids), 2);
        let t = b.finish();
        assert_eq!(t.node(in_x).alloc, 4096);
        assert_eq!(t.node(in_y).alloc, 0);
        assert_eq!(t.node(zeta).alloc, 4096);
        assert_eq!(t.node(alpha).alloc, 0);
        assert_eq!(t.node(t.root()).alloc, 4096 * 3);
        assert!(t.node(in_y).flags.contains(Flags::HARDLINK));
        assert!(!t.node(d).flags.contains(Flags::HARDLINK));
    }

    #[cfg(windows)]
    #[test]
    fn real_hardlinks_count_once() {
        let dir = std::env::temp_dir().join(format!("acre-hl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("x")).unwrap();
        std::fs::write(dir.join("x/data.bin"), vec![7u8; 100_000]).unwrap();
        std::fs::hard_link(dir.join("x/data.bin"), dir.join("alias.bin")).unwrap();
        let mut opts = ScanOptions::new(&dir);
        opts.backend = crate::scan::Backend::Walk;
        let ctl = ScanControl::new(false);
        let out = scan_dir(&dir, &opts, &ctl).unwrap();
        let t = &out.tree;
        assert_eq!(t.summary().extra_link_names, 1);
        assert_eq!(t.node(t.root()).logical, 100_000);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
