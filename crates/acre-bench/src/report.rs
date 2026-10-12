//! Shared result format, WizTree CSV parsing, and path-based comparisons.

use std::collections::HashMap;

use acre_core::tree::{DiskTree, NodeId};
use serde::{Deserialize, Serialize};

/// A scan result in a common tool-independent format; missing fields use defaults.
#[derive(Serialize, Deserialize, Default, Clone, Debug)]
#[serde(default)]
pub struct Report {
    pub tool: String,
    pub root: String,
    pub elevated: bool,
    /// Wall-clock time measured by the launcher, or internal scan time if unavailable.
    pub wall_ms: f64,
    /// Internal scan time, available for Acre and library backends.
    pub scan_ms: f64,
    pub prepare_ms: f64,
    pub read_ms: f64,
    pub finish_ms: f64,
    /// File nodes: one per file record for MFT, or one per name for traversal and WizTree.
    pub files: u64,
    /// File-name count, including each hard-link name, comparable to WizTree's file count.
    pub file_names: u64,
    /// Deduplicated file count. WizTree does not provide this value, so its results use 0.
    pub files_unique: u64,
    pub dirs: u64,
    pub logical: u64,
    pub alloc: u64,
    pub extra_link_names: u64,
    pub cpu_ms: f64,
    pub orphans: u64,
    pub unreadable_dirs: u64,
    pub live_nodes: u64,
    pub slots: u64,
    pub tree_bytes: u64,
    pub peak_working_set: u64,
    pub peak_private: u64,
    pub volume_total: u64,
    pub volume_free: u64,
    /// Used and reserved bytes reported by WizTree, when available.
    pub volume_used_reported: u64,
    pub volume_reserved_reported: u64,
    pub notes: Vec<String>,
    /// Node counts by flag: hard links, WOF, compression, sparse, cloud, streams, encryption, links.
    pub flag_counts: std::collections::BTreeMap<String, FlagCount>,
    pub items: Vec<Item>,
    pub top_extensions: Vec<ExtItem>,
}

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct FlagCount {
    pub nodes: u64,
    pub logical: u64,
    pub alloc: u64,
}

/// Aggregate counts and own sizes by flag without including descendant totals.
pub fn flag_counts(tree: &DiskTree) -> std::collections::BTreeMap<String, FlagCount> {
    use acre_core::tree::Flags;
    let named = [
        (Flags::HARDLINK, "hardlink"),
        (Flags::COMPRESSED, "ntfs_compressed"),
        (Flags::SPARSE, "sparse"),
        (Flags::WOF, "wof"),
        (Flags::PLACEHOLDER, "cloud_placeholder"),
        (Flags::ADS, "alternate_stream"),
        (Flags::ENCRYPTED, "encrypted"),
        (Flags::REPARSE, "symlink_or_junction"),
        (Flags::METAFILE, "metafile"),
    ];
    let mut out = std::collections::BTreeMap::new();
    for n in tree.nodes() {
        if !n.is_used() {
            continue;
        }
        for (f, name) in named {
            if n.flags.contains(f) {
                let e: &mut FlagCount = out.entry(name.to_string()).or_default();
                e.nodes += 1;
                if !n.flags.is_dir() {
                    e.logical += n.logical;
                    e.alloc += n.alloc;
                }
            }
        }
    }
    out
}

/// One exported tree entry within the requested depth.
#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct Item {
    /// Path relative to the scan root, using backslashes; root is empty, without trailing separators.
    pub path: String,
    pub depth: u32,
    pub dir: bool,
    pub logical: u64,
    pub alloc: u64,
    pub files: u64,
    pub dirs: u64,
    pub flags: String,
}

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct ExtItem {
    pub ext: String,
    pub files: u64,
    pub logical: u64,
    pub alloc: u64,
}

/// Export tree entries through `max_depth`.
pub fn items_from_tree(tree: &DiskTree, max_depth: u32) -> Vec<Item> {
    let mut out = Vec::new();
    let root = tree.root();
    let mut stack: Vec<(NodeId, u32, String)> = vec![(root, 0, String::new())];
    while let Some((id, depth, path)) = stack.pop() {
        let n = tree.node(id);
        let t = tree.dir_totals(id);
        out.push(Item {
            path: path.clone(),
            depth,
            dir: n.flags.is_dir(),
            logical: n.logical,
            alloc: n.alloc,
            files: t.files as u64,
            dirs: t.dirs as u64,
            flags: format!("{:?}", n.flags),
        });
        if depth < max_depth {
            for c in tree.children(id) {
                let p = if path.is_empty() {
                    tree.name(c).to_string()
                } else {
                    format!("{path}\\{}", tree.name(c))
                };
                stack.push((c, depth + 1, p));
            }
        }
    }
    out.sort_by(|a, b| a.path.to_lowercase().cmp(&b.path.to_lowercase()));
    out
}

/// Volume information attached to the root row of a WizTree CSV.
#[derive(Serialize, Deserialize, Default, Clone, Copy, Debug)]
pub struct WizVolume {
    pub capacity: u64,
    pub free: u64,
    pub used: u64,
    pub reserved: u64,
}

/// Parse WizTree CSV by column position because the introductory line and headers are localized.
/// Columns are name, size, allocated, modified, attributes, files, folders, followed by
/// optional root-only capacity, free, used, and reserved space columns.
/// Use `root` to convert absolute paths to relative paths.
pub fn parse_wiztree_csv(text: &str, root: &str) -> Result<(Vec<Item>, Option<WizVolume>), String> {
    let mut lines = text.lines();
    lines.next().ok_or("empty WizTree CSV")?; // Introductory line.
    lines.next().ok_or("WizTree CSV has no header")?; // Header.
    let root_norm = root.trim_end_matches('\\').to_lowercase();
    let num = |fields: &[String], i: usize| -> Option<u64> { fields.get(i).and_then(|s| s.trim().parse().ok()) };
    let mut items = Vec::new();
    let mut vol = None;
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let fields = split_csv(line);
        let Some(name) = fields.first() else { continue };
        let dir = name.ends_with('\\');
        // WizTree appends a dot to extensionless filenames such as $MFT; remove it before comparison.
        let abs = name.trim_end_matches('\\');
        let abs = if dir { abs } else { abs.strip_suffix('.').unwrap_or(abs) };
        let lower = abs.to_lowercase();
        let rel = if lower == root_norm {
            String::new()
        } else if lower.starts_with(&(root_norm.clone() + "\\")) {
            abs[root_norm.len() + 1..].to_string()
        } else {
            continue;
        };
        if rel.is_empty() && fields.len() >= 11 {
            vol = Some(WizVolume {
                capacity: num(&fields, 7).unwrap_or(0),
                free: num(&fields, 8).unwrap_or(0),
                used: num(&fields, 9).unwrap_or(0),
                reserved: num(&fields, 10).unwrap_or(0),
            });
        }
        let depth = if rel.is_empty() { 0 } else { rel.matches('\\').count() as u32 + 1 };
        items.push(Item {
            path: rel,
            depth,
            dir,
            logical: num(&fields, 1).unwrap_or(0),
            alloc: num(&fields, 2).unwrap_or(0),
            files: num(&fields, 5).unwrap_or(0),
            dirs: num(&fields, 6).unwrap_or(0),
            flags: num(&fields, 4).map(|a| format!("attr={a}")).unwrap_or_default(),
        });
    }
    if items.is_empty() {
        return Err("WizTree CSV has no rows under the scan root".into());
    }
    items.sort_by(|a, b| a.path.to_lowercase().cmp(&b.path.to_lowercase()));
    Ok((items, vol))
}

fn split_csv(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if quoted && chars.peek() == Some(&'"') => {
                cur.push('"');
                chars.next();
            }
            '"' => quoted = !quoted,
            ',' if !quoted => out.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    out.push(cur);
    out
}

/// One comparison row.
#[derive(Serialize, Clone, Debug)]
pub struct DiffRow {
    pub path: String,
    pub base_alloc: Option<u64>,
    pub other_alloc: Option<u64>,
    pub base_logical: Option<u64>,
    pub other_logical: Option<u64>,
    pub base_files: Option<u64>,
    pub other_files: Option<u64>,
    /// Relative allocated-size difference: `(other - base) / base`.
    pub alloc_rel: f64,
    pub logical_rel: f64,
}

/// Compare two reports by path through `max_depth`.
pub fn compare(base: &Report, other: &Report, max_depth: u32) -> Vec<DiffRow> {
    let key = |p: &str| p.to_lowercase();
    let b: HashMap<String, &Item> = base.items.iter().filter(|i| i.depth <= max_depth).map(|i| (key(&i.path), i)).collect();
    let o: HashMap<String, &Item> = other.items.iter().filter(|i| i.depth <= max_depth).map(|i| (key(&i.path), i)).collect();
    let mut keys: Vec<&String> = b.keys().chain(o.keys()).collect();
    keys.sort();
    keys.dedup();
    let rel = |x: Option<u64>, y: Option<u64>| -> f64 {
        let (x, y) = (x.unwrap_or(0) as f64, y.unwrap_or(0) as f64);
        if x == 0.0 {
            if y == 0.0 { 0.0 } else { f64::INFINITY }
        } else {
            (y - x) / x
        }
    };
    keys.into_iter()
        .map(|k| {
            let bi = b.get(k);
            let oi = o.get(k);
            let path = bi.or(oi).map(|i| i.path.clone()).unwrap_or_default();
            let ba = bi.map(|i| i.alloc);
            let oa = oi.map(|i| i.alloc);
            let bl = bi.map(|i| i.logical);
            let ol = oi.map(|i| i.logical);
            DiffRow {
                path,
                base_alloc: ba,
                other_alloc: oa,
                base_logical: bl,
                other_logical: ol,
                base_files: bi.map(|i| i.files),
                other_files: oi.map(|i| i.files),
                alloc_rel: rel(ba, oa),
                logical_rel: rel(bl, ol),
            }
        })
        .collect()
}

/// Format a byte count for human-readable output.
pub fn human(b: u64) -> String {
    const U: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 { format!("{b} B") } else { format!("{v:.2} {}", U[i]) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_wiztree_export() {
        let csv = "Generated by WizTree 4.31 10/10/2026 12:00:00 (You can turn off this message in the options)\r\n\
File Name,Size,Allocated,Modified,Attributes,Files,Folders\r\n\
\"C:\\\",900,1000,2026/10/10 12:00:00,0,10,3\r\n\
\"C:\\Windows\\\",500,600,2026/10/10 12:00:00,16,7,2\r\n\
\"C:\\pagefile.sys\",400,400,2026/10/10 12:00:00,38,0,0\r\n\
\"C:\\a,b \"\"q\"\"\\\",0,0,2026/10/10 12:00:00,16,0,0\r\n";
        let (items, _) = parse_wiztree_csv(csv, "C:\\").unwrap();
        let zh = "\u{feff}生成由 WizTree 4.31\r\n文件名称,大小,分配,修改时间,属性,文件,文件夹,DRIVECAPACITY,FREESPACE,USEDSPACE,RESERVEDSPACE\r\n\"D:\\\",5,4,2026/10/10 19:04:20,38,1,0,100,10,90,1\r\n";
        let (zi, v) = parse_wiztree_csv(zh, "D:\\").unwrap();
        assert_eq!(zi[0].alloc, 4);
        assert_eq!(v.unwrap().used, 90);
        assert_eq!(items.len(), 4);
        assert_eq!(items[0].path, "");
        assert_eq!(items[0].alloc, 1000);
        let w = items.iter().find(|i| i.path == "Windows").unwrap();
        assert!(w.dir);
        assert_eq!(w.files, 7);
        assert_eq!(w.depth, 1);
        assert!(items.iter().any(|i| i.path == "a,b \"q\""));
    }
}
