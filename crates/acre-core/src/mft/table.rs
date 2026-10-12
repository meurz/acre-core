// Parallel parsing and merging extension-record facts into base records are adapted from mathom
// (https://github.com/gitRasheed/mathom, crates/scanner-ntfs/src/pipeline.rs and assemble.rs),
// MIT license, Copyright (c) 2026 Rasheed Khoshnaw. See third_party/mathom-LICENSE.
//
// Writes parsed records directly into compact tree slots indexed by record number, with names
// in a shared arena. Eliminates intermediate tables and events; TreeBuilder aggregates the tree.
//
//! Convert raw MFT record bytes into a compact directory tree.

use rayon::prelude::*;

use super::record::{self, NO_NAME, ROOT_RECORD, RecordFacts, RecordRef};
use crate::tree::{DiskTree, Flags, NONE, Node, NodeId, Summary, TreeBuilder};

/// Records per parallel parsing task.
const TASK_RECORDS: usize = 512;

/// Temporary record metadata, released after linking.
#[derive(Clone, Copy, Default)]
struct Meta {
    seq: u16,
    parent_seq: u16,
    links: u16,
    rank: u8,
}

const EMPTY_META: Meta = Meta {
    seq: 0,
    parent_seq: 0,
    links: 0,
    rank: NO_NAME,
};

/// Facts from an extension record; name offsets already reference the global arena.
#[derive(Clone, Copy)]
struct Patch {
    /// Extension record number; sorting makes the result independent of I/O completion order.
    rec: u64,
    base: u64,
    logical: u64,
    alloc: u64,
    flags: Flags,
    links: u16,
    rank: u8,
    parent: RecordRef,
    name_off: u32,
    name_len: u16,
    has_logical: bool,
}

/// Counts from one record block for progress reporting.
#[derive(Clone, Copy, Debug, Default)]
pub struct ChunkCounts {
    /// Files in base records.
    pub files: u64,
    /// Directories in base records.
    pub dirs: u64,
    /// Allocation across all records, including extensions and directory indexes, for progress.
    pub alloc: u64,
}

/// Parsing options.
#[derive(Clone, Copy, Debug)]
pub struct TableOptions {
    /// Include $INDEX_ALLOCATION in each directory's own allocation.
    pub count_directory_index: bool,
}

impl Default for TableOptions {
    fn default() -> Self {
        TableOptions {
            count_directory_index: true,
        }
    }
}

/// Parsing statistics.
#[derive(Clone, Copy, Debug, Default)]
pub struct TableStats {
    /// Record slot count.
    pub records: u64,
    /// Torn or unparseable records.
    pub torn: u64,
    /// Extension records whose base record could not be found.
    pub dropped_patches: u64,
    /// Extension record count.
    pub extension_records: u64,
    /// Total $INDEX_ALLOCATION bytes, whether included in directory totals or not.
    pub index_alloc: u64,
}

/// MFT record table indexed by record number.
pub struct RecordTable {
    nodes: Vec<Node>,
    meta: Vec<Meta>,
    names: Vec<u8>,
    patches: Vec<Patch>,
    cluster_size: u32,
    record_size: usize,
    opts: TableOptions,
    stats: TableStats,
    records_consumed: u64,
}

struct TaskOut {
    first: usize,
    arena: Vec<u8>,
    patches: Vec<Patch>,
    counts: ChunkCounts,
    torn: u64,
    index_alloc: u64,
}

impl RecordTable {
    /// Reserve the complete node array, returning an allocation error instead of panicking.
    pub fn new(total_records: u64, record_size: usize, cluster_size: u32, opts: TableOptions) -> Result<Self, String> {
        let total = usize::try_from(total_records).map_err(|_| "record count too large".to_string())?;
        if total_records >= NONE as u64 {
            return Err(format!("{total_records} records exceed the u32 node index"));
        }
        let mut nodes = Vec::new();
        // Reserve one extra slot for an orphan bucket to avoid doubling the array on a final push.
        nodes
            .try_reserve_exact(total + 1)
            .map_err(|_| format!("cannot allocate {total} nodes"))?;
        nodes.resize(total, Node::UNUSED);
        let mut meta = Vec::new();
        meta.try_reserve_exact(total)
            .map_err(|_| format!("cannot allocate {total} record slots"))?;
        meta.resize(total, EMPTY_META);
        Ok(RecordTable {
            nodes,
            meta,
            // Initially reserve 16 name bytes per record; use the first block to estimate the full
            // requirement in consume, avoiding repeated arena growth and high peak memory.
            names: Vec::with_capacity(total.saturating_mul(16)),
            patches: Vec::new(),
            cluster_size,
            record_size,
            opts,
            stats: TableStats {
                records: total_records,
                ..TableStats::default()
            },
            records_consumed: 0,
        })
    }

    /// Record slot count.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Parse a block starting at `first_record` in parallel, applying update-sequence fixups in place.
    pub fn consume(&mut self, first_record: usize, buf: &mut [u8]) -> ChunkCounts {
        let rs = self.record_size;
        assert!(buf.len().is_multiple_of(rs), "buffer must hold whole records");
        let n = buf.len() / rs;
        let n = n.min(self.nodes.len().saturating_sub(first_record));
        let buf = &mut buf[..n * rs];
        let cluster_size = self.cluster_size;
        let count_index = self.opts.count_directory_index;

        let outs: Vec<TaskOut> = self.nodes[first_record..first_record + n]
            .par_chunks_mut(TASK_RECORDS)
            .zip(self.meta[first_record..first_record + n].par_chunks_mut(TASK_RECORDS))
            .zip(buf.par_chunks_mut(TASK_RECORDS * rs))
            .enumerate()
            .map(|(task, ((nodes, meta), bytes))| {
                let first = first_record + task * TASK_RECORDS;
                let mut out = TaskOut {
                    first,
                    arena: Vec::with_capacity(nodes.len() * 24),
                    patches: Vec::new(),
                    counts: ChunkCounts::default(),
                    torn: 0,
                    index_alloc: 0,
                };
                for (i, ((node, m), rec)) in nodes.iter_mut().zip(meta.iter_mut()).zip(bytes.chunks_mut(rs)).enumerate() {
                    match record::parse_record(rec, &mut out.arena, cluster_size) {
                        Ok(Some(facts)) => place(first + i, facts, node, m, &mut out, count_index),
                        Ok(None) => {}
                        Err(_) => out.torn += 1,
                    }
                }
                out
            })
            .collect();

        // Estimate the complete name arena from the mean length observed so far, with 5% headroom.
        // Blocks can arrive out of order, so calculate the mean using the cumulative parsed count.
        let first_call = self.records_consumed == 0;
        self.records_consumed += n as u64;
        let seen = self.records_consumed.max(1) as usize;
        let incoming: usize = outs.iter().map(|o| o.arena.len()).sum();
        let need = self.names.len() + incoming;
        if need > self.names.capacity() || (first_call && n > 0) {
            let per = need as f64 / seen as f64;
            let estimate = (per * self.nodes.len() as f64 * 1.05) as usize;
            if estimate > self.names.capacity() {
                self.names.reserve_exact(estimate.max(need) - self.names.len());
            }
        }
        let mut counts = ChunkCounts::default();
        for out in outs {
            let base = self.names.len() as u32;
            self.names.extend_from_slice(&out.arena);
            let end = (out.first + TASK_RECORDS).min(first_record + n);
            for i in out.first..end {
                if self.meta[i].rank != NO_NAME && !self.nodes[i].flags.contains(Flags::UNUSED) {
                    self.nodes[i].name_off += base;
                }
            }
            for mut p in out.patches {
                if p.rank != NO_NAME {
                    p.name_off += base;
                }
                self.patches.push(p);
            }
            self.stats.torn += out.torn;
            self.stats.index_alloc = self.stats.index_alloc.saturating_add(out.index_alloc);
            counts.files += out.counts.files;
            counts.dirs += out.counts.dirs;
            counts.alloc = counts.alloc.saturating_add(out.counts.alloc);
        }
        counts
    }

    /// Insert a base record from an external source such as ntfs-reader.
    #[allow(clippy::too_many_arguments)]
    pub fn put_base(
        &mut self,
        number: u64,
        seq: u16,
        name: Option<(&str, u64)>,
        links: u16,
        is_dir: bool,
        logical: u64,
        alloc: u64,
        flags: Flags,
    ) {
        let i = number as usize;
        if i >= self.nodes.len() {
            return;
        }
        let mut f = flags;
        if is_dir {
            f.insert(Flags::DIR);
        }
        if links > 1 {
            f.insert(Flags::HARDLINK);
        }
        f.insert(Flags::HAS_LOGICAL);
        let mut node = Node {
            logical,
            alloc,
            flags: f,
            ..Node::UNUSED
        };
        let mut m = Meta {
            seq,
            links,
            ..EMPTY_META
        };
        if let Some((name, parent)) = name {
            let off = self.names.len() as u32;
            let len = name.len().min(u16::MAX as usize);
            self.names.extend_from_slice(&name.as_bytes()[..len]);
            let parent = RecordRef(parent);
            node.parent = parent.number().min(NONE as u64 - 1) as u32;
            node.name_off = off;
            node.name_len = len as u16;
            m.parent_seq = parent.sequence();
            m.rank = 0;
        }
        self.nodes[i] = node;
        self.meta[i] = m;
    }

    /// Merge extension records, link parents, and aggregate. `root_name` is the display name.
    pub fn finish(mut self, root_name: &str) -> Result<(DiskTree, TableStats), String> {
        let trace = std::env::var_os("ACRE_MFT_TRACE").is_some();
        let t0 = std::time::Instant::now();
        let mark = |what: &str| {
            if trace {
                eprintln!("table trace: {what} @ {:?}", t0.elapsed());
            }
        };
        // 1. Merge extension-record facts into base records.
        // Hard-link ownership follows name order: prefer a non-DOS name in the base record;
        // otherwise inspect ascending extension records after the base, then those before it.
        // The sorting key is deterministic and independent of I/O completion order.
        let mut patches = std::mem::take(&mut self.patches);
        patches.sort_unstable_by_key(|p| (p.rec < p.base, p.rec));
        self.stats.extension_records = patches.len() as u64;
        for p in &patches {
            let b = p.base as usize;
            match self.nodes.get(b) {
                Some(n) if n.is_used() => {}
                _ => {
                    self.stats.dropped_patches += 1;
                    continue;
                }
            }
            let n = &mut self.nodes[b];
            let m = &mut self.meta[b];
            if p.has_logical && !n.flags.contains(Flags::HAS_LOGICAL) {
                n.logical = p.logical;
                n.flags.insert(Flags::HAS_LOGICAL);
            }
            n.alloc = n.alloc.saturating_add(p.alloc);
            n.flags = n.flags.union(p.flags);
            m.links = m.links.saturating_add(p.links);
            if p.rank < m.rank {
                m.rank = p.rank;
                m.parent_seq = p.parent.sequence();
                n.parent = p.parent.number().min(NONE as u64 - 1) as u32;
                n.name_off = p.name_off;
                n.name_len = p.name_len;
            }
        }
        drop(patches);
        mark("patches");

        let root = ROOT_RECORD as usize;
        if root >= self.nodes.len() || !is_live_dir(&self.nodes[root]) {
            return Err("volume root record missing from $MFT".into());
        }

        // 2. Mark hard links and records without names.
        let total = self.nodes.len();
        let mut summary = Summary::default();
        for i in 0..total {
            let n = &mut self.nodes[i];
            if !n.is_used() {
                continue;
            }
            if self.meta[i].links > 1 {
                n.flags.insert(Flags::HARDLINK);
                summary.extra_link_names += self.meta[i].links as u64 - 1;
            }
            if i < record::FIRST_NORMAL_RECORD as usize && i != root {
                n.flags.insert(Flags::METAFILE);
            }
        }

        // 3. Validate parent liveness, directory type, and sequence number before linking.
        // Compute validity first because linking mutates each parent's child-list head.
        let valid: Vec<bool> = {
            let nodes = &self.nodes;
            let meta = &self.meta;
            (0..total)
                .into_par_iter()
                .map(|i| {
                    let n = &nodes[i];
                    if !n.is_used() || i == root || meta[i].rank == NO_NAME {
                        return false;
                    }
                    let p = n.parent as usize;
                    p != i && p < total && is_live_dir(&nodes[p]) && meta[p].seq == meta[i].parent_seq
                })
                .collect()
        };
        drop(std::mem::take(&mut self.meta));
        self.nodes.par_iter_mut().for_each(|n| {
            n.first_child = NONE;
            n.next_sibling = NONE;
        });
        let mut orphans: Vec<NodeId> = Vec::new();
        #[allow(clippy::needless_range_loop)] // The loop mutates both nodes[i] and its parent.
        for i in 0..total {
            if !self.nodes[i].is_used() || i == root {
                continue;
            }
            if i < record::FIRST_NORMAL_RECORD as usize && self.nodes[i].name_len == 0 && self.nodes[i].alloc == 0 {
                // Reserved records 12-23 can be marked in use without names or allocation; exclude them from orphans.
                self.nodes[i] = Node::UNUSED;
                continue;
            }
            if valid[i] {
                let p = self.nodes[i].parent as usize;
                let head = self.nodes[p].first_child;
                self.nodes[i].next_sibling = head;
                self.nodes[i].flags.insert(Flags::LINKED);
                self.nodes[p].first_child = i as NodeId;
            } else {
                orphans.push(i as NodeId);
            }
        }
        drop(valid);
        mark("validate + link");

        // 4. Rename the root and attach orphaned records to a synthetic directory.
        let root_off = self.names.len() as u32;
        self.names.extend_from_slice(root_name.as_bytes());
        {
            let r = &mut self.nodes[root];
            r.name_off = root_off;
            r.name_len = root_name.len() as u16;
            r.parent = NONE;
            r.flags.insert(Flags::LINKED);
        }
        summary.orphans = orphans.len() as u64;
        if !orphans.is_empty() {
            let bucket = self.nodes.len() as NodeId;
            let label = "<orphaned records>";
            let off = self.names.len() as u32;
            self.names.extend_from_slice(label.as_bytes());
            let head = self.nodes[root].first_child;
            self.nodes.push(Node {
                parent: root as NodeId,
                first_child: NONE,
                next_sibling: head,
                name_off: off,
                name_len: label.len() as u16,
                flags: Flags::DIR.union(Flags::METAFILE).union(Flags::LINKED),
                ..Node::UNUSED
            });
            self.nodes[root].first_child = bucket;
            for &o in &orphans {
                let head = self.nodes[bucket as usize].first_child;
                let n = &mut self.nodes[o as usize];
                n.parent = bucket;
                n.next_sibling = head;
                n.flags.insert(Flags::LINKED);
                if n.name_len == 0 {
                    // Use the record number when a name is missing, for example after a lost attribute list.
                    let label = format!("<record {o}>");
                    let off = self.names.len() as u32;
                    self.names.extend_from_slice(label.as_bytes());
                    let n = &mut self.nodes[o as usize];
                    n.name_off = off;
                    n.name_len = label.len() as u16;
                }
                self.nodes[bucket as usize].first_child = o;
            }
        }

        // 5. Do not expand junctions or symbolic links; MFT represents them as empty directories.
        mark("orphans + names shrink");
        let builder = TreeBuilder::from_linked(self.nodes, self.names, root as NodeId, summary);
        Ok((builder.finish(), self.stats))
    }
}

fn is_live_dir(n: &Node) -> bool {
    n.is_used() && n.flags.is_dir() && !n.flags.contains(Flags::REPARSE)
}

fn place(i: usize, facts: RecordFacts, node: &mut Node, m: &mut Meta, out: &mut TaskOut, count_index: bool) {
    let mut flags = facts.flags;
    if facts.is_dir {
        flags.insert(Flags::DIR);
    }
    if facts.has_logical {
        flags.insert(Flags::HAS_LOGICAL);
    }
    out.index_alloc = out.index_alloc.saturating_add(facts.index_alloc);
    let alloc = if count_index {
        facts.alloc.saturating_add(facts.index_alloc)
    } else {
        facts.alloc
    };
    let (parent, rank, name_off, name_len) = match facts.name {
        Some(n) => (n.parent, n.rank, n.off, n.len),
        None => (RecordRef(0), NO_NAME, 0, 0),
    };

    if facts.base != 0 {
        // Keep extension slots empty but retain their facts and allocation for merging and progress.
        out.counts.alloc = out.counts.alloc.saturating_add(alloc);
        out.patches.push(Patch {
            rec: i as u64,
            base: facts.base,
            logical: facts.logical,
            alloc,
            flags,
            links: facts.link_names.min(u16::MAX as u32) as u16,
            rank,
            parent,
            name_off,
            name_len,
            has_logical: facts.has_logical,
        });
        return;
    }
    *node = Node {
        logical: if facts.is_dir { 0 } else { facts.logical },
        alloc,
        parent: parent.number().min(NONE as u64 - 1) as u32,
        first_child: NONE,
        next_sibling: NONE,
        name_off,
        aux: 0,
        name_len,
        flags,
    };
    *m = Meta {
        seq: facts.seq,
        parent_seq: parent.sequence(),
        links: facts.link_names.min(u16::MAX as u32) as u16,
        rank,
    };
    if facts.is_dir {
        out.counts.dirs += 1;
    } else {
        out.counts.files += 1;
    }
    out.counts.alloc = out.counts.alloc.saturating_add(alloc);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mft::fixture::{RecordBuilder, image, root_dir};

    fn table_from(img: &mut [u8], opts: TableOptions) -> RecordTable {
        let total = img.len() / 1024;
        let mut t = RecordTable::new(total as u64, 1024, 4096, opts).unwrap();
        t.consume(0, img);
        t
    }

    /// ```text
    /// C:\                       (5)
    /// ├── docs\                 (16)
    /// │   ├── a.txt   1000 B    (17)
    /// │   └── link.bin 512 B    (20, hard links under docs and the root)
    /// ├── big.mkv    2 GiB      (18, $DATA in extension record 19)
    /// ├── junction\             (21, junction; not expanded)
    /// ├── orphan.txt            (22, parent is a file; orphaned)
    /// ├── stale.txt             (23 moved to 25, parent sequence mismatch; orphaned)
    /// └── unused record         (26)
    /// ```
    fn little_volume() -> Vec<u8> {
        image(
            1024,
            vec![
                (5, root_dir()),
                (16, RecordBuilder::dir().name(5, 5, 1, "docs").index_allocation(8192)),
                (17, RecordBuilder::file().name(16, 1, 1, "a.txt").data_nonresident(1000, 4096)),
                (18, RecordBuilder::file().seq(2).attribute_list_stub().name(5, 5, 1, "big.mkv")),
                (19, RecordBuilder::file().extension_of(18, 2).data_nonresident(2 << 30, 2 << 30)),
                (
                    20,
                    RecordBuilder::file()
                        .name(16, 1, 1, "link.bin")
                        .name(5, 5, 1, "link-alias.bin")
                        .data_nonresident(512, 4096),
                ),
                (21, RecordBuilder::dir().name(5, 5, 1, "junction").reparse(0xA000_0003)),
                (22, RecordBuilder::file().name(17, 1, 1, "orphan.txt").data_nonresident(10, 4096)),
                (25, RecordBuilder::file().name(16, 9, 1, "stale.txt").data_nonresident(10, 4096)),
                (26, RecordBuilder::file().name(5, 5, 1, "deleted.txt").freed()),
            ],
        )
    }

    #[test]
    fn builds_tree_with_hardlinks_extensions_and_orphans() {
        let mut img = little_volume();
        let t = table_from(&mut img, TableOptions::default());
        let (tree, stats) = t.finish("C:\\").unwrap();
        assert_eq!(stats.torn, 0);
        assert_eq!(stats.dropped_patches, 0);
        let root = tree.root();
        assert_eq!(tree.name(root), "C:\\");
        let docs = tree.child_by_name(root, "docs").unwrap();
        // docs: a.txt 4096 + link.bin 4096 + directory index 8192.
        assert_eq!(tree.node(docs).alloc, 4096 + 4096 + 8192);
        // A hard-linked file appears once under its first name.
        assert!(tree.child_by_name(root, "link-alias.bin").is_none());
        let link = tree.child_by_name(docs, "link.bin").unwrap();
        assert!(tree.node(link).flags.contains(Flags::HARDLINK));
        assert_eq!(tree.summary().extra_link_names, 1);
        // Extension-record data is merged into big.mkv.
        let big = tree.child_by_name(root, "big.mkv").unwrap();
        assert_eq!(tree.node(big).logical, 2 << 30);
        assert_eq!(tree.node(big).alloc, 2 << 30);
        // A junction is a leaf.
        let j = tree.child_by_name(root, "junction").unwrap();
        assert!(tree.node(j).flags.contains(Flags::REPARSE));
        assert_eq!(tree.children(j).count(), 0);
        // Both orphans are retained in the synthetic bucket.
        let bucket = tree.child_by_name(root, "<orphaned records>").unwrap();
        assert_eq!(tree.children(bucket).count(), 2);
        assert_eq!(tree.summary().orphans, 2);
        // Unused records are absent from the tree.
        assert!(tree.child_by_name(root, "deleted.txt").is_none());
        assert_eq!(tree.summary().files, 5);
        assert_eq!(
            tree.summary().alloc,
            4096 + 4096 + 8192 + (2u64 << 30) + 4096 + 4096
        );
    }

    /// With names spread across $ATTRIBUTE_LIST records, prefer a non-DOS base name; otherwise
    /// inspect ascending extension records after the base, then those before it.
    #[test]
    fn hardlink_names_across_extension_records_follow_wiztree() {
        let dirs = || {
            vec![
                (5u64, root_dir()),
                (24, RecordBuilder::dir().name(5, 5, 1, "packages")),
                (25, RecordBuilder::dir().name(5, 5, 1, "catroot")),
                (27, RecordBuilder::dir().name(5, 5, 1, "catalogs")),
            ]
        };
        // Case 1: base 50 has no name; extension 46 precedes it and extension 60 follows it.
        let mut recs = dirs();
        recs.push((50, RecordBuilder::file().attribute_list_stub()));
        recs.push((
            46,
            RecordBuilder::file()
                .extension_of(50, 1)
                .name(24, 1, 2, "PACKAG~1.CAT")
                .name(24, 1, 1, "package.cat")
                .name(25, 1, 0, "package.cat"),
        ));
        recs.push((60, RecordBuilder::file().extension_of(50, 1).name(27, 1, 0, "3c5a.cat").data_nonresident(10_000, 12_288)));
        let mut img = image(1024, recs);
        let (tree, _) = table_from(&mut img, TableOptions::default()).finish("C:\\").unwrap();
        let cat = tree.child_by_name(tree.root(), "catalogs").unwrap();
        let owner = tree.child_by_name(cat, "3c5a.cat").expect("name from the highest record");
        assert_eq!(tree.node(owner).alloc, 12_288);
        assert!(tree.node(owner).flags.contains(Flags::HARDLINK));
        assert_eq!(tree.summary().extra_link_names, 2);

        // Case 2: extension 42 precedes base 50, which has its own name; the base name wins.
        let mut recs = dirs();
        recs.push((42, RecordBuilder::file().extension_of(50, 1).name(27, 1, 0, "3c5a.cat").data_nonresident(10_000, 12_288)));
        recs.push((50, RecordBuilder::file().attribute_list_stub().name(24, 1, 0, "package.cat")));
        let mut img = image(1024, recs);
        let (tree, _) = table_from(&mut img, TableOptions::default()).finish("C:\\").unwrap();
        let pk = tree.child_by_name(tree.root(), "packages").unwrap();
        assert!(tree.child_by_name(pk, "package.cat").is_some());

        // Case 3: extension 64 follows base 50, but the base still has a preferred name.
        let mut recs = dirs();
        recs.push((50, RecordBuilder::file().attribute_list_stub().name(24, 1, 0, "package.cat")));
        recs.push((64, RecordBuilder::file().extension_of(50, 1).name(27, 1, 0, "3c5a.cat").data_nonresident(10_000, 12_288)));
        let mut img = image(1024, recs);
        let (tree, _) = table_from(&mut img, TableOptions::default()).finish("C:\\").unwrap();
        let pk = tree.child_by_name(tree.root(), "packages").unwrap();
        assert!(tree.child_by_name(pk, "package.cat").is_some());

        // Case 4: the base has only an 8.3 name; extension 60 wins over the earlier extension 46.
        let mut recs = dirs();
        recs.push((50, RecordBuilder::file().attribute_list_stub().name(24, 1, 2, "PACKAG~1.CAT")));
        recs.push((46, RecordBuilder::file().extension_of(50, 1).name(24, 1, 1, "package.cat").name(25, 1, 0, "package.cat")));
        recs.push((60, RecordBuilder::file().extension_of(50, 1).name(27, 1, 0, "3c5a.cat").data_nonresident(10_000, 12_288)));
        let mut img = image(1024, recs);
        let (tree, _) = table_from(&mut img, TableOptions::default()).finish("C:\\").unwrap();
        let cat = tree.child_by_name(tree.root(), "catalogs").unwrap();
        assert!(tree.child_by_name(cat, "3c5a.cat").is_some());

        // Case 5: both extensions follow the base; choose the lower record number, 56.
        let mut recs = dirs();
        recs.push((50, RecordBuilder::file().attribute_list_stub().name(24, 1, 2, "PACKAG~1.CAT")));
        recs.push((70, RecordBuilder::file().extension_of(50, 1).name(27, 1, 0, "3c5a.cat").data_nonresident(10_000, 12_288)));
        recs.push((56, RecordBuilder::file().extension_of(50, 1).name(25, 1, 0, "package.cat").name(24, 1, 1, "package.cat")));
        let mut img = image(1024, recs);
        let (tree, _) = table_from(&mut img, TableOptions::default()).finish("C:\\").unwrap();
        let cr = tree.child_by_name(tree.root(), "catroot").unwrap();
        assert!(tree.child_by_name(cr, "package.cat").is_some());

        // Case 6: both extensions precede the base; choose the lower record number, 30.
        let mut recs = dirs();
        recs.push((50, RecordBuilder::file().attribute_list_stub()));
        recs.push((40, RecordBuilder::file().extension_of(50, 1).name(27, 1, 0, "3c5a.cat").data_nonresident(10_000, 12_288)));
        recs.push((30, RecordBuilder::file().extension_of(50, 1).name(24, 1, 1, "package.cat")));
        let mut img = image(1024, recs);
        let (tree, _) = table_from(&mut img, TableOptions::default()).finish("C:\\").unwrap();
        let pk = tree.child_by_name(tree.root(), "packages").unwrap();
        assert!(tree.child_by_name(pk, "package.cat").is_some());
        assert_eq!(tree.summary().files, 1);
    }

    #[test]
    fn directory_index_can_be_excluded() {
        let mut img = little_volume();
        let t = table_from(
            &mut img,
            TableOptions {
                count_directory_index: false,
            },
        );
        let (tree, stats) = t.finish("C:\\").unwrap();
        let docs = tree.child_by_name(tree.root(), "docs").unwrap();
        assert_eq!(tree.node(docs).alloc, 4096 + 4096);
        assert_eq!(stats.index_alloc, 8192);
    }

    #[test]
    fn chunked_consume_matches_single_shot() {
        let img = little_volume();
        let mut a = img.clone();
        let (single, _) = table_from(&mut a, TableOptions::default()).finish("R").unwrap();

        let total = img.len() / 1024;
        let mut t = RecordTable::new(total as u64, 1024, 4096, TableOptions::default()).unwrap();
        let mut b = img;
        let (x, y) = b.split_at_mut(19 * 1024);
        t.consume(0, x);
        t.consume(19, y);
        let (chunked, _) = t.finish("R").unwrap();
        assert_eq!(single.summary(), chunked.summary());
        let names = |t: &DiskTree| {
            let mut v: Vec<String> = t.nodes().iter().enumerate().filter(|(_, n)| n.is_used()).map(|(i, _)| t.path(i as u32)).collect();
            v.sort();
            v
        };
        assert_eq!(names(&single), names(&chunked));
    }

    #[test]
    fn out_of_order_chunks_match_in_order() {
        // Deliver the second block before the first to verify independence from I/O completion order.
        let img = little_volume();
        let mut a = img.clone();
        let (single, _) = table_from(&mut a, TableOptions::default()).finish("R").unwrap();
        let total = img.len() / 1024;
        let mut t = RecordTable::new(total as u64, 1024, 4096, TableOptions::default()).unwrap();
        let mut b = img;
        let (x, y) = b.split_at_mut(18 * 1024);
        t.consume(18, y);
        t.consume(0, x);
        let (ooo, _) = t.finish("R").unwrap();
        assert_eq!(single.summary(), ooo.summary());
        let big = ooo.child_by_name(ooo.root(), "big.mkv").unwrap();
        assert_eq!(ooo.node(big).alloc, 2 << 30);
    }

    #[test]
    fn name_pool_estimate_is_not_inflated_by_late_first_chunk() {
        // 10,000 records arriving out of order must not cause an oversized name-arena reservation.
        let mut recs = vec![(5u64, root_dir())];
        for i in 24..10_000u64 {
            recs.push((i, RecordBuilder::file().name(5, 5, 1, &format!("file-{i:05}.txt")).data_nonresident(1, 4096)));
        }
        let mut img = image(1024, recs);
        let total = img.len() / 1024;
        let mut t = RecordTable::new(total as u64, 1024, 4096, TableOptions::default()).unwrap();
        let (x, y) = img.split_at_mut(1024 * 1024);
        t.consume(1024, y);
        t.consume(0, x);
        assert!(t.names.capacity() < 10_000 * 64, "capacity {}", t.names.capacity());
        let (tree, _) = t.finish("R").unwrap();
        assert_eq!(tree.summary().files, 10_000 - 24);
    }

    #[test]
    fn missing_root_is_an_error() {
        let mut img = image(1024, vec![(16, RecordBuilder::dir().name(5, 5, 1, "x"))]);
        let t = table_from(&mut img, TableOptions::default());
        assert!(t.finish("C:\\").is_err());
    }

    #[test]
    fn torn_records_are_counted() {
        let mut img = little_volume();
        img[17 * 1024 + 1022] ^= 0xFF;
        let t = table_from(&mut img, TableOptions::default());
        let (tree, stats) = t.finish("C:\\").unwrap();
        assert_eq!(stats.torn, 1);
        let docs = tree.child_by_name(tree.root(), "docs").unwrap();
        assert!(tree.child_by_name(docs, "a.txt").is_none());
    }

    #[test]
    fn put_base_path_matches_parse_path() {
        // Inserting records through put_base must match parsing the equivalent raw bytes.
        let mut t = RecordTable::new(32, 1024, 4096, TableOptions::default()).unwrap();
        let r5 = 5u64 | (5u64 << 48);
        t.put_base(5, 5, Some((".", r5)), 1, true, 0, 0, Flags::default());
        t.put_base(16, 1, Some(("docs", r5)), 1, true, 0, 0, Flags::default());
        t.put_base(17, 1, Some(("a.txt", 16 | (1 << 48))), 1, false, 1000, 4096, Flags::default());
        let (tree, _) = t.finish("C:\\").unwrap();
        let docs = tree.child_by_name(tree.root(), "docs").unwrap();
        assert_eq!(tree.node(docs).alloc, 4096);
        assert_eq!(tree.path(tree.child_by_name(docs, "a.txt").unwrap()), "C:\\docs\\a.txt");
    }
}
