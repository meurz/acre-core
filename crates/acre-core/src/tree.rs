//! Compact directory trees.
//!
//! Nodes occupy 40 bytes each in one Vec<Node>. Parent, first-child, and next-sibling links
//! are u32 indices. UTF-8 names share a byte arena, referenced by offset and length.
//! Directory counts and extension totals live in side tables to keep node storage compact.
//!
//! Traversal and aggregation are iterative, using breadth-first order to avoid stack overflow.

use std::collections::HashMap;

/// Node index: the MFT record number, or discovery order during directory traversal.
pub type NodeId = u32;

/// No node: the end of a linked list or an absent parent.
pub const NONE: NodeId = u32::MAX;

/// Node flags.
#[derive(Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct Flags(pub u16);

impl Flags {
    /// Directory.
    pub const DIR: Flags = Flags(1 << 0);
    /// Symbolic link, junction, or mount point: record the link without expanding it.
    pub const REPARSE: Flags = Flags(1 << 1);
    /// A file with multiple hard-link names; its contents are counted under one name only.
    pub const HARDLINK: Flags = Flags(1 << 2);
    /// NTFS compression (LZNT1).
    pub const COMPRESSED: Flags = Flags(1 << 3);
    /// Sparse file.
    pub const SPARSE: Flags = Flags(1 << 4);
    /// System compression (CompactOS/WOF); content lives in the WofCompressedData stream.
    pub const WOF: Flags = Flags(1 << 5);
    /// Cloud placeholder, typically with little or no local allocation.
    pub const PLACEHOLDER: Flags = Flags(1 << 6);
    /// `FILE_ATTRIBUTE_SYSTEM`。
    pub const SYSTEM: Flags = Flags(1 << 7);
    /// Alternate data streams, excluding the WOF data stream.
    pub const ADS: Flags = Flags(1 << 8);
    /// An unreadable directory; inaccessible or vanished contents are excluded.
    pub const ERROR: Flags = Flags(1 << 9);
    /// NTFS metadata or a synthetic scanner node, such as an orphan bucket.
    pub const METAFILE: Flags = Flags(1 << 10);
    /// EFS encryption.
    pub const ENCRYPTED: Flags = Flags(1 << 11);
    /// Internal: reachable from the root during finalization.
    pub(crate) const REACHED: Flags = Flags(1 << 12);
    /// Internal: linked into the tree.
    pub(crate) const LINKED: Flags = Flags(1 << 13);
    /// Internal: logical size of the unnamed stream is known, for extension-record merging.
    pub(crate) const HAS_LOGICAL: Flags = Flags(1 << 14);
    /// Unused slot: an unused MFT record or extension record, excluded from the tree.
    pub const UNUSED: Flags = Flags(1 << 15);

    /// Whether all bits of `other` are present.
    #[inline]
    pub fn contains(self, other: Flags) -> bool {
        self.0 & other.0 == other.0
    }
    /// Set bits.
    #[inline]
    pub fn insert(&mut self, other: Flags) {
        self.0 |= other.0;
    }
    /// Clear bits.
    #[inline]
    pub fn remove(&mut self, other: Flags) {
        self.0 &= !other.0;
    }
    /// Union of flags.
    #[inline]
    pub fn union(self, other: Flags) -> Flags {
        Flags(self.0 | other.0)
    }
    /// Whether this is an expandable directory rather than a link.
    #[inline]
    pub fn is_dir(self) -> bool {
        self.contains(Flags::DIR)
    }
}

impl std::fmt::Debug for Flags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        const NAMES: [(Flags, &str); 14] = [
            (Flags::DIR, "DIR"),
            (Flags::REPARSE, "REPARSE"),
            (Flags::HARDLINK, "HARDLINK"),
            (Flags::COMPRESSED, "COMPRESSED"),
            (Flags::SPARSE, "SPARSE"),
            (Flags::WOF, "WOF"),
            (Flags::PLACEHOLDER, "PLACEHOLDER"),
            (Flags::SYSTEM, "SYSTEM"),
            (Flags::ADS, "ADS"),
            (Flags::ERROR, "ERROR"),
            (Flags::METAFILE, "METAFILE"),
            (Flags::ENCRYPTED, "ENCRYPTED"),
            (Flags::LINKED, "LINKED"),
            (Flags::UNUSED, "UNUSED"),
        ];
        let mut first = true;
        for (flag, name) in NAMES {
            if self.contains(flag) {
                if !first {
                    f.write_str("|")?;
                }
                f.write_str(name)?;
                first = false;
            }
        }
        if first {
            f.write_str("-")?;
        }
        Ok(())
    }
}

/// A file or directory. Directory logical and allocated sizes are subtree totals in [`DiskTree`].
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Node {
    /// Logical bytes in the unnamed stream, or a directory's subtree total.
    pub logical: u64,
    /// Physical allocated bytes, including alternate streams; resident MFT data uses 0 extra bytes.
    pub alloc: u64,
    /// Parent node; [`NONE`] for the root.
    pub parent: NodeId,
    /// First child.
    pub first_child: NodeId,
    /// Next sibling.
    pub next_sibling: NodeId,
    /// Byte offset in the name arena.
    pub name_off: u32,
    /// Directory totals index for directories, or extension index for files.
    pub aux: u32,
    /// UTF-8 name length in bytes.
    pub name_len: u16,
    /// Flags.
    pub flags: Flags,
}

const _: () = assert!(std::mem::size_of::<Node>() == 40);

impl Node {
    /// An unused slot.
    pub const UNUSED: Node = Node {
        logical: 0,
        alloc: 0,
        parent: NONE,
        first_child: NONE,
        next_sibling: NONE,
        name_off: 0,
        aux: 0,
        name_len: 0,
        flags: Flags::UNUSED,
    };

    /// Whether the node is part of the tree rather than an unused slot.
    #[inline]
    pub fn is_used(&self) -> bool {
        !self.flags.contains(Flags::UNUSED)
    }
}

/// File and directory counts for a complete directory subtree.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DirTotals {
    /// Files in the subtree, excluding the directory itself.
    pub files: u32,
    /// Directories in the subtree, excluding the directory itself.
    pub dirs: u32,
}

/// Totals for one file extension.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExtTotals {
    /// Lowercase extension without a leading dot; empty for no extension.
    pub name: Box<str>,
    /// File count.
    pub files: u64,
    /// Total logical bytes.
    pub logical: u64,
    /// Total allocated bytes.
    pub alloc: u64,
}

/// Whole-tree totals and anomaly counts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Summary {
    /// File count; the MFT backend counts each hard-linked file once.
    pub files: u64,
    /// Directory count, including the root.
    pub dirs: u64,
    /// Total logical bytes.
    pub logical: u64,
    /// Total allocated bytes.
    pub alloc: u64,
    /// Additional hard-link names. Tools that count names, such as WizTree, include these
    /// in their reported file count.
    pub extra_link_names: u64,
    /// Records with missing or invalid parents, attached to a synthetic orphan bucket.
    pub orphans: u64,
    /// Unreadable directories.
    pub unreadable_dirs: u64,
    /// Linked but unreachable nodes, such as parent cycles; excluded from totals.
    pub unreachable: u64,
}

/// An incremental result batch containing newly discovered nodes.
#[derive(Clone, Debug, Default)]
pub struct Batch {
    /// New nodes.
    pub entries: Vec<BatchEntry>,
    /// Shared name bytes for this batch.
    pub names: String,
}

/// One entry in a [`Batch`]; its parent occurs in this batch or an earlier batch.
#[derive(Clone, Copy, Debug)]
pub struct BatchEntry {
    /// Node identifier.
    pub id: NodeId,
    /// Parent identifier.
    pub parent: NodeId,
    /// Name offset in [`Batch::names`].
    pub name_off: u32,
    /// Name length in bytes.
    pub name_len: u16,
    /// Flags.
    pub flags: Flags,
    /// Own logical size, excluding descendants for directories.
    pub logical: u64,
    /// Own allocated size, excluding descendants for directories.
    pub alloc: u64,
}

impl Batch {
    /// Name of one batch entry.
    pub fn name(&self, e: &BatchEntry) -> &str {
        &self.names[e.name_off as usize..e.name_off as usize + e.name_len as usize]
    }
    /// Whether the batch is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Child ordering.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SortKey {
    /// Descending allocated size.
    Alloc,
    /// Descending logical size.
    Logical,
    /// Ascending case-insensitive name.
    Name,
}

/// A finalized compact directory tree.
///
/// Supports in-place subtree removal after deletion through [`DiskTree::remove`] and
/// replacement after rescanning through [`DiskTree::replace_subtree`]. Ancestor sizes,
/// counts, and extension totals stay synchronized; extension order remains stable.
#[derive(Clone)]
pub struct DiskTree {
    nodes: Vec<Node>,
    names: Vec<u8>,
    dir_totals: Vec<DirTotals>,
    exts: Vec<ExtTotals>,
    root: NodeId,
    summary: Summary,
    image: bool,
}

impl DiskTree {
    /// Whether this tree represents read-only virtual disk contents, not host paths.
    pub fn is_read_only(&self) -> bool {
        self.image
    }
    /// Whether paths use Unix separators and case-sensitive names.
    pub fn uses_unix_paths(&self) -> bool {
        self.image
    }
    /// Root node.
    pub fn root(&self) -> NodeId {
        self.root
    }
    /// Number of slots, including unused ones.
    pub fn slots(&self) -> usize {
        self.nodes.len()
    }
    /// A node by identifier.
    #[inline]
    pub fn node(&self, id: NodeId) -> &Node {
        &self.nodes[id as usize]
    }
    /// All slots; unused slots carry [`Flags::UNUSED`].
    pub fn nodes(&self) -> &[Node] {
        &self.nodes
    }
    /// Node name.
    #[inline]
    pub fn name(&self, id: NodeId) -> &str {
        name_at(&self.names, &self.nodes[id as usize])
    }
    /// Direct children in unspecified order.
    pub fn children(&self, id: NodeId) -> Children<'_> {
        Children {
            nodes: &self.nodes,
            next: self.nodes[id as usize].first_child,
        }
    }
    /// Direct children sorted by `key`; sort only the expanded level when rendering a UI.
    pub fn sorted_children(&self, id: NodeId, key: SortKey) -> Vec<NodeId> {
        let mut v: Vec<NodeId> = self.children(id).collect();
        match key {
            SortKey::Alloc => v.sort_unstable_by(|&a, &b| {
                self.node(b)
                    .alloc
                    .cmp(&self.node(a).alloc)
                    .then_with(|| self.name(a).cmp(self.name(b)))
            }),
            SortKey::Logical => v.sort_unstable_by(|&a, &b| {
                self.node(b)
                    .logical
                    .cmp(&self.node(a).logical)
                    .then_with(|| self.name(a).cmp(self.name(b)))
            }),
            SortKey::Name => v.sort_by_cached_key(|&a| self.name(a).to_lowercase()),
        }
        v
    }
    /// Find a direct child (case-sensitive for image contents).
    pub fn child_by_name(&self, id: NodeId, name: &str) -> Option<NodeId> {
        self.children(id)
            .find(|&c| if self.image { self.name(c) == name } else { names_equal_ci(self.name(c), name) })
    }
    /// Subtree file and directory counts; returns zero for files.
    pub fn dir_totals(&self, id: NodeId) -> DirTotals {
        let n = self.node(id);
        if n.flags.is_dir() {
            self.dir_totals
                .get(n.aux as usize)
                .copied()
                .unwrap_or_default()
        } else {
            DirTotals::default()
        }
    }
    /// Full path using Unix separators for images and backslashes for host paths.
    pub fn path(&self, id: NodeId) -> String {
        let mut parts = Vec::new();
        let mut cur = id;
        while cur != NONE {
            parts.push(self.name(cur));
            if cur == self.root {
                break;
            }
            cur = self.node(cur).parent;
        }
        let mut out = String::new();
        let separator = if self.image { '/' } else { '\\' };
        for (i, p) in parts.iter().rev().enumerate() {
            if i > 0 && !out.ends_with(separator) {
                out.push(separator);
            }
            out.push_str(p);
        }
        out
    }
    /// Extension totals, initially sorted by descending allocation.
    pub fn extensions(&self) -> &[ExtTotals] {
        &self.exts
    }
    /// Whole-tree totals and anomaly counts.
    pub fn summary(&self) -> &Summary {
        &self.summary
    }
    /// Heap storage owned by the tree, measured by allocated capacity.
    pub fn memory_bytes(&self) -> usize {
        self.nodes.capacity() * std::mem::size_of::<Node>()
            + self.names.capacity()
            + self.dir_totals.capacity() * std::mem::size_of::<DirTotals>()
            + self.exts.capacity() * std::mem::size_of::<ExtTotals>()
            + self.exts.iter().map(|e| e.name.len()).sum::<usize>()
    }
    /// Number of live nodes, excluding unused slots.
    pub fn live_nodes(&self) -> u64 {
        self.summary.files + self.summary.dirs
    }
    /// Split the tree into batches with parents before children.
    pub fn batches(&self, batch_size: usize) -> Vec<Batch> {
        let order = bfs_order(&self.nodes, self.root);
        let mut out = Vec::new();
        let mut cur = Batch::default();
        for id in order {
            push_batch_entry(&mut cur, &self.nodes, &self.names, id);
            if cur.entries.len() >= batch_size {
                out.push(std::mem::take(&mut cur));
            }
        }
        if !cur.is_empty() {
            out.push(cur);
        }
        out
    }
}

/// Counts and sizes removed or added by a subtree update.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Removed {
    /// File count.
    pub files: u64,
    /// Directory count, including the subtree root if it is a directory.
    pub dirs: u64,
    /// Logical bytes.
    pub logical: u64,
    /// Allocated bytes.
    pub alloc: u64,
}

impl DiskTree {
    /// Own `(logical, allocated)` bytes. For directories, subtract child totals from the
    /// subtree total; MFT directory allocation includes the directory index.
    pub fn own_sizes(&self, id: NodeId) -> (u64, u64) {
        let n = self.node(id);
        if !n.flags.is_dir() {
            return (n.logical, n.alloc);
        }
        let (mut l, mut a) = (0u64, 0u64);
        for c in self.children(id) {
            let cn = self.node(c);
            l = l.saturating_add(cn.logical);
            a = a.saturating_add(cn.alloc);
        }
        (n.logical.saturating_sub(l), n.alloc.saturating_sub(a))
    }

    /// Direct child count.
    pub fn child_count(&self, id: NodeId) -> usize {
        self.children(id).count()
    }

    /// Find a full path using the root-name convention of [`DiskTree::path`]. Matching ignores
    /// case and accepts either separator for host paths. Image paths are exact Unix paths.
    pub fn find_path(&self, path: &str) -> Option<NodeId> {
        if self.image {
            if !path.starts_with('/') { return None; }
            let root = self.name(self.root).trim_end_matches('/');
            let rest = path.strip_prefix(root)?;
            if !rest.starts_with('/') && !rest.is_empty() {
                return None;
            }
            let mut cur = self.root;
            for part in rest.split('/').filter(|p| !p.is_empty()) {
                cur = self.child_by_name(cur, part)?;
            }
            return Some(cur);
        }
        let norm = |s: &str| s.replace('/', "\\").trim_end_matches('\\').to_string();
        let path = norm(path);
        let root_name = norm(self.name(self.root));
        let rest = if path.len() >= root_name.len()
            && path.is_char_boundary(root_name.len())
            && names_equal_ci(&path[..root_name.len()], &root_name)
        {
            &path[root_name.len()..]
        } else {
            return None;
        };
        if !rest.is_empty() && !rest.starts_with('\\') {
            return None;
        }
        let mut cur = self.root;
        for part in rest.split('\\').filter(|p| !p.is_empty()) {
            cur = self.child_by_name(cur, part)?;
        }
        Some(cur)
    }

    /// Remove the subtree rooted at `id` after deleting it on disk. Update ancestor and extension
    /// totals and mark removed nodes unused. Removing the root does nothing and returns zero.
    ///
    /// Removing a hard-link name does not imply that its disk allocation was freed.
    pub fn remove(&mut self, id: NodeId) -> Removed {
        if id == self.root || !self.node(id).is_used() || !self.node(id).flags.contains(Flags::LINKED) {
            return Removed::default();
        }
        let n = *self.node(id);
        self.unlink(id);
        let r = self.subtree_totals(id);
        self.adjust_ancestors(n.parent, -(r.logical as i128), -(r.alloc as i128), -(r.files as i64), -(r.dirs as i64));
        self.clear_subtree(id);
        self.adjust_summary(&r, -1);
        r
    }

    /// Copy the subtree rooted at `id`, renaming its root to `root_name` for folder scans.
    pub fn subtree(&self, id: NodeId, root_name: &str) -> DiskTree {
        let est = if self.node(id).flags.is_dir() {
            let t = self.dir_totals(id);
            t.files as usize + t.dirs as usize + 1
        } else {
            1
        };
        let mut b = TreeBuilder::with_capacity(root_name, est, est.saturating_mul(24));
        b.image = self.image;
        let root = b.root();
        let (l, a) = self.own_sizes(id);
        {
            let r = b.node_mut(root);
            r.logical = l;
            r.alloc = a;
            let keep = self.node(id).flags.0 & !(Flags::LINKED.0 | Flags::REACHED.0 | Flags::HAS_LOGICAL.0 | Flags::UNUSED.0);
            r.flags.insert(Flags(keep));
            r.flags.insert(Flags::DIR);
        }
        let mut extra = 0u64;
        let mut stack = vec![(id, root)];
        while let Some((src, dst)) = stack.pop() {
            for c in self.children(src) {
                let cn = self.node(c);
                let (l, a) = self.own_sizes(c);
                let mut flags = cn.flags;
                flags.remove(Flags::LINKED);
                let nid = b.add(dst, self.name(c), flags, l, a);
                if cn.flags.is_dir() {
                    stack.push((c, nid));
                } else if cn.flags.contains(Flags::HARDLINK) && cn.alloc == 0 && cn.logical == 0 {
                    // Directory traversal retains duplicate hard-link names as zero-size nodes.
                    extra += 1;
                }
            }
        }
        b.summary_mut().extra_link_names = extra;
        b.finish()
    }

    /// Replace the children and totals of directory `id` with `fresh`, preserving its name.
    /// Old children become unused. Update ancestors and extension totals; return `(old, new)`.
    pub fn replace_subtree(&mut self, id: NodeId, fresh: &DiskTree) -> (Removed, Removed) {
        assert!(self.node(id).flags.is_dir(), "replace_subtree needs a directory");
        let old = self.subtree_totals(id);
        // 1. Remove old extension totals and mark old children unused.
        let mut c = self.node(id).first_child;
        while c != NONE {
            let next = self.node(c).next_sibling;
            self.clear_subtree(c);
            c = next;
        }
        self.nodes[id as usize].first_child = NONE;
        // 2. Copy new nodes parent-first and match extensions by name.
        let mut ext_index: HashMap<Box<str>, u32> =
            self.exts.iter().enumerate().map(|(i, e)| (e.name.clone(), i as u32)).collect();
        let mut map: HashMap<NodeId, NodeId> = HashMap::new();
        map.insert(fresh.root, id);
        for src in bfs_order(&fresh.nodes, fresh.root) {
            if src == fresh.root {
                continue;
            }
            let f = *fresh.node(src);
            let parent = map[&f.parent];
            let new_id = self.nodes.len() as NodeId;
            assert!(new_id != NONE, "node count overflow");
            let name = fresh.name(src);
            let off = self.names.len();
            assert!(off + name.len() <= u32::MAX as usize, "name pool overflow");
            self.names.extend_from_slice(name.as_bytes());
            let aux = if f.flags.is_dir() {
                self.dir_totals.push(fresh.dir_totals(src));
                (self.dir_totals.len() - 1) as u32
            } else {
                let e = &fresh.exts[f.aux as usize];
                let gi = *ext_index.entry(e.name.clone()).or_insert_with(|| {
                    self.exts.push(ExtTotals {
                        name: e.name.clone(),
                        ..ExtTotals::default()
                    });
                    (self.exts.len() - 1) as u32
                });
                let t = &mut self.exts[gi as usize];
                t.files += 1;
                t.logical = t.logical.saturating_add(f.logical);
                t.alloc = t.alloc.saturating_add(f.alloc);
                gi
            };
            let head = self.nodes[parent as usize].first_child;
            self.nodes.push(Node {
                parent,
                first_child: NONE,
                next_sibling: head,
                name_off: off as u32,
                name_len: f.name_len,
                aux,
                ..f
            });
            self.nodes[parent as usize].first_child = new_id;
            map.insert(src, new_id);
        }
        // 3. Replace directory totals and apply the difference to its ancestors.
        let fr = *fresh.node(fresh.root);
        let new = fresh.subtree_totals(fresh.root);
        {
            let n = &mut self.nodes[id as usize];
            n.logical = fr.logical;
            n.alloc = fr.alloc;
            let aux = n.aux as usize;
            self.dir_totals[aux] = fresh.dir_totals(fresh.root);
        }
        let parent = self.node(id).parent;
        self.adjust_ancestors(
            parent,
            new.logical as i128 - old.logical as i128,
            new.alloc as i128 - old.alloc as i128,
            new.files as i64 - old.files as i64,
            new.dirs as i64 - old.dirs as i64,
        );
        self.adjust_summary(&old, -1);
        self.adjust_summary(&new, 1);
        (old, new)
    }

    /// Counts and sizes of a subtree including `id` itself.
    fn subtree_totals(&self, id: NodeId) -> Removed {
        let n = self.node(id);
        let (files, dirs) = if n.flags.is_dir() {
            let t = self.dir_totals(id);
            (t.files as u64, t.dirs as u64 + 1)
        } else {
            (1, 0)
        };
        Removed {
            files,
            dirs,
            logical: n.logical,
            alloc: n.alloc,
        }
    }

    /// Unlink `id` from its parent's child list.
    fn unlink(&mut self, id: NodeId) {
        let parent = self.node(id).parent;
        let next = self.node(id).next_sibling;
        let mut prev = NONE;
        let mut c = self.node(parent).first_child;
        while c != NONE && c != id {
            prev = c;
            c = self.node(c).next_sibling;
        }
        if c != id {
            return;
        }
        if prev == NONE {
            self.nodes[parent as usize].first_child = next;
        } else {
            self.nodes[prev as usize].next_sibling = next;
        }
    }

    /// Subtract subtree files from extension totals and mark every subtree slot unused.
    fn clear_subtree(&mut self, id: NodeId) {
        let mut stack = vec![id];
        while let Some(x) = stack.pop() {
            let n = self.nodes[x as usize];
            if n.flags.is_dir() {
                let mut c = n.first_child;
                while c != NONE {
                    stack.push(c);
                    c = self.nodes[c as usize].next_sibling;
                }
            } else if let Some(e) = self.exts.get_mut(n.aux as usize) {
                e.files = e.files.saturating_sub(1);
                e.logical = e.logical.saturating_sub(n.logical);
                e.alloc = e.alloc.saturating_sub(n.alloc);
            }
            self.nodes[x as usize] = Node::UNUSED;
        }
    }

    /// Apply a difference from `from` through all ancestors up to the root.
    fn adjust_ancestors(&mut self, from: NodeId, logical: i128, alloc: i128, files: i64, dirs: i64) {
        let add = |v: u64, d: i128| (v as i128 + d).clamp(0, u64::MAX as i128) as u64;
        let add32 = |v: u32, d: i64| (v as i64 + d).clamp(0, u32::MAX as i64) as u32;
        let mut a = from;
        while a != NONE {
            let n = &mut self.nodes[a as usize];
            n.logical = add(n.logical, logical);
            n.alloc = add(n.alloc, alloc);
            let aux = n.aux as usize;
            let parent = n.parent;
            if let Some(t) = self.dir_totals.get_mut(aux) {
                t.files = add32(t.files, files);
                t.dirs = add32(t.dirs, dirs);
            }
            if a == self.root {
                break;
            }
            a = parent;
        }
    }

    fn adjust_summary(&mut self, r: &Removed, sign: i64) {
        let s = &mut self.summary;
        let f = |v: u64, d: u64| if sign < 0 { v.saturating_sub(d) } else { v.saturating_add(d) };
        s.files = f(s.files, r.files);
        s.dirs = f(s.dirs, r.dirs);
        s.logical = f(s.logical, r.logical);
        s.alloc = f(s.alloc, r.alloc);
    }
}

/// Direct-child iterator.
pub struct Children<'a> {
    nodes: &'a [Node],
    next: NodeId,
}

impl Iterator for Children<'_> {
    type Item = NodeId;
    fn next(&mut self) -> Option<NodeId> {
        if self.next == NONE {
            return None;
        }
        let id = self.next;
        self.next = self.nodes[id as usize].next_sibling;
        Some(id)
    }
}

/// Incremental tree builder. Children are prepended to the parent list in O(1).
pub struct TreeBuilder {
    nodes: Vec<Node>,
    names: Vec<u8>,
    root: NodeId,
    summary: Summary,
    image: bool,
}

impl TreeBuilder {
    /// Create a read-only image tree rooted at `/`, with Unix path semantics.
    pub fn new_image() -> Self {
        let mut builder = Self::new("/");
        builder.image = true;
        builder
    }

    /// Create a tree with only a root directory.
    pub fn new(root_name: &str) -> Self {
        Self::with_capacity(root_name, 0, 0)
    }

    /// Create a tree with reserved capacity.
    pub fn with_capacity(root_name: &str, nodes: usize, name_bytes: usize) -> Self {
        let mut b = TreeBuilder {
            nodes: Vec::with_capacity(nodes.max(1)),
            names: Vec::with_capacity(name_bytes),
            root: 0,
            summary: Summary::default(),
            image: false,
        };
        let off = b.push_name(root_name);
        b.nodes.push(Node {
            name_off: off,
            name_len: clamp_len(root_name),
            flags: Flags::DIR.union(Flags::LINKED),
            ..Node::UNUSED
        });
        b
    }

    /// Adopt an already linked node array for MFT scans; `root` must be a directory.
    pub(crate) fn from_linked(nodes: Vec<Node>, names: Vec<u8>, root: NodeId, summary: Summary) -> Self {
        TreeBuilder {
            nodes,
            names,
            root,
            summary,
            image: false,
        }
    }

    /// Root node.
    pub fn root(&self) -> NodeId {
        self.root
    }

    /// Existing slot count, including unused slots.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether the tree contains only its root.
    pub fn is_empty(&self) -> bool {
        self.nodes.len() <= 1
    }

    /// Add a node under `parent` and return its identifier.
    pub fn add(&mut self, parent: NodeId, name: &str, flags: Flags, logical: u64, alloc: u64) -> NodeId {
        let id = self.nodes.len() as NodeId;
        assert!(id != NONE, "node count overflow");
        let off = self.push_name(name);
        let p = &mut self.nodes[parent as usize];
        let next = p.first_child;
        p.first_child = id;
        let mut flags = flags;
        flags.remove(Flags::UNUSED);
        flags.insert(Flags::LINKED);
        self.nodes.push(Node {
            logical,
            alloc,
            parent,
            first_child: NONE,
            next_sibling: next,
            name_off: off,
            aux: 0,
            name_len: clamp_len(name),
            flags,
        });
        id
    }

    /// Mutate a node, for example to mark a directory unreadable after discovery.
    pub fn node_mut(&mut self, id: NodeId) -> &mut Node {
        &mut self.nodes[id as usize]
    }

    /// A node by identifier.
    pub fn node(&self, id: NodeId) -> &Node {
        &self.nodes[id as usize]
    }

    /// Node name.
    pub fn name(&self, id: NodeId) -> &str {
        name_at(&self.names, &self.nodes[id as usize])
    }

    /// Anomaly counters accumulated by the scanner.
    pub fn summary_mut(&mut self) -> &mut Summary {
        &mut self.summary
    }

    /// Create a batch from newly added nodes in `[from, len)`.
    pub fn batch_since(&self, from: NodeId) -> Batch {
        let mut b = Batch::default();
        for id in from as usize..self.nodes.len() {
            if self.nodes[id].is_used() {
                push_batch_entry(&mut b, &self.nodes, &self.names, id as NodeId);
            }
        }
        b
    }

    /// Finalize bottom-up sizes, counts, and extension totals.
    ///
    /// Breadth-first traversal and bottom-up accumulation are sequential. Extension totals
    /// are computed in parallel blocks, deduplicated locally, then merged.
    pub fn finish(self) -> DiskTree {
        use rayon::prelude::*;

        let TreeBuilder {
            mut nodes,
            names,
            root,
            mut summary,
            image,
        } = self;
        let trace = std::env::var_os("ACRE_MFT_TRACE").is_some();
        let t0 = std::time::Instant::now();
        let mark = |what: &str| {
            if trace {
                eprintln!("tree trace: {what} @ {:?}", t0.elapsed());
            }
        };

        // 1. Traverse parent-first, mark reachable nodes, and allocate directory-total indices.
        let mut order: Vec<NodeId> = Vec::with_capacity(nodes.len());
        let mut dir_totals: Vec<DirTotals> = Vec::new();
        let mut files = 0u64;
        {
            let r = &mut nodes[root as usize];
            r.flags.insert(Flags::REACHED);
            r.aux = 0;
            dir_totals.push(DirTotals::default());
        }
        order.push(root);
        let mut head = 0;
        while head < order.len() {
            let id = order[head];
            head += 1;
            let mut c = nodes[id as usize].first_child;
            while c != NONE {
                let n = &mut nodes[c as usize];
                n.flags.insert(Flags::REACHED);
                if n.flags.is_dir() {
                    n.aux = dir_totals.len() as u32;
                    dir_totals.push(DirTotals::default());
                } else {
                    files += 1;
                }
                order.push(c);
                c = n.next_sibling;
            }
        }
        let dirs = dir_totals.len() as u64;
        mark("bfs");
        summary.unreachable = nodes
            .par_iter()
            .filter(|n| n.flags.contains(Flags::LINKED) && !n.flags.contains(Flags::REACHED))
            .count() as u64;

        // 2. Aggregate extensions in parallel; temporarily store block-local indices in aux.
        const CHUNK: usize = 1 << 16;
        let locals: Vec<Vec<(ExtKey, ExtTotals)>> = nodes
            .par_chunks_mut(CHUNK)
            .map(|chunk| {
                let mut index: HashMap<ExtKey, u32, FnvBuild> = HashMap::with_hasher(FnvBuild);
                let mut list: Vec<(ExtKey, ExtTotals)> = Vec::new();
                for n in chunk.iter_mut() {
                    if !n.flags.contains(Flags::REACHED) || n.flags.is_dir() {
                        continue;
                    }
                    let name = &names[n.name_off as usize..n.name_off as usize + n.name_len as usize];
                    let key = ExtKey::of(name);
                    let i = *index.entry(key).or_insert_with(|| {
                        list.push((key, ExtTotals::default()));
                        (list.len() - 1) as u32
                    });
                    let e = &mut list[i as usize].1;
                    e.files += 1;
                    e.logical = e.logical.saturating_add(n.logical);
                    e.alloc = e.alloc.saturating_add(n.alloc);
                    n.aux = i;
                }
                list
            })
            .collect();
        // Merge globally, sort by allocation, and map block-local indices to final indices.
        let mut global: HashMap<ExtKey, u32, FnvBuild> = HashMap::with_hasher(FnvBuild);
        let mut gkeys: Vec<ExtKey> = Vec::new();
        let mut gtot: Vec<ExtTotals> = Vec::new();
        let mut to_global: Vec<Vec<u32>> = Vec::with_capacity(locals.len());
        for list in &locals {
            let mut m = Vec::with_capacity(list.len());
            for (k, t) in list {
                let g = *global.entry(*k).or_insert_with(|| {
                    gkeys.push(*k);
                    gtot.push(ExtTotals::default());
                    (gkeys.len() - 1) as u32
                });
                let e = &mut gtot[g as usize];
                e.files += t.files;
                e.logical = e.logical.saturating_add(t.logical);
                e.alloc = e.alloc.saturating_add(t.alloc);
                m.push(g);
            }
            to_global.push(m);
        }
        drop(locals);
        let mut perm: Vec<u32> = (0..gkeys.len() as u32).collect();
        perm.sort_unstable_by(|&a, &b| {
            gtot[b as usize]
                .alloc
                .cmp(&gtot[a as usize].alloc)
                .then_with(|| gkeys[a as usize].bytes().cmp(gkeys[b as usize].bytes()))
        });
        let mut rank = vec![0u32; perm.len()];
        for (new, &old) in perm.iter().enumerate() {
            rank[old as usize] = new as u32;
        }
        for m in to_global.iter_mut() {
            for g in m.iter_mut() {
                *g = rank[*g as usize];
            }
        }
        let exts: Vec<ExtTotals> = perm
            .iter()
            .map(|&old| ExtTotals {
                name: String::from_utf8_lossy(gkeys[old as usize].bytes()).into(),
                ..gtot[old as usize].clone()
            })
            .collect();
        nodes.par_chunks_mut(CHUNK).zip(to_global.par_iter()).for_each(|(chunk, map)| {
            for n in chunk.iter_mut() {
                if n.flags.contains(Flags::REACHED) && !n.flags.is_dir() {
                    n.aux = map[n.aux as usize];
                }
            }
        });
        mark("extensions");

        // 3. Accumulate each node into its parent in reverse breadth-first order.
        for &id in order.iter().rev() {
            if id == root {
                continue;
            }
            let n = nodes[id as usize];
            let p = n.parent as usize;
            let (child_files, child_dirs) = if n.flags.is_dir() {
                let t = dir_totals[n.aux as usize];
                (t.files, t.dirs.saturating_add(1))
            } else {
                (1, 0)
            };
            let pn = &mut nodes[p];
            pn.logical = pn.logical.saturating_add(n.logical);
            pn.alloc = pn.alloc.saturating_add(n.alloc);
            let t = &mut dir_totals[pn.aux as usize];
            t.files = t.files.saturating_add(child_files);
            t.dirs = t.dirs.saturating_add(child_dirs);
        }
        drop(order);
        mark("rollup");

        let r = nodes[root as usize];
        summary.files = files;
        summary.dirs = dirs;
        summary.logical = r.logical;
        summary.alloc = r.alloc;
        nodes.par_iter_mut().for_each(|n| {
            n.flags.remove(Flags::HAS_LOGICAL);
            n.flags.remove(Flags::REACHED);
        });
        // Return excess capacity after incremental growth. Keep small amounts of spare capacity
        // to avoid a full copy and the temporary memory peak of holding old and new buffers.
        if nodes.capacity() > nodes.len() + nodes.len() / 4 {
            nodes.shrink_to_fit();
        }
        let mut names = names;
        if names.capacity() > names.len() + names.len() / 4 {
            names.shrink_to_fit();
        }
        dir_totals.shrink_to_fit();
        mark("flags + shrink");

        DiskTree {
            nodes,
            names,
            dir_totals,
            exts,
            root,
            summary,
            image,
        }
    }

    fn push_name(&mut self, name: &str) -> u32 {
        let off = self.names.len();
        assert!(off <= u32::MAX as usize, "name pool overflow");
        let len = clamp_len(name) as usize;
        self.names.extend_from_slice(&name.as_bytes()[..len]);
        off as u32
    }
}

const MAX_EXT: usize = 32;

/// An allocation-free, lowercase ASCII extension key. Names without dots, leading or
/// trailing dots, and extensions longer than 32 bytes are treated as having no extension.
#[derive(Clone, Copy, PartialEq, Eq)]
struct ExtKey {
    len: u8,
    buf: [u8; MAX_EXT],
}

impl ExtKey {
    fn of(name: &[u8]) -> ExtKey {
        let mut k = ExtKey { len: 0, buf: [0; MAX_EXT] };
        let Some(dot) = name.iter().rposition(|&c| c == b'.') else {
            return k;
        };
        let ext = &name[dot + 1..];
        if ext.is_empty() || ext.len() > MAX_EXT || dot == 0 {
            return k;
        }
        for (d, &s) in k.buf.iter_mut().zip(ext) {
            *d = s.to_ascii_lowercase();
        }
        k.len = ext.len() as u8;
        k
    }
    fn bytes(&self) -> &[u8] {
        &self.buf[..self.len as usize]
    }
}

impl std::hash::Hash for ExtKey {
    fn hash<H: std::hash::Hasher>(&self, h: &mut H) {
        h.write(self.bytes());
    }
}

/// FNV-1a for short extension keys; fast but not intended as a collision-resistant hash.
#[derive(Clone, Copy, Default)]
struct FnvBuild;

struct Fnv(u64);

impl std::hash::BuildHasher for FnvBuild {
    type Hasher = Fnv;
    fn build_hasher(&self) -> Fnv {
        Fnv(0xcbf2_9ce4_8422_2325)
    }
}

impl std::hash::Hasher for Fnv {
    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 ^= b as u64;
            self.0 = self.0.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    fn finish(&self) -> u64 {
        self.0
    }
}

/// Limit name length to u16 bytes, truncating on a UTF-8 character boundary.
fn clamp_len(name: &str) -> u16 {
    if name.len() <= u16::MAX as usize {
        return name.len() as u16;
    }
    let mut end = u16::MAX as usize;
    while !name.is_char_boundary(end) {
        end -= 1;
    }
    end as u16
}

#[inline]
fn name_at<'a>(names: &'a [u8], n: &Node) -> &'a str {
    let bytes = &names[n.name_off as usize..n.name_off as usize + n.name_len as usize];
    // Names are inserted from &str and truncated on character boundaries, so UTF-8 is valid.
    std::str::from_utf8(bytes).unwrap_or("\u{FFFD}")
}

/// Breadth-first traversal from the root, with parents before children.
pub(crate) fn bfs_order(nodes: &[Node], root: NodeId) -> Vec<NodeId> {
    let mut order = Vec::with_capacity(nodes.len());
    order.push(root);
    let mut head = 0;
    while head < order.len() {
        let id = order[head];
        head += 1;
        let mut c = nodes[id as usize].first_child;
        while c != NONE {
            order.push(c);
            c = nodes[c as usize].next_sibling;
        }
    }
    order
}

fn push_batch_entry(b: &mut Batch, nodes: &[Node], names: &[u8], id: NodeId) {
    let n = &nodes[id as usize];
    let name = name_at(names, n);
    let off = b.names.len() as u32;
    b.names.push_str(name);
    b.entries.push(BatchEntry {
        id,
        parent: n.parent,
        name_off: off,
        name_len: n.name_len,
        flags: n.flags,
        logical: n.logical,
        alloc: n.alloc,
    });
}

/// Case-insensitive comparison in the style of NTFS.
pub fn names_equal_ci(a: &str, b: &str) -> bool {
    if a.is_ascii() && b.is_ascii() {
        return a.eq_ignore_ascii_case(b);
    }
    a.chars()
        .flat_map(char::to_lowercase)
        .eq(b.chars().flat_map(char::to_lowercase))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> DiskTree {
        let mut b = TreeBuilder::new("C:\\");
        let root = b.root();
        let win = b.add(root, "Windows", Flags::DIR, 0, 0);
        let sys = b.add(win, "System32", Flags::DIR, 0, 0);
        b.add(sys, "a.DLL", Flags::default(), 1000, 4096);
        b.add(sys, "b.dll", Flags::default(), 5000, 8192);
        b.add(win, "notepad.exe", Flags::default(), 300, 4096);
        let users = b.add(root, "Users", Flags::DIR, 0, 0);
        b.add(users, "big.iso", Flags::default(), 1 << 30, 1 << 30);
        b.add(root, "pagefile.sys", Flags::SYSTEM, 1 << 33, 1 << 33);
        b.add(root, "empty", Flags::DIR, 0, 0);
        b.finish()
    }

    #[test]
    fn totals_roll_up() {
        let t = sample();
        let root = t.root();
        assert_eq!(t.node(root).logical, 1000 + 5000 + 300 + (1 << 30) + (1 << 33));
        assert_eq!(t.node(root).alloc, 4096 + 8192 + 4096 + (1 << 30) + (1 << 33));
        let win = t.child_by_name(root, "windows").unwrap();
        assert_eq!(t.node(win).alloc, 4096 + 8192 + 4096);
        assert_eq!(t.dir_totals(win), DirTotals { files: 3, dirs: 1 });
        assert_eq!(t.dir_totals(root), DirTotals { files: 5, dirs: 4 });
        let s = t.summary();
        assert_eq!(s.files, 5);
        assert_eq!(s.dirs, 5); // Including the root.
        assert_eq!(s.unreachable, 0);
    }

    #[test]
    fn sorted_children_by_alloc() {
        let t = sample();
        let names: Vec<&str> = t
            .sorted_children(t.root(), SortKey::Alloc)
            .into_iter()
            .map(|c| t.name(c))
            .collect();
        assert_eq!(names, ["pagefile.sys", "Users", "Windows", "empty"]);
        let by_name: Vec<&str> = t
            .sorted_children(t.root(), SortKey::Name)
            .into_iter()
            .map(|c| t.name(c))
            .collect();
        assert_eq!(by_name, ["empty", "pagefile.sys", "Users", "Windows"]);
    }

    #[test]
    fn extension_table() {
        let t = sample();
        let dll = t.extensions().iter().find(|e| &*e.name == "dll").unwrap();
        assert_eq!(dll.files, 2);
        assert_eq!(dll.alloc, 4096 + 8192);
        // sys sorts first because of pagefile.
        assert_eq!(&*t.extensions()[0].name, "sys");
        // A file node's aux points to the sorted extension entry.
        let root = t.root();
        let win = t.child_by_name(root, "Windows").unwrap();
        let sys = t.child_by_name(win, "System32").unwrap();
        for c in t.children(sys) {
            assert_eq!(&*t.extensions()[t.node(c).aux as usize].name, "dll");
        }
    }

    #[test]
    fn find_path_is_case_insensitive_and_accepts_both_separators() {
        let t = sample();
        let sys = t.find_path("c:\\windows/SYSTEM32\\").unwrap();
        assert_eq!(t.name(sys), "System32");
        assert_eq!(t.find_path("C:\\"), Some(t.root()));
        assert_eq!(t.find_path("C:"), Some(t.root()));
        assert!(t.find_path("C:\\Windows\\nope").is_none());
        assert!(t.find_path("D:\\Windows").is_none());
    }

    #[test]
    fn remove_updates_ancestors_extensions_and_summary() {
        let mut t = sample();
        let root = t.root();
        let before = *t.summary();
        let sys = t.find_path("C:\\Windows\\System32").unwrap();
        let r = t.remove(sys);
        assert_eq!(r, Removed { files: 2, dirs: 1, logical: 6000, alloc: 4096 + 8192 });
        let win = t.find_path("C:\\Windows").unwrap();
        assert_eq!(t.node(win).alloc, 4096);
        assert_eq!(t.dir_totals(win), DirTotals { files: 1, dirs: 0 });
        assert_eq!(t.dir_totals(root), DirTotals { files: 3, dirs: 3 });
        assert_eq!(t.node(root).alloc, before.alloc - 4096 - 8192);
        assert_eq!(t.summary().files, before.files - 2);
        assert_eq!(t.summary().dirs, before.dirs - 1);
        assert_eq!(t.summary().alloc, before.alloc - 4096 - 8192);
        let dll = t.extensions().iter().find(|e| &*e.name == "dll").unwrap();
        assert_eq!((dll.files, dll.alloc), (0, 0));
        assert!(t.child_by_name(win, "System32").is_none());
        assert!(!t.node(sys).is_used());
        // Remove one file.
        let iso = t.find_path("C:\\Users\\big.iso").unwrap();
        t.remove(iso);
        let users = t.find_path("C:\\Users").unwrap();
        assert_eq!(t.node(users).alloc, 0);
        assert_eq!(t.dir_totals(users).files, 0);
        // The root cannot be removed.
        assert_eq!(t.remove(root), Removed::default());
        // Updated totals agree with full recomputation.
        let fresh_sum: u64 = t.children(root).map(|c| t.node(c).alloc).sum();
        assert_eq!(fresh_sum, t.node(root).alloc);
    }

    #[test]
    fn subtree_keeps_own_sizes_and_totals() {
        let mut b = TreeBuilder::new("C:\\");
        let root = b.root();
        let d = b.add(root, "data", Flags::DIR, 0, 8192); // Own directory allocation (directory index).
        let x = b.add(d, "x", Flags::DIR, 0, 0);
        b.add(x, "a.bin", Flags::default(), 10, 4096);
        b.add(d, "b.txt", Flags::default(), 20, 4096);
        b.add(root, "other.bin", Flags::default(), 1, 4096);
        let t = b.finish();
        let data = t.find_path("C:\\data").unwrap();
        assert_eq!(t.own_sizes(data), (0, 8192));
        let s = t.subtree(data, "C:\\data");
        assert_eq!(s.name(s.root()), "C:\\data");
        assert_eq!(s.node(s.root()).alloc, 8192 + 4096 + 4096);
        assert_eq!(s.summary().files, 2);
        assert_eq!(s.summary().dirs, 2);
        assert_eq!(s.dir_totals(s.root()), DirTotals { files: 2, dirs: 1 });
        assert!(s.find_path("C:\\data\\x\\a.bin").is_some());
        let txt = s.extensions().iter().find(|e| &*e.name == "txt").unwrap();
        assert_eq!(txt.files, 1);
    }

    #[test]
    fn replace_subtree_swaps_contents() {
        let mut t = sample();
        let root = t.root();
        let before_root = t.node(root).alloc;
        let win = t.find_path("C:\\Windows").unwrap();
        let old_win = t.node(win).alloc;
        // Rescanned Windows loses System32 and gains a log file and a directory.
        let mut b = TreeBuilder::new("C:\\Windows");
        let r = b.root();
        b.add(r, "notepad.exe", Flags::default(), 300, 4096);
        let logs = b.add(r, "Logs", Flags::DIR, 0, 0);
        b.add(logs, "cbs.LOG", Flags::default(), 50_000, 53_248);
        let fresh = b.finish();
        let (old, new) = t.replace_subtree(win, &fresh);
        assert_eq!(old.files, 3);
        assert_eq!(new.files, 2);
        assert_eq!(new.dirs, 2);
        assert_eq!(t.name(win), "Windows");
        assert_eq!(t.node(win).alloc, 4096 + 53_248);
        assert_eq!(t.node(root).alloc, before_root - old_win + 4096 + 53_248);
        assert!(t.find_path("C:\\Windows\\Logs\\cbs.log").is_some());
        assert!(t.find_path("C:\\Windows\\System32").is_none());
        assert_eq!(t.dir_totals(win), DirTotals { files: 2, dirs: 1 });
        assert_eq!(t.dir_totals(root), DirTotals { files: 4, dirs: 4 });
        assert_eq!(t.summary().files, 4);
        let log = t.extensions().iter().find(|e| &*e.name == "log").unwrap();
        assert_eq!((log.files, log.alloc), (1, 53_248));
        let dll = t.extensions().iter().find(|e| &*e.name == "dll").unwrap();
        assert_eq!(dll.files, 0);
        let exe = t.extensions().iter().find(|e| &*e.name == "exe").unwrap();
        assert_eq!(exe.files, 1);
        // New extension indices point to the correct names.
        let cbs = t.find_path("C:\\Windows\\Logs\\cbs.LOG").unwrap();
        assert_eq!(&*t.extensions()[t.node(cbs).aux as usize].name, "log");
        // Removing the new directory also updates extension and whole-tree totals.
        let logs_id = t.find_path("C:\\Windows\\Logs").unwrap();
        t.remove(logs_id);
        assert_eq!(t.node(win).alloc, 4096);
        assert_eq!(t.summary().files, 3);
    }

    #[test]
    fn ext_key_rules() {
        assert_eq!(ExtKey::of(b"a.TXT").bytes(), b"txt");
        assert_eq!(ExtKey::of(b"a.tar.GZ").bytes(), b"gz");
        assert_eq!(ExtKey::of(b".gitignore").bytes(), b"");
        assert_eq!(ExtKey::of(b"noext").bytes(), b"");
        assert_eq!(ExtKey::of(b"trailing.").bytes(), b"");
        let long = format!("x.{}", "a".repeat(40));
        assert_eq!(ExtKey::of(long.as_bytes()).bytes(), b"");
    }

    #[test]
    fn extension_table_is_consistent_across_chunks() {
        // Cross the 65,536-node block boundary to verify local-to-global extension mapping.
        let mut b = TreeBuilder::new("R");
        let r = b.root();
        for i in 0..200_000u64 {
            let ext = ["a", "b", "c", "dd", "E"][(i % 5) as usize];
            b.add(r, &format!("f{i}.{ext}"), Flags::default(), 1, 1 + (i % 5));
        }
        let t = b.finish();
        let e = t.extensions();
        assert_eq!(e.len(), 4 + 1); // a b c dd e
        let total: u64 = e.iter().map(|x| x.files).sum();
        assert_eq!(total, 200_000);
        for c in t.children(r) {
            let name = t.name(c).to_ascii_lowercase();
            let ext = name.rsplit('.').next().unwrap();
            assert_eq!(&*e[t.node(c).aux as usize].name, ext);
        }
        // Descending allocation places E (allocation 5) first.
        assert_eq!(&*e[0].name, "e");
    }

    #[test]
    fn paths() {
        let t = sample();
        let root = t.root();
        let win = t.child_by_name(root, "Windows").unwrap();
        let sys = t.child_by_name(win, "System32").unwrap();
        let a = t.child_by_name(sys, "A.dll").unwrap();
        assert_eq!(t.path(a), "C:\\Windows\\System32\\a.DLL");
        assert_eq!(t.path(root), "C:\\");
    }

    #[test]
    fn deep_tree_no_recursion() {
        // A 100,000-level chain must not overflow the stack during aggregation or path creation.
        let mut b = TreeBuilder::new("R");
        let mut cur = b.root();
        for i in 0..100_000 {
            cur = b.add(cur, &format!("d{i}"), Flags::DIR, 0, 0);
        }
        b.add(cur, "leaf.bin", Flags::default(), 7, 4096);
        let t = b.finish();
        assert_eq!(t.node(t.root()).alloc, 4096);
        assert_eq!(t.dir_totals(t.root()).dirs, 100_000);
    }

    #[test]
    fn batches_are_parent_first() {
        let t = sample();
        let batches = t.batches(3);
        let mut seen = std::collections::HashSet::new();
        seen.insert(NONE);
        let mut count = 0;
        for b in &batches {
            for e in &b.entries {
                assert!(seen.contains(&e.parent), "parent of {} not seen", b.name(e));
                seen.insert(e.id);
                count += 1;
            }
        }
        assert_eq!(count as u64, t.live_nodes());
    }

    #[test]
    fn batch_since_returns_only_new_nodes() {
        let mut b = TreeBuilder::new("R");
        let r = b.root();
        b.add(r, "a", Flags::default(), 1, 1);
        let mark = b.len() as NodeId;
        b.add(r, "b", Flags::default(), 2, 2);
        b.add(r, "c", Flags::default(), 3, 3);
        let batch = b.batch_since(mark);
        let names: Vec<&str> = batch.entries.iter().map(|e| batch.name(e)).collect();
        assert_eq!(names, ["b", "c"]);
    }

    #[test]
    fn long_names_are_clamped_on_char_boundary() {
        let long = "汉".repeat(30_000); // 90,000 bytes.
        let mut b = TreeBuilder::new("R");
        let r = b.root();
        let id = b.add(r, &long, Flags::default(), 0, 0);
        let t = b.finish();
        assert!(t.name(id).len() <= u16::MAX as usize);
        assert!(t.name(id).chars().all(|c| c == '汉'));
    }

    #[test]
    fn million_nodes_memory_budget() {
        // A million synthetic nodes with names averaging approximately 20 bytes.
        let t = synthetic_tree(1_000_000);
        assert_eq!(t.live_nodes(), 1_000_001);
        let per_node = t.memory_bytes() as f64 / t.live_nodes() as f64;
        assert!(per_node < 72.0, "{per_node} bytes/node");
    }

    /// Build `n` nodes, with 20 files and 3 subdirectories per directory and 12-28-byte names.
    pub(crate) fn synthetic_tree(n: usize) -> DiskTree {
        let mut b = TreeBuilder::with_capacity("C:\\", n + 1, n * 20);
        let mut dirs = vec![b.root()];
        let mut di = 0;
        let mut made = 0usize;
        while made < n {
            let parent = dirs[di % dirs.len()];
            di += 1;
            for k in 0..3 {
                if made >= n {
                    break;
                }
                let d = b.add(parent, &format!("folder_{made:08}_{k}"), Flags::DIR, 0, 0);
                dirs.push(d);
                made += 1;
            }
            for k in 0..20 {
                if made >= n {
                    break;
                }
                let name = format!("file_{made:07}_{}.{}", "x".repeat(k % 9), ["dll", "txt", "png", "json"][k % 4]);
                b.add(parent, &name, Flags::default(), (made as u64 * 37) % 100_000, 4096);
                made += 1;
            }
        }
        b.finish()
    }
}
