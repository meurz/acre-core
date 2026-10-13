# ext4-view provenance and local changes

This directory contains `ext4-view` 1.0.0, licensed under
`MIT OR Apache-2.0`. Both upstream license files and copyright notices are
preserved.

- Repository: <https://github.com/nicholasbishop/ext4-view-rs>
- Upstream commit: `8facbf4c2986b7e2dbdef92514d696f1559a2b90`
- Published package: <https://crates.io/crates/ext4-view/1.0.0>
- Package SHA-256: `0ecf6379b7cfeace5e109ccc51955afc05f5f7f2466ae0cf2697bda46afd01e6`
- Retrieved and checked against the crates.io checksum on 2026-10-13.

The original normalized manifest, `Cargo.toml.orig`, README, and source
files come from that package. The package's Cargo.lock is omitted because
Acre's workspace lockfile pins the dependencies.

## Acre extensions

The upstream reader validates filesystem metadata and replays the journal
into a read-only view, but its public metadata omits the inode identity and
allocated block count needed by a disk usage scanner. The local changes
are limited to three source files (trailing whitespace is also normalized in the README):

- `src/inode.rs` reads the inode's link count and `i_blocks` fields, converts
  allocation to bytes according to the filesystem and inode huge-file
  flags, and rejects allocation overflow. Reserved high bits are ignored
  when the filesystem does not advertise huge-file support.
- `src/metadata.rs` exposes `inode_number() -> u32`,
  `allocated_size() -> u64`, and `link_count() -> u16`. The allocated size
  measures storage charged to the inode inside ext4, not physical storage
  charged to the containing VHDX file. Sparse holes are excluded;
  preallocation and inode-associated metadata blocks are included.
- `src/dir_entry.rs` adds `read_dir()`, which opens the entry's directory
  inode directly and retains the original checked iterator. It does not
  follow symlinks or repeatedly resolve the full path during tree traversal.

No filesystem writing, container parsing, or alternate checksum logic has
been added. Replace this copy with an upstream release when equivalent
public metadata and traversal APIs become available.

The crates.io package excludes upstream `test_data` fixtures, so its
embedded fixture tests cannot run from this directory alone. Acre's core
integration tests exercise this dependency through synthetic ext4 images.
To run the full upstream suite, obtain the matching upstream checkout and
apply these three source-file changes there.

## Alternatives considered

- `ext4` 0.9.0 lacks public allocated block metadata.
- `rust-fs-ext4` 0.8.0 exposes inode identity, links, and blocks and supports
  read-only journal replay. However, its `read_dir_ino` implementation
  traverses directory blocks and extents without using its available
  checksum-verifying helpers, rejects legacy non-extent directories, and
  buffers every entry (up to one million) per directory. Adapting that
  traversal would require more changes than the metadata extension here.

This copy retains the small, read-only, checked traversal implementation
and its existing error behavior.
