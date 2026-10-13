# Reading WSL VHDX images

Acre reads an offline WSL `ext4.vhdx` directly on Windows. It does not mount the
image, start WSL, follow symlinks, or write to the container or filesystem.
Administrator access is not required when the file's permissions allow reading.

```powershell
acre-bench scan D:\Images\ext4.vhdx --backend vhdx --depth 2 --out scan.json
```

`Backend::Auto` detects a `.vhdx` file; `Backend::Vhdx` explicitly selects the
reader. `BackendUsed::Vhdx` identifies the result. A folder whose name ends in
`.vhdx` remains a normal directory target. Cancellation, progress, and batches
use the same scan API as directory traversal. Batch IDs remain stable in the
finished tree.

The resulting tree is read-only and uses case-sensitive Unix paths rooted at
`/`. Clients must check `DiskTree::is_read_only()` before offering host filesystem
operations. `DiskTree::uses_unix_paths()` identifies the path convention.
Image paths cannot be passed to Windows Explorer, recycling, or deletion APIs.

## Sizes

Allocation comes from ext4 inode `i_blocks`, including directory blocks and
long symlinks. Sparse holes consume no allocation; hard-link names are retained
but their logical and allocated bytes are counted only once. Symbolic links
are counted as links, without visiting targets. `count_directory_index = false`
excludes directory allocation. Linux filenames are case-sensitive and may
contain backslashes. Non-UTF-8 names are displayed lossily with a diagnostic.

The total describes reachable files and directories inside ext4. It excludes
ext4's journal, inode tables, bitmaps, and unused filesystem space. It differs
from both the virtual capacity and the host allocation/length of the VHDX;
deleting files inside WSL does not automatically shrink the container.

## Supported images and errors

Fixed and dynamic VHDX version 1 containers are supported, with an ext4
filesystem directly at virtual offset zero, as in ordinary WSL distributions.
Partitioned disks, other filesystems, and differencing images are unsupported.
Unsupported ext4 features and corrupt checksummed metadata produce an error;
they are not silently treated as empty directories or ordinary host files.

The image must be offline and clean. On Windows, the reader denies write and
delete sharing for the entire scan. Save work and stop the relevant distribution
before selecting its disk, or select a clean offline VHDX export. Acre never
terminates a distribution automatically. A pending VHDX log or ext4 recovery
flag is rejected; the reader does not repair the source. The filesystem must
first be cleanly closed by its normal owner.

## Dependencies

`sootmark-vhdx` 0.1.4 supplies checked container reads. `ext4-view` 1.0.0 supplies
checked filesystem traversal. A narrowly extended copy of ext4-view exposes
inode identity, allocated size, link counts, and traversal by directory entry;
see [provenance and changes](../third_party/ext4-view/UPSTREAM.md). No filesystem
writer or mount driver is included.
