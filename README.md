# Acre Core

[中文](README.zh-CN.md)

A Rust disk usage scanner for Windows, used by the [Acre desktop app](https://github.com/meurz/acre).
It reads the NTFS Master File Table directly when administrator access is available and falls back to directory traversal otherwise.

- Compact directory trees with allocated and logical sizes, hard-link deduplication, and extension totals.
- Background scans with progress, cancellation, and incremental traversal batches.
- Drive discovery and optional elevated relaunch on Windows.
- Recycling and permanent deletion with progress and structured failure reasons.
- A benchmark CLI for JSON reports, MFT diagnostics, and optional comparisons with WizTree and ntfs-reader.

## Build and test

Install [Rust](https://rustup.rs/) and the Visual Studio C++ build tools with a Windows SDK.
The repository pins Rust 1.98.1. From a Windows terminal:

```powershell
cargo test --workspace --locked
cargo build --release --locked
.\target\release\acre-bench.exe --help
.\target\release\acre-bench.exe scan C:\ --backend auto --out scan.json
```

Run the last command from an elevated terminal to use NTFS MFT scanning. Without elevation, `auto` uses directory traversal. A folder can also be supplied as the scan root. Set `CARGO_TARGET_DIR` if you want build outputs outside the checkout.

For a reproducible set of local scans:

```powershell
.\scripts\benchmark.ps1 -Root C:\ -Backend auto -Rounds 3 -Out .\bench-out
```

The script scans only the requested path and writes reports to the output directory. Reports contain filesystem paths; review their contents before sharing them. See [benchmarking and accounting](docs/benchmark.md) for methodology and limitations.

## Library

```rust,no_run
use acre_core::{ScanOptions, start};

let handle = start(ScanOptions::new(std::path::PathBuf::from(r"C:\")));
let outcome = handle.join()?;
println!("{} files, {} allocated bytes",
    outcome.tree.summary().files,
    outcome.tree.summary().alloc);
# Ok::<(), acre_core::ScanError>(())
```

`scan` selects the backend; `tree` exposes the result, child sorting, path lookup, extension totals, and subtree updates. `mft` contains NTFS parsing and raw-volume access, while `walk` uses [dua-core](https://crates.io/crates/dua-core). The Windows-only `volume`, `recycle`, and `delete` modules provide drive discovery and file operations. Localized clients should match `ScanError` and `DeleteFailure` variants rather than parsing their English display strings.

## Accounting and limitations

Allocated space is the default size measure. Hard-linked contents count once; the MFT backend chooses a name from NTFS attribute order, while traversal approximates that choice. The same file may therefore be assigned to a different directory across backends. MFT scans can include directory-index allocation and NTFS metadata; traversal cannot see all of that information.

MFT scanning requires Windows, NTFS, and administrator access. Scanning an NTFS folder through MFT reads the full volume table before extracting its subtree. Set `ScanOptions::folder_via_mft` to `false` to use traversal for folders. Traversal does not follow symbolic links or junctions. Inaccessible entries are counted as errors, but their exact locations are not all represented in the tree.

Scans are not filesystem snapshots, so files changing during a scan can affect totals. USN incremental updates are not implemented. Non-NTFS and network-volume behavior has not been broadly validated. The parser and tree code can be tested on other platforms; Windows is the supported application target.

## License and attribution

Acre Core is available under either the [MIT license](LICENSE-MIT) or the [Apache License 2.0](LICENSE-APACHE).

Parts of the NTFS implementation are adapted from [mathom](https://github.com/gitRasheed/mathom), Copyright (c) 2026 Rasheed Khoshnaw, under the MIT license. Source headers retain attribution; its original license is included in [third_party/mathom-LICENSE](third_party/mathom-LICENSE). That third-party code remains subject to its MIT terms. Dependencies retain their respective licenses. WizTree is an optional external comparison tool and is not bundled.
