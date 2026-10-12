# Benchmarking and accounting

`acre-bench` compares scanning backends using a shared JSON report format. It is a development and diagnostics tool, not the desktop application.

## Run a local benchmark

Build with `cargo build --release --locked`, then use the PowerShell helper:

```powershell
.\scripts\benchmark.ps1 -Root C:\ -Backend auto -Rounds 3 -Out .\bench-out
.\target\release\acre-bench.exe summarize .\bench-out
```

The helper accepts `auto`, `mft`, `walk`, `ntfs-reader`, and `ntfs-reader-full`. MFT and ntfs-reader require an elevated terminal. Use a standard-user terminal when measuring the traversal fallback under ordinary permissions. You can provide the executable path with `-Executable`, including when using a custom Cargo target directory.

Raw commands offer more control:

```powershell
.\target\release\acre-bench.exe scan C:\ --backend mft --depth 2 --out mft.json
.\target\release\acre-bench.exe scan C:\ --backend walk --threads 4 --depth 2 --out walk.json
.\target\release\acre-bench.exe compare mft.json walk.json --depth 2 --all
.\target\release\acre-bench.exe progress C:\ --backend auto --cancel-after-ms 1000
.\target\release\acre-bench.exe memtest --nodes 1000000
```

`scan`, `progress`, `launch`, and `memtest` write JSON to stdout unless `--out` is supplied. Progress and human-readable summaries go to stderr. `compare` and `summarize` print Markdown tables. Reports can include personal filesystem paths.

To compare against a separately installed WizTree:

```powershell
.\target\release\acre-bench.exe wiztree C: --admin 1 --csv wiztree.csv --out wiztree.json --depth 2 --exe 'C:\Program Files\WizTree\WizTree64.exe'
.\target\release\acre-bench.exe compare wiztree.json mft.json --depth 2 --all
```

The launcher runs the comparison process on a separate hidden desktop. It measures wall time, CPU time, peak working set, and peak private memory. Its timeout terminates only the launched process. No third-party executable is included in this repository.

## Interpret the results

Record the CPU, storage device, Windows version, filesystem, privilege level, cache state, antivirus settings, thread count, and software versions alongside results. Alternate tools within each round, run multiple rounds, and report the distribution as well as a median. Filesystem changes and concurrent I/O can invalidate exact comparisons. These scripts do not clear the system cache, so results must not be presented as controlled cold-cache measurements.

Compare the same depth and size measure. Allocated bytes describe physical clusters and differ from logical file size for sparse, compressed, resident, encrypted, or cloud-backed files. MFT includes allocation from alternate data streams, and can include directory indexes; `--no-dir-index` disables that last contribution for comparisons. NTFS metadata such as `$MFT` may be visible only to MFT scans.

The MFT backend retains the first non-DOS name in the base record for hard links. If the base has no such name, it examines extension records after the base in ascending record order, then records before it. Traversal approximates the choice using the parent's little-endian file identifier and UTF-16 name order. That approximation can assign allocation differently even when total deduplicated space agrees.

The ntfs-reader comparison has two modes. The basic mode does not expose allocated sizes and reports them as zero. The full mode sums data runs where available, but estimates allocation for compressed or encrypted streams and cannot expose directory-index allocation. Neither mode should be treated as an allocation ground truth.

Memory reports distinguish compact tree storage from total process memory. MFT slots use record numbers directly, so unused record slots also consume node storage. The default scan uses 8 MiB read buffers and six overlapped requests. `ACRE_MFT_BUF_MIB` and `ACRE_MFT_DEPTH` tune these values for experiments.
