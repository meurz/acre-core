//! Acre scanning benchmark and diagnostic CLI.
//!
//! ```text
//! acre-bench scan <root> --backend mft|walk|ntfs-reader|ntfs-reader-full [--depth N] [--no-dir-index] --out r.json
//! acre-bench launch --timeout 900 --out m.json -- <exe> [args...]
//! acre-bench wiztree <drive> --admin 0|1 --csv x.csv --out r.json [--depth N] [--timeout 900]
//! acre-bench compare <baseline.json> <other.json> [--depth N] [--threshold 0.005]
//! acre-bench memtest [--nodes 1000000]
//! acre-bench progress <root>       # Demonstrate progress, batches, and cancellation.
//! acre-bench summarize <results>   # Summarize named result files as Markdown.
//! ```
//!
//! Scan targets are read-only; reports are written to explicitly selected output files.

mod report;
#[cfg(windows)]
mod launch;
#[cfg(windows)]
mod nr;

use std::path::PathBuf;
use std::time::{Duration, Instant};

use acre_core::scan::{Backend, ScanControl, ScanOptions, scan_blocking};
use report::{ExtItem, Report, compare, human, items_from_tree, parse_wiztree_csv};

const HELP: &str = r#"Acre scanning benchmarks and diagnostics

Usage:
  acre-bench scan <root> [--backend auto|mft|walk|ntfs-reader|ntfs-reader-full]
      [--threads N] [--depth N] [--no-dir-index] [--out report.json]
  acre-bench progress <root> [--backend auto|mft|walk] [--cancel-after-ms N]
      [--out progress.json]
  acre-bench compare <baseline.json> <other.json> [--depth N] [--all]
  acre-bench memtest [--nodes 1000000] [--out memory.json]
  acre-bench summarize <results-directory>

Windows-only commands:
  acre-bench record <volume-root> <record-number>... [--out record.txt]
  acre-bench launch [--timeout 900] [--out measurements.json] -- <exe> [args...]
  acre-bench wiztree <drive> --csv export.csv [--admin 0|1] [--exe WizTree64.exe]
      [--depth N] [--timeout 900] [--out report.json]

MFT access requires an elevated terminal and an NTFS volume. Auto falls back to
directory traversal. Scans do not modify their targets. JSON reports go to stdout
unless --out is supplied; progress and diagnostic messages go to stderr.
"#;

struct Args {
    pos: Vec<String>,
    flags: std::collections::HashMap<String, String>,
    tail: Vec<String>,
}

fn parse_args() -> Args {
    let mut pos = Vec::new();
    let mut flags = std::collections::HashMap::new();
    let mut tail = Vec::new();
    let mut it = std::env::args().skip(1).peekable();
    while let Some(a) = it.next() {
        if a == "--" {
            tail.extend(it.by_ref());
            break;
        }
        if let Some(k) = a.strip_prefix("--") {
            let v = match it.peek() {
                Some(n) if !n.starts_with("--") => it.next().unwrap(),
                _ => "1".to_string(),
            };
            flags.insert(k.to_string(), v);
        } else {
            pos.push(a);
        }
    }
    Args { pos, flags, tail }
}

impl Args {
    fn get(&self, k: &str) -> Option<&str> {
        self.flags.get(k).map(String::as_str)
    }
    fn num<T: std::str::FromStr>(&self, k: &str, d: T) -> T {
        self.get(k).and_then(|v| v.parse().ok()).unwrap_or(d)
    }
}

fn main() {
    let args = parse_args();
    let cmd = args.pos.first().cloned().unwrap_or_default();
    if args.get("help").is_some() || matches!(cmd.as_str(), "" | "help" | "-h") {
        print!("{HELP}");
        return;
    }
    let r = match cmd.as_str() {
        "scan" => cmd_scan(&args),
        #[cfg(windows)]
        "launch" => cmd_launch(&args),
        #[cfg(windows)]
        "wiztree" => cmd_wiztree(&args),
        #[cfg(windows)]
        "record" => {
            let Some(mount) = args.pos.get(1).filter(|_| args.pos.len() > 2) else {
                eprintln!("Error: record requires a volume root and at least one record number");
                std::process::exit(1);
            };
            let mut out = String::new();
            for r in &args.pos[2..] {
                let Ok(n) = r.parse::<u64>() else {
                    eprintln!("Error: invalid record number: {r}");
                    std::process::exit(1);
                };
                out.push_str(&acre_core::mft::inspect::dump_record(mount, n).unwrap_or_else(|e| format!("record {n}: {e}\n")));
            }
            match args.get("out") {
                Some(p) => std::fs::write(p, out).map_err(|e| e.to_string()),
                None => { print!("{out}"); Ok(()) }
            }
        }
        "compare" => cmd_compare(&args),
        "memtest" => cmd_memtest(&args),
        "progress" => cmd_progress(&args),
        "summarize" => cmd_summarize(&args),
        _ => Err("Unknown command. Run acre-bench --help for usage.".to_string()),
    };
    if let Err(e) = r {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

fn write_json<T: serde::Serialize>(path: Option<&str>, v: &T) -> Result<(), String> {
    let s = serde_json::to_string_pretty(v).map_err(|e| e.to_string())?;
    match path {
        Some(p) => std::fs::write(p, s).map_err(|e| format!("write {p}: {e}")),
        None => {
            println!("{s}");
            Ok(())
        }
    }
}

fn is_elevated() -> bool {
    #[cfg(windows)]
    {
        acre_core::volume::is_elevated()
    }
    #[cfg(not(windows))]
    {
        false
    }
}

fn cmd_scan(a: &Args) -> Result<(), String> {
    let root = a.pos.get(1).ok_or("scan requires a root path")?.clone();
    let backend = a.get("backend").unwrap_or("auto");
    let depth: u32 = a.num("depth", 1);
    let t0 = Instant::now();
    let mut rep = Report {
        root: root.clone(),
        elevated: is_elevated(),
        ..Report::default()
    };
    let tree = match backend {
        "mft" | "walk" | "auto" => {
            let mut opts = ScanOptions::new(PathBuf::from(&root));
            opts.backend = match backend {
                "mft" => Backend::Mft,
                "walk" => Backend::Walk,
                _ => Backend::Auto,
            };
            opts.threads = a.num("threads", 0);
            opts.count_directory_index = a.get("no-dir-index").is_none();
            let ctl = ScanControl::new(false);
            let out = scan_blocking(&opts, &ctl).map_err(|e| e.to_string())?;
            rep.tool = match out.backend {
                acre_core::BackendUsed::Mft => "acre-mft".into(),
                acre_core::BackendUsed::Walk => "dua-core-walk".into(),
            };
            rep.prepare_ms = out.timings.prepare.as_secs_f64() * 1000.0;
            rep.read_ms = out.timings.read.as_secs_f64() * 1000.0;
            rep.finish_ms = out.timings.finish.as_secs_f64() * 1000.0;
            rep.notes = out.notes;
            out.tree
        }
        #[cfg(windows)]
        "ntfs-reader" | "ntfs-reader-full" => {
            let full = backend == "ntfs-reader-full";
            let out = nr::scan(&root, full)?;
            rep.tool = backend.into();
            rep.prepare_ms = out.prepare_ms;
            rep.read_ms = out.read_ms;
            rep.finish_ms = out.finish_ms;
            rep.notes = out.notes;
            out.tree
        }
        other => return Err(format!("Unknown backend: {other}")),
    };
    rep.scan_ms = t0.elapsed().as_secs_f64() * 1000.0;
    rep.wall_ms = rep.scan_ms;
    let s = *tree.summary();
    rep.files = s.files;
    if rep.tool == "dua-core-walk" {
        rep.file_names = s.files;
        rep.files_unique = s.files.saturating_sub(s.extra_link_names);
    } else {
        rep.file_names = s.files + s.extra_link_names;
        rep.files_unique = s.files;
    }
    rep.dirs = s.dirs;
    rep.logical = s.logical;
    rep.alloc = s.alloc;
    rep.extra_link_names = s.extra_link_names;
    rep.orphans = s.orphans;
    rep.unreadable_dirs = s.unreadable_dirs;
    rep.live_nodes = tree.live_nodes();
    rep.slots = tree.slots() as u64;
    rep.tree_bytes = tree.memory_bytes() as u64;
    rep.items = items_from_tree(&tree, depth);
    if let Some(path) = a.get("hardlinks-out") {
        // Export the counted path of each hard-linked file for comparison with WizTree exports.
        let mut out = String::new();
        for (i, n) in tree.nodes().iter().enumerate() {
            // Traversal retains duplicate names with zero sizes; export only the counted entry.
            if n.is_used()
                && n.flags.contains(acre_core::Flags::HARDLINK)
                && !n.flags.is_dir()
                && (n.logical > 0 || n.alloc > 0)
            {
                out.push_str(&tree.path(i as u32));
                out.push('\n');
            }
        }
        std::fs::write(path, out).map_err(|e| format!("write {path}: {e}"))?;
    }
    rep.flag_counts = report::flag_counts(&tree);
    rep.top_extensions = tree
        .extensions()
        .iter()
        .take(25)
        .map(|e| ExtItem {
            ext: e.name.to_string(),
            files: e.files,
            logical: e.logical,
            alloc: e.alloc,
        })
        .collect();
    #[cfg(windows)]
    {
        let (ws, pv) = launch::self_peak_memory();
        rep.peak_working_set = ws;
        rep.peak_private = pv;
        if let Ok(m) = acre_core::volume::volume_root_of(std::path::Path::new(&root))
            && let Ok((t, f)) = acre_core::volume::disk_space(&m)
        {
            rep.volume_total = t;
            rep.volume_free = f;
        }
    }
    eprintln!(
        "{} {}: {:.0} ms (prepare {:.0} / read {:.0} / finish {:.0}), {} files, {} directories, allocated {}, logical {}, tree {}, peak private {}",
        rep.tool,
        rep.root,
        rep.scan_ms,
        rep.prepare_ms,
        rep.read_ms,
        rep.finish_ms,
        rep.files,
        rep.dirs,
        human(rep.alloc),
        human(rep.logical),
        human(rep.tree_bytes),
        human(rep.peak_private)
    );
    write_json(a.get("out"), &rep)
}

#[cfg(windows)]
fn cmd_launch(a: &Args) -> Result<(), String> {
    let exe = a.tail.first().ok_or("launch requires -- <exe> [args...]")?;
    let timeout = Duration::from_secs(a.num("timeout", 900));
    let m = launch::run_hidden(exe, &a.tail[1..], a.get("raw").unwrap_or(""), timeout)?;
    eprintln!(
        "{:.0} ms, exit code {:?}, peak working set {}, peak private {}{}",
        m.wall_ms,
        m.exit_code,
        human(m.peak_working_set),
        human(m.peak_private),
        if m.timed_out { ", terminated after timeout" } else { "" }
    );
    // Merge external wall time and peak memory into a child scan's report.
    if let Some(merge) = a.get("merge")
        && let Ok(text) = std::fs::read_to_string(merge)
        && let Ok(mut rep) = serde_json::from_str::<Report>(&text)
    {
        rep.wall_ms = m.wall_ms;
        rep.cpu_ms = m.cpu_user_ms + m.cpu_kernel_ms;
        rep.peak_working_set = m.peak_working_set;
        rep.peak_private = m.peak_private;
        write_json(Some(merge), &rep)?;
    }
    write_json(a.get("out"), &m)
}

#[cfg(windows)]
fn cmd_wiztree(a: &Args) -> Result<(), String> {
    let drive = a.pos.get(1).ok_or("wiztree requires a drive letter, such as C:")?.trim_end_matches('\\').to_string();
    let admin = a.get("admin").unwrap_or("1");
    let csv = a.get("csv").ok_or("--csv is required")?;
    let depth: u32 = a.num("depth", 1);
    let exe = a.get("exe").unwrap_or(r"C:\Program Files\WizTree\WizTree64.exe");
    let timeout = Duration::from_secs(a.num("timeout", 900));
    let _ = std::fs::remove_file(csv);
    let raw = format!(
        "/export=\"{csv}\" /admin={admin} /exportfolders=1 /exportfiles=1 /exportmaxdepth={depth} /exportdrivecapacity=1"
    );
    let m = launch::run_hidden(exe, std::slice::from_ref(&drive), &raw, timeout)?;
    if m.timed_out {
        return Err(format!("WizTree timed out after {} s and was terminated: {}", timeout.as_secs(), m.command));
    }
    let text = std::fs::read(csv).map_err(|e| format!("read {csv}: {e} (WizTree exit code {:?})", m.exit_code))?;
    let text = String::from_utf8_lossy(&text);
    let root = format!("{drive}\\");
    let (items, capacity) = parse_wiztree_csv(&text, &root)?;
    let r = items.iter().find(|i| i.path.is_empty()).cloned().unwrap_or_default();
    let mut rep = Report {
        tool: format!("wiztree-admin{admin}"),
        root: root.clone(),
        elevated: is_elevated(),
        wall_ms: m.wall_ms,
        cpu_ms: m.cpu_user_ms + m.cpu_kernel_ms,
        files: r.files,
        file_names: r.files,
        dirs: r.dirs,
        logical: r.logical,
        alloc: r.alloc,
        peak_working_set: m.peak_working_set,
        peak_private: m.peak_private,
        notes: vec![format!("Command: {}; exit code {:?}", m.command, m.exit_code)],
        items,
        ..Report::default()
    };
    if let Some(v) = capacity {
        rep.volume_total = v.capacity;
        rep.volume_used_reported = v.used;
        rep.volume_reserved_reported = v.reserved;
    }
    if let Ok((t, f)) = acre_core::volume::disk_space(&root) {
        rep.volume_total = t;
        rep.volume_free = f;
    }
    eprintln!(
        "WizTree {} admin={admin}: {:.0} ms, {} files, {} directories, allocated {}, logical {}, peak private {}, peak working set {}",
        root,
        m.wall_ms,
        rep.files,
        rep.dirs,
        human(rep.alloc),
        human(rep.logical),
        human(rep.peak_private),
        human(rep.peak_working_set)
    );
    write_json(a.get("out"), &rep)
}

fn load(p: &str) -> Result<Report, String> {
    let t = std::fs::read_to_string(p).map_err(|e| format!("read {p}: {e}"))?;
    serde_json::from_str(&t).map_err(|e| format!("parse {p}: {e}"))
}

fn cmd_compare(a: &Args) -> Result<(), String> {
    let base = load(a.pos.get(1).ok_or("compare requires two JSON report paths")?)?;
    let other = load(a.pos.get(2).ok_or("compare requires two JSON report paths")?)?;
    let depth: u32 = a.num("depth", 1);
    let th: f64 = a.num("threshold", 0.005);
    let min_bytes: u64 = a.num("min-bytes", 64 * 1024 * 1024);
    let rows = compare(&base, &other, depth);
    println!("| Path | {} allocated | {} allocated | Difference | Relative difference | {} files | {} files |", base.tool, other.tool, base.tool, other.tool);
    println!("|---|---:|---:|---:|---:|---:|---:|");
    let show_all = a.get("all").is_some();
    for r in &rows {
        let ba = r.base_alloc.unwrap_or(0);
        let oa = r.other_alloc.unwrap_or(0);
        let diff = oa as i128 - ba as i128;
        let big = r.alloc_rel.abs() > th && diff.unsigned_abs() as u64 >= min_bytes;
        if !(show_all || r.path.is_empty() || big) {
            continue;
        }
        println!(
            "| {} | {} | {} | {}{} | {:+.3}% | {} | {} |",
            if r.path.is_empty() { "(root)" } else { &r.path },
            r.base_alloc.map(human).unwrap_or("—".into()),
            r.other_alloc.map(human).unwrap_or("—".into()),
            if diff < 0 { "-" } else { "+" },
            human(diff.unsigned_abs() as u64),
            r.alloc_rel * 100.0,
            r.base_files.map(|f| f.to_string()).unwrap_or("—".into()),
            r.other_files.map(|f| f.to_string()).unwrap_or("—".into()),
        );
    }
    if let Some(out) = a.get("out") {
        write_json(Some(out), &rows)?;
    }
    Ok(())
}

fn cmd_memtest(a: &Args) -> Result<(), String> {
    let n: usize = a.num("nodes", 1_000_000);
    #[cfg(windows)]
    let before = launch::self_private_bytes();
    let t0 = Instant::now();
    let tree = synthetic(n);
    let build = t0.elapsed();
    #[cfg(windows)]
    let after = launch::self_private_bytes();
    #[cfg(not(windows))]
    let (before, after) = (0u64, 0u64);
    let bytes = tree.memory_bytes();
    let v = serde_json::json!({
        "nodes": tree.live_nodes(),
        "tree_bytes": bytes,
        "bytes_per_node": bytes as f64 / tree.live_nodes() as f64,
        "process_private_delta": after.saturating_sub(before),
        "build_ms": build.as_secs_f64() * 1000.0,
    });
    eprintln!(
        "{} nodes: tree {} ({:.1} bytes/node), private memory increase {}, built in {:.0} ms",
        tree.live_nodes(),
        human(bytes as u64),
        bytes as f64 / tree.live_nodes() as f64,
        human(after.saturating_sub(before)),
        build.as_secs_f64() * 1000.0
    );
    write_json(a.get("out"), &v)
}

/// Synthetic tree: 20 files and 3 subdirectories per directory, with names averaging about 20 bytes.
fn synthetic(n: usize) -> acre_core::DiskTree {
    use acre_core::tree::{Flags, TreeBuilder};
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
            let d = b.add(parent, &format!("dir{made:07}_{k}"), Flags::DIR, 0, 0);
            dirs.push(d);
            made += 1;
        }
        for k in 0..20 {
            if made >= n {
                break;
            }
            let name = format!("f{made:07}_{}.{}", "x".repeat(k % 9), ["dll", "txt", "png", "json"][k % 4]);
            b.add(parent, &name, Flags::default(), (made as u64 * 37) % 100_000, 4096);
            made += 1;
        }
    }
    b.finish()
}

fn cmd_progress(a: &Args) -> Result<(), String> {
    let root = a.pos.get(1).ok_or("progress requires a root path")?.clone();
    let mut opts = ScanOptions::new(PathBuf::from(&root));
    opts.batches = true;
    opts.backend = match a.get("backend").unwrap_or("auto") {
        "mft" => Backend::Mft,
        "walk" => Backend::Walk,
        _ => Backend::Auto,
    };
    let cancel_after = a.get("cancel-after-ms").and_then(|v| v.parse::<u64>().ok());
    let t0 = Instant::now();
    let h = acre_core::start(opts);
    let mut batches = 0usize;
    let mut entries = 0usize;
    let mut first_batch_ms = None;
    while !h.is_finished() {
        std::thread::sleep(Duration::from_millis(200));
        let p = h.progress();
        for b in h.take_batches() {
            batches += 1;
            entries += b.entries.len();
            first_batch_ms.get_or_insert(t0.elapsed().as_millis());
        }
        eprintln!(
            "{:>6} ms  {:?}  items {}  allocated {}  progress {}/{}  batches {batches} ({entries} entries)",
            t0.elapsed().as_millis(),
            p.phase,
            p.items,
            human(p.bytes),
            p.units_done,
            p.units_total
        );
        if let Some(ms) = cancel_after
            && t0.elapsed().as_millis() as u64 >= ms
        {
            h.cancel();
        }
    }
    let p = h.progress();
    let r = h.join();
    let cancelled = matches!(r, Err(acre_core::ScanError::Cancelled));
    let v = serde_json::json!({
        "root": root,
        "final_phase": format!("{:?}", p.phase),
        "cancelled": cancelled,
        "elapsed_ms": t0.elapsed().as_millis() as u64,
        "batches_taken": batches,
        "entries_taken": entries,
        "first_batch_ms": first_batch_ms,
        "files": r.as_ref().ok().map(|o| o.tree.summary().files),
    });
    write_json(a.get("out"), &v)
}

fn median(v: &mut [f64]) -> f64 {
    if v.is_empty() {
        return f64::NAN;
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

/// Summarize files named `<tool>-<drive>-r<round>.json` in a results directory.
fn cmd_summarize(a: &Args) -> Result<(), String> {
    let dir = PathBuf::from(a.pos.get(1).ok_or("summarize requires a results directory")?);
    let mut all: Vec<(String, String, u32, Report)> = Vec::new();
    for e in std::fs::read_dir(&dir).map_err(|e| e.to_string())? {
        let p = e.map_err(|e| e.to_string())?.path();
        let name = p.file_name().unwrap().to_string_lossy().to_string();
        if !name.ends_with(".json") || name.ends_with(".launch.json") {
            continue;
        }
        let stem = name.trim_end_matches(".json");
        let parts: Vec<&str> = stem.rsplitn(3, '-').collect(); // [rN, drive, tool]
        if parts.len() != 3 || !parts[0].starts_with('r') {
            continue;
        }
        let round: u32 = parts[0][1..].parse().unwrap_or(0);
        let rep = load(&p.to_string_lossy())?;
        all.push((parts[2].to_string(), parts[1].to_string(), round, rep));
    }
    all.sort_by(|x, y| (x.1.clone(), x.0.clone(), x.2).cmp(&(y.1.clone(), y.0.clone(), y.2)));
    let order = ["auto", "wiztree1", "mft", "ntfs-reader-full", "ntfs-reader", "wiztree0", "walk"];
    let label = |t: &str| match t {
        "auto" => "Automatic backend",
        "wiztree1" => "WizTree (administrator, MFT)",
        "mft" => "Acre MFT (administrator)",
        "ntfs-reader-full" => "ntfs-reader 0.6.0 with allocation (administrator)",
        "ntfs-reader" => "ntfs-reader 0.6.0 logical size only (administrator)",
        "wiztree0" => "WizTree (standard user, traversal)",
        "walk" => "dua-core 4.1.0 traversal (standard user)",
        _ => "?",
    };
    let mut drives: Vec<String> = all.iter().map(|x| x.1.clone()).collect();
    drives.sort();
    drives.dedup();
    for d in &drives {
        println!("\n### {d}:\n");
        println!("| Backend | Runs (s) | Median (s) | Median peak private memory | Median CPU (s) | File names | Directories | Allocated | Logical |");
        println!("|---|---|---:|---:|---:|---:|---:|---:|---:|");
        for t in order {
            let runs: Vec<&Report> = all.iter().filter(|x| &x.1 == d && x.0 == t).map(|x| &x.3).collect();
            if runs.is_empty() {
                continue;
            }
            let walls: Vec<String> = runs.iter().map(|r| format!("{:.1}", r.wall_ms / 1000.0)).collect();
            let mut w: Vec<f64> = runs.iter().map(|r| r.wall_ms / 1000.0).collect();
            let mut m: Vec<f64> = runs.iter().map(|r| r.peak_private as f64).collect();
            let mut c: Vec<f64> = runs.iter().map(|r| r.cpu_ms / 1000.0).collect();
            let last = runs.last().unwrap();
            println!(
                "| {} | {} | {:.1} | {} | {:.1} | {} | {} | {} | {} |",
                label(t),
                walls.join(" / "),
                median(&mut w),
                human(median(&mut m) as u64),
                median(&mut c),
                last.file_names,
                last.dirs,
                human(last.alloc),
                human(last.logical)
            );
        }
    }
    Ok(())
}
