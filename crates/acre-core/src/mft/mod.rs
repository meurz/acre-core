//! Direct NTFS $MFT scanning from a raw volume (requires administrator access).
//!
//! Read volume parameters from the boot sector and $MFT runs from record 0 or FSCTL.
//! A reader thread issues unbuffered overlapped reads while Rayon parses each received block
//! directly into compact tree nodes. Finally merge extension records, link parents, and aggregate.
//!
//! Parsing and tree construction are portable; raw-volume I/O is compiled only on Windows.
//!
//! The design and much of the low-level code are adapted from mathom (MIT); see file headers.

use std::fmt;

#[allow(missing_docs)]
pub mod boot;
#[cfg(test)]
pub(crate) mod fixture;
pub mod record;
#[allow(missing_docs)]
pub mod runs;
pub mod table;

#[cfg(windows)]
#[allow(missing_docs)]
pub mod io;
#[cfg(windows)]
pub mod inspect;

/// An allocation-free parsing failure. Invalid bytes return errors instead of unchecked access.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParseError(pub &'static str);

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for ParseError {}

#[cfg(windows)]
pub use self::win::scan_volume;

#[cfg(windows)]
mod win {
    use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
    use std::time::{Duration, Instant};

    use super::boot::ReadChunks;
    use super::io::{AlignedBuf, MftMap, ReadRing, Volume, map_mft};
    use super::table::{RecordTable, TableOptions, TableStats};
    use crate::scan::{Phase, ScanControl, ScanError};
    use crate::tree::DiskTree;

    /// Default read size: 8 MiB (8192 records, divided into 16 parallel parsing tasks).
    /// Balances memory use against disk throughput.
    const BUF_BYTES: usize = 8 * 1024 * 1024;
    /// Default number of outstanding overlapped read requests.
    const DEPTH: usize = 6;
    /// Maximum depth allowed by WaitForMultipleObjects.
    const MAX_DEPTH: usize = 32;

    /// Read tuning for benchmarks: ACRE_MFT_BUF_MIB and ACRE_MFT_DEPTH override the defaults.
    fn io_params() -> (usize, usize) {
        let env = |k: &str| std::env::var(k).ok().and_then(|v| v.parse::<usize>().ok());
        let buf = env("ACRE_MFT_BUF_MIB").map_or(BUF_BYTES, |m| m.clamp(1, 256) * 1024 * 1024);
        let depth = env("ACRE_MFT_DEPTH").map_or(DEPTH, |d| d.clamp(1, MAX_DEPTH));
        (buf, depth)
    }

    /// Phase timings and scan statistics.
    #[derive(Clone, Copy, Debug, Default)]
    pub struct MftTimings {
        /// Open the volume and read the boot sector and record 0.
        pub map: Duration,
        /// Read $MFT and parse records in parallel.
        pub read_parse: Duration,
        /// Merge extension records, link parents, and build totals and the extension table.
        pub link_finish: Duration,
        /// MFT length in bytes.
        pub mft_bytes: u64,
        /// Record statistics.
        pub table: TableStats,
    }

    enum ReaderMsg {
        Chunk(usize, AlignedBuf, usize),
        Failed(String),
    }

    /// Scan an NTFS volume by mount point. Requires administrator access; returns
    /// [`ScanError::AccessDenied`] when raw-volume access is unavailable.
    pub fn scan_volume(
        mount: &str,
        opts: TableOptions,
        ctl: &ScanControl,
    ) -> Result<(DiskTree, MftTimings), ScanError> {
        let t0 = Instant::now();
        let trace = std::env::var_os("ACRE_MFT_TRACE").is_some();
        let volume = Volume::open(mount).map_err(classify)?;
        let t_open = t0.elapsed();
        let map = map_mft(&volume, mount).map_err(ScanError::Io)?;
        if trace {
            eprintln!("mft trace: open={t_open:?} map={:?}", t0.elapsed() - t_open);
        }
        let mut timings = MftTimings {
            map: t0.elapsed(),
            mft_bytes: map.mft_bytes,
            ..MftTimings::default()
        };
        let record_size = map.geometry.record_size as usize;
        let mut table = RecordTable::new(
            map.total_records as u64,
            record_size,
            map.geometry.cluster_size,
            opts,
        )
        .map_err(ScanError::Io)?;

        ctl.set_phase(Phase::Reading);
        ctl.progress().set_units_total(map.total_records as u64);
        let t1 = Instant::now();

        let (buf_bytes, depth) = io_params();
        let pool = depth + 2;
        let (full_tx, full_rx) = sync_channel::<ReaderMsg>(pool);
        let (empty_tx, empty_rx) = sync_channel::<AlignedBuf>(pool);
        for _ in 0..pool {
            let _ = empty_tx.send(AlignedBuf::new(buf_bytes));
        }

        let read_result: Result<(), ScanError> = std::thread::scope(|scope| {
            // If parsing panics, dropping empty_tx wakes the reader waiting on recv, so
            // the scoped thread join can finish without a deadlock.
            let empty_tx = empty_tx;
            let map_ref = &map;
            let cancel = ctl.cancel_flag();
            scope.spawn(move || read_mft(volume, map_ref, full_tx, empty_rx, cancel, buf_bytes, depth));

            let mut err = None;
            let mut done_records = 0u64;
            // Read-throughput benchmark: discard blocks without parsing them.
            let no_parse = std::env::var_os("ACRE_MFT_NOPARSE").is_some();
            let mut parse_time = Duration::ZERO;
            let mut wait_time = Duration::ZERO;
            let mut tw = Instant::now();
            for msg in full_rx.iter() {
                wait_time += tw.elapsed();
                match msg {
                    ReaderMsg::Chunk(first, mut buf, valid) => {
                        let tp = Instant::now();
                        let counts = if no_parse {
                            Default::default()
                        } else {
                            table.consume(first, &mut buf.as_mut_slice()[..valid])
                        };
                        parse_time += tp.elapsed();
                        let _ = empty_tx.send(buf);
                        done_records += (valid / record_size) as u64;
                        let p = ctl.progress();
                        p.add_items(counts.files + counts.dirs);
                        p.add_bytes(counts.alloc);
                        p.set_units_done(done_records);
                    }
                    ReaderMsg::Failed(e) => err = Some(e),
                }
                tw = Instant::now();
            }
            if trace {
                eprintln!("mft trace: buf={}MiB depth={depth} parse={parse_time:?} wait_for_io={wait_time:?}", buf_bytes >> 20);
            }
            match err {
                Some(e) => Err(ScanError::Io(e)),
                None => Ok(()),
            }
        });
        read_result?;
        if ctl.is_cancelled() {
            return Err(ScanError::Cancelled);
        }
        timings.read_parse = t1.elapsed();

        ctl.set_phase(Phase::Linking);
        let t2 = Instant::now();
        let root_name = mount.to_string();
        let (tree, stats) = table.finish(&root_name).map_err(ScanError::Io)?;
        if trace {
            eprintln!("mft trace: finish={:?}", t2.elapsed());
        }
        timings.link_finish = t2.elapsed();
        timings.table = stats;
        Ok((tree, timings))
    }

    fn classify(e: String) -> ScanError {
        if e.contains("0x80070005") || e.to_ascii_lowercase().contains("access is denied") || e.contains("拒绝访问") {
            ScanError::AccessDenied(e)
        } else {
            ScanError::Io(e)
        }
    }

    /// Keep overlapping reads in flight and consume the entire MFT in record order.
    fn read_mft(
        volume: Volume,
        map: &MftMap,
        full_tx: SyncSender<ReaderMsg>,
        empty_rx: Receiver<AlignedBuf>,
        cancel: &std::sync::atomic::AtomicBool,
        buf_bytes: usize,
        depth: usize,
    ) {
        let mut chunks = ReadChunks::new(
            &map.extents,
            map.geometry.cluster_size,
            map.geometry.record_size,
            map.total_records,
            buf_bytes,
        );
        let mut ring = match ReadRing::new(&volume, depth) {
            Ok(ring) => ring,
            Err(e) => {
                let _ = full_tx.send(ReaderMsg::Failed(e));
                return;
            }
        };
        let mut meta = [(0usize, 0usize); MAX_DEPTH];
        let mut free: Vec<usize> = (0..depth).collect();
        let mut in_flight = 0usize;
        let mut next_chunk = chunks.next();

        while next_chunk.is_some() || in_flight > 0 {
            if cancel.load(std::sync::atomic::Ordering::Relaxed) {
                return;
            }
            while let (Some(chunk), Some(&slot)) = (next_chunk, free.last()) {
                let Ok(buf) = empty_rx.recv() else { return };
                if let Err(e) = ring.submit(slot, chunk.disk_offset, chunk.bytes, buf) {
                    let _ = full_tx.send(ReaderMsg::Failed(e));
                    return;
                }
                free.pop();
                meta[slot] = (chunk.first_record, chunk.bytes);
                in_flight += 1;
                next_chunk = chunks.next();
            }
            let (slot, buf) = match ring.wait_any() {
                Ok(done) => done,
                Err(e) => {
                    let _ = full_tx.send(ReaderMsg::Failed(e));
                    return;
                }
            };
            in_flight -= 1;
            free.push(slot);
            let (first_record, bytes) = meta[slot];
            if full_tx.send(ReaderMsg::Chunk(first_record, buf, bytes)).is_err() {
                return;
            }
        }
    }

}

#[cfg(windows)]
pub use self::win::MftTimings;
