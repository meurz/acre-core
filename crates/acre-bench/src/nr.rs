//! NTFS scanning through the unmodified public API of ntfs-reader 0.6.0.
//!
//! Two comparison modes:
//! - `floor`: stream MftScan blocks for names, parents, logical sizes, and attributes.
//!   The library parses allocated sizes internally but does not expose them.
//! - `full`: also call open_stream to sum physically allocated data runs without extra I/O.
//!   Compressed and encrypted streams fail here, so estimate their allocation from logical size.

use std::time::Instant;

use acre_core::mft::table::{RecordTable, TableOptions};
use acre_core::tree::{DiskTree, Flags};
use ntfs_reader::{ExtentLocation, MftScan, NtfsAttributeType, NtfsFile, NtfsReaderError, Volume};

pub struct NrOutcome {
    pub tree: DiskTree,
    pub prepare_ms: f64,
    pub read_ms: f64,
    pub finish_ms: f64,
    pub notes: Vec<String>,
}

#[derive(Default)]
struct Counters {
    compressed_fallback: u64,
    encrypted_fallback: u64,
    other_stream_errors: u64,
    wof_files: u64,
}

pub fn scan(drive: &str, full: bool) -> Result<NrOutcome, String> {
    let t0 = Instant::now();
    let letter = drive.trim_end_matches(['\\', '/']);
    // Convert a drive letter to a raw-volume path; preserve volume GUID paths without the final slash.
    let device = if letter.starts_with(r"\\?\") { letter.to_string() } else { format!(r"\\.\{letter}") };
    let volume = Volume::new(&device).map_err(|e| format!("ntfs-reader Volume::new({device}): {e}"))?;
    let cluster = volume.cluster_size();
    let record_size = volume.file_record_size() as usize;
    let mut scan = MftScan::new(volume).map_err(|e| format!("MftScan::new: {e}"))?;
    let total = scan.record_count();
    let mut table = RecordTable::new(
        total,
        record_size,
        cluster as u32,
        TableOptions {
            count_directory_index: false,
        },
    )?;
    let prepare_ms = t0.elapsed().as_secs_f64() * 1000.0;

    let t1 = Instant::now();
    let mut c = Counters::default();
    while let Some(chunk) = scan.next_chunk().map_err(|e| format!("next_chunk: {e}"))? {
        let range = chunk.records();
        if range.start == 0 {
            // files() omits reserved records 0-23, including metadata and the root; request them individually.
            for n in 0..24u64.min(range.end) {
                if let Some(f) = chunk.record(n)
                    && f.is_used()
                    && !f.is_extension()
                {
                    put(&mut table, &f, cluster, full, &mut c);
                }
            }
        }
        for f in chunk.files() {
            put(&mut table, &f, cluster, full, &mut c);
        }
    }
    let corrupt = scan.corrupt_records();
    drop(scan);
    let read_ms = t1.elapsed().as_secs_f64() * 1000.0;

    let t2 = Instant::now();
    let root = format!("{letter}\\");
    let (tree, _) = table.finish(&root)?;
    let finish_ms = t2.elapsed().as_secs_f64() * 1000.0;
    let mut notes = vec![format!("ntfs-reader: {total} record slots, {corrupt} corrupt records")];
    if full {
        notes.push(format!(
            "Allocation uses open_stream runs; {} compressed and {} encrypted streams lack runs and use rounded logical-size estimates; {} other stream errors; {} WOF files",
            c.compressed_fallback, c.encrypted_fallback, c.other_stream_errors, c.wof_files
        ));
    } else {
        notes.push("floor mode: allocation is not exposed by the library and is reported as 0".into());
    }
    notes.push("Directory-index allocation is not exposed by the library and is excluded".into());
    Ok(NrOutcome {
        tree,
        prepare_ms,
        read_ms,
        finish_ms,
        notes,
    })
}

const FILE_ATTRIBUTE_SYSTEM: u32 = 0x4;

fn put(table: &mut RecordTable, f: &NtfsFile, cluster: u64, full: bool, c: &mut Counters) {
    let number = f.number();
    let seq = (f.reference() >> 48) as u16;
    let is_dir = f.is_directory();
    let mut links = 0u16;
    for _ in f.hard_links() {
        links = links.saturating_add(1);
    }
    let best = f.best_name();
    let name_str = best.as_ref().map(|n| n.to_string());
    let name = match (&name_str, &best) {
        (Some(s), Some(n)) => Some((s.as_str(), n.parent_reference())),
        _ => None,
    };

    let mut flags = Flags::default();
    if let Some(si) = f.standard_information()
        && si.file_attributes() & FILE_ATTRIBUTE_SYSTEM != 0
    {
        flags.insert(Flags::SYSTEM);
    }
    // A resident $REPARSE_POINT value begins with the four-byte reparse tag.
    if let Some(tag) = f
        .attributes()
        .find(|a| a.attribute_type() == Some(NtfsAttributeType::ReparsePoint))
        .and_then(|a| a.resident().and_then(|v| v.get(..4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))))
    {
        flags = flags.union(acre_core::mft::record::reparse_flags(tag));
    }

    let mut logical = 0u64;
    let mut alloc = 0u64;
    for s in f.data_streams() {
        let is_default = s.name.is_none();
        if is_default {
            logical = s.size;
        } else if s.name.as_deref() == Some(std::ffi::OsStr::new("WofCompressedData")) {
            flags.insert(Flags::WOF);
        } else {
            flags.insert(Flags::ADS);
        }
        if !full {
            continue;
        }
        match f.open_stream(s.name.as_deref()) {
            Ok(r) => {
                for e in r.extents() {
                    if let ExtentLocation::Volume { .. } = e.location {
                        alloc += e.length.div_ceil(cluster) * cluster;
                    }
                }
            }
            Err(NtfsReaderError::WofCompressedStream) => {
                // The unnamed stream is fully sparse; count physical data in WofCompressedData separately.
                c.wof_files += 1;
            }
            Err(NtfsReaderError::CompressedStream) => {
                c.compressed_fallback += 1;
                flags.insert(Flags::COMPRESSED);
                alloc += s.size.div_ceil(cluster) * cluster;
            }
            Err(NtfsReaderError::EncryptedStream) => {
                c.encrypted_fallback += 1;
                flags.insert(Flags::ENCRYPTED);
                alloc += s.size.div_ceil(cluster) * cluster;
            }
            Err(_) => c.other_stream_errors += 1,
        }
    }
    table.put_base(number, seq, name, links, is_dir, if is_dir { 0 } else { logical }, alloc, flags);
}
