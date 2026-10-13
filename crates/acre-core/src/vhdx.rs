//! Read-only WSL VHDX scanning, without mounting a disk or invoking WSL.
//!
//! `sootmark-vhdx` translates the container's block allocation table and `ext4-view`
//! validates and reads the filesystem. Only metadata and directory blocks are read.
//! Images must be offline and clean. Image paths are Unix paths, never host paths.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use ext4_view::{Ext4, Ext4Read};
use sootmark_vhdx::Vhdx;

use crate::scan::{BackendUsed, Phase, ScanControl, ScanError, ScanOptions, ScanOutcome, Timings};
use crate::tree::{Flags, NodeId, TreeBuilder};

/// Whether a target has the VHDX extension (case-insensitively).
/// This does not open or validate the image.
pub fn is_image_path(path: &Path) -> bool {
    path.extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("vhdx"))
}

type ImageDisk = Vhdx<CancellableInput>;

struct CancellableInput {
    inner: BufReader<File>,
    position: u64,
    cancelled: Arc<AtomicBool>,
}

impl Read for CancellableInput {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.cancelled.load(Ordering::Relaxed) {
            // read_exact retries Interrupted, so cancellation must use another kind.
            return Err(io::Error::other("scan cancelled"));
        }
        let chunk = buf.len().min(256 * 1024);
        let read = self.inner.read(&mut buf[..chunk])?;
        self.position += read as u64;
        Ok(read)
    }
}

impl Seek for CancellableInput {
    fn seek(&mut self, offset: SeekFrom) -> io::Result<u64> {
        if let SeekFrom::Start(position) = offset
            && let Ok(relative) = i64::try_from(i128::from(position) - i128::from(self.position))
        {
            // VHDX seeks before every metadata read. Preserve buffered bytes for
            // nearby inode reads instead of refilling 256 KiB for each inode.
            self.inner.seek_relative(relative)?;
            self.position = position;
        } else {
            self.position = self.inner.seek(offset)?;
        }
        Ok(self.position)
    }
}

struct ImageReader {
    disk: ImageDisk,
    cancelled: Arc<AtomicBool>,
}

impl Ext4Read for ImageReader {
    fn read(
        &mut self,
        offset: u64,
        dst: &mut [u8],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if self.cancelled.load(Ordering::Relaxed) {
            return Err(io::Error::other("scan cancelled").into());
        }
        if offset
            .checked_add(dst.len() as u64)
            .is_none_or(|end| end > self.disk.virtual_size())
        {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "ext4 read exceeds the virtual disk",
            )
            .into());
        }
        self.disk.seek(SeekFrom::Start(offset))?;
        self.disk.read_exact(dst)?;
        Ok(())
    }
}

fn open_image(path: &Path) -> Result<File, ScanError> {
    let mut options = OpenOptions::new();
    options.read(true);
    // Deny existing and future writers for the entire scan. In particular, do not
    // read a live WSL disk just because the container happens to share reads.
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(1); // FILE_SHARE_READ, no write/delete sharing.
    }
    options.open(path).map_err(|e| {
        if cfg!(windows) && matches!(e.raw_os_error(), Some(32 | 33)) {
            ScanError::Io("The VHDX is in use. Save your work and stop its WSL distribution before scanning, or select an offline VHDX export. Acre does not stop WSL automatically.".into())
        } else if e.kind() == io::ErrorKind::PermissionDenied {
            ScanError::AccessDenied(format!("Cannot read the VHDX: {e}"))
        } else {
            ScanError::Io(format!("Cannot open the VHDX: {e}"))
        }
    })
}

fn failure(context: &str, error: impl std::fmt::Display, ctl: &ScanControl) -> ScanError {
    if ctl.is_cancelled() {
        ScanError::Cancelled
    } else {
        ScanError::Io(format!("{context}: {error}"))
    }
}

fn check_cancel(ctl: &ScanControl) -> Result<(), ScanError> {
    if ctl.is_cancelled() {
        Err(ScanError::Cancelled)
    } else {
        Ok(())
    }
}

// Read only the documented superblock fields needed to reject a live/unclean
// filesystem before ext4-view can replay a journal in memory. Filesystem parsing
// and checksum verification remain the library's responsibility.
fn check_superblock(disk: &mut ImageDisk) -> Result<(), ScanError> {
    let mut bytes = [0u8; 1024];
    disk.seek(SeekFrom::Start(1024))
        .and_then(|_| disk.read_exact(&mut bytes))
        .map_err(|e| ScanError::Io(format!("Cannot read the ext4 superblock: {e}")))?;
    let u16_at = |i| u16::from_le_bytes(bytes[i..i + 2].try_into().unwrap());
    let u32_at = |i| u32::from_le_bytes(bytes[i..i + 4].try_into().unwrap());
    if u16_at(0x38) != 0xef53 {
        return Err(ScanError::NotSupported("Expected a WSL ext4 filesystem directly inside the VHDX. Partitioned and non-ext4 disks are not supported.".into()));
    }
    if u16_at(0x3a) & 3 != 1 || u32_at(0x60) & 4 != 0 {
        return Err(ScanError::Io("The ext4 filesystem is not clean. Shut down its distribution cleanly and retry, or select a clean offline export. Acre does not repair or modify images.".into()));
    }
    let shift = u32_at(0x18);
    let blocks = u64::from(u32_at(4))
        | if u32_at(0x60) & 0x80 != 0 {
            u64::from(u32_at(0x150)) << 32
        } else {
            0
        };
    if shift > 6
        || blocks == 0
        || blocks
            .checked_mul(1024u64 << shift)
            .is_none_or(|size| size > disk.virtual_size())
    {
        return Err(ScanError::Io(
            "Invalid ext4 size: the filesystem exceeds the virtual disk.".into(),
        ));
    }
    Ok(())
}

pub(crate) fn scan(opts: &ScanOptions, ctl: &ScanControl) -> Result<ScanOutcome, ScanError> {
    let started = Instant::now();
    check_cancel(ctl)?;
    let file = open_image(&opts.root)?;
    let before = file
        .metadata()
        .map_err(|e| failure("Read image metadata", e, ctl))?;
    if !before.is_file() {
        return Err(ScanError::NotSupported(
            "The VHDX target must be a regular file.".into(),
        ));
    }
    let input = file
        .try_clone()
        .map_err(|e| failure("Open image reader", e, ctl))?;
    let mut disk = Vhdx::open(CancellableInput {
        inner: BufReader::with_capacity(256 * 1024, input),
        position: 0,
        cancelled: ctl.cancel_token(),
    })
    .map_err(|e| failure("Invalid or unsupported VHDX", e, ctl))?;
    if disk.has_pending_log() {
        return Err(ScanError::Io("The VHDX has a pending log. Open and shut down its distribution cleanly before scanning, or select a clean offline export. Acre does not replay VHDX logs or modify images.".into()));
    }
    check_superblock(&mut disk).map_err(|e| {
        if ctl.is_cancelled() {
            ScanError::Cancelled
        } else {
            e
        }
    })?;
    check_cancel(ctl)?;
    let virtual_size = disk.virtual_size();
    let fs = Ext4::load(Box::new(ImageReader {
        disk,
        cancelled: ctl.cancel_token(),
    }))
    .map_err(|e| failure("Read ext4 filesystem", e, ctl))?;
    let root_metadata = fs
        .symlink_metadata("/")
        .map_err(|e| failure("Read ext4 root", e, ctl))?;
    check_allocation(root_metadata.allocated_size(), virtual_size)?;
    let mut builder = TreeBuilder::new_image();
    let root = builder.root();
    if opts.count_directory_index {
        builder.node_mut(root).alloc = root_metadata.allocated_size();
        ctl.progress().add_bytes(root_metadata.allocated_size());
    }
    // Include root allocation so incremental consumers can match final totals.
    if ctl.wants_batches() {
        ctl.push_batch(builder.batch_since(0));
    }
    let mut directories = HashSet::from([root_metadata.inode_number()]);
    let mut files: HashMap<u32, NodeId> = HashMap::new();
    let mut queue: VecDeque<(Option<ext4_view::DirEntry>, NodeId)> = VecDeque::from([(None, root)]);
    let prepare = started.elapsed();
    let reading = Instant::now();
    let mut batch_start = builder.len() as NodeId;
    let mut last_batch = Instant::now();
    let mut lossy_names = 0u64;
    ctl.set_phase(Phase::Reading);
    while let Some((directory, parent)) = queue.pop_front() {
        check_cancel(ctl)?;
        let entries = match directory {
            Some(entry) => entry.read_dir(),
            None => fs.read_dir("/"),
        }
        .map_err(|e| failure("Read ext4 directory", e, ctl))?;
        for entry in entries {
            check_cancel(ctl)?;
            let entry = entry.map_err(|e| failure("Read ext4 directory entry", e, ctl))?;
            let entry_name = entry.file_name();
            let raw_name: &[u8] = entry_name.as_ref();
            if raw_name == b"." || raw_name == b".." {
                continue;
            }
            let name = String::from_utf8_lossy(raw_name);
            lossy_names += u64::from(matches!(name, std::borrow::Cow::Owned(_)));
            let metadata = entry
                .metadata()
                .map_err(|e| failure("Read ext4 inode", e, ctl))?;
            check_allocation(metadata.allocated_size(), virtual_size)?;
            let mut flags = Flags::default();
            if metadata.is_dir() {
                flags.insert(Flags::DIR);
            }
            if metadata.is_symlink() {
                flags.insert(Flags::REPARSE);
            }
            if !metadata.is_dir() && metadata.link_count() > 1 {
                flags.insert(Flags::HARDLINK);
            }
            let mut logical = if metadata.is_dir() { 0 } else { metadata.len() };
            let mut alloc = if metadata.is_dir() && !opts.count_directory_index {
                0
            } else {
                metadata.allocated_size()
            };
            if !metadata.is_dir() && !metadata.is_symlink() && alloc < logical {
                flags.insert(Flags::SPARSE);
            }
            let inode = metadata.inode_number();
            if metadata.is_dir() {
                if !directories.insert(inode) {
                    return Err(ScanError::Io(
                        "Invalid ext4 directory cycle or repeated directory inode.".into(),
                    ));
                }
            } else if let Some(&first) = files.get(&inode) {
                builder.node_mut(first).flags.insert(Flags::HARDLINK);
                flags.insert(Flags::HARDLINK);
                logical = 0;
                alloc = 0;
                builder.summary_mut().extra_link_names += 1;
            }
            let id = builder.add(parent, &name, flags, logical, alloc);
            if metadata.is_dir() {
                queue.push_back((Some(entry), id));
            } else {
                files.entry(inode).or_insert(id);
            }
            ctl.progress().add_items(1);
            ctl.progress().add_bytes(alloc);
            if ctl.wants_batches()
                && (builder.len() - batch_start as usize >= opts.batch_size.max(1)
                    || last_batch.elapsed() >= Duration::from_millis(200))
            {
                ctl.push_batch(builder.batch_since(batch_start));
                batch_start = builder.len() as NodeId;
                last_batch = Instant::now();
            }
        }
    }
    if ctl.wants_batches() {
        ctl.push_batch(builder.batch_since(batch_start));
    }
    check_cancel(ctl)?;
    let after = file
        .metadata()
        .map_err(|e| failure("Recheck image metadata", e, ctl))?;
    if before.len() != after.len() || before.modified().ok() != after.modified().ok() {
        return Err(ScanError::Io(
            "The VHDX changed during scanning. Retry with a clean offline image.".into(),
        ));
    }
    let read = reading.elapsed();
    ctl.set_phase(Phase::Linking);
    let finishing = Instant::now();
    drop(files);
    drop(directories);
    let tree = builder.finish();
    check_cancel(ctl)?;
    let finish = finishing.elapsed();
    let directories_note = if opts.count_directory_index {
        "including"
    } else {
        "excluding"
    };
    let mut notes = vec![format!(
        "Read-only VHDX/ext4 scan; virtual capacity {virtual_size} bytes. Sizes are ext4 inode allocation, {directories_note} directory blocks, with hard links counted once. Container size and filesystem metadata/free space are separate."
    )];
    if lossy_names > 0 {
        notes.push(format!(
            "{lossy_names} non-UTF-8 names are displayed with replacement characters."
        ));
    }
    Ok(ScanOutcome {
        tree,
        backend: BackendUsed::Vhdx,
        timings: Timings {
            total: started.elapsed(),
            prepare,
            read,
            finish,
        },
        notes,
    })
}

fn check_allocation(allocation: u64, virtual_size: u64) -> Result<(), ScanError> {
    if allocation > virtual_size {
        Err(ScanError::Io(
            "Invalid ext4 inode allocation exceeds the virtual disk.".into(),
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancellation_interrupts_container_preparation_without_read_exact_retry() {
        let input = CancellableInput {
            inner: BufReader::new(File::open(std::env::current_exe().unwrap()).unwrap()),
            position: 0,
            cancelled: Arc::new(AtomicBool::new(true)),
        };
        let error = Vhdx::open(input)
            .err()
            .expect("cancelled before file signature");
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert!(error.to_string().contains("cancelled"));
    }
}
