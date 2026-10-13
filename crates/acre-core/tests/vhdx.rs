use std::io::Read;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use acre_core::Flags;
use acre_core::scan::{Backend, BackendUsed, ScanControl, ScanError, ScanOptions, scan_blocking};

const DYNAMIC: &[u8] = include_bytes!("fixtures/fixture-dynamic-1m-512.vhdx.gz");
const DYNAMIC_2M: &[u8] = include_bytes!("fixtures/fixture-dynamic-2m-512.vhdx.gz");
const DYNAMIC_4K: &[u8] = include_bytes!("fixtures/fixture-dynamic-1m-4096.vhdx.gz");
const FIXED: &[u8] = include_bytes!("fixtures/fixture-fixed-1m-512.vhdx.gz");

struct Fixture(std::path::PathBuf);
impl Fixture {
    fn new(compressed: &[u8], edit: impl FnOnce(&mut Vec<u8>)) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let mut bytes = Vec::new();
        flate2::read::GzDecoder::new(compressed)
            .read_to_end(&mut bytes)
            .unwrap();
        edit(&mut bytes);
        let path = std::env::temp_dir().join(format!(
            "acre-vhdx-{}-{}.VHDX",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, bytes).unwrap();
        Self(path)
    }
    fn options(&self) -> ScanOptions {
        ScanOptions::new(&self.0)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn scan(f: &Fixture) -> Result<acre_core::ScanOutcome, ScanError> {
    scan_blocking(&f.options(), &ScanControl::new(false))
}

#[test]
fn dynamic_and_fixed_images_match_independent_debugfs_totals_without_modification() {
    for compressed in [DYNAMIC, DYNAMIC_2M, DYNAMIC_4K, FIXED] {
        let f = Fixture::new(compressed, |_| {});
        let before = std::fs::read(&f.0).unwrap();
        let out = scan(&f).unwrap();
        assert_eq!(out.backend, BackendUsed::Vhdx);
        let tree = &out.tree;
        assert!(tree.is_read_only());
        assert!(tree.uses_unix_paths());
        assert_eq!(tree.name(tree.root()), "/");
        assert_eq!(tree.summary().files, 13); // Nine regular names plus four symlinks.
        assert_eq!(tree.summary().dirs, 5);
        assert_eq!(tree.summary().extra_link_names, 1);
        assert_eq!(tree.summary().alloc, 81_920); // Independent debugfs i_blocks * 512.
        assert_eq!(tree.summary().logical, 8_401_336); // File and symlink sizes, unique inodes.
        assert_eq!(tree.summary().unreadable_dirs, 0);
        let sparse = tree.find_path("/sparse.bin").unwrap();
        assert_eq!(tree.node(sparse).logical, 8_388_731);
        assert_eq!(tree.node(sparse).alloc, 8_192);
        assert!(tree.node(sparse).flags.contains(Flags::SPARSE));
        let a = tree.find_path("/docs/hardlink.bin").unwrap();
        let b = tree.find_path("/docs/nested/data.bin").unwrap();
        assert!(tree.node(a).flags.contains(Flags::HARDLINK));
        assert!(tree.node(b).flags.contains(Flags::HARDLINK));
        assert_eq!(tree.node(a).alloc + tree.node(b).alloc, 16_384);
        assert_eq!(tree.node(a).logical + tree.node(b).logical, 12_345);
        for path in ["/loop", "/outside", "/long-symlink", "/symlink-data"] {
            let id = tree.find_path(path).unwrap();
            assert!(tree.node(id).flags.contains(Flags::REPARSE));
            assert!(!tree.node(id).flags.is_dir());
            assert_eq!(tree.children(id).count(), 0);
        }
        assert_eq!(
            tree.node(tree.find_path("/long-symlink").unwrap()).alloc,
            4096
        );
        assert_ne!(tree.find_path("/Case.txt"), tree.find_path("/case.txt"));
        assert!(tree.find_path("/CASE.TXT").is_none());
        for path in [
            "/name\\with\\slashes.txt",
            "/Unicode-資料.txt",
            "/docs/nested/empty.txt",
        ] {
            assert_eq!(tree.path(tree.find_path(path).unwrap()), path);
        }
        let sub = tree.subtree(tree.find_path("/docs").unwrap(), "/docs");
        assert!(sub.is_read_only());
        assert!(sub.find_path("/docs/nested/data.bin").is_some());
        assert_eq!(std::fs::read(&f.0).unwrap(), before);
    }
}

#[test]
fn batches_keep_parent_before_child_ids_and_can_cancel() {
    let f = Fixture::new(DYNAMIC, |_| {});
    let mut opts = f.options();
    opts.backend = Backend::Vhdx;
    opts.batches = true;
    opts.batch_size = 2;
    let ctl = ScanControl::new(true);
    let out = scan_blocking(&opts, &ctl).unwrap();
    let mut next = 0;
    for batch in ctl.take_batches() {
        for entry in &batch.entries {
            assert_eq!(entry.id, next);
            if entry.id == 0 {
                assert_eq!(entry.parent, u32::MAX);
            } else {
                assert!(entry.parent < entry.id);
            }
            assert_eq!(out.tree.name(entry.id), batch.name(entry));
            assert_eq!(out.tree.own_sizes(entry.id).1, entry.alloc);
            next += 1;
        }
    }
    assert_eq!(next as usize, out.tree.slots());
    ctl.cancel();
    assert!(matches!(
        scan_blocking(&opts, &ctl),
        Err(ScanError::Cancelled)
    ));
    let h = acre_core::start(opts);
    h.cancel();
    while !h.is_finished() {
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(matches!(h.join(), Err(ScanError::Cancelled)));
}

#[test]
fn directory_allocation_can_be_excluded() {
    let f = Fixture::new(DYNAMIC, |_| {});
    let mut opts = f.options();
    opts.count_directory_index = false;
    let out = scan_blocking(&opts, &ScanControl::new(false)).unwrap();
    assert_eq!(out.tree.summary().alloc, 49_152);
}

fn update_header(bytes: &mut [u8], offset: usize, edit: impl FnOnce(&mut [u8])) {
    let header = &mut bytes[offset..offset + 4096];
    edit(header);
    header[4..8].fill(0);
    let checksum = crc::Crc::<u32>::new(&crc::CRC_32_ISCSI).checksum(header);
    header[4..8].copy_from_slice(&checksum.to_le_bytes());
}

// Locate a region in these qemu-generated fixtures, independent of the production reader.
fn region(bytes: &[u8], guid: &[u8; 16]) -> usize {
    let table = &bytes[192 * 1024..256 * 1024];
    let count = u32::from_le_bytes(table[8..12].try_into().unwrap()) as usize;
    for i in 0..count {
        let entry = &table[16 + i * 32..48 + i * 32];
        if &entry[..16] == guid {
            return u64::from_le_bytes(entry[16..24].try_into().unwrap()) as usize;
        }
    }
    panic!("missing region");
}
fn payload(bytes: &[u8]) -> usize {
    let bat = region(
        bytes,
        &[
            0x66, 0x77, 0xc2, 0x2d, 0x23, 0xf6, 0x00, 0x42, 0x9d, 0x64, 0x11, 0x5e, 0x9b, 0xfd,
            0x4a, 0x08,
        ],
    );
    let entry = u64::from_le_bytes(bytes[bat..bat + 8].try_into().unwrap());
    assert_eq!(entry & 7, 6);
    (entry & 0xffff_ffff_fff0_0000) as usize
}

#[test]
fn corrupt_headers_fall_back_only_when_another_valid_header_exists() {
    let one = Fixture::new(DYNAMIC, |b| b[64 * 1024 + 4] ^= 1);
    assert!(scan(&one).is_ok());
    let both = Fixture::new(DYNAMIC, |b| {
        b[64 * 1024 + 4] ^= 1;
        b[128 * 1024 + 4] ^= 1;
    });
    assert!(scan(&both).is_err());
    let truncated = Fixture::new(DYNAMIC, |b| b.truncate(128));
    assert!(scan(&truncated).is_err());
}

#[test]
fn pending_vhdx_log_and_unclean_ext4_are_rejected() {
    let dirty_log = Fixture::new(DYNAMIC, |b| {
        for offset in [64 * 1024, 128 * 1024] {
            update_header(b, offset, |h| h[48] = 1);
        }
    });
    assert!(
        scan(&dirty_log)
            .err()
            .unwrap()
            .to_string()
            .contains("pending log")
    );
    let dirty_fs = Fixture::new(DYNAMIC, |b| {
        let sb = payload(b) + 1024;
        b[sb + 0x60] |= 4;
    });
    assert!(
        scan(&dirty_fs)
            .err()
            .unwrap()
            .to_string()
            .contains("not clean")
    );
    let corrupt_fs = Fixture::new(DYNAMIC, |b| {
        let sb = payload(b) + 1024;
        b[sb + 0x78] ^= 1; // Volume label, covered by the ext4 superblock checksum.
    });
    assert!(scan(&corrupt_fs).is_err());
    let other_fs = Fixture::new(DYNAMIC, |b| {
        let sb = payload(b) + 1024;
        b[sb + 0x38] = 0;
    });
    assert!(matches!(scan(&other_fs), Err(ScanError::NotSupported(_))));
}

#[cfg(windows)]
#[test]
fn a_live_writer_prevents_scanning_and_scanning_does_not_modify_the_image() {
    use std::os::windows::fs::OpenOptionsExt;
    let f = Fixture::new(DYNAMIC, |_| {});
    let writer = std::fs::OpenOptions::new()
        .write(true)
        .share_mode(3)
        .open(&f.0)
        .unwrap();
    assert!(scan(&f).err().unwrap().to_string().contains("in use"));
    drop(writer);
    assert!(scan(&f).is_ok());
}

fn raw_filesystem() -> Vec<u8> {
    let mut container = Vec::new();
    flate2::read::GzDecoder::new(DYNAMIC)
        .read_to_end(&mut container)
        .unwrap();
    let mut disk = sootmark_vhdx::Vhdx::open(std::io::Cursor::new(container)).unwrap();
    let mut raw = Vec::new();
    disk.read_to_end(&mut raw).unwrap();
    raw
}

#[test]
fn inode_allocation_obeys_huge_file_feature_and_preserves_identity() {
    let mut raw = raw_filesystem();
    let sb = 1024;
    let block_size = 1024usize << u32::from_le_bytes(raw[sb + 0x18..sb + 0x1c].try_into().unwrap());
    let inode_size = u16::from_le_bytes(raw[sb + 0x58..sb + 0x5a].try_into().unwrap()) as usize;
    let table =
        u32::from_le_bytes(raw[block_size + 8..block_size + 12].try_into().unwrap()) as usize;
    let inode = table * block_size + inode_size; // Root is inode 2.
    let original_features = u32::from_le_bytes(raw[sb + 0x64..sb + 0x68].try_into().unwrap());
    let original_flags = u32::from_le_bytes(raw[inode + 0x20..inode + 0x24].try_into().unwrap());
    raw[inode + 0x1c..inode + 0x20].copy_from_slice(&8u32.to_le_bytes());
    raw[inode + 0x74..inode + 0x76].copy_from_slice(&1u16.to_le_bytes());
    for (huge_feature, huge_inode, expected) in [
        (false, false, 4096),
        (false, true, 4096),
        (true, false, ((1u64 << 32) + 8) * 512),
        (true, true, ((1u64 << 32) + 8) * block_size as u64),
    ] {
        // Disable metadata checksums only in this in-memory parser fixture so
        // these field-encoding cases are independent of checksum recomputation.
        let features = (original_features & !(0x400 | 0x10 | 8)) | if huge_feature { 8 } else { 0 };
        raw[sb + 0x64..sb + 0x68].copy_from_slice(&features.to_le_bytes());
        let flags = (original_flags & !0x40000) | if huge_inode { 0x40000 } else { 0 };
        raw[inode + 0x20..inode + 0x24].copy_from_slice(&flags.to_le_bytes());
        let fs = ext4_view::Ext4::load(Box::new(raw.clone())).unwrap();
        let metadata = fs.symlink_metadata("/").unwrap();
        assert_eq!(metadata.inode_number(), 2);
        assert_eq!(metadata.link_count(), 4);
        assert_eq!(metadata.allocated_size(), expected);
    }
}

#[test]
fn corrupt_inode_and_directory_checksums_abort_the_scan() {
    let raw = raw_filesystem();
    let block_size = 4096;
    let table =
        u32::from_le_bytes(raw[block_size + 8..block_size + 12].try_into().unwrap()) as usize;
    let root_inode = table * block_size + 256;
    // The root's first extent is stored inline; its physical block is ee_start_lo.
    let directory_block = u32::from_le_bytes(
        raw[root_inode + 0x3c..root_inode + 0x40]
            .try_into()
            .unwrap(),
    ) as usize;
    assert!(root_inode < 1024 * 1024);
    assert!(directory_block * block_size < 1024 * 1024);
    for guest_offset in [
        root_inode + 4,
        directory_block * block_size + block_size - 1,
    ] {
        let f = Fixture::new(DYNAMIC, |b| {
            let offset = payload(b) + guest_offset;
            b[offset] ^= 1;
        });
        assert!(scan(&f).is_err());
    }
}
