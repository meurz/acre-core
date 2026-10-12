// Adapted from mathom (https://github.com/gitRasheed/mathom, crates/scanner-ntfs/src/record.rs), MIT license,
// Copyright (c) 2026 Rasheed Khoshnaw. See third_party/mathom-LICENSE.
//
// Writes names directly as UTF-8 and tracks directory-index allocation, alternate streams,
// WOF, encrypted and cloud files, and $STANDARD_INFORMATION file attributes.
//
//! Parse one FILE record: apply update-sequence fixups, then visit attributes.

use super::ParseError;
use crate::tree::Flags;

/// Root directory record number.
pub const ROOT_RECORD: u64 = 5;
/// First ordinary record number; records 0-23 are reserved NTFS metadata.
pub const FIRST_NORMAL_RECORD: u64 = 24;

/// A packed reference with a 48-bit record number and 16-bit sequence number.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RecordRef(pub u64);

impl RecordRef {
    /// Record number.
    pub fn number(self) -> u64 {
        self.0 & 0x0000_FFFF_FFFF_FFFF
    }
    /// Sequence number.
    pub fn sequence(self) -> u16 {
        (self.0 >> 48) as u16
    }
}

/// A name with its parent reference, namespace priority, and location in the name arena.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NameFact {
    /// Parent reference.
    pub parent: RecordRef,
    /// 0 = Win32, Win32&DOS, or POSIX; 2 = DOS (8.3); 3 = other. Lower ranks win.
    pub rank: u8,
    /// Byte offset in the name arena.
    pub off: u32,
    /// Byte length.
    pub len: u16,
}

/// Facts from one record. Extension records are merged into their base record later.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RecordFacts {
    /// Base record number; 0 means this is a base record.
    pub base: u64,
    /// Sequence number.
    pub seq: u16,
    /// Whether this is a directory.
    pub is_dir: bool,
    /// Logical size of the unnamed $DATA stream.
    pub logical: u64,
    /// Whether `logical` is known.
    pub has_logical: bool,
    /// Physical cluster allocation of all $DATA streams, including alternate and WOF streams.
    pub alloc: u64,
    /// Physical cluster allocation of $INDEX_ALLOCATION attributes, including directory indexes.
    pub index_alloc: u64,
    /// Reparse tag.
    pub reparse_tag: u32,
    /// Non-DOS name count; more than one on a base record indicates hard links.
    pub link_names: u32,
    /// Highest-priority name.
    pub name: Option<NameFact>,
    /// Flags.
    pub flags: Flags,
}

const ATTR_STANDARD_INFORMATION: u32 = 0x10;
const ATTR_FILE_NAME: u32 = 0x30;
const ATTR_DATA: u32 = 0x80;
const ATTR_INDEX_ALLOCATION: u32 = 0xA0;
const ATTR_REPARSE_POINT: u32 = 0xC0;
const ATTR_END: u32 = 0xFFFF_FFFF;

const NS_DOS: u8 = 2;

/// Sentinel used when a name does not fit in the arena; rank-based selection can still proceed.
pub const NO_NAME: u8 = u8::MAX;

/// Parse one FILE record in place. `Ok(None)` denotes an unused or non-FILE record.
pub fn parse_record(
    rec: &mut [u8],
    arena: &mut Vec<u8>,
    cluster_size: u32,
) -> Result<Option<RecordFacts>, ParseError> {
    debug_assert!(rec.len() >= 512 && rec.len().is_power_of_two());
    if &rec[0..4] != b"FILE" {
        return Ok(None);
    }
    let header_flags = u16_at(rec, 0x16);
    if header_flags & 0x1 == 0 {
        return Ok(None);
    }
    apply_fixups(rec)?;

    let seq = u16_at(rec, 0x10);
    let first_attr = u16_at(rec, 0x14) as usize;
    let used = u32_at(rec, 0x18) as usize;
    let base_ref = RecordRef(u64_at(rec, 0x20));
    let limit = used.min(rec.len());
    if first_attr < 0x30 || first_attr + 4 > limit {
        return Err(ParseError("attribute offset out of bounds"));
    }

    let mut facts = RecordFacts {
        base: base_ref.number(),
        seq,
        is_dir: header_flags & 0x2 != 0,
        ..RecordFacts::default()
    };

    let mut pos = first_attr;
    loop {
        if pos + 4 > limit {
            return Err(ParseError("attribute walk past record end"));
        }
        if u32_at(rec, pos) == ATTR_END {
            break;
        }
        if pos + 8 > limit {
            return Err(ParseError("attribute header truncated"));
        }
        let alen = u32_at(rec, pos + 4) as usize;
        if alen < 24 || !alen.is_multiple_of(8) || pos + alen > limit {
            return Err(ParseError("attribute length out of bounds"));
        }
        let attr = &rec[pos..pos + alen];
        match u32_at(attr, 0) {
            ATTR_STANDARD_INFORMATION => std_info(attr, &mut facts)?,
            ATTR_FILE_NAME => file_name(attr, arena, &mut facts)?,
            ATTR_DATA => data(attr, &mut facts, cluster_size)?,
            ATTR_INDEX_ALLOCATION => index_allocation(attr, &mut facts, cluster_size),
            ATTR_REPARSE_POINT => reparse_point(attr, &mut facts),
            // Skip $ATTRIBUTE_LIST because scanning the complete MFT visits extension records directly.
            _ => {}
        }
        pos += alen;
    }
    facts.flags = facts.flags.union(reparse_flags(facts.reparse_tag));
    Ok(Some(facts))
}

/// Data runs for $MFT itself (record 0).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MftSelf {
    /// Length of the MFT $DATA stream.
    pub data_size: u64,
    /// Data runs.
    pub extents: Vec<super::runs::Extent>,
}

/// Read the unnamed $DATA runs of $MFT from record 0.
pub fn parse_record0(rec: &mut [u8]) -> Result<MftSelf, ParseError> {
    if &rec[0..4] != b"FILE" || u16_at(rec, 0x16) & 0x1 == 0 {
        return Err(ParseError("record 0 is not a live FILE record"));
    }
    apply_fixups(rec)?;

    let first_attr = u16_at(rec, 0x14) as usize;
    let limit = (u32_at(rec, 0x18) as usize).min(rec.len());
    if first_attr < 0x30 || first_attr + 4 > limit {
        return Err(ParseError("record 0 attribute offset out of bounds"));
    }
    let mut pos = first_attr;
    loop {
        if pos + 4 > limit {
            return Err(ParseError("record 0 walk past record end"));
        }
        if u32_at(rec, pos) == ATTR_END {
            return Err(ParseError("record 0 has no non-resident $DATA"));
        }
        if pos + 8 > limit {
            return Err(ParseError("record 0 attribute truncated"));
        }
        let alen = u32_at(rec, pos + 4) as usize;
        if alen < 24 || !alen.is_multiple_of(8) || pos + alen > limit {
            return Err(ParseError("record 0 attribute length out of bounds"));
        }
        let attr = &rec[pos..pos + alen];
        pos += alen;
        if u32_at(attr, 0) != ATTR_DATA || attr[8] == 0 || attr[9] != 0 {
            continue;
        }
        if attr.len() < 64 || u64_at(attr, 16) != 0 {
            return Err(ParseError("record 0 $DATA shape unexpected"));
        }
        let highest_vcn = u64_at(attr, 24);
        let data_size = u64_at(attr, 48);
        let run_off = u16_at(attr, 32) as usize;
        if run_off < 64 || run_off >= attr.len() {
            return Err(ParseError("record 0 run list out of bounds"));
        }
        let extents = super::runs::decode_runs(&attr[run_off..])?;
        let covered = extents
            .iter()
            .try_fold(0u64, |acc, e| acc.checked_add(e.clusters))
            .ok_or(ParseError("record 0 run map overflows"))?;
        let span = highest_vcn
            .checked_add(1)
            .ok_or(ParseError("record 0 run map overflows"))?;
        if covered != span {
            // If runs spill into extension records, let the caller use FSCTL instead of following the list.
            return Err(ParseError("$MFT runs incomplete in record 0"));
        }
        return Ok(MftSelf { data_size, extents });
    }
}

/// Map a reparse tag to node flags.
pub fn reparse_flags(tag: u32) -> Flags {
    const NAME_SURROGATE: u32 = 0x2000_0000;
    const WOF: u32 = 0x8000_0017;
    const CLOUD_FAMILY_MASK: u32 = 0xFFFF_0FFF;
    const CLOUD: u32 = 0x9000_001A;
    let mut f = Flags::default();
    if tag == 0 {
        return f;
    }
    if tag & NAME_SURROGATE != 0 {
        f.insert(Flags::REPARSE);
    }
    if tag == WOF {
        f.insert(Flags::WOF);
    }
    if tag & CLOUD_FAMILY_MASK == CLOUD {
        f.insert(Flags::PLACEHOLDER);
    }
    f
}

/// Apply update-sequence fixups; a mismatch identifies a torn record.
pub(crate) fn apply_fixups(rec: &mut [u8]) -> Result<(), ParseError> {
    let usa_off = u16_at(rec, 4) as usize;
    let count = u16_at(rec, 6) as usize;
    if count < 2 {
        return Err(ParseError("fixup array too small"));
    }
    let sectors = count - 1;
    if !rec.len().is_multiple_of(sectors) {
        return Err(ParseError("fixup count does not divide record size"));
    }
    let stride = rec.len() / sectors;
    if stride < 512 || !stride.is_multiple_of(512) || usa_off + 2 * count > stride - 2 {
        return Err(ParseError("implausible fixup layout"));
    }

    let usn = u16_at(rec, usa_off);
    for i in 1..count {
        let end = i * stride - 2;
        if u16_at(rec, end) != usn {
            return Err(ParseError("torn record (fixup mismatch)"));
        }
        let saved = [rec[usa_off + 2 * i], rec[usa_off + 2 * i + 1]];
        rec[end..end + 2].copy_from_slice(&saved);
    }
    Ok(())
}

const FILE_ATTRIBUTE_SYSTEM: u32 = 0x4;
const FILE_ATTRIBUTE_OFFLINE: u32 = 0x1000;
const FILE_ATTRIBUTE_ENCRYPTED: u32 = 0x4000;
// Do not use FILE_ATTRIBUTE_RECALL_ON_OPEN (0x40000): in $STANDARD_INFORMATION,
// the same bit denotes extended attributes, causing ordinary EA-bearing files to look cloud-backed.
const FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS: u32 = 0x40_0000;

fn std_info(attr: &[u8], facts: &mut RecordFacts) -> Result<(), ParseError> {
    let Some(v) = resident_value(attr)? else {
        return Ok(());
    };
    if v.len() < 0x24 {
        return Err(ParseError("standard-information value truncated"));
    }
    let a = u32_at(v, 0x20);
    if a & FILE_ATTRIBUTE_SYSTEM != 0 {
        facts.flags.insert(Flags::SYSTEM);
    }
    if a & FILE_ATTRIBUTE_ENCRYPTED != 0 {
        facts.flags.insert(Flags::ENCRYPTED);
    }
    if a & (FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS) != 0 {
        facts.flags.insert(Flags::PLACEHOLDER);
    }
    Ok(())
}

fn file_name(attr: &[u8], arena: &mut Vec<u8>, facts: &mut RecordFacts) -> Result<(), ParseError> {
    let Some(v) = resident_value(attr)? else {
        return Ok(());
    };
    if v.len() < 0x42 {
        return Err(ParseError("file-name value truncated"));
    }
    let chars = v[0x40] as usize;
    let namespace = v[0x41];
    if 0x42 + 2 * chars > v.len() {
        return Err(ParseError("file-name string out of bounds"));
    }
    if namespace != NS_DOS {
        facts.link_names += 1;
    }
    // Ignore stale sizes in $FILE_NAME; use $DATA for size accounting.
    let rank = name_rank(namespace);
    // Strict comparison retains the first name at a given rank, matching the observed NTFS ordering.
    if facts.name.is_none_or(|n| rank < n.rank) {
        let off = arena.len() as u32;
        let units = v[0x42..0x42 + 2 * chars]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]));
        let mut buf = [0u8; 4];
        for r in char::decode_utf16(units) {
            let c = r.unwrap_or(char::REPLACEMENT_CHARACTER);
            arena.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
        }
        let len = (arena.len() - off as usize) as u16;
        facts.name = Some(NameFact {
            parent: RecordRef(u64_at(v, 0)),
            rank,
            off,
            len,
        });
    }
    Ok(())
}

fn name_rank(namespace: u8) -> u8 {
    match namespace {
        // Win32, Win32&DOS, and POSIX have equal rank; retain the first, including POSIX hard links.
        0 | 1 | 3 => 0,
        NS_DOS => 2,
        _ => 3,
    }
}

const WOF_STREAM: &[u8] = &[
    b'W', 0, b'o', 0, b'f', 0, b'C', 0, b'o', 0, b'm', 0, b'p', 0, b'r', 0, b'e', 0, b's', 0, b's',
    0, b'e', 0, b'd', 0, b'D', 0, b'a', 0, b't', 0, b'a', 0,
];

fn attr_name(attr: &[u8]) -> &[u8] {
    let n = attr[9] as usize;
    let off = u16_at(attr, 10) as usize;
    attr.get(off..off + 2 * n).unwrap_or(&[])
}

fn data(attr: &[u8], facts: &mut RecordFacts, cluster_size: u32) -> Result<(), ParseError> {
    let named = attr[9] != 0;
    if named {
        if attr_name(attr) == WOF_STREAM {
            facts.flags.insert(Flags::WOF);
        } else {
            facts.flags.insert(Flags::ADS);
        }
    }
    if attr[8] == 0 {
        // Resident content occupies no extra clusters; its storage is already accounted for in $MFT.
        let v = resident_value(attr)?.expect("checked resident");
        if !named && !facts.has_logical {
            facts.logical = v.len() as u64;
            facts.has_logical = true;
        }
        return Ok(());
    }

    if attr.len() < 64 {
        return Err(ParseError("non-resident header truncated"));
    }

    // Count only runs with physical clusters. Sparse headers can overstate allocation:
    // $BadClus:$Bad can report the entire volume while having no clusters. Each fragment
    // contributes its own runs, which are summed when extension records are merged.
    let mapping_off = u16_at(attr, 32) as usize;
    let backed = attr
        .get(mapping_off..)
        .filter(|_| mapping_off >= 64)
        .and_then(|runs| super::runs::backed_clusters(runs).ok());

    if u64_at(attr, 16) != 0 {
        // Later fragments (starting VCN > 0) have stale size fields; only count their data runs.
        let clusters = backed.unwrap_or(0);
        facts.alloc = facts
            .alloc
            .saturating_add(clusters.saturating_mul(cluster_size as u64));
        return Ok(());
    }

    let alloc = match backed {
        Some(clusters) => clusters.saturating_mul(cluster_size as u64),
        // If runs cannot be parsed, use the header allocation (compressed size for compressed units).
        None => {
            let compression_unit = u16_at(attr, 34);
            if compression_unit != 0 && attr.len() >= 72 {
                u64_at(attr, 64)
            } else {
                u64_at(attr, 40)
            }
        }
    };
    facts.alloc = facts.alloc.saturating_add(alloc);

    if !named && !facts.has_logical {
        facts.logical = u64_at(attr, 48);
        facts.has_logical = true;
        let attr_flags = u16_at(attr, 12);
        if attr_flags & 0x00FF != 0 {
            facts.flags.insert(Flags::COMPRESSED);
        }
        if attr_flags & 0x4000 != 0 {
            facts.flags.insert(Flags::ENCRYPTED);
        }
        if attr_flags & 0x8000 != 0 {
            facts.flags.insert(Flags::SPARSE);
        }
    }
    Ok(())
}

fn index_allocation(attr: &[u8], facts: &mut RecordFacts, cluster_size: u32) {
    if attr[8] == 0 || attr.len() < 64 {
        return;
    }
    let mapping_off = u16_at(attr, 32) as usize;
    let clusters = attr
        .get(mapping_off..)
        .filter(|_| mapping_off >= 64)
        .and_then(|runs| super::runs::backed_clusters(runs).ok())
        .unwrap_or(0);
    facts.index_alloc = facts
        .index_alloc
        .saturating_add(clusters.saturating_mul(cluster_size as u64));
}

fn reparse_point(attr: &[u8], facts: &mut RecordFacts) {
    if let Ok(Some(v)) = resident_value(attr)
        && v.len() >= 4
    {
        facts.reparse_tag = u32_at(v, 0);
    }
}

fn resident_value(attr: &[u8]) -> Result<Option<&[u8]>, ParseError> {
    if attr[8] != 0 {
        return Ok(None);
    }
    let vlen = u32_at(attr, 16) as usize;
    let voff = u16_at(attr, 20) as usize;
    if voff < 24 || voff + vlen > attr.len() {
        return Err(ParseError("resident value out of bounds"));
    }
    Ok(Some(&attr[voff..voff + vlen]))
}

// All callers have already checked bounds.
pub(crate) fn u16_at(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(b[off..off + 2].try_into().unwrap())
}

pub(crate) fn u32_at(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}

pub(crate) fn u64_at(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mft::fixture::RecordBuilder;

    fn parse(mut rec: Vec<u8>) -> (RecordFacts, Vec<u8>) {
        let mut arena = Vec::new();
        let f = parse_record(&mut rec, &mut arena, 4096).unwrap().unwrap();
        (f, arena)
    }

    #[test]
    fn plain_file() {
        let (f, arena) = parse(
            RecordBuilder::file()
                .name(5, 5, 1, "报告.docx")
                .data_nonresident(10_000, 12_288)
                .build(30, 1024),
        );
        assert_eq!(f.logical, 10_000);
        assert_eq!(f.alloc, 12_288);
        assert_eq!(f.link_names, 1);
        let n = f.name.unwrap();
        assert_eq!(&arena[n.off as usize..(n.off + n.len as u32) as usize], "报告.docx".as_bytes());
        assert_eq!(n.parent.number(), 5);
    }

    #[test]
    fn resident_file_allocates_nothing() {
        let (f, _) = parse(RecordBuilder::file().name(5, 5, 1, "tiny.txt").data_resident_bytes(&[0u8; 300]).build(30, 1024));
        assert_eq!(f.logical, 300);
        assert_eq!(f.alloc, 0);
    }

    #[test]
    fn wof_file_counts_named_stream_allocation() {
        // CompactOS: the unnamed stream is sparse; WofCompressedData holds the physical data.
        let (f, _) = parse(
            RecordBuilder::file()
                .name(5, 5, 1, "notepad.exe")
                .data_nonresident_sparse(360_448, 0)
                .named_data_nonresident("WofCompressedData", 150_000, 151_552)
                .reparse(0x8000_0017)
                .build(30, 1024),
        );
        assert_eq!(f.logical, 360_448);
        assert_eq!(f.alloc, 151_552);
        assert!(f.flags.contains(Flags::WOF));
        assert!(!f.flags.contains(Flags::ADS));
        assert!(!f.flags.contains(Flags::REPARSE));
    }

    #[test]
    fn hardlinks_count_names_and_dos_aliases_do_not() {
        let (f, arena) = parse(
            RecordBuilder::file()
                .name(16, 1, 2, "LONGNA~1.TXT") // DOS
                .name(16, 1, 1, "longname.txt") // Win32
                .name(30, 1, 0, "posix-link") // POSIX hard link
                .data_nonresident(1, 4096)
                .build(30, 1024),
        );
        assert_eq!(f.link_names, 2);
        let n = f.name.unwrap();
        assert_eq!(&arena[n.off as usize..(n.off + n.len as u32) as usize], b"longname.txt");
    }

    #[test]
    fn posix_link_listed_first_is_the_owner_name() {
        // The first non-DOS name wins regardless of namespace; the POSIX hard link appears first here.
        let (f, arena) = parse(
            RecordBuilder::file()
                .name(40, 1, 0, "posix-first.dll") // POSIX
                .name(16, 1, 2, "LONGNA~1.DLL") // DOS
                .name(16, 1, 1, "longname.dll") // Win32
                .data_nonresident(1, 4096)
                .build(30, 1024),
        );
        assert_eq!(f.link_names, 2);
        let n = f.name.unwrap();
        assert_eq!(&arena[n.off as usize..(n.off + n.len as u32) as usize], b"posix-first.dll");
        assert_eq!(n.parent.number(), 40);
    }

    #[test]
    fn ads_and_cloud_and_junction_flags() {
        let (f, _) = parse(
            RecordBuilder::file()
                .name(5, 5, 1, "a.zip")
                .data_nonresident(100, 4096)
                .named_data_resident("Zone.Identifier", 26)
                .build(30, 1024),
        );
        assert!(f.flags.contains(Flags::ADS));
        let (f, _) = parse(RecordBuilder::file().name(5, 5, 1, "cloud.mp4").reparse(0x9000_101A).build(30, 1024));
        assert!(f.flags.contains(Flags::PLACEHOLDER));
        let (f, _) = parse(RecordBuilder::dir().name(5, 5, 1, "junction").reparse(0xA000_0003).build(30, 1024));
        assert!(f.flags.contains(Flags::REPARSE));
    }

    #[test]
    fn ea_bit_is_not_a_cloud_placeholder() {
        // On disk, 0x40000 means extended attributes; 0x400000 means reads recall cloud data.
        let (f, _) = parse(RecordBuilder::file().std_info(0x4_0020, 0).name(5, 5, 1, "wsl-file").build(30, 1024));
        assert!(!f.flags.contains(Flags::PLACEHOLDER));
        let (f, _) = parse(RecordBuilder::file().std_info(0x40_0020, 0).name(5, 5, 1, "cloud.docx").build(30, 1024));
        assert!(f.flags.contains(Flags::PLACEHOLDER));
    }

    #[test]
    fn directory_index_allocation_is_tracked_separately() {
        let (f, _) = parse(
            RecordBuilder::dir()
                .name(5, 5, 1, "WinSxS")
                .index_allocation(8 * 4096)
                .build(30, 1024),
        );
        assert!(f.is_dir);
        assert_eq!(f.alloc, 0);
        assert_eq!(f.index_alloc, 8 * 4096);
    }

    #[test]
    fn torn_record_is_an_error() {
        let mut rec = RecordBuilder::file().name(5, 5, 1, "x").build(30, 1024);
        rec[1022] ^= 0xFF;
        let mut arena = Vec::new();
        assert!(parse_record(&mut rec, &mut arena, 4096).is_err());
    }

    #[test]
    fn free_record_is_none() {
        let mut rec = RecordBuilder::file().name(5, 5, 1, "x").freed().build(30, 1024);
        let mut arena = Vec::new();
        assert_eq!(parse_record(&mut rec, &mut arena, 4096).unwrap(), None);
        let mut zero = vec![0u8; 1024];
        assert_eq!(parse_record(&mut zero, &mut arena, 4096).unwrap(), None);
    }

    #[test]
    fn hostile_attribute_lengths_do_not_panic() {
        for cut in [0x40usize, 0x60, 0x90, 0x100] {
            let mut rec = RecordBuilder::file()
                .name(5, 5, 1, "x")
                .data_nonresident(1, 4096)
                .build(30, 1024);
            // Replace an attribute length with an invalid value.
            rec[cut] = 0xF8;
            rec[cut + 1] = 0xFF;
            let mut arena = Vec::new();
            let _ = parse_record(&mut rec, &mut arena, 4096);
        }
    }
}
