//! Inspect MFT attributes in their on-disk order, including hard-link names and extension records.

use super::boot::Geometry;
use super::io::{AlignedBuf, Volume, map_mft};
use super::record::{apply_fixups, u16_at, u32_at, u64_at};

/// Read a record from `mount` and return attribute descriptions. Requires administrator access.
pub fn dump_record(mount: &str, record: u64) -> Result<String, String> {
    let volume = Volume::open(mount)?;
    let map = map_mft(&volume, mount)?;
    let g: Geometry = map.geometry;
    let rs = g.record_size as u64;
    let cs = g.cluster_size as u64;
    let byte = record * rs;
    let (vcn, within) = (byte / cs, byte % cs);
    let mut start = 0u64;
    let mut lcn = None;
    for e in &map.extents {
        if vcn < start + e.clusters {
            lcn = Some(e.lcn + (vcn - start));
            break;
        }
        start += e.clusters;
    }
    let lcn = lcn.ok_or_else(|| format!("record {record} beyond $MFT"))?;
    let disk = lcn * cs + within;
    let sector = g.bytes_per_sector.max(512) as u64;
    let aligned = disk / sector * sector;
    let pad = (disk - aligned) as usize;
    let len = ((pad as u64 + rs).div_ceil(sector) * sector) as usize;
    let mut buf = AlignedBuf::new(len.max(4096));
    volume.read_at(aligned, &mut buf.as_mut_slice()[..len])?;
    let rec = &mut buf.as_mut_slice()[pad..pad + rs as usize];
    if &rec[0..4] != b"FILE" {
        return Err("not a FILE record".into());
    }
    apply_fixups(rec).map_err(|e| e.to_string())?;
    let mut out = format!(
        "record {record}: flags=0x{:x} seq={} base={}\n",
        u16_at(rec, 0x16),
        u16_at(rec, 0x10),
        u64_at(rec, 0x20) & 0xFFFF_FFFF_FFFF
    );
    let used = (u32_at(rec, 0x18) as usize).min(rec.len());
    let mut pos = u16_at(rec, 0x14) as usize;
    let mut i = 0;
    while pos + 8 <= used && u32_at(rec, pos) != 0xFFFF_FFFF {
        let ty = u32_at(rec, pos);
        let alen = u32_at(rec, pos + 4) as usize;
        if alen < 24 || pos + alen > used {
            break;
        }
        let a = &rec[pos..pos + alen];
        let resident = a[8] == 0;
        let instance = u16_at(a, 14);
        out.push_str(&format!("  #{i} type=0x{ty:x} instance={instance} resident={resident}"));
        if resident {
            let voff = u16_at(a, 20) as usize;
            let vlen = u32_at(a, 16) as usize;
            if voff + vlen <= a.len() {
                let v = &a[voff..voff + vlen];
                if ty == 0x30 && v.len() >= 0x42 {
                    let chars = v[0x40] as usize;
                    let ns = v[0x41];
                    let units: Vec<u16> = v[0x42..0x42 + 2 * chars].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
                    out.push_str(&format!(
                        " ns={ns} parent={} name={}",
                        u64_at(v, 0) & 0xFFFF_FFFF_FFFF,
                        String::from_utf16_lossy(&units)
                    ));
                } else if ty == 0x20 {
                    let mut p = 0;
                    while p + 26 <= v.len() {
                        let et = u32_at(v, p);
                        let el = u16_at(v, p + 4) as usize;
                        let rec_no = u64_at(v, p + 16) & 0xFFFF_FFFF_FFFF;
                        let inst = u16_at(v, p + 24);
                        out.push_str(&format!("\n      list: type=0x{et:x} in_record={rec_no} instance={inst}"));
                        if el == 0 {
                            break;
                        }
                        p += el;
                    }
                }
            }
        }
        out.push('\n');
        pos += alen;
        i += 1;
    }
    Ok(out)
}
