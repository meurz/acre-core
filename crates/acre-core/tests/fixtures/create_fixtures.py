#!/usr/bin/env python3
"""Generate small public-safe VHDX/ext4 fixtures without mounts or admin access."""

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import uuid


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("output", type=Path, help="Scratch directory for generated images")
ROOT = parser.parse_args().output.resolve()
ROOT.mkdir(parents=True, exist_ok=True)
SOURCE = ROOT / "source"
SOURCE.mkdir(exist_ok=True)
RAW = ROOT / "fixture-ext4.raw"
FIXED_TIME = "1577836800"
ENV = dict(os.environ, E2FSPROGS_FAKE_TIME=FIXED_TIME)
REUSE = os.environ.get("ACRE_FIXTURE_REUSE") == "1"


def run(*args, capture=False):
    result = subprocess.run(args, cwd=ROOT, env=ENV, check=True, text=True,
                            stdout=subprocess.PIPE if capture else None,
                            stderr=subprocess.PIPE if capture else None)
    return result.stdout if capture else None


contents = {
    "data.bin": (b"Acre fixture content 0123456789\n" * 500)[:12345],
    "empty.txt": b"",
    "readme.txt": b"Acre public test fixture. No private data.\n",
    "upper.txt": b"UPPER CASE\n",
    "lower.txt": b"lower case\n",
    "unicode.txt": "Synthetic Unicode: 資料\n".encode(),
    "backslash.txt": b"Literal backslash filename.\n",
}
for name, data in contents.items():
    (SOURCE / name).write_bytes(data)
with (SOURCE / "sparse.bin").open("wb") as handle:
    handle.write(b"BEGIN SPARSE\n")
    handle.seek(8 * 1024 * 1024 + 110)
    handle.write(b"END SPARSE!!\n")
if not REUSE:
    with RAW.open("wb") as handle:
        handle.truncate(64 * 1024 * 1024)
    run("mkfs.ext4", "-q", "-F", "-b", "4096", "-I", "256", "-m", "0",
        "-L", "acre-fixture", "-U", "85f1e988-26bb-4b65-bcdd-b5aa7b509af0",
        "-E", "lazy_itable_init=0,lazy_journal_init=0,root_owner=0:0,hash_seed=50a9973d-7046-44c7-b73a-0d3f43d7a1dd",
        str(RAW))
commands = [
    f"set_current_time {FIXED_TIME}",
    "mkdir /docs",
    "mkdir /docs/nested",
    "mkdir /docs/empty-dir",
    "write source/data.bin /docs/nested/data.bin",
    "write source/empty.txt /docs/nested/empty.txt",
    "write source/readme.txt /docs/readme.txt",
    "ln /docs/nested/data.bin /docs/hardlink.bin",
    "sif /docs/nested/data.bin links_count 2",
    "write source/upper.txt /Case.txt",
    "write source/lower.txt /case.txt",
    "write source/unicode.txt /Unicode-資料.txt",
    'write source/backslash.txt "/name\\with\\slashes.txt"',
    "write source/sparse.bin /sparse.bin",
    "symlink /symlink-data docs/nested/data.bin",
    "symlink /loop loop",
    "symlink /outside /outside-fixture/target.bin",
    "symlink /long-symlink " + ("deep/" * 16) + "target.bin",
]
# debugfs otherwise copies the source file mode, which differs on Linux and
# Windows-backed filesystems. Set a fixed synthetic mode for reproducibility.
commands += [f"sif {path} mode 0100777" for path in (
    "/docs/nested/data.bin", "/docs/nested/empty.txt", "/docs/readme.txt",
    "/Case.txt", "/case.txt", "/Unicode-資料.txt", '"/name\\with\\slashes.txt"',
    "/sparse.bin",
)]
(ROOT / "debugfs-create.txt").write_text("\n".join(commands) + "\n")
if not REUSE:
    run("debugfs", "-w", "-f", str(ROOT / "debugfs-create.txt"), str(RAW))
run("e2fsck", "-fn", str(RAW))


def debugfs(command):
    return run("debugfs", "-R", command, str(RAW), capture=True)


def stat_inode(inode):
    output = debugfs(f"stat <{inode}>")
    size = int(re.search(r"Size:\s+(\d+)", output)[1])
    blocks = int(re.search(r"Blockcount:\s+(\d+)", output)[1])
    links = int(re.search(r"Links:\s+(\d+)", output)[1])
    kind = re.search(r"Type:\s+(\S+)", output)[1]
    return dict(inode=inode, kind=kind, size=size, allocated=blocks * 512, links=links)


entries = []


def enumerate_directory(path, inode):
    entry = dict(path=path, **stat_inode(inode))
    entries.append(entry)
    output = debugfs(f"ls -p <{inode}>")
    for line in output.splitlines():
        parts = line.split("/")
        if len(parts) < 7 or not parts[1].isdigit() or parts[5] in (".", ".."):
            continue
        child_inode = int(parts[1])
        if not child_inode:
            continue
        child_path = path.rstrip("/") + "/" + parts[5]
        child = stat_inode(child_inode)
        if child["kind"] == "directory":
            enumerate_directory(child_path, child_inode)
        else:
            entries.append(dict(path=child_path, **child))


enumerate_directory("/", 2)
entries.sort(key=lambda entry: entry["path"])
seen = set()
for entry in entries:
    entry["unique_allocated"] = 0 if entry["inode"] in seen else entry["allocated"]
    entry["unique_size"] = 0 if entry["inode"] in seen else entry["size"]
    seen.add(entry["inode"])
summary = {
    "directories_including_root": sum(e["kind"] == "directory" for e in entries),
    "regular_file_entries": sum(e["kind"] == "regular" for e in entries),
    "unique_regular_file_inodes": len({e["inode"] for e in entries if e["kind"] == "regular"}),
    "symlink_entries": sum(e["kind"] == "symlink" for e in entries),
    "entries_including_root": len(entries),
    "unique_inodes": len(seen),
    "allocated_including_directories_deduplicated": sum(e["unique_allocated"] for e in entries),
    "logical_including_directories_deduplicated": sum(e["unique_size"] for e in entries),
    "logical_excluding_directories_deduplicated": sum(e["unique_size"] for e in entries if e["kind"] != "directory"),
    "regular_file_logical_deduplicated": sum(e["unique_size"] for e in entries if e["kind"] == "regular"),
    "regular_file_allocated_deduplicated": sum(e["unique_allocated"] for e in entries if e["kind"] == "regular"),
}
(ROOT / "expected.json").write_text(json.dumps(dict(summary=summary, entries=entries),
                                               ensure_ascii=False, indent=2) + "\n")


def crc32c(data):
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc ^ 0xFFFFFFFF


def region_offsets(handle):
    handle.seek(192 * 1024)
    region = handle.read(64 * 1024)
    assert region[:4] == b"regi"
    count = struct.unpack_from("<I", region, 8)[0]
    return {str(uuid.UUID(bytes_le=region[16 + i * 32:32 + i * 32])):
            struct.unpack_from("<Q", region, 32 + i * 32)[0] for i in range(count)}


def normalize_vhdx(path):
    """Replace qemu's random identifiers; the payload bytes are unmodified."""
    with path.open("r+b") as handle:
        for offset in (64 * 1024, 128 * 1024):
            handle.seek(offset)
            header = bytearray(handle.read(4096))
            assert header[:4] == b"head"
            stored = struct.unpack_from("<I", header, 4)[0]
            header[4:8] = bytes(4)
            assert crc32c(header) == stored
            header[16:32] = uuid.UUID("6d76bddd-0a49-4b80-9b1d-eb25a94c264f").bytes_le
            header[32:48] = uuid.UUID("58c1b3f1-07cb-4014-982e-ac7138ebfb46").bytes_le
            assert header[48:64] == bytes(16), "Fixture log must be clean"
            struct.pack_into("<I", header, 4, crc32c(header))
            handle.seek(offset)
            handle.write(header)
        metadata_offset = region_offsets(handle)["8b7ca206-4790-4b9a-b8fe-575f050f886e"]
        handle.seek(metadata_offset)
        table = handle.read(64 * 1024)
        count = struct.unpack_from("<H", table, 10)[0]
        disk_id_guid = uuid.UUID("beca12ab-b2e6-4523-93ef-c309e000c746").bytes_le
        for index in range(count):
            entry = 32 + index * 32
            if table[entry:entry + 16] == disk_id_guid:
                value_offset, length = struct.unpack_from("<II", table, entry + 16)
                assert length == 16
                handle.seek(metadata_offset + value_offset)
                handle.write(uuid.UUID("ed153d57-9658-4901-89b8-bddc7d3951bb").bytes_le)


def verify_payload(path, block_size, sector_size):
    """Simple independent BAT mapping oracle for these fully-present fixtures."""
    with path.open("rb") as image, RAW.open("rb") as source:
        regions = region_offsets(image)
        bat_offset = regions["2dc27766-f623-4200-9d64-115e9bfd4a08"]
        chunk_ratio = ((1 << 23) * sector_size) // block_size
        blocks = (RAW.stat().st_size + block_size - 1) // block_size
        for block in range(blocks):
            image.seek(bat_offset + (block + block // chunk_ratio) * 8)
            bat_entry = struct.unpack("<Q", image.read(8))[0]
            state = bat_entry & 7
            if state in (0, 2):
                data = bytes(block_size)
            elif state == 6:
                image.seek(bat_entry & 0xFFFFFFFFFFF00000)
                data = image.read(block_size)
            else:
                raise RuntimeError(f"Unexpected fixture BAT state {state}")
            expected = source.read(block_size)
            assert data[:len(expected)] == expected, f"VHDX payload mismatch at block {block}"
    print(f"Independent BAT payload match: {path.name}")


def logical_sector_size(path, sector_size):
    # VHDX metadata has no table checksum. Fully present BAT entries do not
    # require bitmap changes when changing the logical sector size.
    with path.open("r+b") as handle:
        handle.seek(192 * 1024)
        region = handle.read(64 * 1024)
        if region[:4] != b"regi":
            raise RuntimeError("Missing VHDX region table")
        count = struct.unpack_from("<I", region, 8)[0]
        metadata_guid = uuid.UUID("8b7ca206-4790-4b9a-b8fe-575f050f886e").bytes_le
        metadata_offset = None
        for index in range(count):
            entry = 16 + index * 32
            if region[entry:entry + 16] == metadata_guid:
                metadata_offset = struct.unpack_from("<Q", region, entry + 16)[0]
                break
        if metadata_offset is None:
            raise RuntimeError("Missing VHDX metadata region")
        handle.seek(metadata_offset)
        table = handle.read(64 * 1024)
        count = struct.unpack_from("<H", table, 10)[0]
        sector_guid = uuid.UUID("8141bf1d-a96f-4709-ba47-f233a8faab5f").bytes_le
        for index in range(count):
            entry = 32 + index * 32
            if table[entry:entry + 16] == sector_guid:
                value_offset, length = struct.unpack_from("<II", table, entry + 16)
                assert length == 4
                handle.seek(metadata_offset + value_offset)
                handle.write(struct.pack("<I", sector_size))
                return
        raise RuntimeError("Missing logical sector size metadata")


variants = []
for name, subformat, block_size, sector_size in [
    ("fixture-dynamic-1m-512.vhdx", "dynamic", 1 << 20, 512),
    ("fixture-dynamic-2m-512.vhdx", "dynamic", 2 << 20, 512),
    ("fixture-fixed-1m-512.vhdx", "fixed", 1 << 20, 512),
    ("fixture-dynamic-1m-4096.vhdx", "dynamic", 1 << 20, 4096),
]:
    destination = ROOT / name
    if not REUSE or not destination.exists():
        run("qemu-img", "convert", "-f", "raw", "-O", "vhdx", "-o",
            f"subformat={subformat},block_size={block_size}", str(RAW), str(destination))
    normalize_vhdx(destination)
    if sector_size != 512:
        logical_sector_size(destination, sector_size)
    if sector_size == 512:
        run("qemu-img", "check", "-f", "vhdx", str(destination))
        if not REUSE:
            run("qemu-img", "compare", "-f", "raw", "-F", "vhdx", str(RAW), str(destination))
    verify_payload(destination, block_size, sector_size)
    compressed = destination.with_suffix(destination.suffix + ".gz")
    with destination.open("rb") as source, compressed.open("wb") as output:
        with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0, compresslevel=9) as zipped:
            shutil.copyfileobj(source, zipped)
    variants.append(dict(name=name, subformat=subformat, block_size=block_size,
                         sector_size=sector_size, bytes=destination.stat().st_size,
                         gzip_bytes=compressed.stat().st_size,
                         sha256=hashlib.sha256(destination.read_bytes()).hexdigest(),
                         verification="qemu check + BAT/raw compare" if sector_size == 512 else
                         "BAT/raw compare (qemu does not support 4096-byte logical sectors)"))

reference = dict(summary=summary, variants=variants, entries=entries)
(ROOT / "expected.json").write_text(json.dumps(reference, ensure_ascii=False, indent=2) + "\n")
(ROOT / "debugfs-reference.txt").write_text(debugfs("stats") + "\n" + "\n".join(
    e["path"] + "\n" + debugfs(f"stat <{e['inode']}>") for e in entries))
print(json.dumps(dict(summary=summary, variants=variants), indent=2))
