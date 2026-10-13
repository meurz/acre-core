# WSL VHDX fixtures

These small gzip files contain synthetic ext4 filesystems created with
`mkfs.ext4` and `debugfs`, then wrapped with `qemu-img`. They contain no user
data. The test suite expands them into temporary files; neither WSL nor
administrator access is required to run the tests on Windows.

The filesystem is 64 MiB with 4 KiB blocks. Fixtures cover dynamic 1 MiB and
2 MiB VHDX payload blocks and a fixed VHDX. `expected.json` records an
independent `debugfs stat` oracle. With directory blocks and symlinks included,
the unique inode allocation is 81,920 bytes. File and symlink logical sizes
sum to 8,401,336 bytes after hard-link deduplication. File names include case
variants, Unicode, and literal backslashes. Symlinks are never followed.

To regenerate on Linux, run `python3 create_fixtures.py /path/to/scratch` with
`e2fsprogs` and `qemu-img` installed. The script validates ext4 with `e2fsck`,
checks the 512-byte-sector containers with QEMU, and compares their complete
virtual payloads against the raw filesystem. It also creates a 4096-byte-sector
variant and checks that variant with an independent BAT mapping oracle because
the tested QEMU version cannot open VHDX images with 4096-byte logical sectors.

Timestamps, filesystem UUID, directory hash seed, and VHDX identifiers are
fixed for reproducibility; exact container hashes may still vary across tool
versions. Only compressed fixtures, the oracle, and the generator belong in Git.
