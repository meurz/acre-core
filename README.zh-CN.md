# Acre Core

[English](README.md)

[Acre 桌面应用](https://github.com/meurz/acre)的 Rust 磁盘扫描核心。管理员权限下直接读取 NTFS 文件表，其余情况自动退回逐目录扫描。

提供紧凑目录树、实际占用与逻辑大小、硬链接去重、扩展名汇总、后台进度与取消、盘列表，以及回收站和永久删除接口。界面可根据 `ScanError` 和 `DeleteFailure` 枚举显示本地化错误。

## 构建

安装 [Rust](https://rustup.rs/) 和带 Windows SDK 的 Visual Studio C++ 构建工具。仓库固定 Rust 1.98.1。在 Windows 终端运行：

```powershell
cargo test --workspace --locked
cargo build --release --locked
.\target\release\acre-bench.exe --help
.\target\release\acre-bench.exe scan C:\ --backend auto --out scan.json
```

管理员终端下可使用 MFT 快扫；普通权限自动使用目录遍历。也可传入文件夹路径。扫描报告包含文件路径，分享前请检查内容。

## 限制

默认按实际占用统计，硬链接内容只计一次；MFT 与普通遍历可能把同一文件的占用归到不同目录。MFT 能统计目录索引和 NTFS 元数据，遍历无法取得这些信息。通过 MFT 扫文件夹仍需读取整卷文件表。

遍历不跟随符号链接和目录联接。无法读取的项会计入错误数，但尚未全部标到目录树上。扫描不是文件系统快照，期间发生的文件变化可能影响总量。尚未实现 USN 增量更新，非 NTFS 和网络卷未经过广泛验证。支持的应用平台为 Windows。

详细接口、测试方法与许可见 [英文说明](README.md)。本项目使用 MIT 或 Apache-2.0 双许可；改编自 mathom 的部分保留原 MIT 许可与署名。
