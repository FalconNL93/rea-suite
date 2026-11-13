# Game archives and Xbox discs

Checked: **2026-11-13**. Enable **game-archives** in `rea-suite select`; keep your existing
components selected. Selection runs setup. These are command-line tools, not new REA MCP providers.

Reading needs no component: `rea-suite zar` reads a ZArchive and `rea-suite xbox360 disc` an Xbox 360
game's .zar or disc image, in Python, on every platform ([below](#reading-without-the-tools)).

| Tool | Purpose | Linux x86_64 | macOS ARM | Windows x64 |
|---|---|---|---|---|
| [extract-xiso](https://github.com/XboxDev/extract-xiso) | List, extract, and create Xbox XISO files | Release | Native ARM release | Release |
| [ZArchive](https://github.com/Exzap/ZArchive) | Create ZAR/WUA archives, unpack one whole | Source build + zstd | Source build + zstd | Release EXE |
| [XGDTool](https://github.com/wiredopposite/XGDTool) | OG Xbox/360 ISO, GoD, CCI, CSO, ZAR conversion | Not configured | Not configured | Upstream CLI release |
| [QuickBMS](https://mirror.aluigi.org/quickbms.htm) | Script-defined game archive extraction/reimport | Not configured | Not configured | Author's ZIP (32-bit x86 executables), including large-file variant |
| XEXTool | Legacy Xbox 360 XEX inspection/conversion | Not installed | Not installed | Bring your own verified copy; no automatic download |

ZArchive's Linux/macOS path uses the existing CMake builder and system zstd development files
(Debian `libzstd-dev`, Fedora/RHEL `libzstd-devel`, Arch/macOS `zstd`). It also needs the **build**
component. Source builds run when you request setup; `REA_TOOLS_NO_BUILD=1` leaves this tool uninstalled.
It builds ZArchive v0.1.2 (C++20; zstd found through CMake config or pkg-config): built on Linux
x86_64 (GCC 15.2, zstd 1.5.7) on 2026-11-13, a folder packed and unpacked byte for byte. v0.1.2 (2022)
is still the newest release; master's later commits (2024-2025) add CI builds and stream input, no
format change. Its reader misreads names of 128 bytes or more ("Directory contains invalid node"; it
takes the length's high bits from the wrong byte, at v0.1.2 and master); `rea-suite zar` reads them.

XGDTool's only release (v1.0.0, 2024) provides Windows binaries. It is dormant: no commit since
2024-08-13 (ZArchive's last is 2025-08-30; checked 2026-11-13). Its Linux build needs git
submodules, configure-time downloads and wxWidgets even for the CLI, which the suite's CMake builder
does not provide. QuickBMS 0.12.0 is also published for Linux (static 32-bit x86) and macOS
(x86_64, Rosetta 2); neither is configured until it has run on those hosts.
Its Windows URL is mutable: `update --ai` checks the version inside the ZIP and updates the label.
Use `rea-suite tools reinstall quickbms` to refetch the same labeled download.

## ZAR is ZArchive, for Xbox 360 games too

A .zar is Exzap's ZArchive whatever the console: Cemu's Wii U games (.wua) and Xenia Canary's Xbox 360
games (.zar) are the same format, zstd-compressed 64 KiB blocks with a file tree and a big-endian footer
ending in the magic `0x169f52d6` (`zarchivecommon.h`). A 360 .zar is made either by unpacking a disc
image with extract-xiso and packing the folder with `zarchive`, or by XGDTool `--zar` straight from a
disc image or a Games on Demand package. No other common format uses the .zar extension.

## Reading without the tools

| Command | Gives |
| --- | --- |
| `rea-suite zar info <archive>` | the sections, block count, sizes, file count (JSON) |
| `rea-suite zar list <archive>` | size and path of every file (TSV) |
| `rea-suite zar extract <archive> [path...] -o DIR` | the files or folders named (default: everything) |
| `rea-suite xbox360 disc info\|list\|extract <game>` | the same for a 360 game's .zar or disc image, with its executables and default.xex's title id ([route](XBOX360.md)) |

Only the blocks of the files asked for are read: default.xex comes out of a 6 GB archive in a
fraction of a second. Paths are compared without case, as the formats' own readers do. Names that
could leave the output folder (`..`, a slash, a drive colon) are skipped and reported, never written.
The readers sit behind one interface (`common/rea_suite/containers.py`): `zar.py` for ZArchive,
`xdvdfs.py` for disc images; a new container (a Games on Demand package) is a third reader there.

## Xbox 360 disc images: what exists (2026-11-13)

| Need | Choice | Why |
| --- | --- | --- |
| Redump XGD2/XGD3 image or XISO | `rea-suite xbox360 disc` (own XDVDFS reader); extract-xiso to unpack whole or build an XISO | extract-xiso finds the XGD1/2/3 partitions (released 2026-09, every platform). The own reader lists and takes single files out, the same way as from a .zar |
| A whole image to a .zar for Xenia | extract-xiso, then `zarchive <folder> <out.zar>` | both pinned here on every platform |
| Games on Demand (GOD) package | XGDTool `--zar` or `--extract` (Windows) | no maintained cross-platform reader; below |

Looked at and not taken:

- [xdvdfs](https://github.com/antangelo/xdvdfs) (Rust, MIT, active in 2026): reads 360 images too (it tries
  the XGD1/2/3 offsets, `xdvdfs-core/src/blockdev/offset.rs`), but its last release (v0.8.3, 2024-11) has
  Linux and Windows builds only, and it does what extract-xiso already does here.
- Games on Demand: [god2iso](https://github.com/raburton/god2iso) (Windows, last release 2023-04),
  [xtafkit](https://github.com/rdmrocha/xtafkit) (macOS builds only, ISO to GOD and STFS extraction),
  [iso2god-rs](https://github.com/iliazeus/iso2god-rs) (maintained, every platform, but ISO to GOD only),
  [Velocity](https://github.com/Gualdimar/Velocity) (STFS browser, archived 2016). None is a maintained
  GOD reader on every platform; XGDTool stays the way for now.

## Short examples

Options precede filenames for extract-xiso. Commands below use illustrative input paths and new output paths.

| Goal | Command |
|---|---|
| List an Xbox image | `extract-xiso -l game.iso` |
| Extract an Xbox image | `extract-xiso -x -d work/xbox-files game.iso` |
| Build an XISO without automatic XBE media patching | `extract-xiso -m -c work/xbox-files work/patched.iso` |
| Extract with XGDTool, without online lookup | `XGDTool --extract --offline game.iso work/xbox-files` |
| List a ZAR/WUA | `rea-suite zar list game.zar` |
| Take one file out of a ZAR/WUA | `rea-suite zar extract game.zar default.xex -o work/game` |
| Unpack a whole ZAR/WUA with ZArchive | `zarchive game.zar work/zar-files` |
| Pack a folder into a ZAR | `zarchive work/xbox-files work/game.zar` |
| Extract a known game archive with a reviewed BMS script | `quickbms game.bms game.pak work/assets` |

Confirm the installed tool's help before changing formats. Extraction alone does not decompile
XBE/XEX code. The existing **XEXLoaderWV** Ghidra extension covers XEX loading (`rea-suite xbox360`,
[the Xbox 360 route](XBOX360.md)) and **ghidra-xbe** XBE loading ([original Xbox route](XBOX-CLASSIC.md)); XEXLoaderWV is not a full
replacement for XEXTool's conversion/patching operations. No verified, current upstream XEXTool
download was established, so mirror binaries are not fetched automatically.

BMS files contain executable instructions and can invoke native code or external commands.
Choose a specific script for the game's exact archive version. This suite does not download or
run a script collection automatically. QuickBMS write/reimport modes and XGDTool scrub/rename/
patch options need deliberate use on copies. For preservation, keep original images and hashes;
a reauthored image is not a byte-identical backup.

## Verification

On macOS ARM, extract-xiso's native release passed a synthetic create/list/extract byte comparison.
Windows ZIP layouts and upstream release asset names were checked; Windows tools were not executed.
On Linux x86_64 (2026-11-13): ZArchive v0.1.2 built from source and round-tripped a folder;
`rea-suite zar` read upstream-made archives byte for byte (long names included) and upstream read the
test suite's archives; 18 real Xbox 360 .zar files (Xenia's, 2.8 to 8 GB) listed, with default.xex's
title id matching the owner's own list wherever it had one, and Condemned's default.xex taken out,
decrypted (`xbox360 extract`) and its SPA read (50 achievements). extract-xiso (build-202609111233)
packed a folder, read it back placed at the XGD2 offset, and unpacked the same files as
`rea-suite xbox360 disc`. No real 360 disc image was tried; XGDTool/QuickBMS remain untested.
No XEXTool binary was downloaded. Research and test files live under ignored `work/`.

## Maintenance

`update --ai` rechecks upstream identity, release assets/architectures, source-build dependencies,
licenses, command examples, mutable downloads, and the held tools before proposing changes.
