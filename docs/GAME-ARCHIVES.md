# Game archives and Xbox discs

Checked: **2026-11-03**. Enable **game-archives** in `rea-suite select`; keep your existing
components selected. Selection runs setup. These are command-line tools, not new REA MCP providers.

| Tool | Purpose | Linux x86_64 | macOS ARM | Windows x64 |
|---|---|---|---|---|
| [extract-xiso](https://github.com/XboxDev/extract-xiso) | List, extract, and create Xbox XISO files | Release | Native ARM release | Release |
| [ZArchive](https://github.com/Exzap/ZArchive) | Read/create ZAR and Wii U WUA archives | Source build + zstd | Source build + zstd | Release EXE |
| [XGDTool](https://github.com/wiredopposite/XGDTool) | OG Xbox/360 ISO, GoD, CCI, CSO, ZAR conversion | Not configured | Not configured | Upstream CLI release |
| [QuickBMS](https://mirror.aluigi.org/quickbms.htm) | Script-defined game archive extraction/reimport | Not configured | Not configured | Author's ZIP (32-bit x86 executables), including large-file variant |
| XEXTool | Legacy Xbox 360 XEX inspection/conversion | Not installed | Not installed | Bring your own verified copy; no automatic download |

ZArchive's Linux/macOS path uses the existing CMake builder and system zstd development files
(Debian `libzstd-dev`, Fedora/RHEL `libzstd-devel`, Arch/macOS `zstd`). It also needs the **build**
component. Source builds run when you request setup; `REA_TOOLS_NO_BUILD=1` leaves this tool uninstalled.
It builds ZArchive v0.1.2 (C++20; zstd found through CMake config or pkg-config). This source-build
path has not been executed on any host.

XGDTool's only release (v1.0.0, 2024) provides Windows binaries. Its Linux build needs git
submodules, configure-time downloads and wxWidgets even for the CLI, which the suite's CMake builder
does not provide. QuickBMS 0.12.0 is also published for Linux (static 32-bit x86) and macOS
(x86_64, Rosetta 2); neither is configured until it has run on those hosts.
Its Windows URL is mutable: `update --ai` checks the version inside the ZIP and updates the label.
Use `rea-suite tools reinstall quickbms` to refetch the same labeled download.

## Short examples

Options precede filenames for extract-xiso. Commands below use illustrative input paths and new output paths.

| Goal | Command |
|---|---|
| List an Xbox image | `extract-xiso -l game.iso` |
| Extract an Xbox image | `extract-xiso -x -d work/xbox-files game.iso` |
| Build an XISO without automatic XBE media patching | `extract-xiso -m -c work/xbox-files work/patched.iso` |
| Extract with XGDTool, without online lookup | `XGDTool --extract --offline game.iso work/xbox-files` |
| Extract a ZAR/WUA with ZArchive | `zarchive game.zar work/zar-files` |
| Extract a known game archive with a reviewed BMS script | `quickbms game.bms game.pak work/assets` |

Confirm the installed tool's help before changing formats. Extraction alone does not decompile
XBE/XEX code. The existing **XEXLoaderWV** Ghidra extension covers XEX loading (`rea-suite xbox360`
in the README); it is not a full
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
On Linux x86_64 (2026-11-03) release assets were inspected only; no tool ran. ZArchive source
builds, XGDTool/QuickBMS extraction, and real Xbox images remain untested.
No XEXTool binary was downloaded. Research and test files live under ignored `work/`.

## Maintenance

`update --ai` rechecks upstream identity, release assets/architectures, source-build dependencies,
licenses, command examples, mutable downloads, and the held tools before proposing changes.
