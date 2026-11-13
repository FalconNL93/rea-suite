# Windows 95, 98 and 16-bit Windows games: the era's traps

What is particular to games of the Windows 95 and 98 era (about 1995-2001) and to 16-bit Windows,
beside the route every 32-bit Windows game takes, [PC-WIN32.md](PC-WIN32.md). A 32-bit Win9x game is a
PE32 like any other and goes onto winrt the same way. What differs is around it: the installer, the CD,
the graphics APIs of the time, the palette, the clock and the copy protection. Each section says what
to look for, what the ports did, and where the reference behavior is. Checked 2026-11-13.

## Installers

- **A 16-bit `SETUP.EXE` in front of a 32-bit game** is common on retail discs (an NE executable, not a PE:
  `diec` names it). Don't run it: unpack its archives as data. unshield reads
  InstallShield 5 and later, cabextract Microsoft CABs, 7-Zip many others. Older InstallShield 3 archives
  (`_SETUP.LIB`, `DATA.Z`) need a tool the suite does not have yet (none checked).
- **When it must run** (an installer that writes the registry or patches files as it copies):
  - on 64-bit Windows, which runs no 16-bit code, [winevdm](https://github.com/otya128/winevdm) (otvdm,
    GPL-2.0) runs it. Its newest release is v0.9.0 (2023-09-15), but it is maintained (last commit
    2026-10-24).
  - Wine runs 16-bit programs in its new WoW64 mode since 10.16 (its
    [release notes](https://gitlab.winehq.org/wine/wine/-/raw/wine-10.16/ANNOUNCE.md)); a crash on some
    processors was fixed after it ([bug 58755](https://bugs.winehq.org/show_bug.cgi?id=58755)). The suite
    installs Wine from the distribution in WoW64 mode, and Ubuntu 26.04's package is Wine 10.0
    (`apt-cache policy wine`, 2026-11-13), older than 10.16, so expect it to refuse 16-bit programs. Not
    run here; check before relying on it.
- Record what the installer wrote (registry keys, files outside the game folder) with Wine's `+reg,+file`
  trace or Process Monitor: the port answers those reads itself.

## 16-bit Windows games (NE)

Ghidra has a New Executable loader built in (`NeLoader`). [pcrecomp](https://github.com/sp00nznet/pcrecomp)
lifts NE programs (its `ne/` and `win16/` stages: parsing, Win16 imports, stubs). winrt has no 16-bit
CPU mode or Win16 API, so an NE game is a new route, not a step on this one; no port has needed it yet.

## CD audio

- **The music is on the disc as audio tracks**, played through MCI (`mciSendCommand` or
  `mciSendString` on the `cdaudio` device, winmm). A data-only ISO loses them: keep the whole image as
  CUE/BIN, as for the PS1.
- **The port plays ripped tracks.** Rogue Spear's community release ships them as `music/trackNN.ogg`
  (track 1 is the data track), and winrt's MCI layer (`src/win32/winmm_mci.cpp`) plays those files,
  sending `MM_MCINOTIFY` to the game's window at a track's end so its looping works unchanged. That
  replaced the ogg-winmm wrapper the release shipped.
- Rip the tracks from the user's own disc image; they live in the work or game folder, never in git.

## DirectDraw and Direct3D 3 to 7

winrt answers DirectX 6 in host code: DirectDraw, Direct3D (`IDirect3D3`, `IDirect3DDevice3`), drawn
with OpenGL 3.3 (its README). Rogue Spear uses DirectDraw 4 with Direct3D 3. Traps of the time:

- **Surfaces the game locks and writes**: the CPU copy and the GPU copy must stay in step (winrt's
  `docs/2026-11-05-ddraw-surface-sync-research.md`).
- **Color keys, palettes, lost surfaces and alt-tab** (`WM_ACTIVATEAPP` on a focus change): Wine's
  `ddraw` tests are the reference for what Windows did (winrt's `docs/2026-11-04-gap-research.md`
  lists them).
- **Behavior references, not code**: DDrawCompat (0BSD) and cnc-ddraw's per-game settings show which
  behaviors games depend on; dgVoodoo2 is closed source. Their fixes say what to take care of; winrt's
  layer is its own.
- Direct3D 5 and 7 interfaces (`IDirect3DDevice2`, `IDirect3DDevice7`) are not in winrt's source
  (2026-11-13): check the census before assuming DirectX 6 covers a game.

## Glide (3dfx)

A game that imports `glide2x.dll` or `glide3x.dll` drew straight to a Voodoo card. winrt has no Glide
layer. Many such games also have a Direct3D or software renderer: prefer it. Two wrappers show what
Glide behavior games rely on, and are references only:

- [dgVoodoo2](https://github.com/dege-diosg/dgVoodoo2): Glide, Glide2, Glide3 and Glide3 Napalm, plus
  DirectDraw, Direct3D 3 to 9, on Direct3D 11 or 12. Closed source, free to ship; v2.87.6 (2026-10-26).
  Its repository is archived "for a while" (its README).
- nGlide (Zeus Software): closed source, free. Its site refused automated reads on 2026-11-13, so
  nothing about it was checked.

## 8-bit palettes

A 256-color game sets a palette, through DirectDraw (`IDirectDrawPalette` on an 8-bit primary) or GDI
(`SetPaletteEntries`, `RealizePalette`), and often animates it (fades, water, fire) by changing entries
without touching the pixels. Modern displays have no 8-bit mode, so the port converts at present time:
winrt's DirectDraw converts palette indexes to RGBA as it uploads a surface
(`src/dx/ddraw/pixel_format.cpp`). A palette change must reach the next frame even when no pixel
changed.

## Timers

- `GetTickCount` and `timeGetTime` count milliseconds since boot and wrap after 49.7 days; a game that
  compares them as signed numbers breaks after 24.8 days. Players blamed Rogue Spear's "double speed"
  reports on that; winrt counts from the port's start, so neither happens.
- A game may calibrate RDTSC against the performance counter at start (Rogue Spear's clock does, with
  the counter and `timeGetTime` as fallbacks). A port that recompiles it should check which source the
  game picked.
- `timeBeginPeriod(1)` asked Windows for a 1 ms tick; winrt accepts it and does nothing.
  `timeSetEvent` (multimedia timer callbacks on their own thread) is not in winrt yet.
- Speed tied to the frame rate: a game that steps its world per frame (Rogue Spear, capped at 100 ms a
  step) or per tick runs differently at 144 Hz. Check before removing a frame cap.

## Copy protection

- **CD checks** (`GetDriveTypeA`, `GetVolumeInformationA`, a file read from the disc): winrt answers only
  `C:` as a fixed drive. No port needed a disc so far: the releases the ports start from (Steam, GOG,
  community releases) have no check, or the game skips it.
- **SafeDisc and SecuROM** need a driver that current Windows no longer loads (widely reported; no
  primary source checked). A protected executable stops the route at step 2: start from a release
  without it, or remove it with the owner's permission, as for SteamStub (the README's "SteamStub"
  section has the record a port keeps). The result never goes into git.

## The rest of the era

- **DirectPlay lobbies**: no port imports `DPLAYX`; winrt's own transport replaces a game's networking
  (winrt's `docs/2026-11-04-gap-research.md`, "Considered and rejected").
- **Win9x heap behavior**: some games read freed or uninitialized heap blocks and worked on Windows 9x;
  Proton keeps per-game lists for it. winrt adds that only for a game shown to need it (the same page).

## Sources (read 2026-11-13)

- winevdm: its `releases.atom`, `commits.atom` and LICENSE.
- Wine: `ANNOUNCE.md` at tag wine-10.16; WineHQ bugs 58755 and 58760 (the latter closed as a duplicate of
  the former); `apt-cache policy wine` on Ubuntu 26.04.
- Ghidra: `NeLoader.java` at tag Ghidra_12.1.4_build. pcrecomp: README at HEAD.
- dgVoodoo2: README at HEAD, release v2.87.6.
- winrt: `README.md`, `src/win32/winmm_mci.cpp`, `src/win32/kernel32_time.cpp`,
  `src/dx/ddraw/pixel_format.cpp`, `docs/2026-11-04-gap-research.md`.
- rogue-spear: `docs/00-overview.md`, `02-prior-art.md`, `07-portability.md`.
