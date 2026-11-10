# `rea-suite epic`: a modular analyzer for Epic Games Store games (plan)

Status: plan, 2026-11-10. Nothing here is built yet. The owner asked (2026-11-10): "Maybe build a
reusable tool that does this for other Epic games too, modular. Epic's tools change over time, so the
executable differs. Something like Steamless."

"This" is the first week of the Alan Wake II and Alan Wake Remastered ports, done by hand: name the
build, read the EOS SDK version and import set, map every EOS call site to its function, find the
launcher dependence, ownership gates, features used, the game's own platform layer, the Epic-validity
checks that break offline play, and anything that calls home. The tool does that inventory in one
command and writes a report a port can cite. It stops at the report and at starting points for a
port's own work. It never writes a patched executable.

## In short

- **What it is.** `rea-suite epic scan <install>` reads an Epic install from its files alone and writes
  `epic-report.md` and `epic-report.json`. Detectors name things (build, SDK version, imports, launcher
  arguments, anti-cheat). Analyzers explain them (call sites per EOS interface, features, platform
  layer, offline hazards, calls home). A knowledge base with one module per EOS SDK version range says
  what each imported function is and what is known to bite.
- **What it is like Steamless in.** Steamless has one plugin per SteamStub variant, each saying "this is
  mine" before it does anything ([below](#steamless-what-we-take-and-what-we-do-not)). Here, one
  knowledge module per SDK range says "this version is mine". A new SDK is a new module; nothing
  else changes. An unknown version is reported as unknown, with every fact the version-free detectors
  could still read.
- **What it is not like Steamless in.** Steamless rewrites the executable. This tool only reads. Epic
  has no wrapper to strip: the dependence is ordinary calls into a DLL, and taking them out is a
  port's design decision (AW2 replaced the 42 imports; AWR replaces the game's own 63-slot interface).
- **Built on what exists.** `rea-suite pe` already has the hard parts (imports with call sites and
  containing functions, RTTI with slot states, refs, strings, the `rea-image-sites-v1` declaration).
  The epic tool composes them and adds Epic's own knowledge.
- **Stops at anti-cheat.** When Easy Anti-Cheat or EOS Anti-Cheat is present the tool reports it and
  ends, with exit code 3. It does not analyze, map or describe the anti-cheat's integration.

## What the two ports found by hand

The tool's first job is to reproduce these facts in seconds. They are its acceptance tests.

| Fact | Alan Wake II | Alan Wake Remastered | Where it came from |
|---|---|---|---|
| Store build | 1.2.11 (`.egstore` manifest, BuildId `D8wC5mOw…`) | 1.33 (`.egstore` manifest); developer stamp `.keystoneBuild` BuildID 34885 | manifest meta; `.keystoneBuild` is AWR only |
| Executable | `AlanWake2.exe`, 61 MB, ASLR | `Game_f_x64_EOS.exe`, 12 MB, fixed base | PE headers |
| EOS SDK (DLL) | 1.15.1-20662730, 618 exports | 1.7.1-13992660, 343 exports | DLL version resource `ProductVersion` |
| EOS imports | 42 | 23 | import table |
| Call sites | 129 references, 113 calls (Rizin); `pe imports` agrees exactly | 37 sites in 10 functions | `rea-suite pe imports` |
| Options versions seen | Initialize API 4, Platform API 12, Auth credentials 3, Auth login 2, Connect 1/2 | (not yet read) | immediates stored before each call |
| Launcher | `CheckForLauncherAndRestart`, 3 sites; result 0 quits, 20 continues | 1 site; quits unless a debugger is attached | wrapper decompiled |
| Credentials | exchange code; native offline variant `SignInCredentialsOffline` | exchange code when launched by Epic, else persistent auth | RTTI, constructor |
| Ownership | `EOS_Ecom_QueryOwnership` (pre-order, Deluxe flags) | none (no Ecom import) | imports, continuations |
| Features | achievements (9), stats (2), user info, presence (release only) | achievements unlock, presence (rich text) | imports |
| Platform layer | none in front of EOS; `platform::TServices` contexts | `PlatformServices` / `PlatformServicesEpic`, 63 slots, 21 with behavior | RTTI |
| Offline hazard | input-device loop keeps a pad only while `EOS_EpicAccountId_IsValid` (2 sites) | no `IsValid` import; not that way | owner's runs, retail included |
| Exit | normal close never calls `Platform_Release`/`Shutdown` | neither is imported | runtime trace |
| Calls home | none besides EOS found yet | only EOS; Winsock users unclassified; "Telemetry" is RAD's profiler | strings |

Two corrections to the brief, checked on the installs today:

- **`.keystoneBuild` is not Epic's.** It is a developer build stamp (project "Deer", Debug/Release/Final
  executable names, CodeCL/DataCL) present in AWR only; AW2 has none. Epic's own identity of a build is
  `.egstore/<id>.manifest` (Epic's binary BuildPatchTool manifest, magic `0x44BEC00C`, zlib body) whose
  meta block holds AppName, BuildVersion, LaunchExe, LaunchCommand and BuildId, matched to the install's
  `.egstore/<id>.mancpn` (JSON: CatalogNamespace, CatalogItemId, AppName). AWR's folder holds two
  manifests, an old one (BuildVersion `34885`) and the current one (`1.33`, the one whose AppName the
  `.mancpn` names): the AppName match picks the right one. The launcher's own record,
  `C:\ProgramData\Epic\EpicGamesLauncher\Data\Manifests\<id>.item` (JSON), adds `AppVersionString`,
  `bCanRunOffline` (AW2 true, AWR false) and `bRequiresAuth`, read when present and never required.
- **AWR's "no version string names 1.33"** is settled: the store's BuildVersion is `1.33`.

## Research

Sources were read on 2026-11-10. Where a fact was checked on the two installs instead, it says so.

### Steamless: what we take and what we do not

- **What it is.** "A DRM remover of the various SteamStub variants": variant 1, 2.0, 2.1 (x86) and 3.0.0,
  3.0.1, 3.1.0, 3.1.2 (x86 and x64); the README says those numbers are its author's, from observed
  changes, not Valve's ([atom0s/Steamless][steamless]).
- **Plugins.** One assembly per variant (`Steamless.Unpacker.Variant31.x64` and so on) derived from
  `SteamlessPlugin`, marked `[SteamlessApiVersion(1, 0)]`, with `Name`, `Author`, `Version`,
  `Initialize(LoggingService)`, `CanProcessFile(file)` and `ProcessFile(file, options)`
  ([SteamlessPlugin.cs][steamless-plugin]). The CLI loads every DLL in `Plugins\`, keeps the types of
  API 1.0, sorts them by name and runs the first whose `CanProcessFile` says yes, then the next on
  failure ([Program.cs][steamless-cli]).
- **Detection** (variant 3.1 x64): a 64-bit PE with `.bind`, the stub signature
  `E8 00 00 00 00 50 53 51 52 56 57 55 41 50` in its first 0x3000 bytes, then one of three patterns
  telling 3.0, 3.1 and 3.1.2 apart, and a header size of 0xF0 ([Main.cs][steamless-31]). Unpacking then
  decodes the header, decrypts the payload and the code section, drops `.bind` and writes
  `<file>.unpacked.exe`.
- **License**: CC BY-NC-ND 4.0, so its code is neither reused nor adapted; we take the shape only.
- **What we take**: one self-contained module per variant, each deciding "mine or not" from the file
  before anything runs; one shared API version the modules declare; a host that knows no variant;
  version names the tool's own where the vendor gives none. **What we leave**: the rewrite. Epic has no
  wrapper; the suite already has `rea-suite steamstub` for detection and Steamless (component `steam`)
  for that job.

### The EOS SDK

- **Versions.** Epic's release notes list every release from 1.13 (2021-06-21) to 1.19.2.1
  (2026-09-22); 1.15.1 is 2022-07-01 ([release notes][eos-notes]). Releases before 1.13, AWR's 1.7.1
  among them, are not on that page; their dates are unverified.
- **The version is in the DLL.** Checked today: both DLLs carry a version resource whose
  `ProductVersion` is the full version (`1.7.1-13992660`, `1.15.1-20662730`), the same string appears in
  the DLL's data, and both export `EOS_GetVersion`, which Epic documents as returning
  `MAJOR.MINOR.PATCH-CHANGELIST…` and as matching the headers in use ([EOS_GetVersion][eos-getversion]).
  Names: `EOSSDK-Win64-Shipping.dll`, `EOSSDK-Win32-Shipping.dll`; it may be delay-loaded or loaded with
  `LoadLibrary` ([Windows platform page][eos-windows]), so the import table alone is not the whole story.
- **How the C ABI is versioned.** Every options struct starts with `int32_t ApiVersion`, set to a
  `*_API_LATEST` macro of the header the game was built with ([EOS_Platform_Options][eos-platform-options]).
  The DLL accepts a range: a 1.16.1 DLL refuses `EOS_Platform_Create` version 14 with "expected range (1
  to 13)" ([forum][eos-range]), and a version it cannot serve gets `EOS_IncompatibleVersion`
  ([conventions][eos-conventions]). So a newer DLL serves older games, the struct for a given
  `ApiVersion` never changes, and new fields only ever go at the end under a higher number. That is why
  AW2's Platform options (API 12) end at +0x80 while today's reference shows more fields. The ABI
  promise has slipped before: 1.15.2 fixed "detection of pre-1.15 header files" in `EOS_Platform_Create`,
  and 1.15's DLL crashed `EOS_AntiCheatClient_RegisterPeer` from older headers ([release notes][eos-notes]).
- **Changes that matter to a port** ([release notes][eos-notes]): 1.15 added
  `EOS_Platform_GetDesktopCrossplayStatus` and the `Set/GetApplicationStatus` and `Set/GetNetworkStatus`
  calls, mandatory from then on (a game of 1.15 or later tells EOS when it is offline: a seam), and moved
  Account Portal and External Auth logins on Windows to the EOS redistributable's bootstrapper; 1.16 fixed
  `CheckForLauncherAndRestart`'s detection of a launcher start, deprecated `EOS_LCT_DeviceCode` and renamed
  the `API_LATEST` macros to `EOS_<Interface>_<Function>_API_LATEST`; 1.16.2 raised the Platform options
  to 14; 1.19.0.3 dropped 32-bit Windows. The release that added `CheckForLauncherAndRestart` is before
  1.13 and unverified (AWR's 1.7.1 imports it).
- **The launcher check.** `EOS_Platform_Create` reads the command line; `CheckForLauncherAndRestart`
  returns `EOS_Success` when it restarted the game through the launcher (the game must quit),
  `EOS_NoChange` (20) to go on, or `EOS_UnexpectedError`
  ([reference][eos-launcher]); AW2's wrapper maps exactly 0 and 20.
- **The launcher's arguments.** Epic publishes no specification. Legendary, which reproduces the
  launcher's line, passes `-AUTH_LOGIN=unused -AUTH_PASSWORD=<exchange code> -AUTH_TYPE=exchangecode
  -epicapp=<AppName> -epicenv=Prod [-epicovt=<file>] -EpicPortal -epicusername= -epicuserid= -epiclocale=
  -epicsandboxid=<namespace> [-epicdeploymentid=]` ([legendary core.py][legendary-core]); Epic staff confirm
  the exchange code arrives as `AUTH_PASSWORD` ([forum][eos-exchange]). `-epicovt` names an ownership
  verification token file, used by games that check ownership offline, often with Denuvo.
- **The install's files.** `.egstore/<guid>.manifest` is Epic's binary manifest (magic `0x44BEC00C`,
  header, SHA-1, zlib body) and `<guid>.mancpn` the JSON catalog record ([legendary manifest.py][legendary-manifest]).
  Checked today: the meta block holds AppName, BuildVersion (AW2 `1.2.11`, AWR `1.33`), LaunchExe and
  BuildId, and the launcher's `.item` agrees (`AppVersionString`). `.keystoneBuild` has no public mention;
  its content (project "Deer", Debug/Release/Final executable names) marks it as the developer's.

### Community EOS tools (design reference only)

| Project | What it does | How | License |
|---|---|---|---|
| Goldberg Steam Emulator | Steam API without Steam, LAN play | replaces `steam_api(64).dll` | LGPLv3 ([gitlab][goldberg]) |
| Nemirtingas' Epic emulator | EOS without Epic | replaces the EOS DLL (third-party guide; unverified) | source no longer public; binaries only ([registry][nemirtingas]) |
| ScreamAPI (acidicoala) | makes EOS games report DLC as owned | intercepts `EOS_Ecom_QueryOwnership`/`QueryEntitlements`; proxy DLL, later in-memory hooks | repository disabled by GitHub for a terms violation ([github][screamapi]); license unverified |
| Koaloader (acidicoala) | loads other DLLs into a game | search-order hijack with ~23 proxy DLL names | Unlicense ([github][koaloader]) |
| Legendary | open-source Epic launcher | exchange codes, ownership tokens, `.egstore`; warns on EAC, BattlEye, EQU8 | GPLv3 ([github][legendary]) |

What this tells the design: everything public in this space is either a whole-SDK emulator (a DLL
answering every export) or an ownership spoofer. Our ports did neither: they answer only the imports
the game uses, keep the game's own offline identity, and grant content by the owner's choice in the
game's own flags. The tool follows the ports, and its outputs stop well short of either kind. Legendary's
argument list and manifest layout are facts we cite, not code we copy (its GPLv3 would bind the suite); Koaloader's Unlicense would allow reuse, but nothing here needs injection.

### Anti-cheat

- **Files** named in Epic's release notes: `start_protected_game.exe` (the bootstrapper, which starts the
  executable named in `Settings.json` and forwards its arguments), `EasyAntiCheat_EOS_Setup.exe`,
  `anticheat_integritytool.exe`/`.cfg`, the `EasyAntiCheat/` folder with `Certificates/` and
  `Settings.json` (with `productid`) ([release notes][eos-notes], [EAC support][eac-support]). The
  service's driver is `EasyAntiCheat_EOS.sys` under `Program Files (x86)\EasyAntiCheat_EOS`. The SDK's
  interfaces are `EOS_AntiCheatClient_*` and `EOS_AntiCheatServer_*`; detecting them by import is our
  inference from the names.
- Starting the game executable instead of the bootstrapper skips EAC and keeps the player off protected
  servers ([Redpoint docs][redpoint-eac]): the tool must not suggest that either.
- **Epic's terms.** The Epic Games Store EULA (2025-01-15), section 2, forbids reverse engineering and
  decompiling "it" (Epic's licensed software), circumventing "security technology included in it", and
  "unauthorized software programs to gain advantage in any online or other game modes"
  ([EULA][eula]). Epic's Terms of Service did not load for an automated fetch (403) and were not read.

### Epic and DRM

The store has no store-wide DRM; DRM and launcher requirements are the developer's choice
([Game Informer, 2018][gi-drm]; Epic on Control, [USgamer][usg-control]). Ownership in EOS is the Ecom
interface; `EOS_Ecom_QueryOwnershipToken` returns a signed JWT meant for a backend to verify
([reference][eos-ownership-token]), and the launcher can hand a game an ownership token file
(`-epicovt`). AWR's launcher record says `bCanRunOffline: false`, AW2's `true`: whether the launcher
lets a game start offline is the store's per-game setting, separate from what the executable checks.

## Design

### Shape

One command group, `rea-suite epic`, in `common/rea_suite/epic/` (a package: it grows by modules):

```text
rea-suite epic scan <install-or-exe> [--exe NAME] [--out DIR] [--json]   everything below, one report
rea-suite epic build <install>        the store build (manifest, mancpn, launcher item, developer stamps)
rea-suite epic sdk <install-or-dll>   the EOS SDK: DLL version, exports, the knowledge module that claims it
rea-suite epic calls <exe> [--interface Auth] [--function EOS_X]   call sites per EOS interface
rea-suite epic hazards <exe>          the offline-hazards checklist alone
rea-suite epic sites <exe> [--interface I] > re/eos-sites.json     a rea-image-sites-v1 declaration
rea-suite epic header <exe> --sdk-version 1.15.1 > eos_imports.h   the imported functions' ABI
rea-suite epic kb [list|show 1.15]    the knowledge base: modules, ranges, functions, hazards
```

Exit codes follow `steamstub`: 0 the report was written; 1 it was written with gaps (an unknown SDK
version, an import the knowledge base has no entry for); 2 not readable (not a PE, no executable
found); 3 anti-cheat present, nothing analyzed.

Where a file is a PE, every scan goes through `rea_suite.pemodel.Image` and the existing `scan.py`
(imports with sites, refs, strings) and `rtti.py`. The epic package adds no disassembler of its own.

### Detectors (they name things; each is a module with `detect(target) -> Finding | None`)

| Detector | Reads | Reports |
|---|---|---|
| `build` | `.egstore/*.mancpn`, `.egstore/*.manifest` (meta block only), the launcher's `.item` when on the same machine, developer stamps (`.keystoneBuild`, `codebuild.txt`, `databuild.txt`, a `version.txt`) | AppName, CatalogNamespace, BuildVersion, BuildId, LaunchExe; the launcher record's AppVersionString, bCanRunOffline, bRequiresAuth; developer stamps marked as such |
| `executable` | the LaunchExe, else `--exe`, else the one PE in the root importing `EOSSDK-*` | path, SHA-256, size, machine, base, ASLR, linker version, PDB path, signature present |
| `sdk` | `EOSSDK-Win64-Shipping.dll` / `EOSSDK-Win32-Shipping.dll` beside the executable, or found by import name | `ProductVersion` from the version resource (`1.15.1-20662730`), the version string inside the DLL as a second witness, export count, SHA-256; the knowledge module that claims it |
| `imports` | the executable's import and delay-import tables, and every other PE in the root (bundled DLLs) | the EOS import set in import order with IAT slots; other PEs that import EOS; `GetProcAddress` users that load a string starting `EOS_` (a lead for dynamic resolution) |
| `launcher` | strings in the executable (ASCII and UTF-16LE) with `pe refs --string` | which launcher arguments the game reads (`AUTH_LOGIN`, `AUTH_PASSWORD`, `AUTH_TYPE`, `epicapp`, `epicenv`, `epicuserid`, `epicusername`, `epiclocale`, `EpicPortal`, `epicsandboxid`, `epicdeploymentid`) and the functions loading them |
| `anticheat` | file system and imports | see [Anti-cheat](#anti-cheat-detect-and-stop); stops the run |
| `protection` | the existing `steamstub` signs plus entropy and section names (`.bind`, `.vmp*`, `.denuvo`-like high-entropy code) | "looks unprotected" or the signs; a protected executable gets the report of the files and no call-site work |

### The knowledge base (the Steamless-like part)

One module per EOS SDK version range in `common/rea_suite/epic/kb/`, each a Python file holding data
only, plus one shared loader:

```python
# kb/sdk_1_15.py
MODULE = KnowledgeModule(
    name="eos-1.15",
    claims=VersionRange("1.15.0", "1.16.0"),        # [from, to)
    functions={                                      # every export of that range we have a row for
        "EOS_Initialize": Fn(interface="Platform", kind="sync", returns="EOS_EResult",
                             options="EOS_InitializeOptions", api_latest=4),
        "EOS_Auth_Login": Fn(interface="Auth", kind="async", options="EOS_Auth_LoginOptions",
                             api_latest=2, callback="EOS_Auth_OnLoginCallback",
                             callback_info="EOS_Auth_LoginCallbackInfo"),
        "EOS_Auth_AddNotifyLoginStatusChanged": Fn(interface="Auth", kind="notify", returns="EOS_NotificationId", ...),
        ...
    },
    hazards=[HAZARD_LAUNCHER_RESTART, HAZARD_ACCOUNT_VALID_GATE, HAZARD_OWNERSHIP_QUERY, ...],
    notes={"EOS_Platform_Options": "API 12 ends at +0x80; current headers add tail fields"},
)
```

- **Claims.** The loader asks every module whether it claims the DLL's version; exactly one must. None:
  the report says "EOS SDK 1.18.2: no knowledge module claims this version" at the top, and goes on
  with the version-free facts (imports, call sites by name, strings, RTTI). Two: a test failure, never
  a run-time choice. Without a DLL (a port that already removed it), the module is chosen by the import
  set: the module whose function list contains every import and whose range is newest; the report says
  it was inferred.
- **What a function row holds**: interface (from the name: `EOS_<Interface>_<Verb>`, with the irregular
  ones listed: `EOS_EpicAccountId_*`, `EOS_ProductUserId_*`, `EOS_EResult_ToString`, the `*_Release`
  functions), kind (`sync`, `async` with callback, `notify` returning an id, `remove-notify`, `copy`
  returning an owned object, `release`, `handle`), options struct and its `API_LATEST` in that range,
  callback info struct, the range's first version (when it was added). Facts come from Epic's
  published headers and API reference of that version, cited by version; a module never copies
  Epic's header text (see [License](#licenses-and-what-we-may-ship)).
- **Hazards** are shared objects referenced by several modules, each with an id, a test against the
  report (an import present, a string present, a call pattern), its consequence offline, and the port
  that found it. They are the checklist below.
- **Adding a version** is a new file and a line in its test; older modules are not touched. When a new
  SDK only adds functions, the new module can extend the previous one's table
  (`functions={**sdk_1_15.FUNCTIONS, ...}`), since the C ABI is append-only by design.
- **Seed modules**: `eos-1.7` (from AWR's 343 exports) and `eos-1.15` (AW2's 618), each verified
  against its DLL's export list by the optional local test; then 1.16 and later as games need them.

### Analyzers (they explain; each reads detector output, never the disk again)

| Analyzer | Output |
|---|---|
| `callmap` | per EOS interface, every imported function, every site (`call`, `jmp` thunk, `mov` of the pointer, via-thunk), the containing function, and the functions grouped: "these N functions are the game's Epic code". AWR: 37 sites in 10 functions, all in one span; AW2: 55 functions plus 9 sites without an unwind entry |
| `options` | per site of an options-taking function, the `ApiVersion` immediate stored into the options struct before the call (a `mov dword [rsp+X], imm` in the same function, decoded with Capstone), set against the knowledge module's `API_LATEST`: tells which header the game was compiled with, and which struct layout its options have. A lead, marked "not found" when the store is not a plain immediate |
| `features` | what the game uses, from the import set by interface: lifecycle, launcher, Auth, Connect, Ecom (ownership, entitlements, offers), Achievements, Stats, Leaderboards, Presence, Friends, UserInfo, PlayerDataStorage and TitleStorage (Epic cloud data), Sessions/Lobby/P2P/RTC (multiplayer), UI (overlay), Metrics, Reports/Sanctions, Mods, and the per-interface row "imported: 9 of 14 functions" |
| `platform` | RTTI classes whose names match store words (`Epic`, `EOS`, `Platform`, `Store`, `Online`, `Services`, `Steam`, `GOG`, `Xbox`, `Gdk`) with their vtables and slot states (`pe rtti --slots`); for each class, which of its slots' functions contain EOS call sites; sibling implementations of the same base (`PlatformServicesSteam` beside `PlatformServicesEpic` would be the cheapest seam of all). The verdict line: "the game has its own platform interface: <class>, N slots, M call EOS" or "EOS is called directly from N functions" |
| `hazards` | the checklist below, each item `present`, `absent` or `lead`, with sites and evidence |
| `callhome` | URLs, host names and IP-like strings (ASCII and UTF-16LE) with their loading functions; network imports (WinHTTP, WinINet, Winsock, libcurl in bundled DLLs) with their call sites; known SDKs by strings or DLL names (analytics, crash reporters: Sentry, BugSplat, Backtrace, CrashRpt); `EOS_Metrics_*` and `EOS_Reports_*` imports. Static leads only; the runtime proof stays the port's (the window harness's connection list) |

### The offline-hazards checklist

Every item is something a port either hit or must rule out. Each reports its sites.

1. **Launcher restart**: `EOS_Platform_CheckForLauncherAndRestart` imported; its sites and what the
   wrapper does with result 0 (relaunch, the game quits) and 20 (`EOS_NoChange`, carry on).
2. **Launcher arguments**: which of `AUTH_*`, `epic*`, `EpicPortal` the game reads; whether it chooses
   between exchange code and persistent auth (`EOS_LCT_ExchangeCode`, `EOS_LCT_PersistentAuth`
   immediates near `EOS_Auth_Login`).
3. **A native offline path**: RTTI or strings naming an offline credential or "continue offline"
   (AW2's `SignInCredentialsOffline`, `MENU_AUTHENTICATION_CONTINUE_OFFLINE`; AWR's `MENU_EPIC_FAILED`).
4. **Account-validity gates outside sign-in**: every site of `EOS_EpicAccountId_IsValid` and
   `EOS_ProductUserId_IsValid` grouped by function, with the functions that are not sign-in code
   flagged (AW2's input-device loop). This is the item that cost AW2 a day.
5. **Ownership gates**: `EOS_Ecom_QueryOwnership`, `QueryEntitlements`, `QueryOwnershipToken`,
   `CopyEntitlement*`, and the continuations that read their results (the content a port must keep
   available by the owner's choice).
6. **Asynchronous obligations**: every `async` import whose callback must complete once, and every
   `notify` import whose id the game passes back to `RemoveNotify` (AW2 accepts id 0 for unavailable).
7. **Teardown**: whether `EOS_Platform_Release` and `EOS_Shutdown` are imported; a reminder that a normal
   close may skip them (AW2).
8. **Epic cloud data**: `PlayerDataStorage` or `TitleStorage` imports, meaning saves or config may live
   at Epic.
9. **Store strings**: store URLs and offer ids (AW2's Deluxe upgrade link), the Epic overlay
   (`EOS_UI_*`).
10. **Unseen loads**: `GetProcAddress` with an `EOS_` string, or a bundled DLL that imports EOS.

### Reports

`epic-report.md` for people and `epic-report.json` (schema `rea-epic-report-v1`) for tools, in `--out`
(default `work/epic/<exe-name>-<sha8>/`, ignored by git). The Markdown opens with the summary a port
copies into its inventory: build, executable hash, SDK version and module, import count by interface,
the platform-layer verdict, the hazards present, anti-cheat absent, and then one section per analyzer
with addresses as VAs. Every row names how it was found (`import table`, `pe imports`, `rtti`, `strings`)
so a port can cite the report and the tool's commit, the way the ports cite `rea-suite pe` today. The
report holds no game bytes beyond short instruction encodings and no secrets: strings that look like
EOS client credentials (the `ClientSecret` beside a `ClientId` passed to `EOS_Platform_Create`) are
replaced by `<redacted: 32 chars>`, since AWR's constructor showed they sit in the executable
(PORTING-EOS, section 5).

### Starting points a port may take (optional outputs)

- `epic sites`: a `rea-image-sites-v1` declaration with one `iat` site per EOS import (the import it
  must hold), one `call` site per `call [iat]` (with `target` left empty for the port to fill) and one
  `function` site per containing function, each with `evidence` naming the report. `rea-suite pe
  sites` checks it unchanged. The port deletes what it does not use.
- `epic header`: a C header listing the imported functions with their return types, parameter types,
  calling convention (`EOS_CALL`, `__cdecl` on x64 Windows is the Microsoft x64 convention), the options
  and callback-info structs at the `ApiVersion` the game actually stores, with field offsets as
  `static_assert`s. Written from the knowledge module's own field tables, which are our description of
  Epic's ABI and cite Epic's reference; it is not Epic's header and does not include it. A port's
  embedded backend (AW2's fnet) starts from it.
- **Never**: a patched executable, a proxy `EOSSDK-*.dll`, a ready backend, an "everything succeeds"
  stub set, credential or ownership forging. Those are per port by design (below) and would make the
  tool a crack for games the user does not own.

## What stays with each port

- The replacement itself: AW2's embedded fnet answering 42 imports, AWR's own `PlatformServices`
  implementation, or whatever seam the next game offers. The report says where the seams are; choosing
  one is the port's decision (PORTING-EOS, sections 2 and 4).
- The game's patches, their sites declaration and its build gate.
- Every behavior claim: what a callback does with a result, which flag holds pre-order content, how
  the input loop picks a user. The tool gives sites and leads; decompiling and running stay the port's,
  with REA, rea-ghidra and the Frida observers.
- Runtime proof: modules loaded, connections made, the acceptance table in PORTING-EOS.

## When Epic changes the SDK

- A new DLL version that no module claims: the report says so in its first line, exit 1, and lists the
  imports the newest module does not know. Everything version-free still works.
- Adding support: a module for the range, generated as a draft by `rea-suite epic kb draft <EOSSDK.dll>
  --from eos-1.15` (the new DLL's exports set against the previous module: added, removed, unchanged),
  then filled from Epic's release notes and API reference for that version, and checked by the module
  test. The draft step never reads Epic's headers into the repository.
- A changed `API_LATEST` for an options struct is recorded per module; the `options` analyzer compares
  the game's stored version with it and flags a game built against an older header than its DLL.
- Changes outside the SDK (the store's manifest format, the launcher's arguments, a new anti-cheat
  layout) live in their detector, each with its own fixture.

## Anti-cheat: detect and stop

The tool must never be a step towards tampering with anti-cheat. Signs, any one enough:

- an `EasyAntiCheat/` or `EasyAntiCheat_EOS/` folder, `EasyAntiCheat_EOS_Setup.exe`,
  `EasyAntiCheat_Setup.exe`, `start_protected_game.exe`, `EasyAntiCheat_EOS.sys`, an EAC `Settings.json`;
- an import of any `EOS_AntiCheatClient_*`, `EOS_AntiCheatServer_*` or `EOS_AntiCheatCommon_*` function;
- BattlEye (`BattlEye/`, `BEService*.exe`, `BEClient_x64.dll`) and other kernel anti-cheats, by their
  files, reported the same way.

On a sign the tool writes a short report (build, executable hash, which sign) and exits 3 without
mapping calls, RTTI or hazards. There is no flag to go on. A game with anti-cheat is out of scope for
a port.

## Licenses and what we may ship

- **Purpose, stated in the tool's help and README section.** For games the user owns, to make them
  playable offline on the owner's own platform. It reads files; it unlocks nothing, forges no
  ownership or credentials, and stops at anti-cheat. Content a game sells separately is never turned
  on by the tool; a port decides that from the owner's purchases, as AW2 did.
- **Epic's EULA** forbids reverse engineering Epic's licensed software. Whether it reaches a third-party
  game bought on the store (whose own EULA applies, EULA 1.2) and an analysis made for
  interoperability on the owner's own copy is a legal question for the owner, not settled here. The
  tool never analyzes Epic's launcher or the EOS DLL's code: it reads the DLL's version resource and
  export names only.
- **Epic's SDK headers** come under the EOS Developer Agreement, which sits behind a login; no clause
  allowing their redistribution was found. So the knowledge base holds our own description of each
  function (name, kind, struct versions, field offsets checked against games' code) with links to Epic's
  public API reference, never header text, and `epic header` writes our description, not Epic's file.
- **Third-party code**: none copied. Steamless (CC BY-NC-ND) and Legendary (GPLv3) are cited for
  design and facts only; the closed or withdrawn emulators are not read.
- **The suite's rule** holds: no game bytes, captures or reports in git (`work/` is ignored), and the
  report redacts what looks like EOS client credentials.

## Tests

- **Synthetic PE fixtures** in `samples.py` style (the suite's tests build tiny x64 and x86 programs, no
  game bytes): an executable importing a dozen `EOS_*` functions by name from `EOSSDK-Win64-Shipping.dll`,
  with `call [iat]`, a thunk, a `mov reg, [iat]`, options structs filled with `mov dword [rsp+X], 2`
  before the call, unwind entries for containing functions, strings for launcher arguments and a URL,
  and MSVC RTTI for a `PlatformServices`/`PlatformServicesEpic` pair. A tiny DLL with a version
  resource `ProductVersion 1.15.1-0` and an export table. A fake install tree with a `.mancpn`, a
  manifest written by a test encoder of the meta block (the reader is checked against the encoder and
  against the two real manifests' fields below), and EAC folders for the stop test.
- **Knowledge base tests**: every module's range is disjoint from the others; every function row names
  an interface and kind; a module's options table has `API_LATEST` for every options struct it names;
  every hazard referenced exists.
- **Optional local checks on the two Alan Wake installs** (`REA_EPIC_LOCAL=1`, skipped otherwise; the
  paths in `.env`): the table in [What the two ports found by hand](#what-the-two-ports-found-by-hand)
  is the expected output: build 1.2.11 and 1.33, SDK 1.15.1 and 1.7.1, 42 and 23 imports, AWR's 37
  sites in 10 functions, AW2's call sites equal to the port's committed `eos_call_map.json`, AW2's
  `EOS_EpicAccountId_IsValid` hazard with two sites in the input loop's function, AWR's
  `PlatformServicesEpic` verdict with 63 slots. Each module also checked against its real DLL's export
  list (343 and 618 exports).
- `ruff check`, `ruff format`; `rea-suite lint`.

## Build order

1. **`build` and `sdk` detectors, `epic build`/`epic sdk`** (manifest meta reader, `.mancpn`, launcher
   `.item`, DLL version resource). Local check: 1.2.11/1.33 and 1.15.1/1.7.1.
2. **Knowledge base loader and the two seed modules** (`eos-1.7`, `eos-1.15`), with the claim rules and
   their tests; the "unknown version" path.
3. **`imports` and `callmap`** on top of `scan.py`; `epic calls`. Local check against AW2's committed
   call map and AWR's 37 sites.
4. **`anticheat` detector and the stop**, before any analyzer runs on a third game.
5. **`platform` (RTTI) and `launcher`**; the verdict line. Local check: AWR's 63-slot interface.
6. **`hazards` and `features`**, then `options` (ApiVersion immediates).
7. **`epic scan` and the reports** (Markdown, JSON schema, redaction).
8. **`epic sites` and `epic header`**, last, since they are the outputs a port starts from and need the
   rest to be right. A port tries them on its next Epic game before they are called done.
9. **`callhome`**, then `kb draft` when the first new SDK version arrives.

Documentation moves with it: a section in `docs/PORT-TOOLS.md`, a row in the README's tool table, the
usage line in `bin/rea-suite` and its PowerShell counterpart, and a pointer from master-server's
`PORTING-EOS.md` step 1 ("Establish the boundary") to `rea-suite epic scan`.

## Open questions for the owner

1. Name: `rea-suite epic` (the store) or `rea-suite eos` (the SDK)? Proposed: `epic`, since the build and
   launcher detectors are about the store, and the EOS part is most of it.
2. Should the launcher's `.item` files under `C:\ProgramData\Epic` be read when the tool runs on the same
   machine (WSL sees them under `/mnt/c`)? Proposed: yes, read-only, reported as "launcher record", never
   required.
3. The header output: proposed as our own description of the ABI with citations, never Epic's text. If
   the owner would rather a port use Epic's own SDK headers (downloaded by the owner under Epic's
   license), `epic header` becomes a list of the functions and struct versions to take from them.
4. Epic's store EULA forbids reverse engineering Epic's software; the tool reads only the EOS DLL's
   version and export names and analyzes the game's executable. Is that line, and the purpose stated in
   [Licenses](#licenses-and-what-we-may-ship), the one the owner wants? Proposed: yes.

[steamless]: https://github.com/atom0s/Steamless
[steamless-plugin]: https://github.com/atom0s/Steamless/blob/master/Steamless.API/Model/SteamlessPlugin.cs
[steamless-cli]: https://github.com/atom0s/Steamless/blob/master/Steamless.CLI/Program.cs
[steamless-31]: https://github.com/atom0s/Steamless/blob/master/Steamless.Unpacker.Variant31.x64/Main.cs
[eos-notes]: https://dev.epicgames.com/docs/epic-online-services/release-notes
[eos-getversion]: https://dev.epicgames.com/docs/api-ref/functions/eos-get-version
[eos-windows]: https://dev.epicgames.com/docs/epic-online-services/platforms/windows
[eos-platform-options]: https://dev.epicgames.com/docs/api-ref/structs/eos-platform-options
[eos-range]: https://forums.unrealengine.com/t/epic-ue5-6-error-incompatible-eos-platform-create-version-specified-14-expected-range-1-to-13/2615327
[eos-conventions]: https://dev.epicgames.com/docs/epic-online-services/eos-get-started/working-with-the-eos-sdk/conventions-and-limitations
[eos-launcher]: https://dev.epicgames.com/docs/api-ref/functions/eos-platform-check-for-launcher-and-restart
[eos-exchange]: https://forums.unrealengine.com/t/can-you-detect-if-a-game-is-launched-through-the-epic-games-launcher/1301799/4
[eos-ownership-token]: https://dev.epicgames.com/docs/api-ref/functions/eos-ecom-query-ownership-token
[legendary]: https://github.com/derrod/legendary
[legendary-core]: https://github.com/legendary-gl/legendary/blob/master/legendary/core.py
[legendary-manifest]: https://github.com/legendary-gl/legendary/blob/master/legendary/models/manifest.py
[goldberg]: https://gitlab.com/Mr_Goldberg/goldberg_emulator
[nemirtingas]: https://gitlab.com/Nemirtingas/epicemulatorregistry
[screamapi]: https://github.com/acidicoala/ScreamAPI
[koaloader]: https://github.com/acidicoala/Koaloader
[eac-support]: https://easy.ac/support/articles/error-eac-is-not-installed
[redpoint-eac]: https://redpoint-games-docs.pages.dev/docs/setup/networking/anticheat
[eula]: https://store.epicgames.com/en-US/eula
[gi-drm]: https://www.gameinformer.com/index.php/2018/12/04/tim-sweeney-answers-questions-about-the-new-epic-games-store
[usg-control]: https://www.usgamer.net/articles/controls-new-pc-patch-forces-you-to-launch-through-the-epic-games-store
