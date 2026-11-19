# The RE atlas: a port's map of its game

Every port keeps a short map of its game's engine, written ahead of need (the owner, 2026-11-19): the systems a port
commonly changes, so the next change starts from known addresses and structures instead of a fresh search. The port's
sessions decide per game which systems matter; this page is the shape and the starting list, not a quota.

## Where it lives

In the port's repository, `docs/research/re/`: an `index.md` and one page per system. Docs only: no game data, no
extracted images or screenshots of the game, no long disassembly (describe in your own words, with addresses). A finding
that holds for every game of a platform or engine goes where that layer is documented
(master-server's docs/PORTING.md, "Where a finding goes", and docs/RUNTIMES.md; this suite's platform pages such as
[PS1.md](PS1.md) for what the tools find on every game of a platform).

## The index

`index.md` says which build the atlas maps and how to read its addresses, then lists the pages:

- the build: name, platform, region and version, the file analyzed, and its SHA-256 (or a link to the port's hash
  manifest that has it). A disc serial or a version string alone does not pick out the bytes;
- the address convention: guest addresses in the main executable, an RVA in a PE, or an overlay's own addresses.
  Overlays can share a load address, so an address in an overlay always names the overlay;
- the globals most pages use, in one table;
- one row per page with its state, and the next open question that matters;
- the dated research notes the pages build on, linked instead of repeated.

Start with the systems the port is about to change, not the whole list.

## One page per system

Each page is short and answers, as far as known:

- what the system does, in two or three sentences;
- its entry points and key functions: address, a name, one line each;
- its data: structures with offsets, sizes and meaning, and its globals;
- what calls it and what it calls;
- what is per player (for co-op) and where it lives (overlay, module, DLL);
- confidence, per claim where it differs: **confirmed** (seen in a run or read in the code, for this build),
  **inferred** (a reading no run or second look has checked) or **open** (not known, or the evidence disagrees).
  An address can be confirmed while its meaning is still inferred;
- port hooks: where a port would change it, what the hook relies on (calling convention, layout, lifetime, the
  overlay being loaded) and what is still open.

For a finding a hook depends on, say enough to repeat the check: what was read (the caller, the offset, the
cross-reference) or what was run (the input or game state and what changed), and the date. A link to the dated note
or the test that showed it is enough; one note can back several claims.

Link to other pages instead of repeating them. Keep it readable for a person (the platform's rule "Written for people", master-server's CLAUDE.md).

## Addresses the port's code uses

An address that both the atlas and the port's hooks use has one source, so the two cannot drift apart. Use the suite's
function index (`re/functions.json` and `re/functions.tsv`, README "Function index and gate"): one row per function,
its gate says whether the executable still has it there. The atlas page names the function and links the index; the
port's hook table reads it or is generated from it, never a second hand-kept copy. Add the index when the first hook
needs it, not ahead of time. A new build gets its own image in the index, and each row it keeps is checked again
on that build, the matcher's vote being a lead (README, "Comparing two builds").

## The systems ports usually touch

Take the ones the game has, in the order the port needs them:

| System | Why ports change it |
|---|---|
| Main loop, frame and tick timing | frame rate, slowdowns, pacing, loading speed |
| Player record and state machine | modern movement, co-op, per-player state |
| Input path | modern controls, rebinding, controllers |
| Camera | collision, field of view, shoulder, free look |
| Weapons, ammo, inventory, items | quick keys, wheels, HUD |
| HUD and on-screen text | a modern HUD, scaling, aspect ratios |
| Actors, AI, spawning and pools | limits, difficulty, co-op |
| Collision, rooms and visibility | camera, draw distance, widescreen culling |
| Rendering pipeline | resolution, widescreen, draw distance, effects |
| Sound and music | voice limits, volume, devices |
| Saves and settings storage | cloud saves, formats, slots |
| Level and file loading | packs, mods, loading speed |
| Menus and frontend | the port's own menus, skipping intros |
| Text, strings and fonts | the port's own UI in the game's look |
| Networking (if the game has it) | the master, sessions, IPv6 |
| Cheats and debug leftovers | developer tools, achievements' cheat rule |

Time to Kill's atlas is the first (duke-nukem-time-to-kill `docs/research/re/`, 2026-11-19).
