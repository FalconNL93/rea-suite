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

## One page per system

Each page is short and answers, as far as known:

- what the system does, in two or three sentences;
- its entry points and key functions: address, a name, one line each;
- its data: structures with offsets, sizes and meaning, and its globals;
- what calls it and what it calls;
- what is per player (for co-op) and where it lives (overlay, module, DLL);
- confidence: confirmed (seen in a run or the code) or inferred;
- port hooks: where a port would change it, and what to watch out for.

Link to other pages instead of repeating them. Keep it readable for a person (the platform's rule "Written for people", master-server's CLAUDE.md).

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
