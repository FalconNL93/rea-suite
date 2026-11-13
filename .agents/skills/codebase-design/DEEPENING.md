# Deepening

How to deepen a cluster of shallow modules safely, given its dependencies. Uses the vocabulary in
[SKILL.md](SKILL.md): **module**, **interface**, **seam**, **adapter**.

## Dependency categories

Classify the candidate's dependencies; the category decides how the deepened module is tested
across its seam.

### 1. In-process

Pure computation and in-memory state, no I/O, no guest memory: `<e.g. text and color codes, config
parsing, a file format's reader, protocol encoding>`. Always deepenable: merge the modules and test
through the new interface directly. No adapter needed.

### 2. Local-substitutable

Dependencies with a local stand-in: files (a temporary folder), a database (an in-memory one), a
UDP socket on localhost, guest memory set up by the test. Deepenable when the stand-in exists; the
module is tested with it. The seam stays internal: no port at the module's external interface.

### 3. Owned across a process or network boundary (ports and adapters)

Our own services and processes: `<e.g. the master server, a dedicated server, the test channel>`.
Define a **port** (interface) at the seam; the deep module owns the logic and the transport is
injected as an **adapter**: a socket adapter in the game, an in-memory one in tests.

### 4. Not ours

The recompiled game (guest memory, guest functions), the guest runtime, the master's SDK, the OS,
the GPU driver. The module takes them through a port: a hook passes plain values in and writes
results back; platform calls go through `<the platform layer, e.g. wrt::os>`. Tests provide a fake
behind the port, or the check is a scripted game run (`.claude/skills/diagnosing-bugs`).

## Seam discipline

- **One adapter means a hypothetical seam; two adapters mean a real one** (typically the game's and
  a test's). A port with one adapter and no test is only indirection.
- **Internal seams vs external seams.** A module may have internal seams for its own tests; do not
  expose them through its interface because tests use them.

## Testing: replace, don't layer

- Tests at the deepened module's interface replace the tests of the shallow parts; delete those.
- Tests assert observable outcomes through the interface, not internal state, so they survive
  internal changes. A test that must change with the implementation tests past the interface.
