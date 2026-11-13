---
name: codebase-design
description: Shared vocabulary for designing deep modules. Use when splitting a large file, designing or improving a module's interface, finding deepening opportunities, deciding where a seam goes, making code testable, or when another skill needs the deep-module vocabulary.
metadata:
  shared-template: codebase-design@0cc503338cca
---

# Codebase design

Design **deep modules**: a lot of behavior behind a small interface, placed at a clean seam,
testable through that interface. Use this language wherever code is designed or restructured; the
repository's own rules for it (target layout, one responsibility per file, interfaces in headers)
are in `CLAUDE.md`, `<its structure section>`.

## Glossary

Use these terms exactly; consistent language is the point.

**Module**: anything with an interface and an implementation, at any scale: a function, a class, a
file with its header, a folder. _Avoid_: unit, component, service.

**Interface**: everything a caller must know to use the module correctly: the declarations in its
header, but also invariants, ordering constraints (which thread, before or after which hook),
error modes, required configuration and performance. _Avoid_: API, signature (too narrow).

**Implementation**: what is inside a module, its body of code. Distinct from **Adapter**: a thing
can be a small adapter with a large implementation or a large adapter with a small one.

**Depth**: leverage at the interface: the behavior a caller (or test) can use per unit of interface
it has to learn. **Deep**: much behavior behind a small interface. **Shallow**: the interface is
nearly as complex as the implementation.

**Seam** _(Michael Feathers)_: a place where behavior can change without editing that place; the
location of a module's interface. Where the seam goes is its own decision, apart from what goes
behind it. _Avoid_: boundary.

**Adapter**: a concrete thing that satisfies an interface at a seam. It names a role, not
substance. In this repository, `<a hook or thunk, e.g. cpu::InstallHook>` is an adapter at the
guest seam: it turns the guest's registers and memory into a call on a host module and writes the
result back.

**Leverage**: what callers get from depth: one implementation pays back across every call site and
test. **Locality**: what maintainers get from depth: change, bugs and knowledge sit in one place.

A module has one interface; depth is measured against it; a seam is where it lives; an adapter sits
at a seam and satisfies it; depth gives callers leverage and maintainers locality.

## Deep vs shallow

```
Deep module                      Shallow module (avoid)
+---------------------+          +---------------------------------+
|  small interface    |          |  large interface                |
+---------------------+          +---------------------------------+
|                     |          |  thin implementation            |
|  much behavior      |          +---------------------------------+
|                     |
+---------------------+
```

When designing an interface, ask: can it have fewer functions? simpler parameters? can more of the
complexity move inside?

## Principles

- **Depth is a property of the interface, not the implementation.** A deep module may be built from
  small internal parts, with **internal seams** its own tests use; they are not part of its
  interface.
- **The deletion test.** Imagine deleting the module. If complexity vanishes, it was a
  pass-through. If complexity reappears across its callers, it earns its keep.
- **The interface is the test surface.** Callers and tests cross the same seam; wanting to test past
  the interface means the module has the wrong shape.
- **One adapter means a hypothetical seam; two adapters mean a real one.** Add a seam only where
  something actually varies across it (Windows and POSIX, two renderer backends, single player and
  multiplayer, the game and a test).

## Designing for testability

1. **Accept dependencies, don't create them.**

   ```cpp
   // Testable: the transport is passed in.
   class ChatChannel {
    public:
     explicit ChatChannel(DatagramSocket& socket);
   };

   // Hard to test: the channel opens its own socket and thread.
   class ChatChannel {
    public:
     ChatChannel() : socket_(OpenUdp(28960)) {}
   };
   ```

2. **Return results, don't produce side effects.**

   ```cpp
   // Testable: parsing returns what it found.
   std::optional<ServerInfo> ParseServerInfo(std::span<const uint8_t> datagram);

   // Hard to test: parsing writes into the browser's global list.
   void HandleServerInfo(const uint8_t* data, size_t size);
   ```

3. **Small surface.** Fewer functions need fewer tests; fewer parameters need less setup.

Guest state is the hard dependency in a port: logic that only reads a few guest fields is easier to
test when the hook reads them and passes plain values in.

## Rejected framings

- **Depth as a ratio of implementation lines to interface lines**: it rewards padding. Depth is
  leverage.
- **"Interface" as a class's public methods only**: it is every fact a caller must know.
- **"Boundary"**: say seam or interface.

## Going deeper

- **Deepening a cluster given its dependencies**: [DEEPENING.md](DEEPENING.md).
- **Exploring alternative interfaces with parallel sub-agents**: [DESIGN-IT-TWICE.md](DESIGN-IT-TWICE.md).
