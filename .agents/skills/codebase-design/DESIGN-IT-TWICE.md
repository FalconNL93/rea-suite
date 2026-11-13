# Design it twice

To explore alternative interfaces for a chosen candidate, use parallel sub-agents. Based on "Design
It Twice" (Ousterhout): the first idea is rarely the best. Uses the vocabulary in
[SKILL.md](SKILL.md).

## 1. Frame the problem space

Before spawning sub-agents, write the user an explanation of the candidate:

- the constraints any new interface must meet (threads, the hooks that call it, single player and
  multiplayer, platforms);
- its dependencies and their category ([DEEPENING.md](DEEPENING.md));
- a rough code sketch that makes the constraints concrete (not a proposal).

Show it to the user, then go straight on to step 2; they read while the sub-agents work.

## 2. Spawn sub-agents

Spawn three or more in parallel, each with a fresh context window and its own technical brief (file
paths, coupling, the dependency category, what sits behind the seam, the vocabulary from
[SKILL.md](SKILL.md), the repository's own terms from its docs, and the rules in `CLAUDE.md`), and a
different constraint, so each produces a radically different interface:

- Agent 1: "Minimize the interface: one to three entry points; maximize leverage per entry point."
- Agent 2: "Maximize flexibility: many uses and extension."
- Agent 3: "Optimize for the most common caller: make the default case trivial."
- Agent 4 (if it applies): "Ports and adapters for the dependencies across the seam."

Each returns:

1. the interface (declarations, invariants, ordering, error modes);
2. a usage example from a caller;
3. what the implementation hides behind the seam;
4. the dependency strategy and adapters;
5. trade-offs: where leverage is high and where it is thin.

## 3. Present and compare

Present the designs one by one, then compare them in prose by **depth**, **locality** and **seam
placement**. Then recommend one, and say why; propose a hybrid where parts combine well. Be
opinionated: the user wants a strong read, not a menu.
