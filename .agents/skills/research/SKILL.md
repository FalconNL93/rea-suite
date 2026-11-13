---
name: research
description: Investigate a question against primary sources and record the findings, sources cited, as Markdown in the repository's docs. Use before building a feature or a port's piece, when a topic needs researching, API or format facts gathered, or reading legwork delegated to a background agent.
metadata:
  shared-template: research@3de05518bdce
---

# Research

Research comes before building: what others did, what the platform documents, what the original
does. Its sources go in the plan of the work, so whoever builds from the plan can check them.

Start a **background agent** with a fresh context window and a precise brief (the question, what is
already known or ruled out, where the findings go), and keep working while it reads.

Its job:

1. Investigate the question against **primary sources**: official documentation, specifications,
   source code and its history, first-party APIs, release notes and issue trackers, the original
   game's own files and behavior. A secondary write-up (a forum post, a blog) is a lead to the
   source that owns the claim, never the source itself; follow every claim back to it.
2. Write the findings to one Markdown file: each claim with its source (a URL at a fixed version or
   commit, a file and line, a document's section, the date it was read), what was searched and
   found nothing (that is a finding too), and the open questions. Licenses where code or data could
   be taken over: headers and documents are a map; copying code is asked first.
3. Save it with the repository's other research in `docs/` (a topic's own doc, as
   `docs/EPIC-TOOLS.md`, or a dated report in `docs/audits/`), matching the existing convention;
   say where it went. Findings about a game belong to that game's own repository, not here.

Done when every claim the plan will rely on names its source, and the plan of the work points at
the findings file.
