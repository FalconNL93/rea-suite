# To do

Open work for the suite (tools to add, fixes, upstream reports) is in the work queue: Forgejo issues
on [FalconNL93/rea-suite](https://git.falcon-net.nl/FalconNL93/rea-suite/issues), mirrored one file
per open issue in [docs/work/](docs/work/) for when the forge is away. A session takes and files
them with games/ci-images' `./ci work` (the `work-queue` skill):

```sh
./ci work list --repo FalconNL93/rea-suite                 # the board
./ci work new FalconNL93/rea-suite "Add X" --body brief.md --kind feature --session orchestrator
./ci work sync --repo FalconNL93/rea-suite --checkout <this checkout>   # rewrite docs/work/
```

A tool's issue closes when it is added (following `AGENTS.md`, "Adding a tool": it moves into the
README's tool tables) or dropped (into "Not included" with the reason). The entries this file held
until 2026-11-13 are issues #3 to #28 (and a comment on #2).
