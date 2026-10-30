# To do

Tools still to add to the suite, each with why. An entry moves into the README's tool
tables when it is added (following `AGENTS.md`, "Adding a tool"), or into "Not included"
with the reason when it is dropped.

## Porting old games

- **BinExport + BinDiff, or Ghidra's Version Tracking documented**: diff two builds or
  patch levels of a game function by function; ghidriff covers single patches, and
  BinDiff's last releases target old Ghidra versions (check again before adding).
- **objdiff**: per-function match of recompiled code against the original object code,
  the way decompilation projects check progress.
- **apitrace and RenderDoc**: graphics traces of the original and the port. RenderDoc
  covers modern APIs only (D3D11/12, Vulkan, OpenGL); DirectDraw and D3D7 games need
  apitrace, or a trace taken after Wine's translation to OpenGL/Vulkan.
- **Kaitai Struct (compiler and visualizer)**: describe a game's file formats once and get
  parsers and a structure viewer from the description.
- **DOSBox-X with its debugger**: run and debug DOS-era games and their installers.
