#!/usr/bin/env bash
# Build DOSBox-X with its debugger from a release's source: build-dosbox-x.sh <source> <dest>.
# Run by rea-tools (common/rea_suite/build.py, tools.yml `build: {script: ...}`) on Linux, where
# DOSBox-X publishes no binary and the distributions' packages are built without the debugger.
#
# As upstream's Linux CI (.github/workflows/linux.yml) and build-debug-sdl2 do: SDL2 and SDL2_net
# from the copies in its source tree (vs/sdl2, vs/sdl2net; SDL2_net carries the debugger control
# channel, [dosbox] mcp_server), then `--enable-debug=heavy`, which interrupt breakpoints in every
# CPU mode need. FFmpeg and FluidSynth stay out (video capture and MIDI synthesis, not needed for
# analysis). System packages: component `dos` (curses, libpng, zlib, X11 and ALSA headers) and
# the compilers and autotools of component `build`.
set -euo pipefail

src=$(cd "$1" && pwd)
dest=$2
cd "$src"

./autogen.sh
chmod +x vs/sdl/build-scripts/strip_fPIC.sh vs/sdl2/build-dosbox.sh vs/sdl2net/*.sh

(cd vs/sdl2 && ./build-dosbox.sh)
export PATH="$src/vs/sdl2/linux-host/bin:$PATH"
export CPPFLAGS="-I$src/vs/sdl2/linux-host/include -I$src/vs/sdl2net/linux-host/include"
# --no-as-needed: configure's SDL2_net check links libm before the static SDL2 that needs it
export LDFLAGS="-L$src/vs/sdl2/linux-host/lib -L$src/vs/sdl2net/linux-host/lib -Wl,--no-as-needed"
(cd vs/sdl2net && ./build-dosbox.sh)

./configure --enable-debug=heavy --enable-sdl2 --disable-avcodec --disable-libfluidsynth --prefix=/usr
grep -q '^#define C_SDL2_NET 1' config.h ||
  { echo "build-dosbox-x: SDL2_net not found; the debugger control channel would be missing" >&2; exit 1; }
make -j"$(nproc)"

mkdir -p "$dest/bin"
install -m 755 src/dosbox-x "$dest/bin/dosbox-x"
strip "$dest/bin/dosbox-x"
cp COPYING "$dest/"
