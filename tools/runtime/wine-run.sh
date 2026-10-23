#!/bin/sh
# Run a Windows IL2CPP game under wine with the Frida gadget preloaded, on a private Xvfb display.
#   tools/runtime/wine-run.sh <game dir (a copy)> <exe name> <trace.js from `udk trace --log`> [seconds] [prefix]
# The gadget config written by `udk trace` sits next to trace.js; the gadget reads <name>.config next
# to the .so, so the gadget is copied beside the script. The game runs for [seconds] (default 180).
# Xvfb and wineserver run with fd 9 closed: heavy.sh holds the machine's job lock on fd 9, and a
# daemon that inherits it and outlives the game keeps every other heavy job waiting.
set -eu
KIT=$(cd "$(dirname "$0")/../.." && pwd)
GAME=$1 EXE=$2 JS=$3 SECS=${4:-180}
export WINEPREFIX=${5:-$KIT/out/rt/prefix} WINEDEBUG=-all DISPLAY=:77
GADGET=${JS%.js}.gadget.so
[ -s "$GADGET" ] || cp "$KIT/third_party/frida-gadget.so" "$GADGET"
XVFB=${XVFB:-Xvfb}  # XVFB_LIBS: library dir for a Xvfb unpacked outside the system
LD_LIBRARY_PATH=${XVFB_LIBS:-} $XVFB :77 -screen 0 1280x720x24 -nolisten tcp >/dev/null 2>&1 9>&- &
XPID=$!
trap 'wineserver -k 9>&- 2>/dev/null; kill $XPID 2>/dev/null' EXIT
sleep 2
[ -d "$WINEPREFIX" ] || timeout 300 wineboot -i >/dev/null 2>&1 9>&-
cd "$GAME"
set +e
LD_PRELOAD=$GADGET timeout "$SECS" wine "$EXE" -screen-fullscreen 0 -screen-width 1280 -screen-height 720 \
    -logFile "$WINEPREFIX/../player.log" 9>&-
echo "game exit $?"
