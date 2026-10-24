#!/bin/sh
# Run a rebuilt Windows player for a fixed time with UdkProbe recording, and summarise what it reached.
# Usage: run-player.sh <build dir> <out dir> <seconds> [<original game dir>]
#   original game dir: its Steam files (steam_api64.dll, loader/emulator files next to the exe) are copied in, so a
#   game that quits without Steam keeps running. The build's exe and _Data folder are renamed to the original's.
# Env: UDK_PROBE_CALLS (see UdkProbe.cs) is passed through.
set -eu
build=$1 out=$2 secs=$3 orig=${4:-}
mkdir -p "$out"
if [ -n "$orig" ]; then
  exe=$(cd "$orig" && ls *.exe | grep -v -i -E 'crash|setting|start|unins' | head -1)
  name=${exe%.exe}
  if [ -f "$build/Game.exe" ]; then mv "$build/Game.exe" "$build/$exe"; mv "$build/Game_Data" "$build/${name}_Data"; fi
  for f in "$orig"/*; do
    b=$(basename "$f")
    case "$b" in "$exe"|"${name}_Data"|GameAssembly.dll|UnityPlayer.dll|baselib.dll|UnityCrashHandler64.exe|D3D12|MonoBleedingEdge|*.url) continue ;; esac
    cp -r "$f" "$build/"
  done
  for d in "$orig/${name}_Data/Plugins/x86_64"/steam_api64.dll; do [ -f "$d" ] && cp "$d" "$build/${name}_Data/Plugins/x86_64/"; done
else
  exe=$(cd "$build" && ls *.exe | grep -v -i crash | head -1)
fi
(cd "$build" && UDK_PROBE_DIR=$(cd "$out" && pwd -W 2>/dev/null || pwd) timeout "$secs" "./$exe" -logFile "$out/Player.log" \
  -screen-width 1280 -screen-height 720 -screen-fullscreen 0 >/dev/null 2>&1) || true
echo "== probe"; cat "$out/probe-summary.json" 2>/dev/null | cut -c1-1500; echo
echo "== stubs reached (first run order)"; grep -o '\[udk-stub\] .*' "$out/Player.log" | head -60
echo "== exceptions"; grep -E '^[A-Za-z.]*Exception' "$out/Player.log" | sort | uniq -c | sort -rn | head -15
