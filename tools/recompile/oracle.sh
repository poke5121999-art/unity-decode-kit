#!/bin/sh
# Usage: oracle.sh <index|compile|repair> <skeleton-src> <asm> [extra Oracle args...]
# References resolve first-wins: full BCL reference assemblies (a game ships a stripped mscorlib), then the
# game's own DLLs (its UnityEngine modules match its Unity version), then the editor's engine modules.
# Env: UNITY_DATA (Editor/Data of any Unity 6 install), GAME_PLUGINS (AssetRipper DllExport Assets/Plugins)
set -eu
here=$(cd "$(dirname "$0")" && pwd)
dll="${ORACLE_DLL:-$here/Oracle/bin/Release/net8.0/Oracle.dll}"
[ -f "$dll" ] || dotnet build -c Release "$here/Oracle" >/dev/null
cmd=$1 src=$2 asm=$3; shift 3
exec dotnet "$dll" "$cmd" --src "$src" --asm "$asm" \
  --refs "$UNITY_DATA/UnityReferenceAssemblies/unity-4.8-api" \
  --refs "$UNITY_DATA/UnityReferenceAssemblies/unity-4.8-api/Facades" \
  --refs "$GAME_PLUGINS" \
  --refs "$UNITY_DATA/Managed/UnityEngine" "$@"
