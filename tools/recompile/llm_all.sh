#!/bin/sh
# Translate every outstanding method of the given assemblies in resumable chunks.
# Usage: llm_all.sh <game.json> <model> <asm>...
set -eu
cfg=$1 model=$2; shift 2
work=$(py -3.12 -c "import json,sys;print(json.load(open(sys.argv[1]))['work'])" "$cfg")
cd "$(dirname "$0")/../.."
for asm in "$@"; do
  PYTHONIOENCODING=utf-8 py -3.12 -m udk.recompile "$cfg" todo "$asm" "$work/todo.$asm.txt"
  split -l 800 -d "$work/todo.$asm.txt" "$work/todo.$asm.chunk."
  for chunk in "$work/todo.$asm.chunk."*; do
    PYTHONIOENCODING=utf-8 py -3.12 -m udk.recompile "$cfg" llm "$asm" "$chunk" model="$model" workers=8
    rm -f "$chunk"
  done
done
