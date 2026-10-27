#!/bin/sh
# Full divergence census over one recompile work dir (main game or 3p). Read-only on the pipeline's files except
# the cand.trivial/cand.folded it generates in the same (copied) work dir. Prints per-class counts.
# Usage: census_all.sh <scratch dir> <work dir> <asm>...
S="$1"; W="$2"; shift 2
GA="D:/walking-trade-ref/game/The.Walking.Trade.v1.1.13_LinkNeverDie.Com/GameAssembly.dll"
DUMP="D:/walking-trade-ref/il2cpp-dump/dump.cs"
META="D:/walking-trade-ref/game/The.Walking.Trade.v1.1.13_LinkNeverDie.Com/The Walking Trade_Data/il2cpp_data/Metadata/global-metadata.dat"
OUT="$W/census"; mkdir -p "$OUT"
t0=$(date +%s)
echo "== ctorgap";      python -I "$S/ctorgap.py" "$W" "$@" > "$OUT/ctorgap.txt"; grep -v "^   " "$OUT/ctorgap.txt"
echo "== stubcallees";  for a in "$@"; do python -I "$S/stubcallees.py" "$W" "$a" > "$OUT/stubcallees.$a.txt"; echo "$a: $(tail -1 "$OUT/stubcallees.$a.txt")"; done
echo "== trivial";      python -I "$S/trivial.py" "$W" "$@"
echo "== folded";       python -I "$S/folded.py" "$W" "$GA" "$DUMP" "$@"
echo "== rvablobs";     python -I "$S/rvablobs.py" "$W/ghidra.jsonl" "$DUMP" "$META" "$OUT/rvablobs.jsonl" > /dev/null; python -I -c "import json,io,sys,collections;rows=[json.loads(l) for l in io.open(sys.argv[1],encoding='utf-8')];print(len({r['key'] for r in rows}),'methods load InitializeArray blobs')" "$OUT/rvablobs.jsonl"
if [ -d "$W/skel" ]; then echo "== lintcensus"; (cd D:/walking-trade-ref/udk-lint && python -m udk.lintcensus "$W/game.json" "$OUT/lintcensus.tsv" | tail -12); fi
echo "== divergence";   (cd D:/walking-trade-ref/udk-lint && python -m udk.divergence "$W/game.json" "$OUT/divergence.tsv" | tail -12)
echo "elapsed $(( $(date +%s) - t0 ))s"
