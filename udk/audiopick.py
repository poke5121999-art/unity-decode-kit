"""Copy the rendered audio of chosen Wwise events into a project, with an index.

The audio step (udk/audio.py) renders every embedded wem to audio/wem/<id>.ogg and maps events to wems
in audio/events.tsv. A rebuilt game needs a handful of them as plain clips: this copies the wems of
every event matching one of the patterns to <dest>/<wem id>.ogg and writes <dest>/events.json
{event: {"bank": ..., "clips": [<wem id>, ...], "seconds": [...]}}.
Usage: python -m udk.audiopick <dump> <dest> <event regex>...
"""
import csv
import json
import os
import re
import shutil
import sys


def run(dump, dest, patterns):
    rx = [re.compile(p) for p in patterns]
    os.makedirs(dest, exist_ok=True)
    index = {}
    with open(os.path.join(dump, "audio", "events.tsv"), encoding="utf-8") as fh:
        for r in csv.DictReader(fh, delimiter="\t"):
            if not any(x.search(r["event"]) for x in rx):
                continue
            wems = [w for w in r["wems"].split(",") if w]
            secs = [float(s) for s in r["wem_seconds"].split(",") if s]
            kept = []
            for w in wems:
                src = os.path.join(dump, "audio", "wem", w + ".ogg")
                if os.path.exists(src):
                    shutil.copy2(src, os.path.join(dest, w + ".ogg"))
                    kept.append(w)
            if kept:
                index[r["event"]] = {"bank": r["banks"], "clips": kept, "seconds": secs[:len(kept)]}
    with open(os.path.join(dest, "events.json"), "w", encoding="utf-8") as fh:
        json.dump(index, fh, ensure_ascii=False, indent=1)
    return index


if __name__ == "__main__":
    idx = run(sys.argv[1], sys.argv[2], sys.argv[3:])
    print(f"[audiopick] {len(idx)} events, {sum(len(v['clips']) for v in idx.values())} clips")
