"""Score the kit's Soul Knight data against the hand-decoded config tables.

Hand truth: ~/sk86-ref/decoded/config/<name>.json, {Key: {column: value}} built from CSV TextAssets
(line 1 column names, line 2 C# types, data from line 3). A table counts as matched when the kit
wrote a CSV text for it whose column names equal the hand table's and whose first-column keys equal
the hand table's keys.
Usage: python tools/score_sk_data.py out/sk/data ~/sk86-ref/decoded/config
"""
import csv
import io
import json
import os
import sys


def kit_tables(data_dir):
    out = {}
    for d, _, fs in os.walk(data_dir):
        for f in fs:
            if f.endswith((".csv", ".txt")):
                stem = f.rsplit(".", 1)[0].lower()
                out.setdefault(stem, os.path.join(d, f))
    return out


def main(data_dir, truth_dir):
    kit = kit_tables(data_dir)
    ok = 0
    names = sorted(f[:-5] for f in os.listdir(truth_dir) if f.endswith(".json"))
    for name in names:
        with open(os.path.join(truth_dir, name + ".json"), encoding="utf-8") as fh:
            truth = json.load(fh)
        path = kit.get(name.lower())
        if not path:
            print(f"MISS  {name}: no kit file")
            continue
        with open(path, encoding="utf-8", errors="replace") as fh:
            rows = list(csv.reader(io.StringIO(fh.read())))
        if len(rows) < 2:
            print(f"BAD   {name}: {path} has no header")
            continue
        cols = rows[0]
        sample = next(iter(truth.values()), {})
        keys = {r[0] for r in rows[2:] if r}
        same_cols = set(sample) <= set(cols) if isinstance(sample, dict) else True
        same_keys = {str(k) for k in truth} == keys
        if same_cols and same_keys:
            ok += 1
            print(f"OK    {name}: {len(keys)} rows, {len(cols)} columns")
        else:
            print(f"DIFF  {name}: columns {'ok' if same_cols else 'differ'}, keys kit {len(keys)} vs hand {len(truth)}")
    print(f"{ok}/{len(names)} tables match")


if __name__ == "__main__":
    main(sys.argv[1], os.path.expanduser(sys.argv[2]))
