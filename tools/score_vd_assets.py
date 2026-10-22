"""Check a VOID DIVER asset dump against the counts measured by hand in vd-ref/ASSETS.md.

Usage: python tools/score_vd_assets.py <dump dir> [vd-ref dir]
"""
import csv
import os
import re
import sys

dump = sys.argv[1]
ref = sys.argv[2] if len(sys.argv) > 2 else os.path.expanduser("~/vd-src/vd-ref")
assets = os.path.join(dump, "assets", "ExportedProject", "Assets")
files = []
for d, _, fs in os.walk(assets):
    files += [os.path.join(d, f) for f in fs if not f.endswith(".meta")]
names = {os.path.basename(f) for f in files}
csv.field_size_limit(1 << 30)


def script_users(script):
    n = 0
    rx = re.compile(r"m_Script: \{fileID: 11500000, guid: (" + "|".join(script_guids(script)) + ")")
    for f in files:
        if f.endswith(".asset"):
            with open(f, "rb") as fh:
                if rx.search(fh.read(4096).decode("utf-8", "replace")):
                    n += 1
    return n


def script_guids(script):
    out = []
    with open(os.path.join(dump, "assets", "guids.tsv"), encoding="utf-8") as fh:
        for r in csv.DictReader(fh, delimiter="\t"):
            if r["path"].endswith("/" + script + ".cs"):
                out.append(r["guid"])
    return out or ["x" * 32]


def table_ids(name, col="Id"):
    with open(os.path.join(ref, "tables", name + ".csv"), encoding="utf-8-sig") as fh:
        rows = list(csv.reader(fh))
    i = rows[0].index(col)
    return {r[i] for r in rows[1:] if len(r) > i and r[i].strip().isdigit()}


def particle_systems():
    n = 0
    for f in files:
        if f.endswith(".prefab"):
            with open(f, "rb") as fh:
                n += fh.read().count(b"\nParticleSystem:\n")
    return n


checks = [
    ("Spine skeletons (.skel)", 134, sum(1 for f in files if re.search(r"\.skel(\.bytes)?$", f))),
    ("Spine summaries readable", 134, sum(1 for f in files if f.endswith(".spine.txt") and not open(f).read().startswith("unreadable"))),
    ("SkeletonDataAsset", 134, script_users("SkeletonDataAsset")),
    ("SpineAtlasAsset", 86, script_users("SpineAtlasAsset")),
    ("AudioClip (1003 SFX + 46 BGM)", 1049, sum(1 for f in files if f.endswith((".ogg", ".wav")))),
    ("ParticleSystem components", 5652, particle_systems()),
    ("Sector.csv ids with a prefab", len(table_ids("Sector")), len({i for i in table_ids("Sector") if i + ".prefab" in names})),
]
w = max(len(c[0]) for c in checks)
for label, want, got in checks:
    print(f"{label:<{w}}  want {want:>6}  got {got:>6}  {'OK' if got >= want else 'GAP'}")
