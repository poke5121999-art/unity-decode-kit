"""ScriptableObject assets of an AssetRipper export as JSON, readable without the game's scripts.

AssetRipper writes every serialized field of a MonoBehaviour asset into its .asset YAML, even when
the script it exports is an empty stub (no field declarations). A rebuilt project that cannot
compile field-accurate scripts can still read the data: each matching asset becomes
<dest>/<path under Assets>.json = {"script": <class>, "fields": {...}}. Scalars stay strings as
Unity wrote them (numbers, and hex blobs for primitive arrays such as `Children: 01000000`), so
nothing is reinterpreted on the way.
Usage: python -m udk.sojson <ExportedProject> <dest> <path regex>... [--flat]  (--flat: no subfolders)
"""
import json
import os
import re
import sys

import yaml

HEADER = re.compile(r"^--- !u!(\d+) &(-?\d+)(?: stripped)?\s*$", re.M)
SCRIPT = re.compile(r"m_Script: \{fileID: -?\d+, guid: ([0-9a-f]{32})")
GUID = re.compile(r"^guid: ([0-9a-f]{32})", re.M)
SKIP = {"m_ObjectHideFlags", "m_CorrespondingSourceObject", "m_PrefabInstance", "m_PrefabAsset", "m_GameObject",
        "m_Enabled", "m_EditorHideFlags", "m_Script", "m_EditorClassIdentifier"}


def script_names(export):
    out = {}
    root = os.path.join(export, "Assets", "Scripts")
    for d, _, fs in os.walk(root):
        for f in fs:
            if f.endswith(".cs.meta"):
                with open(os.path.join(d, f), encoding="utf-8", errors="replace") as fh:
                    m = GUID.search(fh.read())
                if m:
                    out[m.group(1)] = f[:-8]
    return out


def convert(path, scripts):
    with open(path, encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    docs = HEADER.split(text)
    if len(docs) < 4 or docs[1] != "114":  # first object is not a MonoBehaviour
        return None
    body = docs[3]
    data = yaml.load(body, Loader=yaml.CBaseLoader)["MonoBehaviour"]
    m = SCRIPT.search(body)
    return {"script": scripts.get(m.group(1), m.group(1)) if m else None,
            "name": data.get("m_Name"),
            "fields": {k: v for k, v in data.items() if k not in SKIP and k != "m_Name"}}


def run(export, dest, patterns, flat=False):
    rx = [re.compile(p) for p in patterns]
    scripts = script_names(export)
    written = []
    assets = os.path.join(export, "Assets")
    for d, _, fs in os.walk(assets):
        for f in fs:
            if not f.endswith(".asset"):
                continue
            rel = os.path.relpath(os.path.join(d, f), export)
            if rx and not any(r.search(rel) for r in rx):
                continue
            doc = convert(os.path.join(d, f), scripts)
            if doc is None:
                continue
            out = os.path.join(dest, f if flat else os.path.relpath(os.path.join(d, f), assets)) + ".json"
            os.makedirs(os.path.dirname(out), exist_ok=True)
            with open(out, "w", encoding="utf-8") as fh:
                json.dump(doc, fh, ensure_ascii=False, separators=(",", ":"))
            written.append(rel)
    return written


if __name__ == "__main__":
    flat = "--flat" in sys.argv
    args = [a for a in sys.argv[1:] if a != "--flat"]
    done = run(args[0], args[1], args[2:], flat)
    print(f"[sojson] {len(done)} ScriptableObject assets as JSON")
