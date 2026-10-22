"""Cross-link an AssetRipper Unity-project export: which asset uses which, through which field.

Every exported asset has a `.meta` holding its guid; YAML assets (prefab, scene, material,
controller, anim, ScriptableObject...) reference others as `{fileID: N, guid: G, type: T}`.
build_refs() turns those into assets/refs.tsv rows: src, field path, dst. print_refs() answers
"what does X use" and "what uses X" from that table.
"""
import csv
import os
import re
import sys

GUID_RE = re.compile(rb"^guid: ([0-9a-f]{32})", re.M)
INLINE_REF_RE = re.compile(rb"\{fileID: (-?\d+), guid: ([0-9a-f]{32}), type: \d\}")
KEY_RE = re.compile(rb"^(\s*)(-\s+)?([\w ]+):", re.M)
YAML_EXT = {".prefab", ".unity", ".asset", ".mat", ".controller", ".anim", ".overrideController",
            ".playable", ".mask", ".physicMaterial", ".spriteatlas", ".spriteatlasv2", ".renderTexture",
            ".flare", ".signal", ".lighting", ".terrainlayer", ".brush", ".guiskin", ".fontsettings",
            ".preset", ".mixer", ".cubemap", ".shadervariants"}
csv.field_size_limit(1 << 30)


def export_dir(root):
    return os.path.join(root, "assets", "ExportedProject")


def guid_map(project):
    out = {}
    for d, _, files in os.walk(os.path.join(project, "Assets")):
        for f in files:
            if f.endswith(".meta"):
                p = os.path.join(d, f)
                with open(p, "rb") as fh:
                    m = GUID_RE.search(fh.read(512))
                if m:
                    out[m.group(1).decode()] = os.path.relpath(p[:-5], project)
    return out


SCRIPT_RE = re.compile(rb"^  m_Script: \{fileID: -?\d+, guid: ([0-9a-f]{32})", re.M)


def field_paths(text, guids):
    """Yield (owner.field path, guid) for each reference. The owner is the component class,
    or the script name for a MonoBehaviour, so a row reads like `SkeletonAnimation.skeletonDataAsset`."""
    for doc in text.split(b"\n--- "):
        first = KEY_RE.search(doc)
        if not first:
            continue
        owner = first.group(3).decode("utf-8", "replace").strip()
        sm = SCRIPT_RE.search(doc)
        if sm and sm.group(1).decode() in guids:
            owner = os.path.splitext(os.path.basename(guids[sm.group(1).decode()]))[0]
        stack = []
        for line in doc.split(b"\n"):
            km = KEY_RE.match(line)
            if km:
                indent = len(km.group(1)) + (2 if km.group(2) else 0)
                while stack and stack[-1][0] >= indent:
                    stack.pop()
                stack.append((indent, km.group(3).decode("utf-8", "replace").strip()))
            for rm in INLINE_REF_RE.finditer(line):
                field = ".".join(k for _, k in stack[1:])
                if field != "m_Script":
                    yield owner + "." + field, rm.group(2).decode()


def build_refs(root, project=None):
    project = project or export_dir(root)
    os.makedirs(os.path.join(root, "assets"), exist_ok=True)
    guids = guid_map(project)
    rows = 0
    with open(os.path.join(root, "assets", "refs.tsv"), "w", encoding="utf-8") as out:
        out.write("src\tfield\tdst\n")
        for d, _, files in os.walk(os.path.join(project, "Assets")):
            for f in files:
                if os.path.splitext(f)[1] not in YAML_EXT:
                    continue
                p = os.path.join(d, f)
                src = os.path.relpath(p, project)
                with open(p, "rb") as fh:
                    text = fh.read()
                seen = set()
                for field, g in field_paths(text, guids):
                    dst = guids.get(g)
                    if dst is None or (field, dst) in seen:
                        continue
                    seen.add((field, dst))
                    out.write(f"{src}\t{field}\t{dst}\n")
                    rows += 1
    with open(os.path.join(root, "assets", "guids.tsv"), "w", encoding="utf-8") as out:
        out.write("guid\tpath\n")
        for g, p in sorted(guids.items(), key=lambda x: x[1]):
            out.write(f"{g}\t{p}\n")
    return len(guids), rows


def print_refs(root, spec, n):
    rx = re.compile(spec, re.I)
    uses, used_by = [], []
    with open(os.path.join(root, "assets", "refs.tsv"), encoding="utf-8") as fh:
        for r in csv.DictReader(fh, delimiter="\t"):
            if rx.search(r["src"]):
                uses.append(r)
            if rx.search(r["dst"]):
                used_by.append(r)
    if not uses and not used_by:
        sys.exit(f"no asset matches {spec!r}")
    print(f"== uses ({len(uses)})")
    for r in uses[:n]:
        print(f"{r['src']}  [{r['field']}] -> {r['dst']}")
    print(f"== used by ({len(used_by)})")
    for r in used_by[:n]:
        print(f"{r['src']}  [{r['field']}] -> {r['dst']}")
