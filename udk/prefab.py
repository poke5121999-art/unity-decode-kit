"""Print one prefab or scene as a hierarchy: each GameObject, its components, and what each
component's object fields point at, local objects by hierarchy path and other assets by file.

This answers "which component wires X" inside a prefab, which refs.tsv (asset -> asset) cannot.
"""
import os
import re

from udk import assets

DOC_RE = re.compile(r"^--- !u!(\d+) &(-?\d+)", re.M)
FIELD_RE = re.compile(r"^  (\w+):(?: (.*))?$")
LOCAL_RE = re.compile(r"\{fileID: (-?\d+)\}")
ASSET_RE = re.compile(r"\{fileID: (-?\d+), guid: ([0-9a-f]{32}), type: \d\}")
LIST_ITEM_RE = re.compile(r"^  - (?:component: )?(\{.*\})$")


def parse(text):
    """fileID -> {"type": str, "fields": {name: raw value}, "items": {name: [raw list items]}}."""
    objs = {}
    heads = list(DOC_RE.finditer(text))
    for i, h in enumerate(heads):
        body = text[h.end():heads[i + 1].start() if i + 1 < len(heads) else len(text)].split("\n")
        typ = body[1].rstrip(":") if len(body) > 1 else "?"
        fields, items, last = {}, {}, None
        for line in body[2:]:
            m = FIELD_RE.match(line)
            if m:
                last = m.group(1)
                fields[last] = m.group(2) or ""
            elif last and (lm := LIST_ITEM_RE.match(line)):
                items.setdefault(last, []).append(lm.group(1))
            elif last and line.startswith("    ") and "fileID" in line:
                items.setdefault(last, []).append(line.strip())
        objs[h.group(2)] = {"type": typ, "fields": fields, "items": items}
    return objs


def describe(path, guids, verbose=False):
    with open(path, encoding="utf-8", errors="replace") as fh:
        objs = parse(fh.read())
    script_names = {}
    for fid, o in objs.items():
        m = ASSET_RE.search(o["fields"].get("m_Script", ""))
        if m and m.group(2) in guids:
            script_names[fid] = os.path.splitext(os.path.basename(guids[m.group(2)]))[0]

    def kind(fid):
        return script_names.get(fid) or objs[fid]["type"]

    def go_of(fid):
        m = LOCAL_RE.search(objs.get(fid, {}).get("fields", {}).get("m_GameObject", ""))
        return m.group(1) if m else None

    def name(go):
        return objs.get(go, {}).get("fields", {}).get("m_Name", "?")

    transforms = {fid: o for fid, o in objs.items() if o["type"] in ("Transform", "RectTransform")}
    parent = {}
    for fid, o in transforms.items():
        m = LOCAL_RE.search(o["fields"].get("m_Father", ""))
        parent[fid] = m.group(1) if m and m.group(1) != "0" else None
    tr_of_go = {go_of(fid): fid for fid in transforms}

    def path_of(go):
        parts, t = [], tr_of_go.get(go)
        while t:
            parts.append(name(go_of(t)))
            t = parent.get(t)
        return "/".join(reversed(parts)) or name(go)

    def target(raw):
        m = ASSET_RE.search(raw)
        if m:
            return guids.get(m.group(2), f"guid {m.group(2)}")
        m = LOCAL_RE.search(raw)
        if not m or m.group(1) == "0":
            return None
        fid = m.group(1)
        if fid not in objs:
            return f"fileID {fid}"
        if objs[fid]["type"] == "GameObject":
            return path_of(fid)
        return f"{path_of(go_of(fid))} ({kind(fid)})"

    lines = []

    def walk(t, depth):
        go = go_of(t)
        o = objs.get(go, {"fields": {}, "items": {}})
        active = "" if o["fields"].get("m_IsActive", "1") == "1" else "  [inactive]"
        lines.append("  " * depth + name(go) + active)
        for raw in o["items"].get("m_Component", []):
            m = LOCAL_RE.search(raw)
            if not m or m.group(1) not in objs or m.group(1) in transforms:
                continue
            c = m.group(1)
            refs = []
            for k, v in objs[c]["fields"].items():
                if k in ("m_GameObject", "m_Script", "m_ObjectHideFlags", "m_CorrespondingSourceObject",
                         "m_PrefabInstance", "m_PrefabAsset"):
                    continue
                tg = target(v)
                if tg:
                    refs.append(f"{k} -> {tg}")
                elif verbose and v and "{" not in v and len(v) < 60:
                    refs.append(f"{k} = {v}")
            for k, vals in objs[c]["items"].items():
                if k == "m_Component":
                    continue
                tgs = [x for x in map(target, vals) if x]
                if tgs:
                    refs.append(f"{k}[] -> " + "; ".join(tgs[:6]) + (f"; +{len(tgs) - 6}" if len(tgs) > 6 else ""))
            lines.append("  " * depth + f"  [{kind(c)}]" + (" " + ", ".join(refs) if refs else ""))
        children = [c for c, p in parent.items() if p == t]
        order = [LOCAL_RE.search(x).group(1) for x in transforms[t]["items"].get("m_Children", []) if LOCAL_RE.search(x)]
        for c in order + [c for c in children if c not in order]:
            if c in transforms:
                walk(c, depth + 1)

    for t in transforms:
        if parent.get(t) is None:
            walk(t, 0)
    return lines


def print_prefab(root, spec, n=1, verbose=False):
    project = assets.export_dir(root)
    cached = os.path.join(root, "assets", "guids.tsv")
    if os.path.exists(cached):
        with open(cached, encoding="utf-8") as fh:
            guids = dict(line.rstrip("\n").split("\t", 1) for line in fh if "\t" in line)
    else:
        guids = assets.guid_map(project)
    rx = re.compile(spec, re.I)
    hits = sorted(p for p in guids.values() if p.endswith((".prefab", ".unity")) and rx.search(p))
    if not hits:
        raise SystemExit(f"no prefab or scene matches {spec!r}")
    for rel in hits[:n]:
        print(f"### {rel}")
        print("\n".join(describe(os.path.join(project, rel), guids, verbose)))
    if len(hits) > n:
        print(f"... {len(hits) - n} more matches: " + ", ".join(os.path.basename(h) for h in hits[n:n + 8]))
