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


SHADER_RE = re.compile(r'^\s*Shader\s+"([^"]+)"', re.M)


def shader_of(project, mat, guids, cache={}):
    """Shader name a material uses: the ShaderLab name in the exported .shader, or the built-in id."""
    if mat not in cache:
        cache[mat] = None
        p = os.path.join(project, mat)
        if os.path.exists(p):
            with open(p, encoding="utf-8", errors="replace") as fh:
                m = re.search(r"m_Shader: \{fileID: (-?\d+)(?:, guid: ([0-9a-f]{32}))?", fh.read())
            if m and m.group(2) in guids:
                sp = os.path.join(project, guids[m.group(2)])
                head = open(sp, encoding="utf-8", errors="replace").read(4096) if os.path.exists(sp) else ""
                n = SHADER_RE.search(head)
                cache[mat] = n.group(1) if n else os.path.splitext(os.path.basename(guids[m.group(2)]))[0]
            elif m:
                cache[mat] = f"built-in shader fileID {m.group(1)}"
    return cache[mat]


def describe(path, guids, verbose=False, project=None):
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
            p = guids.get(m.group(2), f"guid {m.group(2)}")
            sh = shader_of(project, p, guids) if project and p.endswith(".mat") else None
            return f"{p} [shader {sh}]" if sh else p
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
        print("\n".join(describe(os.path.join(project, rel), guids, verbose, project)))
    if len(hits) > n:
        print(f"... {len(hits) - n} more matches: " + ", ".join(os.path.basename(h) for h in hits[n:n + 8]))


def find_objects(root, name_rx, n=50):
    """GameObjects whose name matches name_rx in every prefab and scene: asset and hierarchy path."""
    import subprocess
    project = os.path.join(root, "assets", "ExportedProject")
    rg = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "third_party", "rg")
    r = subprocess.run([rg, "-l", "-g", "*.prefab", "-g", "*.unity", "-P", rf"^  m_Name: (?:{name_rx})\s*$", project],
                       capture_output=True, text=True)
    rx = re.compile(rf"^(?:{name_rx})$")
    shown = 0
    for path in sorted(r.stdout.split("\n")):
        if not path:
            continue
        with open(path, encoding="utf-8", errors="replace") as fh:
            objs = parse(fh.read())
        tr = {}
        for fid, o in objs.items():
            if o["type"] in ("Transform", "RectTransform"):
                g = LOCAL_RE.search(o["fields"].get("m_GameObject", ""))
                f = LOCAL_RE.search(o["fields"].get("m_Father", ""))
                if g:
                    tr[g.group(1)] = (fid, f.group(1) if f else "0")
        go_of_tr = {t: g for g, (t, _) in tr.items()}

        def path_of(go):
            parts = []
            while go:
                parts.append(objs.get(go, {}).get("fields", {}).get("m_Name", "?"))
                father = tr.get(go, (None, "0"))[1]
                go = go_of_tr.get(father) if father != "0" else None
            return "/".join(reversed(parts))
        for fid, o in objs.items():
            if o["type"] == "GameObject" and rx.match(o["fields"].get("m_Name", "")):
                print(f"{os.path.relpath(path, project)}\t{path_of(fid)}")
                shown += 1
                if shown >= n:
                    print(f"... more; raise -n")
                    return
