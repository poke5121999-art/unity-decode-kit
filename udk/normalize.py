"""Rewrite objects of a modified Unity engine into the stock layout of their version.

Some studios ship a patched engine whose built-in classes carry extra fields. Seen (Zing Speed,
2019.4.41f1): MeshRenderer gains m_RendererGroupIndex, m_ScriptableRendererFeatureLayer and
m_StaticShadowCaster, and m_RenderingLayerMask widens to UInt64; ParticleSystem,
ParticleSystemRenderer, SkinnedMeshRenderer, AnimationClip and Mesh differ too. AssetRipper
reads by version layout, so every such object fails ("Read 128 but expected 156") and is
dropped from the export: the track scenes lose all their renderers.

The bundles embed their type trees, so each object can be read with its own tree and written
back with the stock tree of its version (UnityPy's TPK): fields matched by name, extra fields
dropped, missing fields given defaults, integers masked to the stock width. MonoBehaviour is left
alone (its tree is the script's). Bundles that need no change are hard-linked into the mirror.
"""
import os
import sys
from concurrent.futures import ProcessPoolExecutor

INT_BITS = {"SInt8": 8, "UInt8": 8, "char": 8, "SInt16": 16, "UInt16": 16, "short": 16, "unsigned short": 16,
            "int": 32, "SInt32": 32, "UInt32": 32, "unsigned int": 32, "Type*": 32, "long long": 64,
            "SInt64": 64, "UInt64": 64, "unsigned long long": 64, "FileSize": 64}
SIGNED = {"SInt8", "SInt16", "short", "int", "SInt32", "long long", "SInt64"}
FLOATS = {"float", "double"}
SKIP_CLASSES = {114}  # MonoBehaviour: its tree is the script's fields, not an engine layout


def is_array(node):
    return bool(node.m_Children) and node.m_Children[0].m_Type == "Array"


def default(node):
    t = node.m_Type
    if t in INT_BITS:
        return 0
    if t in FLOATS:
        return 0.0
    if t == "bool":
        return False
    if t == "string":
        return ""
    if t == "TypelessData":
        return b""
    if t == "pair":
        return (default(node.m_Children[0]), default(node.m_Children[1]))
    if is_array(node):
        return []
    return {c.m_Name: default(c) for c in node.m_Children}


def conform(value, node):
    t = node.m_Type
    if t in INT_BITS:
        bits = INT_BITS[t]
        v = int(value) & ((1 << bits) - 1)
        return v - (1 << bits) if t in SIGNED and v >= 1 << (bits - 1) else v
    if t in FLOATS:
        return float(value)
    if t == "bool":
        return bool(value)
    if t in ("string", "TypelessData"):
        return value
    if t == "pair":
        return (conform(value[0], node.m_Children[0]), conform(value[1], node.m_Children[1]))
    if is_array(node):
        sub = node.m_Children[0].m_Children[1]
        if isinstance(value, (bytes, bytearray)):
            return value
        return [conform(x, sub) for x in value]
    if not isinstance(value, dict):
        return default(node)
    return {c.m_Name: conform(value[c.m_Name], c) if c.m_Name in value else default(c) for c in node.m_Children}


def same(a, b):
    if a.m_Name != b.m_Name or a.m_Type != b.m_Type or len(a.m_Children) != len(b.m_Children):
        return False
    return all(same(x, y) for x, y in zip(a.m_Children, b.m_Children))


def stock_node(class_id, version, cache={}):
    from UnityPy.helpers import Tpk
    from UnityPy.helpers.UnityVersion import UnityVersion
    key = (class_id, version)
    if key not in cache:
        try:
            node = Tpk.get_typetree_node(class_id, UnityVersion.from_str(version))
        except Exception:  # noqa: BLE001 - class unknown to the TPK: leave its objects as they are
            node = None
        if node is not None:  # TPK nodes leave the blob-only fields unset; the file writer needs them
            for i, n in enumerate(node.traverse()):
                n.m_Index = i
                n.m_TypeFlags = n.m_TypeFlags if n.m_TypeFlags is not None else int(n.m_Type == "Array")
                n.m_VariableCount = n.m_VariableCount or 0
                n.m_RefTypeHash = n.m_RefTypeHash or 0
                n.m_MetaFlag = n.m_MetaFlag or 0
        cache[key] = node
    return cache[key]


def normalize_file(src, dst):
    """Rewrite one bundle or serialized file; returns {class name: objects rewritten} (empty when
    nothing differed, in which case dst is a hard link to src)."""
    import UnityPy
    env = UnityPy.load(src)
    changed, plan = {}, {}  # plan: id(serialized type) -> (type, original node, stock node) or None
    for o in env.objects:
        if o.class_id in SKIP_CLASSES:
            continue
        st = o.serialized_type
        if st is None or st.node is None:
            continue
        if id(st) not in plan:
            stock = stock_node(o.class_id, o.assets_file.unity_version)
            plan[id(st)] = None if stock is None or same(st.node, stock) else (st, st.node, stock)
        entry = plan[id(st)]
        if entry is None:
            continue
        _, orig, stock = entry
        try:
            tree = o.read_typetree(nodes=orig)
            o.save_typetree(conform(tree, stock), nodes=stock)
        except Exception as e:  # noqa: BLE001 - keep the original object; AssetRipper will report it
            changed.setdefault("errors", []).append(f"{o.type.name} {o.path_id}: {type(e).__name__}: {e}"[:200])
            continue
        changed[o.type.name] = changed.get(o.type.name, 0) + 1
    for entry in plan.values():
        if entry:
            entry[0].node = entry[2]
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    if os.path.lexists(dst):
        os.remove(dst)
    if not any(k != "errors" for k in changed):
        os.link(src, dst)
        return changed
    f = env.file
    data = f.save(packer="lz4") if type(f).__name__ == "BundleFile" else f.save()
    with open(dst, "wb") as fh:
        fh.write(data)
    return changed


def _job(args):
    src, dst = args
    try:
        return src, normalize_file(src, dst)
    except Exception as e:  # noqa: BLE001 - not a Unity file, or unreadable: mirror it unchanged
        if os.path.lexists(dst):
            os.remove(dst)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        os.link(src, dst)
        return src, {"skipped": f"{type(e).__name__}: {e}"[:200]}


def run(src_root, dst_root, workers=6):
    """Mirror src_root into dst_root with normalized Unity files. Returns (files, rewritten, totals)."""
    jobs = []
    for d, _, fs in os.walk(src_root):
        for f in fs:
            p = os.path.join(d, f)
            jobs.append((p, os.path.join(dst_root, os.path.relpath(p, src_root))))
    totals, rewritten, errors = {}, 0, []
    log = dst_root + ".log"  # written last: its presence means the mirror is complete
    with ProcessPoolExecutor(workers) as ex, open(log + ".part", "w", encoding="utf-8") as lf:
        for src, changed in ex.map(_job, jobs, chunksize=8):
            counts = {k: v for k, v in changed.items() if isinstance(v, int)}
            if counts:
                rewritten += 1
                for k, v in counts.items():
                    totals[k] = totals.get(k, 0) + v
                lf.write(f"{os.path.relpath(src, src_root)}\t{counts}\n")
            for e in changed.get("errors", []):
                errors.append(e)
                lf.write(f"{os.path.relpath(src, src_root)}\terror\t{e}\n")
    os.replace(log + ".part", log)
    return len(jobs), rewritten, totals, errors


if __name__ == "__main__":
    n, r, totals, errors = run(sys.argv[1], sys.argv[2], int(sys.argv[3]) if len(sys.argv) > 3 else 6)
    print(f"[normalize] {n} files, {r} rewritten; objects per class {totals}; {len(errors)} errors")
