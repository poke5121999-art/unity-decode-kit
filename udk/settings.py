"""Project settings from the player build (PlayerSettings, QualitySettings, TagManager, ...).

AssetRipper does not export PlayerSettings (colour space, orientation, product name...), and a
rebuilt project needs the tags, layers, physics and quality settings as shipped. Each settings
object found in globalgamemanagers (loose, or inside data.unity3d) is written as
settings/<Type>.json from its type tree.
"""
import glob
import json
import os

SETTINGS = {"PlayerSettings", "QualitySettings", "GraphicsSettings", "TagManager", "TimeManager", "PhysicsManager",
            "Physics2DSettings", "InputManager", "AudioManager", "BuildSettings", "NavMeshProjectSettings",
            "MonoManager", "ResourceManager", "PreloadData", "RuntimeInitializeOnLoadManager", "StreamingManager",
            "VFXManager", "DelayedCallManager", "UnityConnectSettings", "ScriptMapper"}
SKIP_FIELDS = {"m_Container", "m_Assets"}  # ResourceManager / PreloadData lists: large and in refs already


def sources(data_dir):
    names = ["globalgamemanagers", "data.unity3d"]
    return [p for n in names for p in glob.glob(os.path.join(data_dir, n))]


def log(msg):
    print(f"[settings] {msg}", flush=True)


def read_prefix(o):
    """Top-level fields of `o` read one by one with its stock type tree until one fails or runs past
    the object. Fields after a layout change read shifted bytes, hence the note in the output."""
    from UnityPy.helpers.TypeTreeHelper import TypeTreeConfig, read_value
    node = o._get_typetree_node()
    r = o.reader
    r.Position = o.byte_start
    config = TypeTreeConfig(True, o.assets_file, False)
    tree = {}
    for child in node.m_Children:
        try:
            value = read_value(child, r, config)
        except Exception:  # noqa: BLE001 - the first unreadable field ends the trustworthy prefix
            break
        if r.Position - o.byte_start > o.byte_size:
            break
        tree[child.m_Name] = value
    if tree:
        tree["_udk_partial"] = (f"stock layout does not fit this {o.byte_size}-byte object; fields were read in order "
                                f"from the start, so early ones are right and later ones may be shifted "
                                f"({len(tree)} of {len(node.m_Children)} read)")
    return tree


def run(out, data_dir):
    import UnityPy
    d = os.path.join(out, "settings")
    os.makedirs(d, exist_ok=True)
    found = []
    for src in sources(data_dir):
        env = UnityPy.load(src)
        for o in env.objects:
            name = o.type.name
            if name not in SETTINGS or name in found:
                continue
            try:
                tree = o.read_typetree()
            except Exception:  # noqa: BLE001
                # The stock type tree does not fit: UnityPy's tree can be a field off for new editors
                # (6000.3 PlayerSettings), or the engine is patched (Zing Speed's PlayerSettings and
                # QualitySettings). Fields read in order from the start stay right up to the change.
                tree = read_prefix(o)
                if not tree:
                    log(f"settings: {name} unreadable with the stock type tree, skipped")
                    continue
            tree = {k: v for k, v in tree.items() if k not in SKIP_FIELDS}
            with open(os.path.join(d, name + ".json"), "w", encoding="utf-8") as fh:
                json.dump(tree, fh, indent=1, default=str, ensure_ascii=False)
            found.append(name)
    return found
