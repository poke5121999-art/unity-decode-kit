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
            except ValueError:
                # UnityPy's bundled type tree can be a field off for new editors (6000.3 PlayerSettings
                # reads 4 bytes past the end); keep what parsed and say so.
                try:
                    tree = o.read_typetree(check_read=False)
                    tree["_udk_partial"] = "type tree did not match the object size; trailing fields may be off"
                except Exception:  # noqa: BLE001
                    continue
            except Exception:  # noqa: BLE001 - a settings object without a readable tree is skipped
                continue
            tree = {k: v for k, v in tree.items() if k not in SKIP_FIELDS}
            with open(os.path.join(d, name + ".json"), "w", encoding="utf-8") as fh:
                json.dump(tree, fh, indent=1, default=str, ensure_ascii=False)
            found.append(name)
    return found
