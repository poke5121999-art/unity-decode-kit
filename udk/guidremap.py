"""Re-point MonoBehaviour references from a removed stub DLL to the real package's script files.

AssetRipper's DllExport project binds every component to {fileID: FileIDForType(ns, class), guid: <stub dll guid>}.
Replacing a stub plugin (UnityEngine.UI, Unity.TextMeshPro, URP...) with its real package breaks those bindings:
the package defines the same classes in .cs files, referenced as {fileID: 11500000, guid: <.cs meta guid>}.
This rewrites the references in every scene, prefab and asset, keyed by namespace + class name.

Usage: python -m udk.guidremap <project Assets dir> <removed-stubs dir> <package root> [<package root>...]
"""
import os
import re
import struct
import sys
from collections import defaultdict
from pathlib import Path


def _md4(data):
    def f(x, y, z): return (x & y) | (~x & z)
    def g(x, y, z): return (x & y) | (x & z) | (y & z)
    def h(x, y, z): return x ^ y ^ z
    def rol(v, s): return ((v << s) | (v >> (32 - s))) & 0xFFFFFFFF
    msg = bytearray(data)
    ml = len(msg) * 8
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack("<Q", ml)
    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    for i in range(0, len(msg), 64):
        x = struct.unpack("<16I", msg[i:i + 64])
        aa, bb, cc, dd = a, b, c, d
        for k in range(16):
            s = (3, 7, 11, 19)[k % 4]
            a, b, c, d = d, rol((a + f(b, c, d) + x[k]) & 0xFFFFFFFF, s), b, c
        for k in range(16):
            s = (3, 5, 9, 13)[k % 4]
            idx = (k % 4) * 4 + k // 4
            a, b, c, d = d, rol((a + g(b, c, d) + x[idx] + 0x5A827999) & 0xFFFFFFFF, s), b, c
        for k in range(16):
            s = (3, 9, 11, 15)[k % 4]
            idx = (0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15)[k]
            a, b, c, d = d, rol((a + h(b, c, d) + x[idx] + 0x6ED9EBA1) & 0xFFFFFFFF, s), b, c
        a, b, c, d = (a + aa) & 0xFFFFFFFF, (b + bb) & 0xFFFFFFFF, (c + cc) & 0xFFFFFFFF, (d + dd) & 0xFFFFFFFF
    return struct.pack("<4I", a, b, c, d)


def file_id(namespace, name):
    """Unity's FileIDForType for a MonoScript inside a DLL: first 4 bytes of MD4("s\\0\\0\\0" + ns + name)."""
    return struct.unpack("<i", _md4(b"s\0\0\0" + (namespace + name).encode("utf-8"))[:4])[0]


def meta_guid(path):
    m = re.search(r"^guid: ([0-9a-f]{32})", Path(str(path) + ".meta").read_text(encoding="utf-8", errors="replace"), re.M)
    return m.group(1) if m else None


def package_scripts(roots):
    """(namespace, class) -> guid of the .cs file declaring it, for every non-Editor script under the roots."""
    out = {}
    for root in roots:
        for dirpath, dirs, files in os.walk(root):
            if "Editor" in Path(dirpath).parts or "Tests" in Path(dirpath).parts:
                continue
            for f in files:
                if not f.endswith(".cs") or not os.path.exists(os.path.join(dirpath, f) + ".meta"):
                    continue
                p = os.path.join(dirpath, f)
                text = open(p, encoding="utf-8", errors="replace").read()
                ns = re.search(r"^\s*namespace\s+([\w.]+)", text, re.M)
                stem = f[:-3]
                if re.search(r"\b(class|struct)\s+" + re.escape(stem) + r"\b", text):
                    out[(ns.group(1) if ns else "", stem)] = meta_guid(p)
    return out


def main(assets, removed, roots):
    stubs = {}
    for f in os.listdir(removed):
        if f.endswith(".dll") and os.path.exists(os.path.join(removed, f) + ".meta"):
            stubs[meta_guid(os.path.join(removed, f))] = f
    scripts = package_scripts(roots)
    by_id = {(file_id(ns, name)): guid for (ns, name), guid in scripts.items()}
    pat = re.compile(r"\{fileID: (-?\d+), guid: ([0-9a-f]{32}), type: 3\}")
    hits, misses, files = 0, defaultdict(int), 0
    for dirpath, _, fs in os.walk(assets):
        for f in fs:
            if not f.endswith((".unity", ".prefab", ".asset")):
                continue
            p = os.path.join(dirpath, f)
            text = open(p, encoding="utf-8", errors="replace").read()
            if not any(g in text for g in stubs):
                continue

            def sub(m):
                nonlocal hits
                fid, guid = int(m.group(1)), m.group(2)
                if guid not in stubs:
                    return m.group(0)
                target = by_id.get(fid)
                if target is None:
                    misses[(stubs[guid], fid)] += 1
                    return m.group(0)
                hits += 1
                return "{fileID: 11500000, guid: " + target + ", type: 3}"
            new = pat.sub(sub, text)
            if new != text:
                open(p, "w", encoding="utf-8", newline="").write(new)
                files += 1
    print(f"guidremap: {hits} references re-pointed in {files} files; {sum(misses.values())} unresolved "
          f"({len(misses)} distinct): {sorted(misses.items(), key=lambda kv: -kv[1])[:8]}")


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "--selftest":
        print(file_id("UnityEngine.UI", "Image"))
    else:
        main(sys.argv[1], sys.argv[2], sys.argv[3:])
