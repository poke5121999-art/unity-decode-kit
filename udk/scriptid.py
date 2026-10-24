"""Name the class behind an m_Script reference into a DLL, and find references whose class the DLL lacks.

A MonoBehaviour in a scene or prefab points at a class inside a plugin DLL as {fileID: N, guid: <dll guid>}. N is the
first four bytes (little-endian int32) of MD4("s\\0\\0\\0" + namespace + "." + class name). When the player logs
"The referenced script on this Behaviour is missing", this shows which class it wanted and whether the skeleton has it.

Usage: python -m udk.scriptid <skeleton src dir> <dll .meta> <Assets dir>
"""
import os
import re
import struct
import sys
from collections import Counter


def md4(data):
    def f(x, y, z): return (x & y) | (~x & z)
    def g(x, y, z): return (x & y) | (x & z) | (y & z)
    def h(x, y, z): return x ^ y ^ z
    def rol(x, n): return ((x << n) | (x >> (32 - n))) & 0xffffffff
    msg = data + b"\x80" + b"\0" * ((55 - len(data)) % 64) + struct.pack("<Q", len(data) * 8)
    a, b, c, d = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
    for i in range(0, len(msg), 64):
        x = struct.unpack("<16I", msg[i:i + 64])
        aa, bb, cc, dd = a, b, c, d
        for k in range(16):
            s = (3, 7, 11, 19)[k % 4]
            a, b, c, d = d, rol((a + f(b, c, d) + x[k]) & 0xffffffff, s), b, c
        for k in range(16):
            s = (3, 5, 9, 13)[k % 4]
            j = (k % 4) * 4 + k // 4
            a, b, c, d = d, rol((a + g(b, c, d) + x[j] + 0x5a827999) & 0xffffffff, s), b, c
        for k, j in enumerate((0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15)):
            s = (3, 9, 11, 15)[k % 4]
            a, b, c, d = d, rol((a + h(b, c, d) + x[j] + 0x6ed9eba1) & 0xffffffff, s), b, c
        a, b, c, d = (a + aa) & 0xffffffff, (b + bb) & 0xffffffff, (c + cc) & 0xffffffff, (d + dd) & 0xffffffff
    return struct.pack("<4I", a, b, c, d)


def file_id(namespace, name):
    return struct.unpack("<i", md4(b"s\0\0\0" + (namespace + name).encode("utf-8"))[:4])[0]


def classes(src):
    """Top-level classes of a skeleton (file-scoped namespace per file, as ILSpy writes it)."""
    out = {}
    for dirpath, _, files in os.walk(src):
        for fn in files:
            if fn.endswith(".cs"):
                text = open(os.path.join(dirpath, fn), encoding="utf-8", errors="replace").read()
                m = re.search(r"^namespace ([\w.]+);", text, re.M)
                ns = m.group(1) if m else ""
                for c in re.finditer(r"^(?:public |internal )?(?:sealed |abstract |static |partial )*class (\w+)", text, re.M):
                    out[file_id(ns, c.group(1))] = (ns + "." if ns else "") + c.group(1)
    return out


def main(src, meta, assets):
    guid = re.search(r"^guid: (\w+)", open(meta, encoding="utf-8").read(), re.M).group(1)
    known = classes(src)
    refs = Counter()
    pat = re.compile(r"m_Script: \{fileID: (-?\d+), guid: " + guid)
    for dirpath, _, files in os.walk(assets):
        for fn in files:
            if fn.endswith((".unity", ".prefab", ".asset")):
                for m in pat.finditer(open(os.path.join(dirpath, fn), encoding="utf-8", errors="replace").read()):
                    refs[int(m.group(1))] += 1
    missing = {fid: n for fid, n in refs.items() if fid not in known}
    for fid, n in sorted(refs.items(), key=lambda kv: -kv[1]):
        print(f"{fid:>12} x{n:<5} {known.get(fid, '(no class in skeleton)')}")
    print(f"scriptid: {len(refs)} classes referenced, {len(missing)} not in the skeleton")


if __name__ == "__main__":
    main(*sys.argv[1:4])
