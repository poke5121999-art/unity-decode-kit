"""Find and peel simple wrappers (single-byte XOR, gzip, zlib, LZ4) off loose data files.

Each file becomes one row of out/<game>/data/report.tsv: path, layers peeled, detected
kind, and where the decoded copy went. Keys are found by trying every byte, never hardcoded.
"""
import gzip
import math
import os
import zlib
from collections import Counter

import lz4.frame

MAGIC = [
    (b"UnityFS", "unity-bundle"),
    (b"UnityWeb", "unity-bundle"),
    (b"\x89PNG", "png"),
    (b"\xff\xd8\xff", "jpg"),
    (b"OggS", "ogg"),
    (b"RIFF", "riff"),
    (b"PK\x03\x04", "zip"),
    (b"\x1bLua", "lua-bytecode"),
    (b"\x1bLJ", "luajit-bytecode"),
    (b"FSB5", "fmod-bank"),
]
UNWRAP = [
    (b"\x1f\x8b", "gzip", gzip.decompress),
    (b"\x04\x22\x4d\x18", "lz4", lz4.frame.decompress),
    (b"\x78\x9c", "zlib", zlib.decompress),
    (b"\x78\xda", "zlib", zlib.decompress),
    (b"\x78\x01", "zlib", zlib.decompress),
]
XOR_TABLES = [bytes(b ^ k for b in range(256)) for k in range(256)]
SAMPLE = 64 * 1024


def text_score(b):
    """Share of the sample that decodes as UTF-8 text without control bytes."""
    if not b:
        return 0.0
    try:
        s = b[:SAMPLE].decode("utf-8")
    except UnicodeDecodeError as e:
        if e.start < len(b[:SAMPLE]) - 4:
            return 0.0
        s = b[: e.start].decode("utf-8")
    if not s:
        return 0.0
    bad = sum(1 for c in s if ord(c) < 32 and c not in "\r\n\t")
    return 1.0 - bad / len(s)


def entropy(b):
    b = b[:SAMPLE]
    n = len(b)
    return -sum(c / n * math.log2(c / n) for c in Counter(b).values()) if n else 0.0


def text_kind(b):
    head = b[:4096].decode("utf-8", "replace").lstrip("﻿ \r\n\t")
    if head[:1] in "{[":
        return "json"
    if head.startswith("<"):
        return "xml"
    if any(w in head for w in ("function ", "local ", "end\n", "then\n", "return ")):
        return "lua"
    lines = [l for l in head.splitlines()[:5] if l]
    if lines and lines[0].count(",") >= 1:
        return "csv"
    if len(lines) > 1 and lines[0].count("\t"):
        return "tsv"
    return "txt"


COMMON = frozenset(b" \n\r\t,.;:_-=()\"'0123456789etaoinsrhldcumETAOINSRHLDCUM")


def best_xor(b):
    """Try every single-byte key on a sample; among keys giving clean text, pick the one
    whose output has the most everyday text bytes (several keys can all print cleanly)."""
    sample = b[:4096]
    best = (None, 0.0, -1)
    for k in range(1, 256):
        t = sample.translate(XOR_TABLES[k])
        sc = text_score(t)
        if sc > 0.98:
            common = sum(1 for c in t if c in COMMON)
            if common > best[2]:
                best = (k, sc, common)
    return best[:2]


class KeyRing:
    """Candidate repeating XOR keys, taken from the game's own string literals.
    A key that decoded one file is tried first on the next; when none of those reads well, every
    literal is tried and the one whose output reads best wins (a wrong key can still print)."""

    def __init__(self, literals=()):
        seen = set()
        self.keys = []
        for t in literals:
            if 4 <= len(t) <= 64 and t.isascii() and t.isprintable() and t not in seen:
                seen.add(t)
                self.keys.append(t)
        self.hits = []

    def find(self, b):
        """(key, share of everyday text bytes in its output), or (None, 0)."""
        try:
            text = b[:4096].decode("utf-8")
        except UnicodeDecodeError:
            text = None
        best = (None, 0.6)
        for i, key in enumerate(self.hits + self.keys):
            if i == len(self.hits) and best[1] > GOOD_TEXT:
                break  # a key that worked on a sibling file reads well here too
            out = xor_key(b[:4096], text, key, check_only=True)
            if out is not None and text_score(out) > 0.98 and common_share(out) > best[1]:
                best = (key, common_share(out))
        if best[0] is not None and best[0] not in self.hits:
            self.hits.insert(0, best[0])
        return best if best[0] is not None else (None, 0.0)


FORMAT = "2: best-reading xor key wins"  # bump when decoding changes, so old dumps redo the data step
GOOD_TEXT = 0.8  # share of everyday bytes in real CSV/JSON/Lua text; garbage that prints scores lower


def common_share(b):
    return sum(1 for c in b if c in COMMON) / max(1, len(b))


def xor_key(b, text, key, check_only=False):
    """XOR with a repeating key. Games often XOR the C# string per character and then
    write UTF-8, so when the input is valid UTF-8 the key runs over characters."""
    kb = key.encode()
    if text is not None:
        probe = text[:12] if check_only else text
        if check_only and not all(32 <= (ord(c) ^ kb[i % len(kb)]) < 127 or (ord(c) ^ kb[i % len(kb)]) in (9, 10, 13)
                                  for i, c in enumerate(probe)):
            return None
        src = text if check_only else b.decode("utf-8")
        return "".join(chr(ord(c) ^ kb[i % len(kb)]) for i, c in enumerate(src)).encode("utf-8")
    if check_only and not all(32 <= (c ^ kb[i % len(kb)]) < 127 or (c ^ kb[i % len(kb)]) in (9, 10, 13)
                              for i, c in enumerate(b[:12])):
        return None
    return bytes(c ^ kb[i % len(kb)] for i, c in enumerate(b))


def peel(b, ring=None, depth=0):
    """Return (decoded bytes, layers, kind). Layers is a list like ['xor 0xCC', 'gzip']."""
    for magic, kind in MAGIC:
        if b.startswith(magic):
            return b, [], kind
    for magic, name, fn in UNWRAP:
        if b.startswith(magic):
            try:
                out, layers, kind = peel(fn(b), ring, depth + 1)
                return out, [name] + layers, kind
            except Exception:
                pass
    if text_score(b) > 0.98:
        return b, [], text_kind(b)
    if depth < 2:
        k, sc = best_xor(b)
        single = common_share(b[:4096].translate(XOR_TABLES[k])) if k is not None and sc > 0.98 else 0.0
        key, share = ring.find(b) if ring and single < GOOD_TEXT else (None, 0.0)
        if single > 0 and (key is None or single >= share):
            out, layers, kind = peel(b.translate(XOR_TABLES[k]), ring, depth + 1)
            return out, [f"xor 0x{k:02X}"] + layers, kind
        for magic, name, fn in UNWRAP:
            for k in range(1, 256):
                if b[: len(magic)].translate(XOR_TABLES[k]) == magic:
                    try:
                        out, layers, kind = peel(fn(b.translate(XOR_TABLES[k])), ring, depth + 1)
                        return out, [f"xor 0x{k:02X}", name] + layers, kind
                    except Exception:
                        pass
        if key is not None and share > single:
            try:
                text = b.decode("utf-8")
            except UnicodeDecodeError:
                text = None
            out, layers, kind = peel(xor_key(b, text, key), ring, depth + 1)
            return out, [f"xor key {key!r}" + (" per char" if text is not None else "")] + layers, kind
    e = entropy(b)
    if e > 7.9 and len(b) % 16 == 0:
        return b, [], "encrypted-block-cipher?"
    if e > 7.5:
        return b, [], "compressed-or-encrypted?"
    return b, [], "binary"


SKIP_DIRS = {"aa", "StandaloneWindows64", "Android", "iOS", "bin", "AssetBundles"}
TEXT_EXT = ("csv", "lua", "json", "xml", "tsv", "txt", "png", "jpg", "ogg")


def files_under(roots):
    """Loose files on disk as (output name, bytes) pairs."""
    for root in roots:
        top = os.path.basename(os.path.normpath(root))
        for d, dirs, files in os.walk(root):
            dirs[:] = [x for x in dirs if x not in SKIP_DIRS]
            for f in files:
                p = os.path.join(d, f)
                yield os.path.join(top, os.path.relpath(p, root)), open(p, "rb").read()


def run(items, out_dir, literals=()):
    """items: (name, bytes) pairs. Writes decoded copies and report.tsv under out_dir."""
    os.makedirs(out_dir, exist_ok=True)
    ring = KeyRing(literals)
    rows = []
    for name, raw in items:
        dec, layers, kind = peel(raw, ring)
        dest = ""
        if kind != "unity-bundle":
            stem = os.path.splitext(name)[0] if layers or kind in TEXT_EXT[:5] + ("lua-bytecode",) else name
            ext = "." + kind if kind in TEXT_EXT else ".luac" if kind == "lua-bytecode" else ""
            dest = stem if stem.endswith(ext) else stem + ext
            full = os.path.join(out_dir, dest)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "wb") as fh:
                fh.write(dec)
        rows.append((name, " > ".join(layers) or "-", kind, len(raw), dest))
    bytecode = [os.path.join(out_dir, r[4]) for r in rows if r[2] == "lua-bytecode"]
    if bytecode:
        from udk import luadec
        ok, bad = luadec.decompile_files(bytecode)
        rows = [r if r[2] != "lua-bytecode" else r[:2] + ("lua-bytecode -> .lua" if os.path.exists(
            os.path.join(out_dir, r[4][:-5] + ".lua")) else "lua-bytecode (unluac failed)",) + r[3:] for r in rows]
    with open(os.path.join(out_dir, "report.tsv"), "w", encoding="utf-8") as fh:
        fh.write("path\tlayers\tkind\tbytes\tdecoded\n")
        for r in rows:
            fh.write("\t".join(map(str, r)) + "\n")
    return rows
