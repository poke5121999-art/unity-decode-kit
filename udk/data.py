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


def peel(b, depth=0):
    """Return (decoded bytes, layers, kind). Layers is a list like ['xor 0xCC', 'gzip']."""
    for magic, kind in MAGIC:
        if b.startswith(magic):
            return b, [], kind
    for magic, name, fn in UNWRAP:
        if b.startswith(magic):
            try:
                out, layers, kind = peel(fn(b), depth + 1)
                return out, [name] + layers, kind
            except Exception:
                pass
    if text_score(b) > 0.98:
        return b, [], text_kind(b)
    if depth < 2:
        k, sc = best_xor(b)
        if k is not None and sc > 0.98:
            out, layers, kind = peel(b.translate(XOR_TABLES[k]), depth + 1)
            return out, [f"xor 0x{k:02X}"] + layers, kind
        for magic, name, fn in UNWRAP:
            for k in range(1, 256):
                if b[: len(magic)].translate(XOR_TABLES[k]) == magic:
                    try:
                        out, layers, kind = peel(fn(b.translate(XOR_TABLES[k])), depth + 1)
                        return out, [f"xor 0x{k:02X}", name] + layers, kind
                    except Exception:
                        pass
    e = entropy(b)
    if e > 7.9 and len(b) % 16 == 0:
        return b, [], "encrypted-block-cipher?"
    if e > 7.5:
        return b, [], "compressed-or-encrypted?"
    return b, [], "binary"


SKIP_DIRS = {"aa", "StandaloneWindows64", "Android", "iOS"}


def walk(roots):
    for root in roots:
        for d, dirs, files in os.walk(root):
            dirs[:] = [x for x in dirs if x not in SKIP_DIRS]
            for f in files:
                yield root, os.path.join(d, f)


def run(roots, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    rows = []
    for root, path in walk(roots):
        raw = open(path, "rb").read()
        dec, layers, kind = peel(raw)
        rel = os.path.relpath(path, root)
        dest = ""
        if kind not in ("unity-bundle",):
            stem = os.path.splitext(rel)[0] if layers or kind in ("csv", "lua", "json", "xml", "tsv") else rel
            ext = "." + kind if kind in ("csv", "lua", "json", "xml", "tsv", "txt", "png", "jpg", "ogg") else ""
            dest = os.path.join(os.path.basename(os.path.normpath(root)), stem + (ext if not stem.endswith(ext) else ""))
            full = os.path.join(out_dir, dest)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "wb") as fh:
                fh.write(dec)
        rows.append((rel, " > ".join(layers) or "-", kind, len(raw), dest))
    with open(os.path.join(out_dir, "report.tsv"), "w", encoding="utf-8") as fh:
        fh.write("path\tlayers\tkind\tbytes\tdecoded\n")
        for r in rows:
            fh.write("\t".join(map(str, r)) + "\n")
    return rows
