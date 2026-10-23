"""Find the game's own native plugins: libraries whose exports the managed code binds to.

IL2CPP keeps every [DllImport] method as an `extern` declaration in types.cs, without the library
name. A library is a plugin of the game when its exported symbols include those method names; the
ghidra step then decompiles it with full analysis (it has symbols, unlike libil2cpp's methods).
"""
import os
import re

EXTERN = re.compile(r"\bextern\b[^(;]*?\b(\w+)\s*\(")


def extern_names(types_cs):
    with open(types_cs, encoding="utf-8", errors="replace") as fh:
        return set(EXTERN.findall(fh.read()))


def exports(path):
    with open(path, "rb") as fh:
        b = fh.read()
    if b[:4] == b"\x7fELF":
        from udk import elf
        return elf.exported_names(b)
    if b[:2] == b"MZ":
        import pefile
        pe = pefile.PE(data=b, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
        sym = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
        return {s.name.decode("latin-1") for s in sym.symbols if s.name} if sym else set()
    return set()


def plugins(lib_dirs, types_cs, skip=(), min_hits=3):
    """[(path, matched extern names)] for libraries in lib_dirs bound by at least min_hits externs."""
    want = extern_names(types_cs)
    out = []
    for d in lib_dirs:
        if not os.path.isdir(d):
            continue
        for f in sorted(os.listdir(d)):
            p = os.path.join(d, f)
            if not f.endswith((".so", ".dll")) or not os.path.isfile(p) or os.path.realpath(p) in skip:
                continue
            hits = sorted(want & exports(p))
            if len(hits) >= min_hits:
                out.append((p, hits))
    return out
