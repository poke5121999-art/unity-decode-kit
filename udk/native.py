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


def add_export_thunks(lib_path, out_dir):
    """Ghidra treats a one-instruction export (ARM `b target`) as a thunk, which the decompile script
    skips; add each such export to functions.tsv at its target's body. Returns rows added."""
    import csv
    import struct
    from udk import elf
    with open(lib_path, "rb") as fh:
        b = fh.read()
    if b[:4] != b"\x7fELF" or b[4] != 1:
        return 0
    tsv = os.path.join(out_dir, "functions.tsv")
    with open(tsv, encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh, delimiter="\t"))
    names = {r["name"] for r in rows}
    symbols = elf.exported_symbols(b)
    # Ghidra loads a shared object at its own image base (0x10000): find the shift from the
    # exports both sides name the same.
    from collections import Counter
    shift = Counter(int(r["address"], 16) - (symbols[r["name"]] & ~1) for r in rows if r["name"] in symbols).most_common(1)
    if not shift:
        return 0
    shift = shift[0][0]
    by_addr = {int(r["address"], 16) - shift: r for r in rows}
    segs = elf.load_segments(bytearray(b))
    added = []
    for name, va in symbols.items():
        va &= ~1
        if name in names or va in by_addr:
            continue
        off = elf.va_to_off(segs, va)
        if off is None or off + 4 > len(b):
            continue
        w = struct.unpack_from("<I", b, off)[0]
        if (w >> 24) & 0xFE == 0xEA:  # B or BL, condition always
            imm = w & 0xFFFFFF
            imm = imm - 0x1000000 if imm & 0x800000 else imm
            dest = va + 8 + imm * 4
            target = by_addr.get(dest)
            if target is None:  # through the PLT, to the symbol its GOT slot binds
                sym = elf.plt_target_symbol(b, segs, dest)
                addr = symbols.get(sym) if sym else None
                target = by_addr.get(addr & ~1) if addr else None
            if target:
                added.append({"name": name, "address": f"0x{va + shift:X}", "file": target["file"], "line": target["line"]})
    if added:
        with open(tsv, "a", encoding="utf-8") as fh:
            for r in added:
                fh.write(f"{r['name']}\t{r['address']}\t{r['file']}\t{r['line']}\n")
    return len(added)
