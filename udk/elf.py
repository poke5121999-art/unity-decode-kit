"""Make a protected Android libil2cpp.so readable by static tools.

Seen (Zing Speed, ARM32): a protector appends LOAD segments that map the same file offset to
several virtual addresses (its loader stub, entered through DT_INIT). Il2CppInspector and Cpp2IL
both fail on that layout. sanitize() writes a copy where every LOAD that shares its file offset
with another LOAD and holds no section is turned into PT_NULL; code and data are untouched.
"""
import struct

PT_NULL, PT_LOAD = 0, 1


def _layout(b):
    if b[:4] != b"\x7fELF":
        raise ValueError("not an ELF file")
    is64 = b[4] == 2
    end = "<" if b[5] == 1 else ">"
    if is64:
        phoff, shoff = struct.unpack_from(end + "QQ", b, 0x20)
        phentsize, phnum, shentsize, shnum = struct.unpack_from(end + "HHHH", b, 0x36)
        ph = end + "IIQQQQQQ"
        sh = end + "IIQQQQIIQQ"
    else:
        phoff, shoff = struct.unpack_from(end + "II", b, 0x1C)
        phentsize, phnum, shentsize, shnum = struct.unpack_from(end + "HHHH", b, 0x2A)
        ph = end + "IIIIIIII"
        sh = end + "IIIIIIIIII"
    return is64, end, phoff, phentsize, phnum, ph, shoff, shentsize, shnum, sh


def sanitize(src, dst):
    b = bytearray(open(src, "rb").read())
    is64, end, phoff, phentsize, phnum, ph, shoff, shentsize, shnum, sh = _layout(b)
    segs = []
    for i in range(phnum):
        f = struct.unpack_from(ph, b, phoff + i * phentsize)
        if is64:
            p_type, _, p_offset, p_vaddr, _, p_filesz = f[0], f[1], f[2], f[3], f[4], f[5]
        else:
            p_type, p_offset, p_vaddr, _, p_filesz = f[0], f[1], f[2], f[3], f[4]
        segs.append((i, p_type, p_offset, p_vaddr, p_filesz))
    sections = []
    for i in range(shnum):
        f = struct.unpack_from(sh, b, shoff + i * shentsize)
        addr, size = (f[3], f[5]) if is64 else (f[3], f[5])
        if addr:
            sections.append((addr, size))
    loads = [s for s in segs if s[1] == PT_LOAD]
    dropped = []
    for i, _, off, vaddr, size in loads:
        twins = [s for s in loads if s[2] == off and s[0] != i]
        holds_section = any(vaddr <= a < vaddr + max(size, 1) for a, _ in sections)
        if twins and not holds_section:
            struct.pack_into(end + "I", b, phoff + i * phentsize, PT_NULL)
            dropped.append(hex(vaddr))
    with open(dst, "wb") as fh:
        fh.write(b)
    return dropped


GRAIN = 256
SHF_ALLOC, SHT_NOBITS = 0x2, 8


def sections(b):
    is64, end, _, _, _, _, shoff, shentsize, shnum, sh = _layout(b)
    out = []
    for i in range(shnum):
        f = struct.unpack_from(sh, b, shoff + i * shentsize)
        sh_type, flags, offset, size = f[1], f[2], f[4], f[5]
        if flags & SHF_ALLOC and sh_type != SHT_NOBITS and size >= 1 << 16:
            out.append((offset, size))
    return out


def unxor_sections(b, min_gain=0.002):
    """Undo periodic single-byte XOR windows inside each allocated section, in place.

    Seen (Zing Speed): 16 KB of every 64 KB of .rodata, .text and the il2cpp code section XOR'd with
    0x42, each section at its own phase. Per section: build, for each GRAIN-sized slot of a 64 KB
    period, a histogram of byte values; the key is the byte whose swap with 0x00 gains the most
    zero bytes; a slot is XOR'd when the key outnumbers 0x00 there. Sections without a clear gain
    are left alone. Returns (offset, size, key, window slots, cells XOR'd, cells left) per section."""
    import numpy as np
    period = 1 << 16
    slots = period // GRAIN
    arr = np.frombuffer(bytes(b), dtype=np.uint8)
    done = []
    for off, size in sections(b):
        lo, hi = (off // GRAIN) * GRAIN, ((off + size) // GRAIN) * GRAIN
        cells = arr[lo:hi].reshape(-1, GRAIN)
        pos = ((np.arange(len(cells)) * GRAIN + lo) % period) // GRAIN
        hist = np.zeros((slots, 256), dtype=np.int64)
        for v in range(256):
            np.add.at(hist[:, v], pos, (cells == v).sum(1))
        zeros = hist[:, 0]
        gains = np.maximum(hist - zeros[:, None], 0).sum(0)
        gains[0] = 0
        key = int(gains.argmax())
        if gains[key] < min_gain * size:
            continue
        mask = hist[:, key] > zeros
        if not 0 < mask.sum() < slots * 3 // 4:
            continue  # a byte more common than 0x00 everywhere is the data's nature, not a window
        table = bytes(x ^ key for x in range(256))
        applied = 0
        for c in range(len(cells)):
            # Tables can be XOR'd whole on top of the window pattern (the two cancel inside a window),
            # so each cell follows its own evidence; only cells with no clear evidence (code) follow
            # the window mask.
            k, z = int((cells[c] == key).sum()), int((cells[c] == 0).sum())
            on = k > z + 4 if abs(k - z) > 4 else bool(mask[pos[c]])
            if on:
                a, e = max(lo + c * GRAIN, off), min(lo + (c + 1) * GRAIN, off + size)
                b[a:e] = bytes(b[a:e]).translate(table)
                applied += 1
        skipped = len(cells) - applied
        done.append((hex(off), size, hex(key), int(mask.sum()), applied, skipped))
    return done


IL2CPP_TYPE_OBJECT = 0x1C
CORRUPT = set()  # Il2CppType addresses found unreadable; restore_typedef_types rebuilds what it can


def encrypted_ranges(b, cell=4096, threshold=7.8):
    """File ranges whose byte entropy says they are still encrypted (no XOR pattern undid them)."""
    import math
    out = []
    for o in range(0, len(b) - cell, cell):
        c = bytes(b[o:o + cell])
        counts = [c.count(bytes([v])) for v in set(c)]
        e = -sum(n / cell * math.log2(n / cell) for n in counts)
        if e > threshold:
            if out and out[-1][1] == o:
                out[-1][1] = o + cell
            else:
                out.append([o, o + cell])
    return out
CLASS_KINDS, PARAM_KINDS, POINTER_KINDS = {0x11, 0x12}, {0x13, 0x1E}, {0x0F, 0x14, 0x15, 0x1D}
TYPE_KINDS = set(range(0x01, 0x17)) | {0x18, 0x19, 0x1B, 0x1C, 0x1D, 0x1E}  # Il2CppTypeEnum values a types[] entry can hold


def type_ok(data, bits, n_typedefs, file_size, b=None, n_params=1 << 20, depth=0):
    """An Il2CppType (pre-27.2 bitfield) whose kind and data agree: class/valuetype name a typedef,
    VAR/MVAR a generic parameter, PTR/SZARRAY point at a sound type, GENERICINST at a generic class
    naming a typedef, ARRAY inside the file. With b given, pointed-to structures are checked too."""
    kind, mods = (bits >> 16) & 0xFF, (bits >> 24) & 0x3F
    if mods > 31 or kind not in TYPE_KINDS:
        return False
    if kind in CLASS_KINDS:
        return data < n_typedefs
    if kind in PARAM_KINDS:
        return data < n_params
    if kind in POINTER_KINDS:
        if not 0 < data < file_size - 16:
            return False
        if b is None or depth > 4:
            return True
        if kind in (0x0F, 0x1D):  # PTR, SZARRAY -> element Il2CppType
            d2, b2 = struct.unpack_from("<II", b, data)
            return type_ok(d2, b2, n_typedefs, file_size, b, n_params, depth + 1)
        if kind == 0x15:  # GENERICINST -> Il2CppGenericClass { typeDefinitionIndex, context... }
            tdi, class_inst = struct.unpack_from("<iI", b, data)
            if not (-1 <= tdi < n_typedefs and 0 < class_inst < file_size - 8):
                return False
            argc, argv = struct.unpack_from("<II", b, class_inst)
            return 0 < argc < 64 and 0 < argv < file_size - 4 * argc
    return True


def neutralize_types(b, n_typedefs, n_params=1 << 20):
    """Find MetadataRegistration (fieldOffsetsCount == typeDefinitionsSizesCount == n_typedefs, two
    words apart, 32-bit layout) and replace Il2CppType entries that are still unreadable (encrypted
    at rest) with a plain `object` type, so static tools can read every other type. Returns
    (registration offset, types checked, types replaced) or None."""
    pat = struct.pack("<I", n_typedefs)
    i = b.find(pat)
    while i >= 0:
        if b[i + 8:i + 12] == pat:
            reg = i - 40  # fieldOffsetsCount is word 10 of the v24 struct
            types_count, types_ptr = struct.unpack_from("<II", b, reg + 24)
            if 0 < types_count < 10_000_000 and 0 < types_ptr < len(b) - 4 * types_count:
                bad = 0
                hot = encrypted_ranges(b)
                for p in struct.unpack_from(f"<{types_count}I", b, types_ptr):
                    if not 0 < p < len(b) - 8:
                        continue
                    data, bits = struct.unpack_from("<II", b, p)
                    if not type_ok(data, bits, n_typedefs, len(b), b, n_params) or any(lo <= p < hi for lo, hi in hot):
                        struct.pack_into("<II", b, p, 0, IL2CPP_TYPE_OBJECT << 16)
                        CORRUPT.add(p)
                        bad += 1
                return hex(reg), types_count, bad, bad_method_specs(b, reg)
        i = b.find(pat, i + 1)
    return None


def bad_method_specs(b, reg):
    """Count methodSpecs entries that are duplicates or point outside the generic instance table.
    Seen (Zing Speed): 12,408 of 232,264, in 16 KB runs overwritten with another table. The patched
    Il2CppInspector skips such entries one by one, so the table stays and the rest keep their names."""
    count, ptr = struct.unpack_from("<II", b, reg + 32)
    insts = struct.unpack_from("<I", b, reg + 8)[0]
    if not 0 < count < 10_000_000 or ptr + 12 * count > len(b):
        return 0
    seen, bad = set(), 0
    for k in range(count):
        t = struct.unpack_from("<iii", b, ptr + 12 * k)
        if t in seen or t[0] < 0 or not -1 <= t[1] < insts or not -1 <= t[2] < insts:
            bad += 1
        seen.add(t)
    return bad


def repair_generic_tables(b, reg, code_reg, modules, n_modules, meta, method_size=32):
    """Make the generic tables consistent for every reader (Il2CppDumper, Cpp2IL, Il2CppInspector).
    Seen (Zing Speed): 16 KB runs of methodSpecs overwritten by another table, genericMethodTable rows
    pointing nowhere, and rgctxRanges with repeated garbage tokens.
    - A bad spec becomes (m, -1, -1) for a distinct non-generic method m: a plain reference, never a
      fake instantiation, never a duplicate.
    - genericMethodTable (v24.5 rows: spec, methodIndex, invokerIndex, adjustorThunk) keeps rows with a
      valid first-seen spec and in-range indices; rgctxRanges keeps rows whose token is a type or
      method token, first seen, and whose range lies inside rgctxs. Nothing indexes into those two
      tables (they are looked up by key), so compacting them is safe.
    Returns (specs rewritten, generic table rows dropped, rgctx ranges dropped)."""
    insts = struct.unpack_from("<I", b, reg + 8)[0]
    gmt_count, gmt_ptr = struct.unpack_from("<II", b, reg + 16)
    count, ptr = struct.unpack_from("<II", b, reg + 32)
    gmp_count = struct.unpack_from("<I", b, code_reg + 8)[0]
    inv_count = struct.unpack_from("<I", b, code_reg + 20)[0]  # v24.5: genericAdjustorThunks sits at +16
    m_off, m_size = struct.unpack_from("<II", meta, 8 + 8 * 5)
    n_methods = m_size // method_size
    generic = {i for i in range(n_methods) if struct.unpack_from("<i", meta, m_off + method_size * i + 16)[0] != -1}

    def ok(t):
        return 0 <= t[0] < n_methods and -1 <= t[1] < insts and -1 <= t[2] < insts and (t[1], t[2]) != (-1, -1)

    specs = [struct.unpack_from("<iii", b, ptr + 12 * k) for k in range(count)]
    seen, bad = set(), []
    for k, t in enumerate(specs):
        if not ok(t) or t in seen:
            bad.append(k)
        seen.add(t)
    used = {t[0] for t in specs if ok(t) and t[1:] == (-1, -1)}
    spare = (m for m in range(n_methods) if m not in generic and m not in used)
    good = set(range(count)) - set(bad)
    for k in bad:
        struct.pack_into("<iii", b, ptr + 12 * k, next(spare), -1, -1)

    rows, firsts = [], set()
    for i in range(gmt_count):
        g, mi, ii, adj = struct.unpack_from("<iiii", b, gmt_ptr + 16 * i)
        if g in good and g not in firsts and 0 <= mi < gmp_count and -1 <= ii < inv_count:
            rows.append((g, mi, ii, adj))
            firsts.add(g)
    for i, r in enumerate(rows):
        struct.pack_into("<iiii", b, gmt_ptr + 16 * i, *r)
    struct.pack_into("<I", b, reg + 16, len(rows))

    dropped_ranges = 0
    for a in struct.unpack_from(f"<{n_modules}I", b, modules):
        n_ranges, ranges, n_rgctx = struct.unpack_from("<III", b, a + 32)
        if not 0 < n_ranges < 1 << 20 or not 0 < ranges < len(b) - 12 * n_ranges:
            continue
        keep, tokens = [], set()
        for i in range(n_ranges):
            tok, start, length = struct.unpack_from("<Iii", b, ranges + 12 * i)
            if tok >> 24 in (0x02, 0x06) and tok not in tokens and 0 <= start and 0 < length and start + length <= n_rgctx:
                keep.append((tok, start, length))
                tokens.add(tok)
        for i, r in enumerate(keep):
            struct.pack_into("<Iii", b, ranges + 12 * i, *r)
        struct.pack_into("<I", b, a + 32, len(keep))
        dropped_ranges += n_ranges - len(keep)
    return len(bad), gmt_count - len(rows), dropped_ranges


def restore_typedef_types(b, reg, meta, typedef_size=92):
    """Every type definition k names its own Il2CppType twice (byvalTypeIndex, byrefTypeIndex): a
    CLASS or VALUETYPE whose data is k. Rebuild those among the unreadable types (CORRUPT); a
    definition derived from System.ValueType or System.Enum is a VALUETYPE. Returns the count."""
    td_off, td_size = struct.unpack_from("<II", meta, 8 + 8 * 19)
    so = struct.unpack_from("<I", meta, 8 + 16)[0]
    n = td_size // typedef_size
    types_count, types_ptr = struct.unpack_from("<II", b, reg + 24)
    ptrs = struct.unpack_from(f"<{types_count}I", b, types_ptr)

    def field(k, i):
        return struct.unpack_from("<i", meta, td_off + typedef_size * k + 4 * i)[0]

    def name(k):
        i = so + field(k, 0)
        return meta[i:meta.index(b"\0", i)]

    by_byval = {field(k, 2): k for k in range(n)}

    def is_value_type(k):
        parent = field(k, 5)
        pk = by_byval.get(parent)
        return pk is not None and name(pk) in (b"ValueType", b"Enum")

    fixed = 0
    for k in range(n):
        for idx, is_ref in ((field(k, 2), 0), (field(k, 3), 1)):
            if 0 <= idx < types_count and ptrs[idx] in CORRUPT:
                kind = 0x11 if is_value_type(k) else 0x12
                struct.pack_into("<II", b, ptrs[idx], k, (kind << 16) | (is_ref << 30))
                fixed += 1
    return fixed


def append_segment(b, data, align=0x1000):
    """Append data at the end of the file and map it read-only through a PT_NULL program header
    (sanitize() leaves some), above every other address. Returns its virtual address."""
    is64, end, phoff, phentsize, phnum, ph, *_ = _layout(b)
    top, slot = 0, None
    for i in range(phnum):
        f = struct.unpack_from(ph, b, phoff + i * phentsize)
        p_type, vaddr, memsz = (f[0], f[3], f[6]) if is64 else (f[0], f[2], f[5])
        top = max(top, vaddr + memsz)
        if p_type == PT_NULL and slot is None:
            slot = i
    if slot is None:
        raise ValueError("no free program header to map appended data")
    off = (len(b) + align - 1) // align * align
    vaddr = (top + align - 1) // align * align + (off % align)
    b.extend(b"\0" * (off - len(b)) + data)
    if is64:
        struct.pack_into(end + "IIQQQQQQ", b, phoff + slot * phentsize, 1, 4, off, vaddr, vaddr, len(data), len(data), align)
    else:
        struct.pack_into(end + "IIIIIIII", b, phoff + slot * phentsize, 1, off, vaddr, vaddr, len(data), len(data), 4, align)
    return vaddr


TYPEDEF_LAYOUT = {24: (92, 68), 31: (88, 64)}  # metadata version: (Il2CppTypeDefinition size, method_count offset)


def load_segments(b):
    """(vaddr, file offset, file size) of every PT_LOAD."""
    is64, end, phoff, phentsize, phnum, ph, *_ = _layout(b)
    out = []
    for i in range(phnum):
        f = struct.unpack_from(ph, b, phoff + i * phentsize)
        p_type, off, vaddr, filesz = (f[0], f[2], f[3], f[5]) if is64 else (f[0], f[1], f[2], f[4])
        if p_type == PT_LOAD and filesz:
            out.append((vaddr, off, filesz))
    return out


def va_to_off(segs, va):
    for v, o, n in segs:
        if v <= va < v + n:
            return o + va - v
    return None


def off_to_va(segs, off):
    for v, o, n in segs:
        if o <= off < o + n:
            return v + off - o
    return None


def find_modules(b):
    """Locate (codeGenModulesCount, file offset of the codeGenModules array, file offset of the count
    field) from the mscorlib module: its name string, the module struct pointing at it, the array
    holding that struct, and the count stored just before the array pointer in
    Il2CppCodeRegistration. Pointers are virtual addresses, mapped through the load segments."""
    raw, segs = bytes(b), load_segments(b)
    name = raw.find(b"mscorlib.dll\0")
    name_va = off_to_va(segs, name) if name >= 0 else None
    if name_va is None:
        return None

    def module_like(va):
        # Aligned, and its name and methodPointers fields are mapped addresses (a relocation table
        # of (offset, 0x17) pairs would otherwise pass).
        o = va_to_off(segs, va) if va and va % 4 == 0 else None
        if o is None or o + 12 > len(raw):
            return False
        name_p, count, ptrs = struct.unpack_from("<III", raw, o)
        return count < 1 << 20 and va_to_off(segs, name_p) is not None and (count == 0 or va_to_off(segs, ptrs) is not None)

    module = raw.find(struct.pack("<I", name_va))
    while module >= 0:
        needle = struct.pack("<I", off_to_va(segs, module) or 0)
        slot = raw.find(needle)
        while slot >= 0:  # the first hits can be four bytes of code that happen to match
            start = slot
            while module_like(struct.unpack_from("<I", raw, start - 4)[0]):
                start -= 4
            start_va = off_to_va(segs, start)
            ref = raw.find(struct.pack("<I", start_va))
            while ref >= 0:
                count = struct.unpack_from("<I", raw, ref - 4)[0]
                if start < slot + 4 <= start + 4 * count < len(raw) and count < 4096 and \
                        all(module_like(v) for v in struct.unpack_from(f"<{count}I", raw, start)):
                    return count, start, ref - 4
                ref = raw.find(struct.pack("<I", start_va), ref + 1)
            slot = raw.find(needle, slot + 1)
        module = raw.find(struct.pack("<I", name_va), module + 1)
    return None


def repair_module_names(b, modules, n_modules, meta, version=24):
    """Point every Il2CppCodeGenModule at its real assembly name. Protected builds scramble some name
    pointers; a module is matched to its image by method count (unique except for empty modules,
    whose order does not matter). A name already present in the binary is reused, else it goes into
    an appended segment."""
    typedef_size, mc_off = TYPEDEF_LAYOUT[version]
    segs = load_segments(b)
    so = struct.unpack_from("<I", meta, 8 + 16)[0]
    io, isz = struct.unpack_from("<II", meta, 8 + 8 * 20)
    to = struct.unpack_from("<I", meta, 8 + 8 * 19)[0]

    def mstr(i):
        e = meta.index(b"\0", so + i)
        return meta[so + i:e]

    images = {}
    for k in range(isz // 40):
        name, _, ts, tc = struct.unpack_from("<4I", meta, io + 40 * k)
        images[mstr(name)] = sum(struct.unpack_from("<H", meta, to + typedef_size * t + mc_off)[0] for t in range(ts, ts + tc))
    named, broken = set(), []
    for va in struct.unpack_from(f"<{n_modules}I", b, modules):
        a = va_to_off(segs, va)
        if a is None:
            continue
        p, count = struct.unpack_from("<II", b, a)
        po = va_to_off(segs, p)
        nm = bytes(b[po:po + 128]).split(b"\0")[0] if po is not None else b""
        if nm in images:
            named.add(nm)
        else:
            broken.append((a, count))
    free = {n: c for n, c in images.items() if n not in named}
    blob, places, fixes = bytearray(), {}, []
    for a, count in broken:
        cands = sorted(n for n, c in free.items() if c == count)
        if not cands:
            continue
        name = cands[0]
        del free[name]
        # A fresh copy by default: a matching string elsewhere can sit in a region another repair
        # rewrites (Zing Speed stores some inside a corrupted invoker index array).
        places[a] = len(blob)
        blob += name + b"\0"
        fixes.append(name.decode())
    if blob:
        try:
            base = append_segment(b, bytes(blob))
        except ValueError:  # no free program header: point at an existing copy of each name instead
            raw = bytes(b)
            for a, rel in places.items():
                nm = bytes(blob[rel:blob.index(b"\0", rel) + 1])
                hit = raw.find(nm)
                while hit > 0 and raw[hit - 1] != 0:
                    hit = raw.find(nm, hit + 1)
                va = off_to_va(segs, hit) if hit > 0 else None
                if va is not None:
                    struct.pack_into("<I", b, a, va)
            return fixes
        for a, rel in places.items():
            struct.pack_into("<I", b, a, base + rel)
    return fixes


def find_code_registration(b):
    """v24.5: (codeGenModulesCount, codeGenModules offset, Il2CppCodeRegistration offset)."""
    found = find_modules(b)
    if not found:
        return None
    count, start, count_field = found
    return count, start, count_field - 60  # 15 words precede codeGenModulesCount


def clamp_invoker_indices(b, modules, n_modules, code_reg):
    """Set per-method invoker indices outside invokerPointers to -1 (no invoker). Encrypted windows
    leave garbage there, and readers index an array with it. Returns how many were cleared."""
    inv_count = struct.unpack_from("<I", b, code_reg + 20)[0]
    cleared = 0
    for a in struct.unpack_from(f"<{n_modules}I", b, modules):
        count, inv = struct.unpack_from("<I", b, a + 4)[0], struct.unpack_from("<I", b, a + 20)[0]
        if not 0 < inv < len(b) - 4 * count:
            continue
        for k in range(count):
            if not -1 <= struct.unpack_from("<i", b, inv + 4 * k)[0] < inv_count:
                struct.pack_into("<i", b, inv + 4 * k, -1)
                cleared += 1
    return cleared


def _typedefs(meta, typedef_size=92):
    td_off, td_size = struct.unpack_from("<II", meta, 8 + 8 * 19)
    so = struct.unpack_from("<I", meta, 8 + 16)[0]

    def field(k, i):
        return struct.unpack_from("<i", meta, td_off + typedef_size * k + 4 * i)[0]

    def text(i):
        return meta[so + i:meta.index(b"\0", so + i)]

    return td_size // typedef_size, field, text


def fix_enums_and_generic_args(b, reg, meta, n_params):
    """Second pass after neutralize_types. An enum whose underlying type is unreadable or not an integer gets I4
    (enums need a primitive underlying type); a generic argument pointing at an unsound type is
    pointed at System.Object's real Il2CppType. Returns (enums fixed, arguments fixed)."""
    n, field, text = _typedefs(meta)
    types_count, types_ptr = struct.unpack_from("<II", b, reg + 24)
    ptrs = struct.unpack_from(f"<{types_count}I", b, types_ptr)
    by_byval = {field(k, 2): k for k in range(n)}
    obj = next((ptrs[field(k, 2)] for k in range(n) if text(field(k, 0)) == b"Object" and text(field(k, 1)) == b"System"), None)
    enums = 0
    for k in range(n):
        parent = by_byval.get(field(k, 5))
        if parent is None or text(field(parent, 0)) != b"Enum" or text(field(parent, 1)) != b"System":
            continue
        t = field(k, 6)  # elementTypeIndex: an enum's underlying type
        if 0 <= t < types_count and (ptrs[t] in CORRUPT or (struct.unpack_from("<I", b, ptrs[t] + 4)[0] >> 16) & 0xFF
                                     not in range(0x02, 0x0C)):
            struct.pack_into("<II", b, ptrs[t], 0, 0x08 << 16)  # IL2CPP_TYPE_I4
            enums += 1
    args = 0
    inst_count, inst_ptr = struct.unpack_from("<II", b, reg + 8)
    if obj:
        for inst in struct.unpack_from(f"<{inst_count}I", b, inst_ptr):
            argc, argv = struct.unpack_from("<II", b, inst)
            for j in range(argc):
                a = struct.unpack_from("<I", b, argv + 4 * j)[0]
                ok = 0 < a < len(b) - 8 and a not in CORRUPT and type_ok(*struct.unpack_from("<II", b, a), n, len(b), b, n_params)
                if not ok:
                    struct.pack_into("<I", b, argv + 4 * j, obj)
                    args += 1
    return enums, args


def drop_corrupt_defaults(meta, b, reg):
    """In the metadata, retype default values whose type is an unreadable binary type as System.Int32
    (slots 6/7: parameter/field defaults in v24). Readers expect every enum default to carry an
    integer; unsetting the value instead makes them fail. Returns the patched metadata and a count."""
    m = bytearray(meta)
    n, field, text = _typedefs(meta)
    int32 = next((field(k, 2) for k in range(n) if text(field(k, 0)) == b"Int32" and text(field(k, 1)) == b"System"), None)
    types_count, types_ptr = struct.unpack_from("<II", b, reg + 24)
    ptrs = struct.unpack_from(f"<{types_count}I", b, types_ptr)
    changed = 0
    for slot in (6, 7):
        off, size = struct.unpack_from("<II", m, 8 + 8 * slot)
        for e in range(off, off + size, 12):
            t = struct.unpack_from("<i", m, e + 4)[0]
            if int32 is not None and 0 <= t < types_count and ptrs[t] in CORRUPT:
                struct.pack_into("<i", m, e + 4, int32)
                changed += 1
    return bytes(m), changed
