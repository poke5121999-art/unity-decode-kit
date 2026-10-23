"""Binary cross-references: every place in the game binary that calls, jumps to, or takes the
address of a method (its code, or its MethodInfo, which is what a delegate is built from).

Decompiled text only shows calls Ghidra resolved to a name. A method passed as a delegate, called
through a tail jump, or called from a function Ghidra left unnamed is missing there. Scanning the
machine code finds those too.
  x86-64: any 32-bit displacement whose rip-relative target is the address (call, jmp, lea, mov).
  ARM32:  BL/B instructions, and literal-pool words holding the absolute address.
Each site is attributed to the method containing it, from Il2CppInspector's address map, cached as
code/functions.tsv (start address, size-ordered, .NET signature with its type).
"""
import bisect
import json
import os
import struct

import numpy as np


def functions(root):
    """Sorted (address, label) of every method body in the binary (definitions and generic instances)."""
    cache = os.path.join(root, "code", "functions.tsv")
    if not os.path.exists(cache):
        with open(os.path.join(root, "inspector", "metadata.json"), encoding="utf-8") as fh:
            am = json.load(fh)["addressMap"]
        rows, shared = {}, {}
        for key in ("methodDefinitions", "constructedGenericMethods"):
            for m in am.get(key, []):
                group = m.get("group", "").split("/")[-1]
                a = int(m["virtualAddress"], 16)
                rows.setdefault(a, f"{group}: {m.get('dotNetSignature', m['name'])}")
                shared[a] = shared.get(a, 0) + 1
        for a in am.get("functionAddresses", []):  # every function start, named or not: site boundaries
            a = int(a, 16) if isinstance(a, str) else int(a)
            if a and a not in rows:
                rows[a] = ""
                shared[a] = 0
        infos = {int(m["virtualAddress"], 16): int(m["methodAddress"], 16) for m in am.get("methodInfoPointers", [])
                 if m.get("methodAddress")}
        with open(cache, "w", encoding="utf-8") as fh:
            for a in sorted(rows):
                fh.write(f"{a:x}\t{shared[a]}\t{rows[a]}\n")
        with open(os.path.join(root, "code", "methodinfos.tsv"), "w", encoding="utf-8") as fh:
            for info, code in sorted(infos.items()):
                fh.write(f"{info:x}\t{code:x}\n")
    starts, labels, shared = [], [], []
    with open(cache, encoding="utf-8") as fh:
        for line in fh:
            a, n, label = line.rstrip("\n").split("\t", 2)
            starts.append(int(a, 16))
            shared.append(int(n))
            labels.append(label or f"unnamed function at 0x{int(a, 16):X}")
    return starts, labels, shared


def method_infos(root, code_addr):
    out = []
    path = os.path.join(root, "code", "methodinfos.tsv")
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                info, code = line.split()
                if int(code, 16) == code_addr:
                    out.append(int(info, 16))
    return out


def code_sections(b):
    """(file offset, size, virtual address, arch) of executable sections."""
    if b[:2] == b"MZ":
        pe = struct.unpack_from("<I", b, 0x3C)[0]
        n_sec, opt_size = struct.unpack_from("<H", b, pe + 6)[0], struct.unpack_from("<H", b, pe + 20)[0]
        opt = pe + 24
        base = struct.unpack_from("<Q", b, opt + 24)[0] if struct.unpack_from("<H", b, opt)[0] == 0x20B else \
            struct.unpack_from("<I", b, opt + 28)[0]
        out = []
        for i in range(n_sec):
            s = opt + opt_size + 40 * i
            vsize, va, raw_size, raw = struct.unpack_from("<IIII", b, s + 8)
            if struct.unpack_from("<I", b, s + 36)[0] & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
                out.append((raw, min(raw_size, vsize), base + va, "x64"))
        return out
    if b[:4] == b"\x7fELF" and b[4] == 1:
        phoff, = struct.unpack_from("<I", b, 28)
        phentsize, phnum = struct.unpack_from("<HH", b, 42)
        out = []
        for i in range(phnum):
            p_type, off, vaddr, _, filesz, _, flags, _ = struct.unpack_from("<IIIIIIII", b, phoff + i * phentsize)
            if p_type == 1 and flags & 1 and filesz:
                out.append((off, filesz, vaddr, "arm32"))
        return out
    return []


RIP_OPCODES = {0x8D: "lea", 0x8B: "mov load", 0x89: "mov store", 0xFF: "call/jmp indirect", 0x3B: "cmp", 0x39: "cmp"}


def scan(b, targets):
    """Yield (site address, kind) for references to any address in targets."""
    t = np.array(sorted(targets), dtype=np.int64)
    for off, size, va, arch in code_sections(b):
        data = np.frombuffer(b, dtype=np.uint8, count=size, offset=off)
        if arch == "x64":
            for phase in range(4):
                n = (size - phase) // 4
                disp = np.frombuffer(data[phase:phase + 4 * n].tobytes(), dtype="<i4").astype(np.int64)
                site = va + phase + 4 * np.arange(n, dtype=np.int64)
                hit = np.nonzero(np.isin(site + 4 + disp, t))[0]
                for k in hit:
                    j = phase + 4 * k
                    if j < 2:
                        continue
                    op, modrm = int(data[j - 1]), int(data[j - 1])
                    if op in (0xE8, 0xE9):
                        yield int(site[k]) - 1, "call" if op == 0xE8 else "jmp"
                    elif (modrm & 0xC7) == 0x05 and int(data[j - 2]) in RIP_OPCODES:
                        yield int(site[k]) - 2, RIP_OPCODES[int(data[j - 2])]
                    # anything else is four bytes that merely look like a displacement
        else:
            n = size // 4
            w = np.frombuffer(data[:4 * n].tobytes(), dtype="<u4").astype(np.int64)
            site = va + 4 * np.arange(n, dtype=np.int64)
            branch = ((w >> 25) & 0x7) == 0x5
            imm = w & 0xFFFFFF
            imm = np.where(imm & 0x800000, imm - 0x1000000, imm)
            dest = site + 8 + imm * 4
            for k in np.nonzero(branch & np.isin(dest, t))[0]:
                yield int(site[k]), "bl" if (w[k] >> 24) & 1 else "b"
            for k in np.nonzero(np.isin(w, t))[0]:
                yield int(site[k]), "address word"


def binary_path(root):
    """The binary the dump was made from: a repaired copy in inspector/, else the one INDEX.md names."""
    import re
    with open(os.path.join(root, "INDEX.md"), encoding="utf-8") as fh:
        m = re.search(r"Binary `([^`]+)`", fh.read())
    if not m:
        return None
    fixed = os.path.join(root, "inspector", os.path.basename(m.group(1)))
    return fixed if os.path.exists(fixed) else m.group(1)


def shared_count(root, addr):
    """How many methods share this code address (identical code folding merges tiny bodies)."""
    starts, _, shared = functions(root)
    i = bisect.bisect_left(starts, addr)
    return shared[i] if i < len(starts) and starts[i] == addr else 0


def xrefs(root, binary, addr):
    """[(site, kind, containing function label)] for code address addr and its MethodInfo pointers."""
    starts, labels, _ = functions(root)
    targets = [addr] + method_infos(root, addr)
    with open(binary, "rb") as fh:
        b = fh.read()
    out = []
    for site, kind in scan(b, targets):
        i = bisect.bisect_right(starts, site) - 1
        label = labels[i] if i >= 0 else "?"
        if i >= 0 and starts[i] == addr:
            continue  # inside the method itself
        out.append((site, kind, label))
    return out
