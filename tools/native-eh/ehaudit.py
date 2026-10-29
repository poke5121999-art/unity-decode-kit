import io, json, os, struct, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import capstone
import fh4

# usage: ehaudit.py <GameAssembly.dll> <script.json> <name prefix> <out.tsv>
# For every native method whose name starts with the prefix, list the exception types its catch funclets test
# (Ghidra drops funclets, so recovered bodies silently lose their catch clauses).
path, sj, prefix, outp = sys.argv[1:5]
data = open(path, "rb").read()
pe = struct.unpack_from("<I", data, 0x3C)[0]
nsec = struct.unpack_from("<H", data, pe + 6)[0]
optsz = struct.unpack_from("<H", data, pe + 20)[0]
base = struct.unpack_from("<Q", data, pe + 24 + 24)[0]
secs = []
for i in range(nsec):
    o = pe + 24 + optsz + 40 * i
    vsz, vaddr, rsz, raddr = struct.unpack_from("<IIII", data, o + 8)
    secs.append((vaddr, max(vsz, rsz), raddr))

def off(rva):
    for v, s, r in secs:
        if v <= rva < v + s:
            return r + rva - v
    raise KeyError(hex(rva))

exc_rva, exc_sz = struct.unpack_from("<II", data, pe + 24 + 112 + 3 * 8)
starts = {}
for i in range(exc_sz // 12):
    b, e, u = struct.unpack_from("<III", data, off(exc_rva) + 12 * i)
    starts[b] = (e, u)

j = json.load(open(sj, encoding="utf-8"))
meta = {m["Address"]: m["Name"] for m in j["ScriptMetadata"]}
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True

def catch_types(rva):
    e, u = starts[rva]
    uo = off(u)
    if not (data[uo] >> 3) & 3:
        return None
    nc = data[uo + 2]
    p = uo + 4 + 2 * ((nc + 1) & ~1)
    _, fi = struct.unpack_from("<II", data, p)
    types = []
    for _, _, disp, _ in fh4.handlers(data, off, fi):
        if disp not in starts:
            continue
        fe = starts[disp][0]
        for ins in md.disasm(data[off(disp):off(fe)], base + disp):
            for o in ins.operands:
                if o.type == capstone.x86.X86_OP_MEM and o.mem.base == capstone.x86.X86_REG_RIP:
                    n = meta.get(ins.address + ins.size + o.mem.disp - base, "")
                    if n.endswith("Exception_TypeInfo") and n[:-9] not in types:
                        types.append(n[:-9])
    return types

rows = 0
with io.open(outp, "w", encoding="utf-8", newline="\n") as out:
    out.write("address\tmethod\tcatch_types\n")
    seen = set()
    for m in j["ScriptMethod"]:
        a, n = m["Address"], m["Name"]
        if not n.startswith(prefix) or a in seen or a not in starts:
            continue
        seen.add(a)
        try:
            t = catch_types(a)
        except (KeyError, struct.error, IndexError):
            continue
        if t:
            out.write("%x\t%s\t%s\n" % (base + a, n, ",".join(t)))
            rows += 1
print(rows, "methods with catch funclets")
