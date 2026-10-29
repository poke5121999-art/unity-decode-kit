import json, os, struct, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import capstone

# usage: ehscan.py <GameAssembly.dll> <script.json> <function va hex>
# Lists the catch/finally funclets the C++ EH tables of a function point at (Ghidra decompiles only the
# parent body) and disassembles each with RIP-relative refs named from script.json.
path, sj, va = sys.argv[1], sys.argv[2], int(sys.argv[3], 16)
data = open(path, "rb").read()
pe = struct.unpack_from("<I", data, 0x3C)[0]
nsec = struct.unpack_from("<H", data, pe + 6)[0]
optsz = struct.unpack_from("<H", data, pe + 20)[0]
base = struct.unpack_from("<Q", data, pe + 24 + 24)[0]
secs = []
for i in range(nsec):
    o = pe + 24 + optsz + 40 * i
    name = data[o:o + 8].rstrip(b"\0").decode()
    vsz, vaddr, rsz, raddr = struct.unpack_from("<IIII", data, o + 8)
    secs.append((name, vaddr, max(vsz, rsz), raddr))

def off(rva):
    for _, v, s, r in secs:
        if v <= rva < v + s:
            return r + rva - v
    raise KeyError(hex(rva))

ddir = pe + 24 + 112
exc_rva, exc_sz = struct.unpack_from("<II", data, ddir + 3 * 8)
funcs = []
for i in range(exc_sz // 12):
    b, e, u = struct.unpack_from("<III", data, off(exc_rva) + 12 * i)
    funcs.append((b, e, u))
starts = {b: (e, u) for b, e, u in funcs}

meta = {}
j = json.load(open(sj, encoding="utf-8"))
for m in j["ScriptMetadata"] + j["ScriptMetadataMethod"]:
    meta[m["Address"]] = m["Name"]
for m in j["ScriptString"]:
    meta[m["Address"]] = repr(m["Value"])
meth = {m["Address"]: m["Name"] for m in j["ScriptMethod"]}

rva = va - base
fb = max(b for b, e, u in funcs if b <= rva)
fe, fu = starts[fb]
uo = off(fu)
flags = data[uo] >> 3
ncodes = data[uo + 2]
p = uo + 4 + 2 * ((ncodes + 1) & ~1)
print("func %x-%x flags=%d" % (base + fb, base + fe, flags))
if not flags & 3:
    sys.exit("no exception handler")
handler, fi = struct.unpack_from("<II", data, p)
print("handler %s  funcinfo rva %x" % (meth.get(handler, hex(base + handler)), fi))
import fh4
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True

def dump(start, end, limit=None):
    for k, ins in enumerate(md.disasm(data[off(start):off(end)], base + start)):
        if limit and k >= limit:
            break
        note = ""
        for o in ins.operands:
            if o.type == capstone.x86.X86_OP_MEM and o.mem.base == capstone.x86.X86_REG_RIP:
                note = meta.get(ins.address + ins.size + o.mem.disp - base, "")
            elif o.type == capstone.x86.X86_OP_IMM and ins.mnemonic in ("call", "jmp"):
                note = meth.get(o.imm - base, "")
        print("%x	%s	%s	%s" % (ins.address, ins.mnemonic, ins.op_str, note))

for lo, hi, disp, conts in fh4.handlers(data, off, fi):
    print("\n== try states %d-%d, funclet %x, continuations %s" % (lo, hi, base + disp, [hex(base + fb + c) for c in conts]))
    if disp in starts:
        dump(disp, starts[disp][0])
    for c in conts:
        print("-- continuation %x" % (base + fb + c))
        dump(fb + c, fe, int(sys.argv[4]) if len(sys.argv) > 4 else 40)
