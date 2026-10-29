import json, struct, sys, capstone

# usage: disx.py <GameAssembly.dll> <va hex> <length> [script.json]
# With script.json, call targets and RIP-relative operands are named (methods, metadata, string literals).
path, va, n = sys.argv[1], int(sys.argv[2], 16), int(sys.argv[3])
data = open(path, "rb").read()
pe = struct.unpack_from("<I", data, 0x3C)[0]
nsec = struct.unpack_from("<H", data, pe + 6)[0]
optsz = struct.unpack_from("<H", data, pe + 20)[0]
base = struct.unpack_from("<Q", data, pe + 24 + 24)[0]
sec = pe + 24 + optsz
rva = va - base
for i in range(nsec):
    o = sec + 40 * i
    vsz, vaddr, rsz, raddr = struct.unpack_from("<IIII", data, o + 8)
    if vaddr <= rva < vaddr + max(vsz, rsz):
        off = raddr + rva - vaddr
        break
names = {}
if len(sys.argv) > 4:
    j = json.load(open(sys.argv[4], encoding="utf-8"))
    for m in j["ScriptMetadata"] + j["ScriptMetadataMethod"] + j["ScriptMethod"]:
        names.setdefault(m["Address"], m["Name"])
    for m in j["ScriptString"]:
        names[m["Address"]] = repr(m["Value"])
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = bool(names)
for ins in md.disasm(data[off:off + n], va):
    note = ""
    if names:
        for o in ins.operands:
            if o.type == capstone.x86.X86_OP_MEM and o.mem.base == capstone.x86.X86_REG_RIP:
                note = names.get(ins.address + ins.size + o.mem.disp - base, "")
            elif o.type == capstone.x86.X86_OP_IMM and ins.mnemonic in ("call", "jmp"):
                note = names.get(o.imm - base, "")
    print("%x\t%s\t%s\t%s" % (ins.address, ins.mnemonic, ins.op_str, note))
