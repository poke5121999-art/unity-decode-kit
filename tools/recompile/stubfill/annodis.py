"""Annotated disassembly of one native method, for the cases Ghidra prunes as "unreachable" (it folds a local to 0
and drops the branch that holds the real work). Calls resolve to managed names, rip-relative loads to TypeInfo /
MethodInfo / string literals, all from Il2CppDumper's script.json. Stops at the next known method start.
Usage: python annodis.py <GameAssembly.dll> <script.json> <va>"""
import bisect, io, json, struct, sys
import capstone
sys.stdout.reconfigure(encoding="utf-8")

dll, script, va = sys.argv[1], sys.argv[2], int(sys.argv[3], 16)
data = open(dll, "rb").read()
pe = struct.unpack_from("<I", data, 0x3C)[0]
nsec = struct.unpack_from("<H", data, pe + 6)[0]
base = struct.unpack_from("<Q", data, pe + 24 + 24)[0]
sect = pe + 24 + struct.unpack_from("<H", data, pe + 20)[0]
sections = [struct.unpack_from("<IIII", data, sect + 40 * i + 8) for i in range(nsec)]


def file_off(rva):
    return next(raddr + rva - vaddr for vsize, vaddr, rsize, raddr in sections if vaddr <= rva < vaddr + max(vsize, rsize))


sj = json.load(io.open(script, encoding="utf-8"))
methods = {}
for m in sj["ScriptMethod"]:
    methods.setdefault(m["Address"], []).append(m["Name"])
meta = {e["Address"]: e["Name"] for e in sj["ScriptMetadata"]}
meta.update({e["Address"]: "Method(" + e["Name"] + ")" for e in sj["ScriptMetadataMethod"]})
meta.update({e["Address"]: repr(e["Value"]) for e in sj["ScriptString"]})
del sj
starts = sorted(methods)
rva = va - base
end = starts[bisect.bisect_right(starts, rva)] if bisect.bisect_right(starts, rva) < len(starts) else rva + 8192

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True
off = file_off(rva)
for ins in md.disasm(data[off:off + (end - rva)], va):
    note = ""
    if ins.mnemonic in ("call", "jmp") and ins.operands and ins.operands[0].type == capstone.x86.X86_OP_IMM:
        t = ins.operands[0].imm - base
        if t in methods:
            names = methods[t]
            note = " | ".join(names[:2]) + (f" (+{len(names) - 2})" if len(names) > 2 else "")
    for op in ins.operands:
        if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
            t = ins.address + ins.size + op.mem.disp - base
            if t in meta:
                note = meta[t]
    print(f"{ins.address & 0xFFFFFF:06x}  {ins.mnemonic:6} {ins.op_str:38} {('; ' + note) if note else ''}".rstrip())
