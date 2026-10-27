"""Metadata a native method references (typeof handles, TypeInfo, MethodInfo, string literals), in instruction
order, resolved through Il2CppDumper's script.json ScriptMetadata. Ghidra hides which type a typeof() names.
Usage: python metarefs.py <GameAssembly.dll> <script.json> <va> [max_bytes]"""
import io, json, struct, sys
import capstone
sys.stdout.reconfigure(encoding="utf-8")

dll, script, va = sys.argv[1], sys.argv[2], int(sys.argv[3], 16)
size = int(sys.argv[4]) if len(sys.argv) > 4 else 2048
data = open(dll, "rb").read()
pe = struct.unpack_from("<I", data, 0x3C)[0]
nsec = struct.unpack_from("<H", data, pe + 6)[0]
base = struct.unpack_from("<Q", data, pe + 24 + 24)[0]
sect = pe + 24 + struct.unpack_from("<H", data, pe + 20)[0]
rva = va - base
off = next(raddr + rva - vaddr for vsize, vaddr, rsize, raddr in
           (struct.unpack_from("<IIII", data, sect + 40 * i + 8) for i in range(nsec))
           if vaddr <= rva < vaddr + max(vsize, rsize))
meta = {e["Address"]: e["Name"] for e in json.load(io.open(script, encoding="utf-8"))["ScriptMetadata"]}
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True
for ins in md.disasm(data[off:off + size], va):
    for op in ins.operands:
        if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
            target = ins.address + ins.size + op.mem.disp - base
            if target in meta:
                print(f"{ins.address:#x}  {ins.mnemonic} {ins.op_str.split(',')[0]:5}  {meta[target]}")
    if ins.mnemonic == "int3":
        break
