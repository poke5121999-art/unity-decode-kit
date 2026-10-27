"""String literals a native method loads, in instruction order: Ghidra truncates long array initializers, the
machine code does not. Usage: python litorder.py <GameAssembly.dll> <stringliteral.json> <va> [max_bytes]"""
import io, json, struct, sys
import capstone
sys.stdout.reconfigure(encoding="utf-8")

dll, lits, va = sys.argv[1], sys.argv[2], int(sys.argv[3], 16)
size = int(sys.argv[4]) if len(sys.argv) > 4 else 4096
data = open(dll, "rb").read()
pe = struct.unpack_from("<I", data, 0x3C)[0]
nsec = struct.unpack_from("<H", data, pe + 6)[0]
opt = pe + 24
base = struct.unpack_from("<Q", data, opt + 24)[0]
sect = opt + struct.unpack_from("<H", data, pe + 20)[0]
rva = va - base
off = None
for i in range(nsec):
    s = sect + 40 * i
    vsize, vaddr, rsize, raddr = struct.unpack_from("<IIII", data, s + 8)
    if vaddr <= rva < vaddr + max(vsize, rsize):
        off = raddr + rva - vaddr
if off is None:
    sys.exit(f"va {va:#x} is in no section")
by_rva = {int(x["address"], 16): x["value"] for x in json.load(io.open(lits, encoding="utf-8"))}
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True
n = 0
for ins in md.disasm(data[off:off + size], va):
    for op in ins.operands:
        if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
            target = ins.address + ins.size + op.mem.disp - base
            if target in by_rva:
                n += 1
                print(f"{ins.address:#x}  {n:3}  {ins.mnemonic} {ins.op_str.split(',')[0]:5}  {by_rva[target]!r}")
    if ins.mnemonic == "int3":
        break
