import struct, sys, capstone

# usage: disx.py <GameAssembly.dll> <va hex> <length>
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
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
for ins in md.disasm(data[off:off + n], va):
    print("%x\t%s\t%s" % (ins.address, ins.mnemonic, ins.op_str))
