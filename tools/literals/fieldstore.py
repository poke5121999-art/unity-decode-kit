import json, re, struct, sys, collections, capstone
from capstone import x86

# usage: fieldstore.py <GameAssembly.dll> <script.json> <dump.cs> <stfld.tsv> <out.tsv> [namespace prefix]
# Fields our recompiled IL stores (ldstr.exe ... stfld) on an object the native method allocates itself, where the
# native code never writes that field: WriteSnapshotEnvelope set SaveEnvelope.Magic, which the original leaves at
# its constructor default (the literal belonged to CryptoInfo.Alg on the other new object).
dll, script, dump, ours_path, out = sys.argv[1:6]
want = sys.argv[6] if len(sys.argv) > 6 else "Runtime."
sys.stdout.reconfigure(encoding="utf-8")
data = open(dll, "rb").read()
pe = struct.unpack_from("<I", data, 0x3C)[0]
nsec = struct.unpack_from("<H", data, pe + 6)[0]
optsz = struct.unpack_from("<H", data, pe + 20)[0]
base = struct.unpack_from("<Q", data, pe + 24 + 24)[0]
secs = [struct.unpack_from("<IIII", data, pe + 24 + optsz + 40 * i + 8) for i in range(nsec)]


def foff(rva):
    for vsz, vaddr, rsz, raddr in secs:
        if vaddr <= rva < vaddr + max(vsz, rsz):
            return raddr + rva - vaddr


j = json.load(open(script, encoding="utf-8"))
typeinfo = {m["Address"]: m["Name"][:-9] for m in j["ScriptMetadata"] if m["Name"].endswith("_TypeInfo")}
methods = sorted({m["Address"]: m["Name"] for m in j["ScriptMethod"]}.items())
addrs = [a for a, _ in methods]

# class -> (parent full name or None, {offset: field}); nested classes are written Outer.Inner like ldstr.exe does
classes, ns, cur, stack = {}, "", None, []
for line in open(dump, encoding="utf-8"):
    if line.startswith("// Namespace: "):
        ns = line[14:].strip()
        continue
    m = re.match(r"^(?:\[.*?\] )*(?:public |internal |private |protected |sealed |abstract |static )*(?:class|struct) ([^\s:]+)(?: : ([^,/{]+?))?(?:,[^/]*)? // TypeDefIndex", line)
    if m:
        name = m.group(1).replace("<", "<").split("<")[0] if "`" not in m.group(1) else m.group(1)
        full = (ns + "." if ns else "") + m.group(1)
        cur = classes.setdefault(full, [m.group(2), {}])
        continue
    m = re.match(r"^\t(?:\[.*?\] )*(?:public |private |protected |internal |readonly |static |const )*[^;(]+? ([\w<>]+); // 0x([0-9A-F]+)$", line)
    if m and cur is not None and " static " not in line and "const " not in line:
        cur[1][int(m.group(2), 16)] = m.group(1)
short = collections.defaultdict(list)
for k in classes:
    short[k.split(".")[-1]].append(k)


def resolve(cls, off):
    seen = 0
    while cls in classes and seen < 20:
        parent, f = classes[cls]
        if off in f:
            return cls, f[off]
        if not parent:
            return None
        parent = parent.strip()
        cand = [c for c in short.get(parent.split(".")[-1].split("<")[0], [])]
        cls = parent if parent in classes else (cand[0] if len(cand) == 1 else None)
        seen += 1
    return None


def chain(cls):
    out, seen = [], 0
    while cls in classes and seen < 20:
        out.append(cls)
        parent = (classes[cls][0] or "").strip()
        cand = short.get(parent.split(".")[-1].split("<")[0], [])
        cls = parent if parent in classes else (cand[0] if len(cand) == 1 else None)
        seen += 1
    return out


VOL = {x86.X86_REG_RAX, x86.X86_REG_RCX, x86.X86_REG_RDX, x86.X86_REG_R8, x86.X86_REG_R9, x86.X86_REG_R10, x86.X86_REG_R11}
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True
native_alloc = collections.defaultdict(set)
native_store = collections.defaultdict(set)
for k, (addr, name) in enumerate(methods):
    if not name.startswith(want):
        continue
    end = addrs[k + 1] if k + 1 < len(addrs) else addr + 0x2000
    off = foff(addr)
    if off is None:
        continue
    reg, prev = {}, ""
    for ins in md.disasm(data[off:off + min(end - addr, 0x10000)], addr + base):
        if ins.mnemonic == "int3" and prev in ("ret", "jmp"):
            break
        prev = ins.mnemonic
        ops = ins.operands
        if ins.mnemonic in ("call", "jmp"):
            ti = reg.get(x86.X86_REG_RCX)
            for r in VOL:
                reg.pop(r, None)
            if ti and ti[0] == "ti":
                reg[x86.X86_REG_RAX] = ("obj", ti[1])
                native_alloc[name].add(ti[1])
            continue
        if len(ops) == 2 and ops[0].type == x86.X86_OP_MEM and ins.mnemonic.startswith("mov"):
            b = reg.get(ops[0].mem.base)
            if b and b[0] == "obj" and ops[0].mem.index == 0:
                # one wide store can fill several small fields (three bools by `mov word` + `mov byte`, a struct by movups)
                for o in range(ops[0].mem.disp, ops[0].mem.disp + max(ops[0].size, 1)):
                    r = resolve(b[1], o)
                    if r:
                        native_store[name].add(r)
            continue
        if ins.mnemonic in ("mov", "lea") and len(ops) == 2 and ops[0].type == x86.X86_OP_REG:
            dst, s = ops[0].reg, ops[1]
            if s.type == x86.X86_OP_MEM and s.mem.base == x86.X86_REG_RIP and ins.mnemonic == "mov":
                t = ins.address + ins.size + s.mem.disp - base
                if t in typeinfo:
                    reg[dst] = ("ti", typeinfo[t])
                else:
                    reg.pop(dst, None)
            elif s.type == x86.X86_OP_REG and ins.mnemonic == "mov" and s.reg in reg:
                reg[dst] = reg[s.reg]
            else:
                reg.pop(dst, None)
            continue
        if len(ops) >= 1 and ops[0].type == x86.X86_OP_REG and ins.mnemonic not in ("cmp", "test", "push"):
            reg.pop(ops[0].reg, None)

ours = collections.defaultdict(set)
for line in open(ours_path, encoding="utf-8"):
    n, _, l = line.rstrip("\n").split("\t", 2)
    n = n.replace("_003C", "<").replace("_003E", ">")
    for x in l.split("\x01"):
        if x:
            d, f = json.loads(x).rsplit("::", 1)
            ours[n].add((d, f))

rows = 0
with open(out, "w", encoding="utf-8") as fo:
    for name in sorted(set(native_alloc) & set(ours)):
        decl = set()
        for c in native_alloc[name]:
            decl |= set(chain(c))
        extra = sorted((d, f) for d, f in ours[name] if d in decl and (d, f) not in native_store[name])
        # an allocated class the native code never writes a field of was probably filled through a ctor/setter call
        touched = {d for d, _ in native_store[name]}
        extra = [(d, f) for d, f in extra if d in touched]
        if extra:
            rows += 1
            fo.write("%s\t%s\n" % (name, json.dumps(["%s::%s" % x for x in extra], ensure_ascii=False)))
print("methods allocating", len(native_alloc), "with ours", len(set(native_alloc) & set(ours)), "flagged", rows)
