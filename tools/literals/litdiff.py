import json, re, struct, sys, collections, capstone
from capstone import x86

# usage: litdiff.py <GameAssembly.dll> <script.json> <ldstr.tsv> <out.tsv> [namespace prefix]
# Per method name, the string literals the native code loads against the ldstr operands of our recompiled IL
# (ldstr.tsv from ldstr.exe). A literal on one side only is a candidate divergence: WriteSnapshotEnvelope-style
# misplaced constants, " " written for "", or a dropped log/format string.
dll, script, ours, out = sys.argv[1:5]
want = sys.argv[5] if len(sys.argv) > 5 else "Runtime."
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
lits = {m["Address"]: m["Value"] for m in j["ScriptString"]}
methods = sorted({m["Address"]: m["Name"] for m in j["ScriptMethod"]}.items())
addrs = [a for a, _ in methods]


def norm(n):
    return n.replace("_003C", "<").replace("_003E", ">")


md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True
native = collections.defaultdict(list)
for k, (addr, name) in enumerate(methods):
    if not name.startswith(want):
        continue
    end = addrs[k + 1] if k + 1 < len(addrs) else addr + 0x2000
    off = foff(addr)
    if off is None:
        continue
    prev = ""
    s = set()
    for ins in md.disasm(data[off:off + min(end - addr, 0x10000)], addr + base):
        if ins.mnemonic == "int3" and prev in ("ret", "jmp"):
            break
        prev = ins.mnemonic
        for o in ins.operands:
            if o.type == x86.X86_OP_MEM and o.mem.base == x86.X86_REG_RIP:
                t = ins.address + ins.size + o.mem.disp - base
                # `lea rcx, [lit]` feeds the once-per-method metadata init. Kept: a literal used only in a catch
                # funclet (placed outside the method) shows up here and nowhere else. Cost: an init block shared
                # with a sibling method (CloseStore initializes OpenStore's "Open") reads as a missing literal.
                if t in lits:
                    s.add(lits[t])
    native[name].append(s)

mine = collections.defaultdict(list)
for line in open(ours, encoding="utf-8"):
    name, _, l = line.rstrip("\n").split("\t", 2)
    name = norm(name)
    if not name.startswith(want):
        continue
    mine[name].append({json.loads(x) for x in l.split("\x01") if x})

def pair(ns, os):
    """Overloads by name: pair each of our bodies with the native body sharing the most literals, so a wrong literal
    in GetValueWithSign(int) is not hidden by the right one in GetValueWithSign(float)."""
    if len(ns) == 1 and len(os) == 1:
        return [(ns[0], os[0])]
    left, out = list(range(len(ns))), []
    for o in sorted(os, key=len, reverse=True):
        if not left:
            out.append((set().union(*ns), o))
            continue
        best = max(left, key=lambda i: (len(ns[i] & o) / (len(ns[i] | o) or 1), -abs(len(ns[i]) - len(o))))
        left.remove(best)
        out.append((ns[best], o))
    return out


rows = 0
with open(out, "w", encoding="utf-8") as fo:
    for name in sorted(set(native) & set(mine)):
        miss, extra = set(), set()
        for n, o in pair(native[name], mine[name]):
            miss |= n - o
            extra |= o - n
        if miss or extra:
            rows += 1
            fo.write("%s\t%s\t%s\n" % (name, json.dumps(sorted(miss), ensure_ascii=False), json.dumps(sorted(extra), ensure_ascii=False)))
print("native methods", len(native), "ours", len(mine), "both", len(set(native) & set(mine)), "differ", rows)
