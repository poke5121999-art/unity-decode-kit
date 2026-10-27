"""Deterministic bodies for stubbed getters whose native code was folded with another type's identical getter.
Ghidra then names the other type's field, so the name is useless; the machine code is `mov reg, [rcx + off]; ret`
and dump.cs gives this type's field at that offset. Writes cand.folded.<asm>.jsonl.
Usage: python folded.py <work dir> <GameAssembly.dll> <dump.cs> <asm>..."""
import io, json, re, struct, sys
from pathlib import Path
import capstone
sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, "D:/walking-trade-ref/udk")
from udk.recompile import loose
sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent))
from recovered import recovered

W, dll, dump = sys.argv[1], sys.argv[2], sys.argv[3]
data = open(dll, "rb").read()
pe = struct.unpack_from("<I", data, 0x3C)[0]
nsec = struct.unpack_from("<H", data, pe + 6)[0]
base = struct.unpack_from("<Q", data, pe + 24 + 24)[0]
sect = pe + 24 + struct.unpack_from("<H", data, pe + 20)[0]
sections = [struct.unpack_from("<IIII", data, sect + 40 * i + 8) for i in range(nsec)]
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True


def code_at(va, n=32):
    rva = va - base
    for vsize, vaddr, rsize, raddr in sections:
        if vaddr <= rva < vaddr + max(vsize, rsize):
            return data[raddr + rva - vaddr:raddr + rva - vaddr + n]
    return b""


def field_offset(va):
    """Offset of `this` field a getter returns, when its whole body is one load from [rcx + off] and ret."""
    ins = list(md.disasm(code_at(va), va))[:2]
    if len(ins) < 2 or ins[1].mnemonic != "ret" or ins[0].mnemonic not in ("mov", "movss", "movsd", "movzx", "movups", "movsxd"):
        return None
    ops = ins[0].operands
    if len(ops) != 2 or ops[1].type != capstone.x86.X86_OP_MEM or ops[1].mem.base != capstone.x86.X86_REG_RCX or ops[1].mem.index:
        return None
    return ops[1].mem.disp


fields = {}
cls, ns = None, ""
for line in io.open(dump, encoding="utf-8", errors="replace"):
    if line.startswith("// Namespace:"):
        ns = line.split(":", 1)[1].strip()
    if "// TypeDefIndex:" in line:
        # Every type header (class, struct, enum, interface, nested, compiler-generated) carries this marker.
        m = re.search(r"\b(?:class|struct|enum|interface)\s+(\S+)", line)
        name = m.group(1) if m else line
        cls = f"{ns}.{name}" if ns else name
        fields.setdefault(cls, {})
        continue
    f = re.match(r"^\s*(?:\[[^\]]*\]\s*)*((?:public|private|protected|internal|readonly|\s)+)[\w<>\[\],.\s]+?\s([\w<>]+);\s*//\s*0x([0-9A-F]+)", line)
    if f and cls and "static" not in f.group(1) and "const" not in line:
        fields[cls][int(f.group(3), 16)] = f.group(2)

addr = {}
for l in io.open(f"{W}/ghidra.jsonl", encoding="utf-8"):
    r = json.loads(l)
    if r.get("addr"):
        addr.setdefault(loose(r["key"]), int(r["addr"], 16))

for asm in sys.argv[4:]:
    ok = recovered(W, asm, "folded")
    keys = [l.split("\t")[0] for l in io.open(f"{W}/keys.{asm}.tsv", encoding="utf-8").read().splitlines()[1:] if l]
    out, miss = [], 0
    for k in keys:
        typ, name = k.split("::", 1)
        if loose(k) in ok or not re.match(r"get_\w+\(\)$", name) or loose(k) not in addr:
            continue
        off = field_offset(addr[loose(k)])
        if off is None:
            continue
        fname = fields.get(re.sub(r"`\d+", "", typ.replace("/", ".")), {}).get(off)
        if not fname:
            miss += 1
            continue
        if not re.fullmatch(r"[A-Za-z_]\w*", fname):
            # Backing fields and compiler names: `return X;` would call the stubbed property itself.
            miss += 1
            continue
        out.append({"key": k, "src": "folded", "body": f"return {fname};", "native": f"{addr[loose(k)]:#x} mov [rcx+{off:#x}]"})
    with io.open(f"{W}/cand.folded.{asm}.jsonl", "w", encoding="utf-8", newline="\n") as w:
        w.writelines(json.dumps(r) + "\n" for r in out)
    print(f"{asm}: {len(out)} folded getters, {miss} with no field at that offset")
