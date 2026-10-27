"""Static array data that IL2CPP methods load with RuntimeHelpers.InitializeArray. Ghidra shows only the field
handle, so translators guessed the values; the bytes live in global-metadata.dat at the offset dump.cs prints.
Usage: python rvablobs.py <ghidra.jsonl> <dump.cs> <global-metadata.dat> [out.jsonl]"""
import io, json, re, struct, sys
sys.stdout.reconfigure(encoding="utf-8")

ghidra, dump, meta = sys.argv[1:4]
out_path = sys.argv[4] if len(sys.argv) > 4 else None
BLOB = re.compile(r"__StaticArrayInitTypeSize=(\d+) ([0-9A-F]{64}) /\*Metadata offset 0x([0-9A-F]+)\*/")
blobs = {}
for line in io.open(dump, encoding="utf-8", errors="replace"):
    m = BLOB.search(line)
    if m:
        blobs[m.group(2)] = (int(m.group(3), 16), int(m.group(1)))
data = open(meta, "rb").read()
ELEM = re.compile(r"TypeInfo__System__(Single|Int32|UInt32|Int16|UInt16|Byte|SByte|Int64|UInt64|Double|Char|Boolean)(?:__Array|\[\])")
FMT = {"Single": "f", "Int32": "i", "UInt32": "I", "Int16": "h", "UInt16": "H", "Byte": "B", "SByte": "b",
       "Int64": "q", "UInt64": "Q", "Double": "d", "Char": "H", "Boolean": "?"}

rows = []
for l in io.open(ghidra, encoding="utf-8"):
    r = json.loads(l)
    c = r["c"]
    if "InitializeArray" not in c:
        continue
    types = ELEM.findall(c)
    for i, h in enumerate(re.findall(r"_([0-9A-F]{64})_Field", c)):
        off, size = blobs.get(h, (None, None))
        if off is None:
            rows.append({"key": r["key"], "hash": h, "error": "hash not in dump.cs"})
            continue
        raw = data[off:off + size]
        t = types[i] if i < len(types) else None
        if t is None:
            # Element type not visible in the pseudo-C: floats that decode to denormals are really ints.
            asf = struct.unpack(f"<{size // 4}f", raw[:size // 4 * 4]) if size % 4 == 0 else ()
            t = "Single" if asf and all(v == 0 or 1e-30 < abs(v) < 1e30 for v in asf) else ("Int32" if size % 4 == 0 else "Byte")
        n = size // struct.calcsize(FMT[t])
        vals = list(struct.unpack(f"<{n}{FMT[t]}", raw[:n * struct.calcsize(FMT[t])]))
        if t == "Single":
            vals = [round(v, 6) for v in vals]
        rows.append({"key": r["key"], "addr": r.get("addr"), "hash": h, "elem": t, "count": n,
                     "values": vals if n <= 64 else vals[:64] + ["..."]})
for row in rows:
    v = row.get("values")
    print(f"{row['key']}\n    {row.get('elem')}[{row.get('count')}] = {v if v is not None else row.get('error')}")
if out_path:
    with io.open(out_path, "w", encoding="utf-8", newline="\n") as w:
        w.writelines(json.dumps(r) + "\n" for r in rows)
