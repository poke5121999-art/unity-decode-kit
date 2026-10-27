import io, json, re, sys
sys.stdout.reconfigure(encoding="utf-8")
c = io.open(sys.argv[1], encoding="utf-8").read()
pairs = re.findall(r"\(lVar16 \+ (0x[0-9a-f]+|\d+)\)\s*=\s*\*\(undefined8 \*\)\(lVar14 \+ (0x[0-9a-f]+|\d+)\)", c)
native = [(int(src, 0) - 0x20) // 12 for dst, src in sorted(pairs, key=lambda p: int(p[0], 0))]
print("native vertex->corner:", native, len(native))
row = json.loads([l for l in io.open(sys.argv[2], encoding="utf-8") if '"FXV.VolumeFog::InitializeBoxRenderMesh()"' in l][0])
m = re.search(r"Vector3\[\] vertices =\s*\{(.*?)\};", row["body"], re.S)
llm = [int(x) for x in re.findall(r"corners\[(\d+)\]", m.group(1))]
print("llm    vertex->corner:", llm, len(llm))
print("match" if native == llm else "DIFFERENT at " + str([i for i, (a, b) in enumerate(zip(native, llm)) if a != b]))
