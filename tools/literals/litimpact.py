import io, json, re, sys, collections

# usage: litimpact.py <inspector metadata.json> <litdiff.tsv> <out.tsv>
# Which litdiff rows are explained by StringLiteral_ name collisions: a literal on our side only and one on the
# native side only that share a Ghidra name. "unique" rows have exactly one native candidate per wrong literal.
buf = io.open(sys.argv[1], encoding="utf-8").read()
pat = re.compile(r'"name": "(StringLiteral_[^"]*)",\s*"string": "((?:[^"\\]|\\.)*)"')
group = collections.defaultdict(set)
for m in pat.finditer(buf):
    group[m.group(1)].add(json.loads('"' + m.group(2) + '"'))
name_of = {}
for k, v in group.items():
    if len(v) > 1:
        for s in v:
            name_of[s] = k
rows, unique = [], 0
for line in io.open(sys.argv[2], encoding="utf-8"):
    meth, miss, extra = line.rstrip("\n").split("\t")
    miss, extra = json.loads(miss), json.loads(extra)
    pairs = []
    for e in extra:
        g = name_of.get(e)
        cands = [m for m in miss if g and name_of.get(m) == g]
        if cands:
            pairs.append((e, cands))
    if pairs:
        ok = all(len(c) == 1 for _, c in pairs)
        unique += ok
        rows.append("%s\t%s\t%s" % ("unique" if ok else "ambiguous", meth, json.dumps(pairs, ensure_ascii=False)))
io.open(sys.argv[3], "w", encoding="utf-8").write("\n".join(rows) + "\n")
print("methods with collision-swapped literals", len(rows), "unique fix", unique)
