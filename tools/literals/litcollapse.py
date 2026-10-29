import io, json, re, sys, collections
sys.stdout.reconfigure(encoding="utf-8")

# usage: litcollapse.py <inspector metadata.json> <litdiff.tsv> <ldstr.tsv>
# The collision case litimpact.py cannot see: native loads two literals that share a Ghidra name (inside/outside),
# the recompile kept one of them for both uses, so ours has no extra literal, only a missing one whose group-mate
# it does load. Each row needs a hand fix (the choice between the two is a condition in the native code).
buf = io.open(sys.argv[1], encoding="utf-8").read()
pat = re.compile(r'"name": "(StringLiteral_[^"]*)",\s*"string": "((?:[^"\\]|\\.)*)"')
group = collections.defaultdict(set)
for m in pat.finditer(buf):
    group[m.group(1)].add(json.loads('"' + m.group(2) + '"'))
name_of = {s: k for k, v in group.items() if len(v) > 1 for s in v}
ours = collections.defaultdict(set)
for line in io.open(sys.argv[3], encoding="utf-8"):
    n, _, l = line.rstrip("\n").split("\t", 2)
    ours[n.replace("_003C", "<").replace("_003E", ">")] |= {json.loads(x) for x in l.split("\x01") if x}
for line in io.open(sys.argv[2], encoding="utf-8"):
    meth, miss, extra = line.rstrip("\n").split("\t")
    for m in json.loads(miss):
        g = name_of.get(m)
        mates = sorted(x for x in ours[meth] if g and name_of.get(x) == g)
        if mates:
            print("%s\t%s\tours has %s" % (meth, json.dumps(m, ensure_ascii=False)[:60], json.dumps(mates, ensure_ascii=False)[:80]))
