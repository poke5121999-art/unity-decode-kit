import io, json, sys, collections
sys.stdout.reconfigure(encoding="utf-8")

# usage: litwhere.py <litdiff rows.tsv> <ldstr.tsv>
# For each literal a native method has and ours lacks, where else ours loads it. Found in another method usually
# means the native compiler inlined a callee; found nowhere means our build has lost it.
where = collections.defaultdict(set)
for line in io.open(sys.argv[2], encoding="utf-8"):
    name, _, l = line.rstrip("\n").split("\t", 2)
    for x in l.split("\x01"):
        if x:
            where[json.loads(x)].add(name.replace("_003C", "<").replace("_003E", ">"))
for line in io.open(sys.argv[1], encoding="utf-8"):
    if not line.strip():
        continue
    meth, miss, extra = line.rstrip("\n").split("\t")
    for m in json.loads(miss):
        w = sorted(where.get(m, ()))
        tag = "LOST" if not w else "elsewhere"
        print("%s\t%s\t%s\t%s" % (tag, meth, json.dumps(m, ensure_ascii=False)[:70], ",".join(x.split(".")[-1] for x in w[:3])))
