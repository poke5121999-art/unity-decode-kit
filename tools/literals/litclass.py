import json, re, sys
# Buckets litdiff.tsv rows: STUB (our body is a stub marker), LOG (only free text differs), REVIEW (identifier-like literal differs).
stub = re.compile(r"^[\w.<>`]+::[\w.<>`]+\(")
def ident(s): return bool(re.fullmatch(r"[A-Za-z_][\w.\-/]*", s)) or s in ("", " ", "N", "D", "X", "F0", "F1", "F2")
out = {"STUB": [], "LOG": [], "REVIEW": []}
for line in open(sys.argv[1], encoding="utf-8"):
    name, miss, extra = line.rstrip("\n").split("\t")
    miss, extra = json.loads(miss), json.loads(extra)
    if any(stub.match(x) for x in extra): k = "STUB"
    elif any(ident(x) for x in miss + extra): k = "REVIEW"
    else: k = "LOG"
    out[k].append(line.rstrip("\n"))
for k, v in out.items():
    print(k, len(v))
    open(sys.argv[1].replace(".tsv", "." + k + ".tsv"), "w", encoding="utf-8").write("\n".join(v) + "\n")
