"""Census of methods whose Ghidra C dropped blocks as "unreachable". Ghidra folds a local it cannot track (an out
parameter, a struct on the stack) to a constant and deletes the branch that depends on it, so the LLM translated a
body with the real work missing. Ground truth: native call targets the C no longer mentions. With deployed
decompiles, also says whether the shipped body has those calls anyway (a later Cecil fix, or the LLM guessed).
Read the dropped branches with annodis.py.
Usage: python pruned.py <work dir> <out.tsv> [<asm>=<ilspycmd -p dir>...]"""
import glob, io, json, re, sys
from pathlib import Path
sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, str(Path(__file__).parent))
import backlog

W, out = sys.argv[1], sys.argv[2]
backlog.W = Path(W)
backlog.decomp = dict(a.split("=", 1) for a in sys.argv[3:])


def mentions(text, name):
    if name in (".ctor", ".cctor"):
        return True  # Ghidra and ilspy spell constructors too many ways to tell; not the class of loss we hunt.
    if re.search(rf"__{re.escape(name)}[_(<]|::{re.escape(name)}\b|\b{re.escape(name)}\s*[(<]|\.{re.escape(name)}\b", text):
        return True
    # Decompiled C# spells special names as syntax.
    op = {"op_Equality": r"==", "op_Inequality": r"!=", "op_Implicit": r"\bif\b|!|\?|&&|\|\|",
          "Concat": r"\+|\$\"", "ToString": r"\+|\$\"", "GetTypeFromHandle": r"\btypeof\(",
          "InitializeArray": r"new\s+[\w.]+\[\d*\]\s*\{", "AddWithResize": r"\.Add\("}.get(name)
    if op:
        return re.search(op, text)
    m = re.match(r"(get|set|add|remove)_(\w+)$", name)
    if m:
        kind, prop = m.groups()
        pat = {"get": rf"\b{prop}\b", "set": rf"\b{prop}\s*=[^=]|{prop}\s*\??\?=", "add": rf"\b{prop}\s*\+=", "remove": rf"\b{prop}\s*-="}[kind]
        return re.search(pat, text)
    return None


calls = {}
for l in io.open(f"{W}/native_calls.jsonl", encoding="utf-8"):
    r = json.loads(l)
    calls[r["key"]] = r["calls"]

asm_of = {}
for f in glob.glob(f"{W}/keys.*.tsv"):
    asm = f.replace("\\", "/").rsplit("/keys.", 1)[1][:-4]
    for line in io.open(f, encoding="utf-8").read().splitlines()[1:]:
        asm_of.setdefault(line.split("\t")[0], asm)

rows = []
for l in io.open(f"{W}/ghidra.jsonl", encoding="utf-8"):
    r = json.loads(l)
    n = r["c"].count("Removing unreachable block")
    if not n:
        continue
    names = lambda alts: {a.split("::")[-1].split("(")[0] for a in alts}
    missing = [alts for alts in calls.get(r["key"], []) if not any(mentions(r["c"], x) for x in names(alts))]
    if not missing:
        continue
    asm = asm_of.get(r["key"], "?")
    status = "unknown"
    if asm in backlog.decomp:
        body = backlog.method_body(asm, r["key"])
        if body is None:
            status = "not found"
        else:
            still = [alts[0] for alts in missing if not any(mentions(body, x) for x in names(alts))]
            status = ("open: " + ",".join(dict.fromkeys(still))) if still else "deployed has them"
    lost = ",".join(dict.fromkeys(alts[0] for alts in missing))
    rows.append((r["key"], asm, n, len(calls.get(r["key"], [])), len(missing), status, r.get("addr", ""), lost))

rows.sort(key=lambda x: -x[4])
with io.open(out, "w", encoding="utf-8", newline="\n") as w:
    w.write("key\tasm\tpruned_blocks\tnative_calls\tcalls_missing_from_c\tdeployed\taddr\tmissing\n")
    for row in rows:
        w.write("\t".join(map(str, row)) + "\n")
by = {}
for row in rows:
    a = by.setdefault(row[1], [0, 0])
    a[0] += 1
    a[1] += row[5].startswith("open")
for a, (n, still) in sorted(by.items()):
    print(f"{a:28} {n:4} methods lost native calls to pruning, {still:4} still missing them in the deployed DLL")
