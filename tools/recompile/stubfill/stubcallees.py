"""Stubbed methods of an assembly that its recovered bodies call: the closure only seeded what the game calls,
so a recovered body can still land on a stub inside the same library (I2's InitializeIfNeeded -> pInstance)."""
import io, json, re, sys
sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, "D:/walking-trade-ref/udk")
from udk.recompile import own_name

W, asm = sys.argv[1], sys.argv[2]
keys = [l.split("\t")[0] for l in io.open(f"{W}/keys.{asm}.tsv", encoding="utf-8").read().splitlines()[1:] if l]
res = {json.loads(l)["Key"]: json.loads(l) for l in io.open(f"{W}/res.best.{asm}.jsonl", encoding="utf-8")}
ok = {k for k, r in res.items() if r["Status"] == "ok"}
by_name = {}
for k in keys:
    by_name.setdefault(own_name(k), []).append(k)
sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent))
from trivial import code_lines

DEFAULT_RETURN = re.compile(r"^return\s+(?:\([^()]*\)\s*)?(?:0|0x0|0\.0|false|NULL)\s*;$")
native = set()
for l in io.open(f"{W}/ghidra.jsonl", encoding="utf-8"):
    r = json.loads(l)
    # A one-line getter (`return this->fields.x;`) is real code; only an empty or default-returning body is not.
    if r.get("asm") == asm and [s for s in code_lines(r["c"]) if not DEFAULT_RETURN.match(s)]:
        native.add(r["key"])
hits = {}
for k in ok:
    for c in res[k].get("Calls") or []:
        for target in by_name.get(c, []):
            if target not in ok and target in native:
                hits.setdefault(target, set()).add(k)
for t, src in sorted(hits.items(), key=lambda x: -len(x[1])):
    print(f"{len(src):3}  {t}   <- {sorted(src)[0]}")
print(f"{len(hits)} stubbed callees reached from {len(ok)} recovered bodies")
