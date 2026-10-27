"""Constructors with no recovered body whose native code allocates objects into fields: their field initializers
are lost, so the first use of the field throws (I2 ResourceManager.mResourcesCache -> GetAsset NRE at boot).
Usage: python ctorgap.py <work dir> <asm>..."""
import io, json, re, sys
sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, "D:/walking-trade-ref/udk")
from udk.recompile import loose

W = sys.argv[1]
nat = {}
for l in io.open(f"{W}/ghidra.jsonl", encoding="utf-8"):
    r = json.loads(l)
    nat.setdefault(loose(r["key"]), r["c"])
STORE = re.compile(r"\(this->fields\)\.(\w+)\s*=\s*p\w+;")
STATIC_STORE = re.compile(r"static_fields->(\w+)\s*=")
for asm in sys.argv[2:]:
    ok = {loose(json.loads(l)["Key"]) for l in io.open(f"{W}/res.best.{asm}.jsonl", encoding="utf-8")
          if json.loads(l)["Status"] == "ok"}
    hits = []
    for l in io.open(f"{W}/keys.{asm}.tsv", encoding="utf-8").read().splitlines()[1:]:
        k = l.split("\t")[0]
        if ("::.ctor(" not in k and "::.cctor(" not in k) or loose(k) in ok:
            continue
        c = nat.get(loose(k), "")
        if "il2cpp_object_new" in c:
            hits.append((k, sorted(set(STORE.findall(c)) | set(STATIC_STORE.findall(c)))))
    print(f"{asm}: {len(hits)} constructors allocate into fields but have no recovered body")
    for k, f in hits:
        print(f"   {k}  fields={f}")
