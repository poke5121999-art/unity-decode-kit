"""Backlog of census findings checked against the DEPLOYED DLLs, so Cecil/xplant fixes that the pipeline does not
know about are not reported again. Reads the census outputs of one work dir and an ilspycmd -p decompile per assembly.
Usage: python backlog.py <work dir> <asm>=<decompile dir>... > backlog.tsv
Status: open (deployed body still stub/default/missing), patched (deployed body has real code), unknown (not found)."""
import io, json, re, sys
from pathlib import Path
sys.stdout.reconfigure(encoding="utf-8")

W = Path(sys.argv[1]) if __name__ == "__main__" else None
decomp = dict(a.split("=", 1) for a in sys.argv[2:]) if __name__ == "__main__" else {}
STUB = re.compile(r"^\s*(?:return\s+(?:null|default(?:\([^)]*\))?|0[fFdDmMuUlL]?|0\.0[fFdD]?|false)\s*;)?\s*$")
_files = {}


def type_text(asm, typ):
    """Source of a type in an ilspycmd -p tree: <dir>/<Namespace>/<Type>.cs, nested types inside their parent."""
    key = (asm, typ)
    if key not in _files:
        root = Path(decomp[asm])
        top = re.sub(r"`\d+", "", typ.split("/")[0])
        ns, _, name = top.rpartition(".")
        cands = [root / ns / f"{name}.cs", root / f"{name}.cs"] + list(root.glob(f"**/{name}.cs"))
        _files[key] = next((p.read_text(encoding="utf-8", errors="replace") for p in cands if p.exists()), None)
    return _files[key]


def method_body(asm, key):
    typ, rest = key.split("::", 1)
    name = rest.split("(", 1)[0]
    nparams = 0 if rest.endswith("()") else rest.count(",") + 1
    text = type_text(asm, typ)
    if text is None:
        return None
    simple = re.sub(r"`\d+", "", typ.split("/")[-1].split(".")[-1])
    if name in (".ctor", ".cctor"):
        pat = rf"(?:static\s+)?{re.escape(simple)}\s*\(([^)]*)\)\s*(:\s*(?:base|this)\s*\([^)]*\))?\s*\{{"
        if name == ".cctor":
            pat = rf"static\s+{re.escape(simple)}\s*\(\s*\)\s*\{{"
    elif name.startswith(("get_", "set_")):
        prop = name[4:]
        m = re.search(rf"\b{re.escape(prop)}\s*(=>\s*([^;]+);|\{{)", text)
        if not m:
            return None
        if m.group(2) is not None:
            return m.group(2)
        start = m.end()
        acc = "get" if name.startswith("get_") else "set"
        block = balanced(text, start - 1)
        am = re.search(rf"\b{acc}\s*(=>\s*([^;]+);|\{{)", block)
        if not am:
            return None
        return am.group(2) if am.group(2) is not None else balanced(block, am.end() - 1)[1:-1]
    else:
        pat = rf"\b{re.escape(name)}\s*(?:<[^>]*>)?\s*\(([^)]*)\)\s*(?:where[^{{]*)?\{{"
    for m in re.finditer(pat, text):
        params = m.group(1) if m.groups() else ""
        n = 0 if not params.strip() else params.count(",") + 1
        if name == ".cctor" or n == nparams:
            body = balanced(text, m.end() - 1)
            init = m.group(2) if name == ".ctor" and m.lastindex and m.lastindex >= 2 and m.group(2) else ""
            return (init + "\n" + body[1:-1]) if init else body[1:-1]
    return None


def balanced(text, i):
    depth = 0
    for j in range(i, len(text)):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                return text[i:j + 1]
    return text[i:]


_native = None


def native_c(key):
    global _native
    if _native is None:
        _native = {}
        for l in io.open(W / "ghidra.jsonl", encoding="utf-8"):
            r = json.loads(l)
            _native.setdefault(r["key"], r["c"])
    return _native.get(key)


def status(asm, key, needs=()):
    if asm not in decomp:
        return "unknown", "no decompile for asm"
    body = method_body(asm, key)
    if body is None:
        if "::.ctor(" in key or "::.cctor(" in key:
            # ilspycmd omits compiler-generated empty ctors; only a native body that stores fields is a real gap.
            c = native_c(key)
            if c is not None and not re.search(r"fields\)?(?:\._)*\.\w+\s*=|static_fields->\w+\s*=", c.split("\n{", 1)[-1]):
                return "patched", "empty ctor; native stores no fields"
        return "open", "not in deployed DLL"
    code = re.sub(r"//[^\n]*", "", body)
    if STUB.match(code):
        return "open", "deployed body is a stub"
    miss = [n for n in needs if not re.search(rf"\b{re.escape(n)}\b", code)]
    if miss:
        return "open", "deployed body lacks " + ", ".join(miss)
    return "patched", ""


def main():
  rows = []
  for f in sorted((W / "census").glob("stubcallees.*.txt")):
      asm = f.name[len("stubcallees."):-4]
      for line in f.read_text(encoding="utf-8").splitlines():
          m = re.match(r"\s*(\d+)\s+(\S+)\s+<-\s+(\S+)", line)
          if m:
              st, why = status(asm, m.group(2))
              rows.append(("stub_callee", asm, m.group(2), st, f"called by {m.group(3)} ({m.group(1)}x); {why}"))
  ctor = (W / "census" / "ctorgap.txt").read_text(encoding="utf-8").splitlines() if (W / "census" / "ctorgap.txt").exists() else []
  asm = None
  for line in ctor:
      m = re.match(r"^(\S+): \d+ constructors", line)
      if m:
          asm = m.group(1)
          continue
      m = re.match(r"\s+(\S+)\s+fields=\[(.*)\]", line)
      if m and asm:
          fields = [x.strip(" '") for x in m.group(2).split(",") if x.strip()]
          st, why = status(asm, m.group(1), [re.sub(r"^_?(\w+?)_k__BackingField$", r"\1", x) for x in fields])
          rows.append(("ctor_gap", asm, m.group(1), st, why))
  lint = W / "census" / "lintcensus.tsv"
  if lint.exists():
      for line in lint.read_text(encoding="utf-8").splitlines()[1:]:
          cls, asm, where, ev = line.split("\t", 3)
          if cls == "ctor_init_lost":
              st, why = status(asm, where)
              rows.append((cls, asm, where, st, ev + ("; " + why if why else "")))
          elif cls == "base_defaults":
              rows.append((cls, asm, where, "check", ev))
          else:
              rows.append((cls, asm, where, "check", ev))
  blobs = W / "census" / "rvablobs.jsonl"
  if blobs.exists():
      seen = set()
      for r in map(json.loads, io.open(blobs, encoding="utf-8")):
          if "values" not in r or (r["key"], r["hash"]) in seen:
              continue
          seen.add((r["key"], r["hash"]))
          asm = next((a for a in decomp if r["key"].startswith(("Runtime.", "FXV.")) and a == "Runtime" or a == "Assembly-CSharp"), None)
          body = None
          for a in decomp:
              body = method_body(a, r["key"])
              if body is not None:
                  asm = a
                  break
          vals = [v for v in r["values"] if v != "..."]
          sig = [str(int(v)) if float(v).is_integer() else repr(v).rstrip("0") for v in vals if v not in (0, 0.0)][:4]
          if body is None:
              st, why = "unknown", "method not found in deployed decompile"
          elif all(re.search(rf"(?<![\d.]){re.escape(s)}", body) for s in sig):
              st, why = "patched", ""
          else:
              st, why = "open", "real values not in deployed body"
          rows.append(("blob_data", asm or "?", r["key"], st, f"{r['elem']}[{r['count']}]={vals[:12]}; {why}"))

  print("class\tasm\tkey\tstatus\tdetail")
  for r in rows:
      print("\t".join(str(x).replace("\t", " ") for x in r))


if __name__ == "__main__":
    main()
