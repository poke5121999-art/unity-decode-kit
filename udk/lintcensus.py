"""Census of recompile defect classes that compile cleanly but break the game at runtime.

Each class was first found by hand in The Walking Trade (see docs/RECOMPILE.md). The census reads the pipeline's own
files, so it runs on any game config without a build:
  skel/<asm>/**/*.cs        skeleton sources (constructor initializers live here, never in a candidate body)
  cand.best.<asm>.jsonl     {key, src, body} the body assemble picked per method
  ghidra.jsonl              {key, c} native pseudo-C per method

Usage: python -m udk.lintcensus <game.json> [out.tsv] [--decomp=<ilspycmd -p dir of a built DLL>]...
Prints a count per class and writes one row per finding: class, asm, where, evidence.
"""
import re
import sys
from collections import Counter
from pathlib import Path

from .recompile import Game, jsonl, loose

CTOR_INIT = re.compile(r"(\w+)\s*\(([^()]*)\)\s*:\s*base\s*\(([^;{]*)\)\s*\{")
CAST = re.compile(r"^\((?:[\w.]+(?:<[^()]*>)?(?:\[\])?)\)\s*")
DEFAULT_ARG = re.compile(r"^(?:0+(?:\.0+)?[fFdDmMuUlL]*|null|false|default|default\([^()]*\))$")
BACKING_LITERAL = re.compile(r"\"([^\"]*k__BackingField)\"")
GOOD_BACKING = re.compile(r"^<\w+>k__BackingField$")
NATIVE_FIELD_RETURN = re.compile(r"return\s+\(?\s*\(?this->fields\)?\.(\w+)")
NATIVE_CALL = re.compile(r"\b([A-Za-z]\w*__\w+?__)\s*\(")
NATIVE_COLLECTION = re.compile(r"TypeInfo__System__Collections__Generic__((?:List|Dictionary|HashSet|Queue|Stack)<[^\n]*?>)\s*\)")
NEW_COLLECTION = re.compile(r"\bnew\s+(?:[\w.]+\.)?(?:List|Dictionary|HashSet|Queue|Stack)\s*<")
EMPTY_OR_BASE = re.compile(r"\s*(?:base\.\w+\(\s*\)\s*;\s*)?(?:return\s*;\s*)?")
CLASS_DECL = re.compile(r"\b(?:class|struct)\s+(\w+)")
FIELD_DECL = re.compile(r"^\s*(?:\[[^\]\n]*\]\s*)*(?:(?:private|protected|public|internal|readonly|static)\s+)+[\w<>\[\],.? ]+?\s+(\w+)\s*(?:=(?!>)[^;\n]*)?;\s*$", re.M)
NULL_PROP = re.compile(r"\s(\w+)\s*=>\s*null\s*;|\s(\w+)\s*\{\s*get\s*\{\s*return\s+null\s*;\s*\}")
RUNTIME_HELPERS = ("il2cpp_", "thunk_", "System__Object__", "UnityEngine__Object__op_")


def split_args(s):
    out, depth, cur = [], 0, ""
    for ch in s:
        if ch in "(<[":
            depth += 1
        elif ch in ")>]":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def is_default(arg):
    return bool(DEFAULT_ARG.match(CAST.sub("", arg)))


def base_defaults(g, asm):
    """A constructor whose base(...) passes only default literals. The skeleton comes from stub DLLs, and a candidate
    can only replace the body, so every such initializer reaches the built game as-is."""
    root = g.p(f"skel/{asm}")
    for f in sorted(root.rglob("*.cs")):
        text = f.read_text(encoding="utf-8", errors="replace")
        for m in CTOR_INIT.finditer(text):
            args = split_args(m.group(3))
            if args and all(is_default(a) for a in args):
                line = text.count("\n", 0, m.start()) + 1
                yield f"{f.relative_to(root)}:{line}", f"{m.group(1)}({m.group(2).strip()}) : base({m.group(3).strip()})"


def native_index(g):
    nat, asm_of = {}, {}
    for r in jsonl(g.p("ghidra.jsonl")):
        nat.setdefault(r["key"], r["c"])
        asm_of.setdefault(r["key"], r.get("asm"))
    return nat, {loose(k): k for k in nat}, asm_of


def native_for(key, nat, loose_nat):
    if key in nat:
        return nat[key]
    k = loose_nat.get(loose(key))
    return nat.get(k) if k else None


def native_body(c):
    return c.split("{", 1)[1] if "{" in c else ""


def native_calls(key, c):
    own = key.split("::", 1)[1].split("(", 1)[0].replace(".", "__")
    return {n for n in NATIVE_CALL.findall(native_body(c))
            if not n.startswith(RUNTIME_HELPERS) and not n.endswith(f"__{own}__")}


def collections_allocated(c):
    return len(set(NATIVE_COLLECTION.findall(native_body(c))))


def body_findings(g, asm, nat, loose_nat, asm_of):
    best = {r["key"]: r["body"] for r in jsonl(g.p(f"cand.best.{asm}.jsonl"))}
    for key, body in best.items():
        c = native_for(key, nat, loose_nat)
        if re.search(r"::get_\w+\(\)$", key) and re.fullmatch(r"\s*return\s+null\s*;\s*", body):
            fm = NATIVE_FIELD_RETURN.search(c or "")
            if fm:
                yield "null_getter", key, f"native returns this->fields.{fm.group(1)}"
        for lit in BACKING_LITERAL.findall(body):
            if not GOOD_BACKING.match(lit):
                yield "backing_field_name", key, f'"{lit}" (the compiler names it <Prop>k__BackingField)'
        if c is not None and EMPTY_OR_BASE.fullmatch(re.sub(r"//[^\n]*", "", body)):
            calls = native_calls(key, c)
            if len(calls) >= 2:
                yield "thin_body", key, f"body is empty or only base.X() vs {len(calls)} native callees: " + ", ".join(sorted(calls)[:4])
    best_loose = {loose(k) for k in best}
    for key, c in nat.items():
        if asm_of.get(key) != asm or "::.ctor(" not in key and "::.cctor(" not in key:
            continue
        want = collections_allocated(c)
        if not want:
            continue
        body = best.get(key)
        if body is None and loose(key) in best_loose:
            body = next(b for k, b in best.items() if loose(k) == loose(key))
        have = len(NEW_COLLECTION.findall(body or ""))
        if have < want:
            src = "no recovered body" if body is None else f"{have} collection new(s) in the body"
            yield "ctor_init_lost", key, f"native allocates {want} collection type(s), {src}"


def null_getter_fields(decomp):
    """Decompiled-DLL scan: a getter that returns null in a class that declares a field named like the property
    (BaseWeaponObject<T>.Data => null next to `private T _data`). Catches bodies that never went through a candidate."""
    root = Path(decomp)
    for f in sorted(root.rglob("*.cs")):
        text = f.read_text(encoding="utf-8", errors="replace")
        starts = [(m.start(), m.group(1)) for m in CLASS_DECL.finditer(text)] or [(0, f.stem)]
        for i, (pos, cls) in enumerate(starts):
            seg = text[pos:starts[i + 1][0] if i + 1 < len(starts) else len(text)]
            fields = {norm(m.group(1)): m.group(1) for m in FIELD_DECL.finditer(seg)}
            for m in NULL_PROP.finditer(seg):
                prop = m.group(1) or m.group(2)
                fld = fields.get(norm(prop))
                if fld:
                    line = text.count("\n", 0, pos + m.start()) + 1
                    yield f"{f.relative_to(root)}:{line}", f"{cls}.{prop} returns null; field {fld} exists"


def norm(name):
    return re.sub(r"^(m_|_+)", "", name.replace("<", "").replace(">k__BackingField", "")).lower()


def main(argv):
    if len(argv) < 2:
        sys.exit(__doc__)
    g = Game(argv[1])
    decomp = [a.split("=", 1)[1] for a in argv[2:] if a.startswith("--decomp=")]
    argv = [a for a in argv if not a.startswith("--decomp=")]
    out = Path(argv[2]) if len(argv) > 2 else g.p("lintcensus.tsv")
    nat, loose_nat, asm_of = native_index(g)
    rows = []
    for asm in g.assemblies:
        if g.p(f"skel/{asm}").exists():
            rows += [("base_defaults", asm, where, ev) for where, ev in base_defaults(g, asm)]
        if g.p(f"cand.best.{asm}.jsonl").exists():
            rows += [(cls, asm, key, ev) for cls, key, ev in body_findings(g, asm, nat, loose_nat, asm_of)]
    for d in decomp:
        rows += [("null_getter_field", Path(d).name, where, ev) for where, ev in null_getter_fields(d)]
    with out.open("w", encoding="utf-8", newline="\n") as w:
        w.write("class\tasm\twhere\tevidence\n")
        for r in rows:
            w.write("\t".join(x.replace("\t", " ").replace("\n", " ") for x in r) + "\n")
    counts = Counter((r[0], r[1]) for r in rows)
    for (cls, asm), n in sorted(counts.items()):
        print(f"{cls:20} {asm:30} {n}")
    print(f"{len(rows)} findings -> {out}")


if __name__ == "__main__":
    main(sys.argv)
