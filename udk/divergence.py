"""Rank recovered methods by how far they diverge from the native code, beyond call recall.

fidelity() in recompile.py only checks that the C# body makes the native method's calls. It scores 1.0 for a ctor
that calls base(0f) where native passes baseWeight, and None for a getter that returns null where native returns a
field. This scorer also compares what the body touches, read from the same files the pipeline already writes:
  calls      native direct calls the body also makes (fidelity's own matching)
  params     parameters native uses that the body (or the ctor initializer) also uses
  stores     fields native assigns that the body assigns
  loads      fields native reads that the body mentions
  consts     numeric constants native uses (not 0, not addresses) that appear in the body
  allocs     types native allocates with il2cpp_object_new that the body news up
score = matched / native features. rank = (1 - score) * log2(2 + native lines) * reach, reach growing with native
callers and with Unity messages and constructors, which the engine calls without a call site.

Usage: python -m udk.divergence <game.json> [out.tsv] [--asm=A,B]
"""
import io
import math
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

from .recompile import (Game, FAITHFUL, UNITY_MESSAGES, fidelity, jsonl, loose, loose_index, native_index, nat_key,
                        own_name, skeleton_keys)

NUM = re.compile(r"(?<![\w.])(-?(?:\d+\.\d*|\.\d+)(?:[eE]-?\d+)?|0x[0-9a-fA-F]+|\d+)(?![\w.])")
FIELD_STORE = re.compile(r"(?:fields\)?(?:\._)*\.|static_fields->)(\w+)\s*=(?!=)\s*([^;]*);")
ZERO_RHS = re.compile(r"^(?:\([^()]*\)\s*)?(?:0|0\.0|0x0|false|NULL|'\\0')$")
FIELD_REF = re.compile(r"(?:fields\)?(?:\._)*\.|static_fields->)(\w+)")
ALLOC = re.compile(r"object_new\(\s*&?\s*TypeInfo__([\w:<>,\s]+?)\s*\)")
CS_NEW = re.compile(r"\bnew\s+([A-Za-z_][\w.]*)")
CS_STORE = re.compile(r"([A-Za-z_]\w*)\s*(?:[+\-*/|&^]|\?\?)?=(?![=>])")
CS_IDENT = re.compile(r"[A-Za-z_]\w*")
CS_NUM = re.compile(r"(?<![\w.])((?:\d+\.\d*|\.\d+|\d+)(?:[eE]-?\d+)?|0x[0-9a-fA-F]+)[fFdDmMuUlL]*(?![\w.])")
NOISE_FIELDS = {"klass", "monitor", "fields", "static_fields", "_"}
# Inlined runtime code, not game logic: SignalBus bookkeeping and delegate internals (each in 2-4% of all methods
# of The Walking Trade), compiler state-machine fields, and the il2cpp sret/state params.
RUNTIME_FIELDS = {"signalcallbacklookup", "reversesubscriptionlookup", "subscriptionlookup",
                  "identifiersubscriptionlookup", "reverseidentifiersubscriptionlookup", "methodcode", "invokeimpl",
                  "method", "methodptr", "invokeimplthis"}
RUNTIME_PARAMS = {"__return_storage_ptr__", "__1__state", "stateMachine"}
# A constant in more than this share of all native methods is runtime boilerplate (3.0 is in 46%, 8.0 in 9%).
CONST_DF_MAX = 0.04


def norm(name):
    name = re.sub(r"_?k__BackingField$", "", name)
    return name.strip("_<>").replace("_", "").lower()


def number(tok):
    try:
        v = float(int(tok, 16)) if tok.lower().startswith(("0x", "-0x")) else float(tok)
    except ValueError:
        return None
    return round(v, 5)


def native_consts(c):
    out = set()
    for m in NUM.finditer(c):
        before = c[max(0, m.start() - 3):m.start()]
        after = c[m.end():m.end() + 3]
        if re.search(r"(\+ |- |\[|>> |<< |& |\| |\^ |% )$", before) or re.match(r" ?(>>|<<|&|\|)", after):
            continue
        v = number(m.group(1))
        if v is None or v == 0 or v in (1.0, -1.0) and "." not in m.group(1) or abs(v) > 0xFFFFFF:
            continue
        out.add(v)
    return out


def native_params(c):
    head = c.split("\n{", 1)[0]
    i = head.rfind("(")
    names = set()
    for p in head[i + 1:].rstrip(") \n").split(","):
        n = re.split(r"[\s*]+", p.strip())[-1] if p.strip() else ""
        if n and n not in ("this", "method", "__this") and not n.startswith("param_"):
            names.add(n)
    return names


def game_field(n):
    k = norm(n)
    return n not in NOISE_FIELDS and k and not k[0].isdigit() and k not in RUNTIME_FIELDS


def native_features(c):
    body = c.split("\n{", 1)[-1]
    all_stores = FIELD_STORE.findall(body)
    stores = {norm(n) for n, rhs in all_stores if game_field(n) and not ZERO_RHS.match(rhs.strip())}
    loads = {norm(n) for n in FIELD_REF.findall(body) if game_field(n)} - {norm(n) for n, _ in all_stores}
    allocs = {re.split(r"__|::", t.split("<", 1)[0])[-1] for t in ALLOC.findall(body)}
    params = {p for p in native_params(c) if p not in RUNTIME_PARAMS and re.search(rf"\b{re.escape(p)}\b", body)}
    return {"params": params, "stores": stores, "loads": loads, "consts": native_consts(body), "allocs": allocs}


def folded(key, c):
    """Identical-code folding: the native body was emitted for another method and only carries its names."""
    typ = re.sub(r"`\d+", "", key.split("::", 1)[0].split("/")[-1].split(".")[-1])
    return typ not in c.split("\n{", 1)[0].split("*/", 1)[-1]


def cs_features(text):
    code = re.sub(r"//[^\n]*", "", text)
    code = re.sub(r'"(?:\\.|[^"\\])*"', '""', code)
    idents = {norm(i) for i in CS_IDENT.findall(code)}
    return {
        "params": set(CS_IDENT.findall(code)),
        "stores": {norm(n) for n in CS_STORE.findall(code)},
        "loads": idents,
        "consts": {v for v in (number(t) for t in CS_NUM.findall(code)) if v is not None},
        "allocs": {n.split(".")[-1] for n in CS_NEW.findall(code)},
    }


def ctor_initializers(path, type_name):
    """All `Type(...) : base/this(...)` initializers of a type in its skeleton file; candidates carry only the body."""
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    simple = re.sub(r"`\d+", "", type_name.split("/")[-1].split(".")[-1])
    return " ".join(m.group(1) for m in re.finditer(rf"\b{re.escape(simple)}\s*\([^()]*\)\s*:\s*((?:base|this)\s*\([^;{{]*\))", text))


def callers(nat):
    n = Counter()
    for r in nat.values():
        for alts in r["calls"]:
            for a in set(alts):
                n[a] += 1
    return n


def score_asm(g, asm, nat, callees, loose_nat, ghidra, n_callers, common_consts):
    files = {}
    for l in g.p(f"keys.{asm}.tsv").read_text(encoding="utf-8").splitlines()[1:]:
        parts = l.split("\t")
        if len(parts) >= 3:
            files[parts[0]] = parts[2]
    best = {r["key"]: r for r in jsonl(g.p(f"cand.best.{asm}.jsonl"))}
    best_loose = {loose(k): r for k, r in best.items()}
    calls_of = {r["Key"]: r.get("Calls") or [] for r in jsonl(g.p(f"res.best.{asm}.jsonl")) if r["Status"] == "ok"}
    for key in skeleton_keys(g, asm, loose_nat):
        nk = nat_key(key, loose_nat) or key
        c = ghidra.get(nk) or ghidra.get(loose(key))
        if not c:
            continue
        cand = best.get(key) or best_loose.get(loose(key))
        body = cand["body"] if cand else ""
        method = key.split("::", 1)[1].split("(", 1)[0]
        if method in (".ctor", ".cctor"):
            body += "\n" + ctor_initializers(files.get(key, ""), key.split("::", 1)[0])
        nf, cf = native_features(c), cs_features(body)
        nf["consts"] -= common_consts
        if folded(key, c):
            nf = {k: set() for k in nf}
        missing = {k: sorted(map(str, nf[k] - cf[k])) for k in nf}
        hits = sum(len(nf[k]) - len(missing[k]) for k in nf)
        total = sum(len(v) for v in nf.values())
        n_calls = len((nat.get(nk) or {}).get("calls") or [])
        if n_calls:
            f = fidelity(key, calls_of.get(key, []) if cand else [], nat, callees, loose_nat) or 0.0
            hits += f * n_calls
            total += n_calls
            if f < FAITHFUL:
                missing["calls"] = [f"{f:.2f} of {n_calls}"]
        if not total:
            continue
        score = hits / total
        if score >= 0.999:
            continue
        lines = c.count("\n")
        reach = 1 + math.log2(1 + n_callers.get(own_name(key), 0))
        if method in UNITY_MESSAGES or method == ".ctor":
            reach *= 1.5
        rank = (1 - score) * math.log2(2 + lines) * reach
        yield rank, score, key, cand["src"] if cand else "stub", lines, {k: v for k, v in missing.items() if v}


def main(argv):
    if len(argv) < 2:
        sys.exit(__doc__)
    g = Game(argv[1])
    only = next((a.split("=", 1)[1].split(",") for a in argv if a.startswith("--asm=")), None)
    rest = [a for a in argv[2:] if not a.startswith("--")]
    out = Path(rest[0]) if rest else g.p("divergence.tsv")
    nat, callees = native_index(g)
    loose_nat = loose_index(nat)
    ghidra = {}
    addr = {}
    for r in jsonl(g.p("ghidra.jsonl")):
        ghidra.setdefault(r["key"], r["c"])
        ghidra.setdefault(loose(r["key"]), r["c"])
        addr.setdefault(r["key"], r.get("addr", ""))
    n_callers = callers(nat)
    const_df = Counter()
    natives = [ghidra[k] for k in addr]
    for c in natives:
        const_df.update(native_consts(c.split("\n{", 1)[-1]))
    common_consts = {v for v, n in const_df.items() if n > CONST_DF_MAX * len(natives)}
    rows = []
    for asm in only or g.assemblies:
        if not g.p(f"keys.{asm}.tsv").exists():
            continue
        rows += [(asm,) + r for r in score_asm(g, asm, nat, callees, loose_nat, ghidra, n_callers, common_consts)]
    rows.sort(key=lambda r: -r[1])
    with io.open(out, "w", encoding="utf-8", newline="\n") as w:
        w.write("rank\tasm\tkey\taddr\tscore\tsrc\tnative_lines\tmissing\n")
        for asm, rank, score, key, src, lines, miss in rows:
            m = "; ".join(f"{k}: {', '.join(v[:6])}" for k, v in miss.items())
            w.write(f"{rank:.2f}\t{asm}\t{key}\t{addr.get(key, '')}\t{score:.2f}\t{src}\t{lines}\t{m}\n")
    by = defaultdict(list)
    for r in rows:
        by[r[0]].append(r[2])
    for asm, scores in by.items():
        print(f"{asm:28} {len(scores):6} divergent, {sum(1 for s in scores if s < 0.5):6} below 0.5")
    print(f"{len(rows)} rows -> {out}")


if __name__ == "__main__":
    main(sys.argv)
