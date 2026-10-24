"""Recover compilable C# method bodies for an IL2CPP game and measure how many survive.

Data flow, one record shape per stage (all JSONL, keyed by the same method key):
  ghidra.jsonl     {key, addr, c}                  native pseudo-C per method (udk dump)
  cand.<src>.jsonl {key, src, body}                a candidate C# body from one producer
  res.<src>.jsonl  {Key, Src, Status, Errors, ...} the Roslyn oracle verdict for each candidate

Method key: "<Namespace.Type/Nested`N>::<metadata name>(<short param types>)", the format Oracle's
Keys.Method writes for skeleton symbols. Producers only need to get close; Oracle matches loosely.

Usage: python -m udk.recompile <config.json> <command> [args]
  prep                    build ghidra.jsonl, strings.tsv, offsets.jsonl
  pack <key>              print the translator context for one method
  llm <asm> <keys-file>   translate+repair the listed methods, append to cand.llm.jsonl
  score                   coverage report over every producer
"""
import concurrent.futures as cf
import json
import os
import random
import re
import subprocess
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
ORACLE = HERE.parent / "tools" / "recompile" / "oracle.sh"


class Game:
    def __init__(self, cfg_path):
        cfg = json.loads(Path(cfg_path).read_text(encoding="utf-8"))
        self.cfg = cfg
        self.work = Path(cfg["work"])
        self.dump = Path(cfg["udk_dump"])
        self.assemblies = cfg["assemblies"]
        self.work.mkdir(parents=True, exist_ok=True)
        os.environ.setdefault("UNITY_DATA", cfg["unity_data"])
        os.environ.setdefault("GAME_PLUGINS", cfg["plugins"])

    def p(self, name):
        return self.work / name


def jsonl(path):
    if not Path(path).exists():
        return []
    with open(path, encoding="utf-8") as f:
        return [json.loads(l) for l in f if l.strip()]


def write_jsonl(path, rows, mode="w"):
    with open(path, mode, encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


# ---------- keys ----------

def split_top(s, sep=","):
    out, depth, cur = [], 0, ""
    for ch in s:
        if ch in "[<(":
            depth += 1
        elif ch in "]>)":
            depth -= 1
        if ch == sep and depth == 0:
            out.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur)
    return [x.strip() for x in out]


def short_type(t):
    t = t.strip()
    suffix = ""
    while True:
        if t.endswith("[]"):
            suffix = "[]" + suffix
            t = t[:-2]
        elif t.endswith("&") or t.endswith("*"):
            suffix = t[-1] + suffix
            t = t[:-1]
        else:
            break
    t = re.sub(r"\[.*\]$", "", t)
    t = re.sub(r"`\d+$", "", t)
    t = re.split(r"[.+/]", t)[-1]
    return t + suffix


def ghidra_type_from_path(rel):
    """Runtime/Runtime/Vehicle/A+_B_d__3.c -> (Runtime, Runtime.Vehicle.A/_B_d__3, is_generic_instance)"""
    rel = rel[:-2] if rel.endswith(".c") else rel
    parts, depth, cur = [], 0, ""
    for ch in rel:
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
        if ch == "/" and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    parts.append(cur)
    asm, ns, typ = parts[0], parts[1:-1], parts[-1]
    inst = "[" in typ
    typ = re.sub(r"\[[^\]]*(\[[^\]]*\][^\]]*)*\]", "", typ).replace("+", "/")
    return asm, ".".join(ns + [typ]), inst


def ghidra_key(typ, c_name, sig):
    m = re.match(r"^(?:(\S+)\s+)?([^\s(]+)\((.*)\)$", sig.strip())
    if not m:
        return None
    name, params = m.group(2), m.group(3)
    simple = typ.split("/")[-1].split(".")[-1]
    if m.group(1) is None or name == re.sub(r"`\d+$", "", simple):
        name = ".cctor" if c_name.endswith("__cctor") else ".ctor"
    ps = ",".join(short_type(x) for x in split_top(params))
    return f"{typ}::{name}({ps})"


# ---------- prep ----------

def oracle(*args):
    out = subprocess.run(["sh", str(ORACLE), *map(str, args)], capture_output=True, text=True, encoding="utf-8")
    if out.returncode != 0:
        raise RuntimeError(out.stdout[-1500:] + out.stderr[-1500:])
    return out.stdout


def oracle_tool(*args):
    dll = HERE.parent / "tools" / "recompile" / "Oracle" / "bin" / "Release" / "net8.0" / "Oracle.dll"
    out = subprocess.run(["dotnet", str(dll), *map(str, args)], capture_output=True, text=True, encoding="utf-8")
    if out.returncode != 0:
        raise RuntimeError(out.stdout[-1500:] + out.stderr[-1500:])
    return out.stdout


def prep_skeletons(g):
    for asm in g.assemblies:
        skel = g.p(f"skel/{asm}")
        if not skel.exists():
            subprocess.run(["ilspycmd", "-p", "-o", str(skel), str(Path(g.cfg["plugins"]) / f"{asm}.dll")], check=True,
                           capture_output=True)
            print(oracle("repair", skel, asm, "--orig", Path(g.cfg["plugins"]) / f"{asm}.dll").strip())
        print(oracle("index", skel, asm, "--out", g.p(f"keys.{asm}.tsv")).strip().split("\n")[0])
        print(oracle_tool("decls", "--src", skel, "--out", g.p(f"decls.{asm}.jsonl")).strip())


def baseline(g):
    root = g.cfg.get("il2csharp")
    for asm in g.assemblies:
        if not root or not (Path(root) / asm).exists():
            continue
        cand = g.p(f"cand.il2csharp.{asm}.jsonl")
        oracle_tool("extract", "--src", Path(root) / asm, "--out", cand, "--srcname", "il2csharp")
        out = oracle("compile", g.p(f"skel/{asm}"), asm, "--candidates", cand, "--out", g.p(f"res.il2csharp.{asm}.jsonl"))
        print(asm, out.strip().split("\n")[-1])


def prep(g):
    prep_skeletons(g)
    rows, by_key = [], {}
    files = {}
    with open(g.dump / "code" / "methods.tsv", encoding="utf-8", errors="replace") as f:
        next(f)
        for line in f:
            c_name, sig, addr, rel, ln = line.rstrip("\n").split("\t")
            asm, typ, inst = ghidra_type_from_path(rel)
            if asm not in g.assemblies:
                continue
            key = ghidra_key(typ, c_name, sig)
            if key is None:
                continue
            prev = by_key.get(key)
            if prev is not None and (inst or not prev["inst"]) and "Canon" not in rel:
                continue
            files.setdefault(rel, None)
            by_key[key] = {"key": key, "asm": asm, "addr": addr, "rel": rel, "line": int(ln), "inst": inst}
    unreadable = 0
    for rel in files:
        try:
            files[rel] = (g.dump / "code" / "decomp" / rel).read_text(encoding="utf-8", errors="replace").split("\n")
        except OSError:
            # A dump made on Linux can hold names Windows cannot (| in local-function types); tar skips them.
            files[rel] = []
            unreadable += 1
    if unreadable:
        print(f"decomp files unreadable on this OS: {unreadable}")
    for r in by_key.values():
        lines = files[r["rel"]]
        i = r["line"] - 1
        j = i + 1
        while j < len(lines) and not re.match(r"^// .*  @0x[0-9A-Fa-f]+$", lines[j]):
            j += 1
        r["c"] = "\n".join(lines[i:j]).strip()
        del r["line"]
        rows.append(r)
    write_jsonl(g.p("ghidra.jsonl"), rows)
    print(f"ghidra.jsonl: {len(rows)} methods in {sorted(Counter(r['asm'] for r in rows).items())}")

    lits = {}
    pat = re.compile(r'"name": "(StringLiteral_[^"]*)",\s*"string": "((?:[^"\\]|\\.)*)"')
    buf = (g.dump / "inspector" / "metadata.json").read_text(encoding="utf-8")
    for m in pat.finditer(buf):
        lits[m.group(1)] = json.loads('"' + m.group(2) + '"')
    with open(g.p("strings.tsv"), "w", encoding="utf-8") as f:
        for k, v in lits.items():
            f.write(k + "\t" + json.dumps(v, ensure_ascii=False) + "\n")
    print(f"strings.tsv: {len(lits)} literals")

    offs, ns, cur = {}, "", None
    for line in (g.dump / "inspector" / "types.cs").read_text(encoding="utf-8", errors="replace").split("\n"):
        m = re.match(r"^namespace (\S+)", line)
        if m:
            ns = m.group(1)
            continue
        m = re.match(r"^\s*(?:\[.*\]\s*)?(?:public|internal|private|protected|sealed|abstract|static|\s)*\s*(?:class|struct|enum|interface) ([^\s:<]+(?:<[^>]*>)?).*// TypeDefIndex", line)
        if m:
            cur = offs.setdefault(re.sub(r"<.*", "", m.group(1)), [])
            continue
        m = re.match(r"^\s*(?:\[.*?\]\s*)*((?:public|private|protected|internal|static|readonly|const|\s)+)\s*(.+?)\s+(\S+?)(?: = .*)?; // (0x[0-9A-F]+)$", line)
        if m and cur is not None and "const" not in m.group(1):
            cur.append(f"{m.group(4)} {'static ' if 'static' in m.group(1) else ''}{m.group(2)} {m.group(3)}")
    write_jsonl(g.p("offsets.jsonl"), [{"type": k, "fields": v} for k, v in offs.items() if v])
    print(f"offsets.jsonl: {len(offs)} types")


# ---------- context ----------

class Context:
    def __init__(self, g):
        self.g = g
        self.ghidra = {r["key"]: r for r in jsonl(g.p("ghidra.jsonl"))}
        self.decls, self.decl_by_name = {}, defaultdict(list)
        for asm in g.assemblies:
            for d in jsonl(g.p(f"decls.{asm}.jsonl")):
                self.decls[d["type"]] = d
                self.decl_by_name[d["name"]].append(d)
        self.offsets = {r["type"]: r["fields"] for r in jsonl(g.p("offsets.jsonl"))}
        self.strings = {}
        for line in g.p("strings.tsv").read_text(encoding="utf-8").split("\n"):
            if "\t" in line:
                k, v = line.split("\t", 1)
                self.strings[k] = v
        self.il2csharp = {r["key"]: r["body"] for asm in g.assemblies for r in jsonl(g.p(f"cand.il2csharp.{asm}.jsonl"))}
        self.loose = {}
        for k in list(self.ghidra) + list(self.il2csharp):
            self.loose.setdefault(loose(k), k)

    def lookup(self, table, key):
        if key in table:
            return table[key]
        alt = self.loose.get(loose(key))
        return table.get(alt) if alt else None

    def decl_of(self, typ):
        return self.decls.get(typ) or next((d for k, d in self.decls.items() if loose(k + "::x()") == loose(typ + "::x()")), None)

    def native(self, key):
        gh = self.lookup(self.ghidra, key)
        return gh["c"] if gh else "(no native decompilation found)"

    def pack(self, keys, native_calls=None, budget=60000, draft_cap=3000):
        """Translator context for methods sharing one declaring type: shared declarations first, then each method."""
        typ = keys[0].split("::")[0]
        decl = self.decl_of(typ)
        outer = typ.rsplit("/", 1)[0] if "/" in typ else None
        parts = []
        if decl:
            parts.append("DECLARING TYPE (C# skeleton, bodies removed):\n" + decl["text"])
        if outer and outer in self.decls:
            parts.append("ENCLOSING TYPE:\n" + self.decls[outer]["text"])
        tokens, sections = set(), []
        for k in keys:
            c = self.native(k)
            tokens |= set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", c))
            sec = [f"### {k}"]
            nc = (native_calls or {}).get(k)
            if nc:
                sec.append("NATIVE CALLS (direct calls in machine-code order; identical-code-folding alternatives "
                           "separated by |):\n" + "\n".join(" | ".join(alts) for alts in nc))
            sec.append("NATIVE DECOMPILATION (Ghidra, IL2CPP x64):\n" + c)
            il = self.lookup(self.il2csharp, k)
            if il:
                il = il.strip()
                sec.append("il2csharp DRAFT (often wrong, pointer arithmetic):\n" + (il[:draft_cap] + "\n..." if len(il) > draft_cap else il))
            sections.append("\n".join(sec))
        names = {piece for t in tokens for piece in re.split(r"__+", t) if piece in self.decl_by_name}
        own = self._simple(typ)
        scope = names | {own} | ({self._simple(outer)} if outer else set())
        offs = [f"{n}: " + "; ".join(self.offsets[n]) for n in sorted(scope) if n in self.offsets]
        lits = [f"{k} = {self.strings[k]}" for k in sorted(tokens) if k in self.strings]
        if offs:
            parts.append("FIELD OFFSETS (from IL2CPP metadata; object header is 0x10 bytes):\n" + "\n".join(offs))
        if lits:
            parts.append("STRING LITERALS:\n" + "\n".join(lits))
        fixed = len("\n\n".join(parts + sections))
        ref_txt = ""
        for n in sorted(names - {own}):
            r = self.decl_by_name[n][0]["text"]
            if fixed + len(ref_txt) + len(r) > budget:
                break
            ref_txt += r + "\n"
        if ref_txt:
            parts.append("REFERENCED TYPES (C# skeletons):\n" + ref_txt)
        return "\n\n".join(parts + ["METHODS TO TRANSLATE:"] + sections)

    @staticmethod
    def _simple(t):
        return t.split("/")[-1].split(".")[-1]


def loose(key):
    k = key.replace("_003C", "_").replace("_003E", "_").replace("<", "_").replace(">", "_")
    i = k.find("::")
    p = k.find("(", i)
    name = k[i + 2:p]
    dots = name.split(".")
    if len(dots) > 2:
        name = dots[-2] + "." + dots[-1]
    ps = re.sub(r"(_|`)\d+(?=[,)\[&*])", "", k[p:])
    return k[:i + 2] + name + ps


# ---------- llm ----------

SYSTEM = """You translate IL2CPP native decompilation back into the original C# method bodies of a Unity game.
Write idiomatic, managed C# that compiles inside the given declaring type: no unsafe code, no pointers, no offsets.
IL2CPP noise to drop: il2cpp_init_metadata / runtime_class_init guards, MethodInfo* arguments, explicit null-reference
throws (C# throws them implicitly), GC write-barrier loops after stores (LOCK/UNLOCK bit sets), array bounds checks.
Idioms: rgctx get_Instance chains are Singleton<T>.Instance; il2cpp_object_new(TypeInfo_X)+ctor is `new X(...)`;
delegate ctor(obj, MethodInfo_M) is a method group; *(T*)(p+0xNN) is the field at that offset (see FIELD OFFSETS);
klass->static_fields->F is a static field; vtable calls (klass->vtable[n].methodPtr) are virtual/interface calls.
UnityEngine.Object null checks (op_Implicit / op_Inequality calls) must stay `obj != null` / `if (obj)` on the Unity type.
NATIVE CALLS lists what the machine code really calls: every listed call should appear in your body (small getters
may have been inlined away, so the reverse does not hold). Identical-code folding means a callee's name can belong
to an unrelated type with the same machine code; pick the alternative that fits the types and arguments.
Constructors: write field initialisations and other statements only; the base constructor call is implicit.
Async/iterator MoveNext bodies stay explicit state machines over the struct's own fields.
For each method reply with a line `### <method key>` followed by one ```csharp block holding only the body statements
(no signature, no outer braces)."""


def call_llm(prompt, model, timeout=600):
    cmd = ["claude", "-p", "--model", model, "--system-prompt", SYSTEM, "--tools", "", "--strict-mcp-config",
           "--setting-sources", "", "--no-session-persistence", "--output-format", "json"]
    t0 = time.time()
    try:
        r = subprocess.run(cmd, input=prompt, capture_output=True, text=True, encoding="utf-8", timeout=timeout)
        d = json.loads(r.stdout)
    except (subprocess.TimeoutExpired, json.JSONDecodeError) as e:
        return None, {"error": type(e).__name__, "secs": round(time.time() - t0, 1)}
    u = d.get("usage", {})
    meta = {"in": u.get("input_tokens", 0) + u.get("cache_read_input_tokens", 0) + u.get("cache_creation_input_tokens", 0),
            "out": u.get("output_tokens", 0), "secs": round(time.time() - t0, 1), "cost": d.get("total_cost_usd") or 0}
    if d.get("is_error"):
        meta["error"] = (d.get("result") or "")[:200]
        return None, meta
    return d.get("result") or "", meta


def parse_bodies(text, keys):
    """### <key> + ```csharp block per method; a lone block answers a single-method prompt."""
    out = {}
    by_loose = {loose(k): k for k in keys}
    for m in re.finditer(r"###\s*(.+?)\s*\n+```(?:csharp|cs|c#)?[ \t]*\n(.*?)```", text, re.S):
        k = m.group(1).strip().strip("`")
        k = k if k in keys else (by_loose.get(loose(k)) if "::" in k and "(" in k else None)
        if k:
            out[k] = m.group(2)
    if not out and len(keys) == 1:
        m = re.search(r"```(?:csharp|cs|c#)?[ \t]*\n(.*?)```", text, re.S)
        if m:
            out[keys[0]] = m.group(1)
    for k, b in out.items():
        b = b.strip()
        if b.startswith("{") and b.endswith("}"):
            b = b[1:-1]
        out[k] = b
    return out


def oracle_compile(g, asm, cands, tag):
    cpath, rpath = g.p(f"cand.{tag}.jsonl"), g.p(f"res.{tag}.jsonl")
    write_jsonl(cpath, cands)
    out = oracle("compile", g.p(f"skel/{asm}"), asm, "--candidates", cpath, "--out", rpath)
    return {r["Key"]: r for r in jsonl(rpath)}, out.strip().split("\n")[-1]


def batches(keys, ctx, max_methods=8, max_chars=30000):
    by_type = defaultdict(list)
    for k in keys:
        by_type[k.split("::")[0]].append(k)
    for ks in by_type.values():
        cur, size = [], 0
        for k in ks:
            n = len(ctx.native(k))
            if cur and (len(cur) >= max_methods or size + n > max_chars):
                yield cur
                cur, size = [], 0
            cur.append(k)
            size += n
        if cur:
            yield cur


FAITHFUL = 0.8


def rank(st):
    """Order of preference between two attempts at one method."""
    if st is None or st.get("status") != "ok":
        return (0, 0.0)
    f = st.get("fidelity")
    return (2 if f is None or f >= FAITHFUL else 1, 1.0 if f is None else f)


def run_llm(g, asm, keys_file, model="haiku", rounds=3, workers=8):
    ctx = Context(g)
    nat, callees = native_index(g)
    loose_nat = {loose(k): k for k in nat}
    keys = [k.strip() for k in Path(keys_file).read_text(encoding="utf-8").split("\n") if k.strip()]
    calls_of = {}
    for k in keys:
        r = nat.get(k) or nat.get(loose_nat.get(loose(k), ""))
        if r and r["calls"]:
            calls_of[k] = r["calls"]
    log_path = g.p(f"llm.{asm}.log.jsonl")
    done = {r["key"] for r in jsonl(log_path) if r.get("final")}
    keys = [k for k in keys if k not in done]
    print(f"llm {asm}: {len(keys)} methods to translate with {model}", flush=True)
    best, retry, pending = {}, {}, list(keys)
    for rnd in range(1, rounds + 1):
        if not pending:
            break
        if rnd == 1:
            jobs = [(b, ctx.pack(b, calls_of)) for b in batches(pending, ctx)]
        else:
            jobs = []
            for k in pending:
                prev = best[k]
                if prev["status"] == "ok":
                    fb = "It compiles, but these NATIVE CALLS are missing from it:\n" + "\n".join(" | ".join(a) for a in retry[k])
                else:
                    fb = "COMPILER ERRORS:\n" + "\n".join(prev["errors"])
                jobs.append(([k], ctx.pack([k], calls_of) + "\n\nYOUR PREVIOUS BODY FOR " + k + ":\n```csharp\n" +
                             (prev["body"] or "") + "\n```\n" + fb + "\nReply with the corrected body."))

        def job(item):
            ks, prompt = item
            text, meta = call_llm(prompt, model)
            return ks, (parse_bodies(text, ks) if text is not None else {}), meta

        with cf.ThreadPoolExecutor(workers) as ex:
            results = list(ex.map(job, jobs))
        cands, logs, got = [], [], {}
        tin = tout = 0
        cost = 0.0
        for ks, bodies, meta in results:
            tin += meta.get("in", 0)
            tout += meta.get("out", 0)
            cost += meta.get("cost", 0) or 0
            for k in ks:
                if k in bodies:
                    got[k] = bodies[k]
                    cands.append({"key": k, "src": "llm", "body": bodies[k]})
        verdict, summary = oracle_compile(g, asm, cands, f"llmround.{asm}") if cands else ({}, "no candidates")
        nxt = []
        for k in pending:
            v = verdict.get(k)
            st = {"status": v["Status"] if v else "llm_fail", "errors": (v or {}).get("Errors", [])[:4],
                  "body": got.get(k), "calls": (v or {}).get("Calls") or []}
            if st["status"] == "ok":
                st["fidelity"] = fidelity(k, st["calls"], nat, callees, loose_nat)
            if k not in best or rank(st) > rank(best[k]):
                best[k] = st
            b = best[k]
            missing = []
            if b["status"] == "ok" and b.get("fidelity") is not None and b["fidelity"] < FAITHFUL:
                missing = [alts for alts in calls_of.get(k, []) if not any(x in set(b["calls"]) for x in alts)]
            fixable = b["status"] in ("compile_error", "syntax_error", "llm_fail") or bool(missing)
            again = rnd < rounds and fixable
            if b["status"] == "llm_fail":
                b["errors"] = ["(no answer parsed; reply with a ### key line and one csharp block)"]
            logs.append({"key": k, "round": rnd, "status": st["status"], "fidelity": st.get("fidelity"),
                         "final": not again, "errors": st["errors"], "body": None if again else b["body"],
                         "best_status": b["status"], "best_fidelity": b.get("fidelity")})
            if again:
                retry[k] = missing
                nxt.append(k)
        write_jsonl(log_path, logs, mode="a")
        write_jsonl(g.p(f"llm.{asm}.cost.jsonl"), [{"round": rnd, "prompts": len(jobs), "methods": len(pending),
                                                   "in": tin, "out": tout, "cost": round(cost, 3)}], mode="a")
        print(f"round {rnd}: {len(jobs)} prompts, in={tin} out={tout} cost=${cost:.2f}; {summary}", flush=True)
        pending = nxt
    merged = {r["key"]: r for r in jsonl(g.p(f"cand.llm.{asm}.jsonl"))}
    for r in jsonl(log_path):
        if r.get("final") and r.get("best_status", r["status"]) == "ok" and r.get("body"):
            merged[r["key"]] = {"key": r["key"], "src": "llm", "body": r["body"]}
    write_jsonl(g.p(f"cand.llm.{asm}.jsonl"), merged.values())
    print(f"cand.llm.{asm}.jsonl: {len(merged)} compiling bodies so far", flush=True)


# ---------- score ----------

def native_index(g):
    nat = {r["key"]: r for r in jsonl(g.p("native_calls.jsonl"))}
    callees = json.loads(g.p("callees.json").read_text(encoding="utf-8")) if g.p("callees.json").exists() else {}
    for k, r in nat.items():
        typ, rest = k.split("::", 1)
        callees.setdefault(simple_name(typ) + "::" + rest.split("(")[0], [x for alts in r["calls"] for x in alts])
    return nat, callees


def simple_name(typ):
    return re.sub(r"`\d+", "", typ.split("/")[-1].split(".")[-1])


# Names too common to identify a callee without its type.
COMMON = {".ctor", ".cctor", "Invoke", "get_Item", "set_Item", "MoveNext", "Dispose", "GetEnumerator", "get_Current",
          "Add", "Remove", "Clear", "Contains", "get_Count", "Equals", "GetHashCode", "ToString", "op_Equality",
          "op_Inequality", "op_Implicit", "op_Explicit", "Start", "SetResult", "SetException", "GetResult",
          "get_IsCompleted", "GetAwaiter", "Create", "get_Instance", "TryGetValue", "set_Value", "get_Value"}


def fidelity(key, calls, nat, callees, loose_nat):
    """Share of the native method's resolved direct calls that the C# body also makes (None: nothing to compare).

    A C# call counts for the native callees it was inlined into (one level), and an async builder's Start counts
    for the state machine's MoveNext it always runs. Name-only matches skip names too common to identify a callee.
    """
    r = nat.get(key) or nat.get(loose_nat.get(loose(key), ""))
    if r is None or not r["calls"]:
        return None
    have = set(calls)
    for c in calls:
        have.update(callees.get(c, ()))
    names = {c.split("::")[-1] for c in have} - COMMON
    starts_sm = any(c.endswith("::Start") and "Builder" in c for c in calls)

    def hit(alts):
        for a in alts:
            t, n = a.split("::", 1)
            if a in have or n in names:
                return True
            if n == "MoveNext" and "d__" in t and starts_sm:
                return True
        return False

    return sum(1 for alts in r["calls"] if hit(alts)) / len(r["calls"])


def skeleton_keys(g, asm, loose_nat):
    """Bodies the game really has: every skeleton body, plus re-added constructors only where native code exists."""
    out = []
    for l in g.p(f"keys.{asm}.tsv").read_text(encoding="utf-8").splitlines()[1:]:
        if not l:
            continue
        key, kind = l.split("\t")[:2]
        if kind.startswith("new") and loose(key) not in loose_nat:
            continue
        out.append(key)
    return out


def native_coverage(g, asm, skel_set, best, gh_keys):
    """Classify native methods: recovered body (best compiling, managed), compiler-generated (auto-property or
    field-like event accessor the declaration already implies), or not recovered."""
    skel_loose = {loose(k): k for k in skel_set}
    decls = {d["type"]: d["text"] for d in jsonl(g.p(f"decls.{asm}.jsonl"))}
    row = Counter(asm=0, native=0, body=0, faithful=0, auto=0, missing=0)
    for k in gh_keys:
        row["native"] += 1
        sk = k if k in skel_set else skel_loose.get(loose(k))
        if sk is not None:
            if sk in best:
                row["body"] += 1
                row["faithful"] += best[sk] is None or best[sk] >= FAITHFUL
            else:
                row["missing"] += 1
            continue
        typ, rest = k.split("::", 1)
        name = rest.split("(")[0]
        m = re.match(r"^(get_|set_|add_|remove_)(.+)$", name)
        text = decls.get(typ) or next((t for kk, t in decls.items() if loose(kk + "::x()") == loose(typ + "::x()")), "")
        if m and re.search(r"\b" + re.escape(m.group(2)) + r"\b", text):
            row["auto"] += 1
        else:
            row["missing"] += 1
    row = dict(row)
    row["asm"] = asm
    return row


def score(g, producers):
    nat, callees = native_index(g)
    loose_nat = {loose(k): k for k in nat}
    native_rows, gh_by_asm = [], defaultdict(list)
    for r in jsonl(g.p("ghidra.jsonl")):
        gh_by_asm[r["asm"]].append(r["key"])
    lines = ["| asm | producer | skeleton bodies | matched | compile ok | ok (managed) | judged | fidelity>=0.8 | fidelity=1 |",
             "|---|---|---|---|---|---|---|---|---|"]
    totals = defaultdict(Counter)
    for asm in g.assemblies:
        keys_path = g.p(f"keys.{asm}.tsv")
        if not keys_path.exists():
            continue
        skel = skeleton_keys(g, asm, loose_nat)
        skel_set = set(skel)
        best = {}
        for prod in producers:
            cand = g.p(f"cand.{prod}.{asm}.jsonl")
            if cand.exists():
                oracle("compile", g.p(f"skel/{asm}"), asm, "--candidates", cand, "--out", g.p(f"res.{prod}.{asm}.jsonl"))
            res = {r["Key"]: r for r in jsonl(g.p(f"res.{prod}.{asm}.jsonl")) if r["Key"] in skel_set}
            if not res:
                continue
            row = Counter(skel=len(skel))
            for k, r in res.items():
                if r["Status"] in ("no_target", "ambiguous"):
                    continue
                row["matched"] += 1
                if r["Status"] != "ok":
                    continue
                row["ok"] += 1
                row["managed"] += not r["Unsafe"]
                f = fidelity(k, r.get("Calls") or [], nat, callees, loose_nat)
                if f is not None:
                    row["judged"] += 1
                    row["f80"] += f >= 0.8
                    row["f100"] += f == 1
                if not r["Unsafe"]:
                    prev = best.get(k)
                    if prev is None or (f or 0) > (prev or 0):
                        best[k] = f
            lines.append(f"| {asm} | {prod} | {len(skel)} | {row['matched']} | {row['ok']} | {row['managed']} | "
                         f"{row['judged']} | {row['f80']} | {row['f100']} |")
            totals[prod].update(row)
        row = Counter(skel=len(skel), managed=len(best), judged=sum(f is not None for f in best.values()),
                      f80=sum(f is not None and f >= 0.8 for f in best.values()),
                      f100=sum(f == 1 for f in best.values()))
        lines.append(f"| {asm} | **best of all** | {len(skel)} | | | {row['managed']} | {row['judged']} | {row['f80']} | {row['f100']} |")
        totals["best"].update(row)
        native_rows.append(native_coverage(g, asm, skel_set, best, gh_by_asm.get(asm, [])))
    lines += ["", "Native coverage: every method that exists as machine code, by how its C# is recovered.",
              "| asm | native methods | managed body | of which faithful | compiler-generated by declaration | not recovered |",
              "|---|---|---|---|---|---|"]
    for r in native_rows:
        lines.append(f"| {r['asm']} | {r['native']} | {r['body']} | {r['faithful']} | {r['auto']} | {r['missing']} |")
    tn = Counter()
    for r in native_rows:
        tn.update({k: v for k, v in r.items() if k != "asm"})
    lines.append(f"| **all** | {tn['native']} | {tn['body']} ({100 * tn['body'] / max(tn['native'], 1):.1f}%) | "
                 f"{tn['faithful']} | {tn['auto']} | {tn['missing']} |")
    lines.append("")
    for prod, t in totals.items():
        pct = lambda n: f"{100 * n / max(t['skel'], 1):.1f}%"
        lines.append(f"- {prod}: managed compile {t['managed']}/{t['skel']} ({pct(t['managed'])}), "
                     f"fidelity>=0.8 on {t['f80']}/{t['judged']} judged")
    report = "\n".join(lines)
    g.p("SCORE.md").write_text(report + "\n", encoding="utf-8")
    print(report)


def todo(g, asm, out_path):
    """Skeleton bodies that have native code but no faithful compiling body from any producer yet."""
    nat, callees = native_index(g)
    loose_nat = {loose(k): k for k in nat}
    skel = skeleton_keys(g, asm, loose_nat)
    good = set()
    for prod in ("il2csharp", "llm"):
        for r in jsonl(g.p(f"res.{prod}.{asm}.jsonl")):
            if r["Status"] == "ok" and not r["Unsafe"]:
                f = fidelity(r["Key"], r.get("Calls") or [], nat, callees, loose_nat)
                if f is None or f >= FAITHFUL:
                    good.add(r["Key"])
    tried = {r["key"] for r in jsonl(g.p(f"llm.{asm}.log.jsonl")) if r.get("final")}
    keys = [k for k in skel if k not in good and k not in tried and loose(k) in loose_nat]
    Path(out_path).write_text("\n".join(keys) + "\n", encoding="utf-8", newline="\n")
    print(f"todo {asm}: {len(keys)} of {len(skel)} bodies need translation")


def main(argv):
    g = Game(argv[1])
    cmd = argv[2]
    if cmd == "prep":
        prep(g)
    elif cmd == "baseline":
        baseline(g)
    elif cmd == "todo":
        todo(g, argv[3], argv[4])
    elif cmd == "score":
        score(g, argv[3].split(",") if len(argv) > 3 else ["il2csharp", "llm"])
    elif cmd == "pack":
        print(Context(g).pack([argv[3]]))
    elif cmd == "llm":
        kw = dict(a.split("=", 1) for a in argv[5:])
        run_llm(g, argv[3], argv[4], model=kw.get("model", "haiku"), rounds=int(kw.get("rounds", 3)),
                workers=int(kw.get("workers", 8)))
    else:
        sys.exit(f"unknown command '{cmd}'")


if __name__ == "__main__":
    main(sys.argv)
