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
import math
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
        if cfg.get("extra_refs"):
            os.environ.setdefault("EXTRA_REFS", cfg["extra_refs"])

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

def free_memory_gb():
    """Free commit on Windows, MemAvailable on Linux; None when it cannot be read."""
    try:
        if os.name == "nt":
            out = subprocess.run(["powershell", "-NoProfile", "-Command",
                                  "(Get-CimInstance Win32_OperatingSystem).FreeVirtualMemory"],
                                 capture_output=True, text=True, timeout=60).stdout
            return int(out.strip()) / 1024 / 1024
        for line in open("/proc/meminfo"):
            if line.startswith("MemAvailable:"):
                return int(line.split()[1]) / 1024 / 1024
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return None
    return None


def wait_for_memory():
    """Machines are shared: hold off heavy steps until UDK_MIN_FREE_GB (default 6) is free, instead of being reaped."""
    need = float(os.environ.get("UDK_MIN_FREE_GB", "6"))
    waited = 0
    while (free := free_memory_gb()) is not None and free < need:
        if waited % 600 == 0:
            print(f"waiting for memory: {free:.1f} GB free, need {need:.0f}", flush=True)
        time.sleep(60)
        waited += 60


def oracle(*args):
    wait_for_memory()
    out = subprocess.run(["sh", str(ORACLE), *map(str, args)], capture_output=True, text=True, encoding="utf-8")
    if out.returncode != 0:
        raise RuntimeError(out.stdout[-1500:] + out.stderr[-1500:])
    return out.stdout


def oracle_tool(*args):
    dll = os.environ.get("ORACLE_DLL") or HERE.parent / "tools" / "recompile" / "Oracle" / "bin" / "Release" / "net8.0" / "Oracle.dll"
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
        try:
            print(oracle("repair", skel, asm, "--orig", Path(g.cfg["plugins"]) / f"{asm}.dll").strip())
        except RuntimeError as e:
            # Repair stops when a pass makes no progress; index below reports what is left as base errors.
            print(f"repair {asm}: stopped without progress\n{str(e)[-600:]}")
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
    print(oracle_tool("slots", "--refs", g.cfg["plugins"], "--refs", Path(g.cfg["unity_data"]) / "Managed" / "UnityEngine",
                      "--refs", Path(g.cfg["unity_data"]) / "UnityReferenceAssemblies" / "unity-4.8-api",
                      "--out", g.p("slots.json")).strip())
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
        self.slots = load_slots(g)
        mp = g.p("mathnames.json")
        self.math = {int(k, 16): v for k, v in json.loads(mp.read_text(encoding="utf-8")).items()} if mp.exists() else {}
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
        self.listings = {r["key"]: r["asm"] for r in jsonl(g.p("listings.jsonl"))}
        self.state_machine = state_machines(list(self.ghidra))
        # Stub DLLs drop closure classes (<>c, <>c__DisplayClass), so a lambda's native body only reaches the
        # translator through the method that declares it: <Parent>b__N_M / <Parent>g__Local|N_M of the same type.
        self.lambdas = defaultdict(list)
        for k in self.ghidra:
            typ, rest = k.split("::", 1)
            m = re.match(r"^<([^>]+)>[bg]__", rest)
            if not m:
                continue
            closure = "/" in typ and re.search(r"/(__c|_003C_003Ec|<>c)", typ)
            owner = typ.rsplit("/", 1)[0] if closure else typ
            self.lambdas[(loose(owner + "::x()").split("::")[0], m.group(1))].append(k)
        self.loose = {}
        for k in list(self.ghidra) + list(self.il2csharp):
            self.loose.setdefault(loose(k), k)
            if generic_shape(k):
                self.loose.setdefault(generic_shape(k), k)

    def lookup(self, table, key):
        if key in table:
            return table[key]
        alt = self.loose.get(loose(key)) or self.loose.get(generic_shape(key) or "")
        return table.get(alt) if alt else None

    def decl_of(self, typ):
        return self.decls.get(typ) or next((d for k, d in self.decls.items() if loose(k + "::x()") == loose(typ + "::x()")), None)

    def native(self, key):
        gh = self.lookup(self.ghidra, key)
        return annotate_math(annotate_slots(gh["c"], self.slots), self.math) if gh else "(no native decompilation found)"

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
            mn = self.state_machine.get(k) or self.state_machine.get(self.loose.get(loose(k), ""))
            if mn:
                sec.append(f"THIS IS AN ASYNC/ITERATOR METHOD. Its logic is the state machine's MoveNext below ({mn.split('::')[0]}). "
                           "Write the method body as the original source: async code with await (the method becomes async) or an "
                           "iterator with yield return. Do not create or reference the state machine struct or its builder.\n"
                           + self.native(mn))
            owner = loose(k.split("::")[0] + "::x()").split("::")[0]
            name = re.sub(r"`\d+$", "", k.split("::")[1].split("(")[0])
            for lk in self.lambdas.get((owner, name), [])[:12]:
                sec.append(f"LAMBDA / LOCAL FUNCTION DECLARED IN THIS METHOD ({lk.split('::', 1)[1]}; its closure class is "
                           "not in the skeleton, so write it inline as a lambda or local function):\n" + self.native(lk))
            lst = self.lookup(self.listings, k)
            if lst:
                sec.append("DISASSEMBLY (Ghidra dropped C runtime call arguments; they are in xmm0/xmm1 here):\n" + lst)
            il = self.lookup(self.il2csharp, k)
            if il:
                il = il.strip()
                sec.append("il2csharp DRAFT (often wrong, pointer arithmetic):\n" + (il[:draft_cap] + "\n..." if len(il) > draft_cap else il))
            sections.append("\n".join(sec))
            # MoveNext and lambda bodies name types the method itself never mentions; their declarations matter too.
            tokens |= set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", sections[-1]))
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


# IL2CPP interface call: SomeInvoker(slot, TypeInfo__Ns__IFace, obj, ...); slot indexes the interface's methods.
SLOT_CALL = re.compile(r"(?<![\w])((?:FUN_|func_0x)[0-9a-f]+)\((\d+),\s*TypeInfo__(\w+?)\s*(?=[,)])")


def load_slots(g):
    path = g.p("slots.json")
    if not path.exists():
        return {}
    table = json.loads(path.read_text(encoding="utf-8"))
    return {re.sub(r"[.+]", "__", name): (name, methods) for name, methods in table.items()}


def slot_calls(c, slots):
    """[(interface simple name, method name)] for every resolvable interface-slot call in Ghidra C."""
    out = []
    for m in SLOT_CALL.finditer(c):
        hit = slots.get(m.group(3))
        if hit and int(m.group(2)) < len(hit[1]):
            out.append((re.sub(r"`\d+", "", hit[0].split("+")[-1].split(".")[-1]), hit[1][int(m.group(2))]))
    return out


def annotate_slots(c, slots):
    if not slots:
        return c

    def sub(m):
        hit = slots.get(m.group(3))
        if not hit or int(m.group(2)) >= len(hit[1]):
            return m.group(0)
        return f"{m.group(1)}/*interface call {hit[0]}.{hit[1][int(m.group(2))]}*/({m.group(2)},TypeInfo__{m.group(3)}"
    return SLOT_CALL.sub(sub, c)


def annotate_math(c, names):
    """FUN_1804e5a00( -> FUN_1804e5a00/*C runtime sinf*/( for callees udk.mathnames identified by emulation."""
    if not names:
        return c

    def sub(m):
        n = names.get(int(m.group(2), 16))
        return f"{m.group(1)}/*C runtime {n}*/(" if n else m.group(0)
    return re.sub(r"(?<![\w])((?:FUN_|func_0x0*)([0-9a-f]{8,}))\(", sub, c)


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


def generic_shape(key):
    """A method of a generic type or a generic method, by name and parameter count only. The native key carries one
    instantiation's types (SignalProperty`1::.ctor(Int32)), the skeleton the type parameter (.ctor(TValue)); any
    instantiation is the same source body."""
    head = key.split("(", 1)[0]
    if "`" not in head:
        return None
    params = key[len(head) + 1:key.rfind(")")]
    return "#" + loose(head + "()")[:-2] + "/" + str(params.count(",") + 1 if params else 0)


def loose_index(nat):
    idx = {loose(k): k for k in nat}
    for k in nat:
        shape = generic_shape(k)
        if shape:
            idx.setdefault(shape, k)
    return idx


def nat_key(key, loose_nat):
    """The native key of a skeleton key: exact, then loose spelling, then generic shape."""
    return loose_nat.get(loose(key)) or loose_nat.get(generic_shape(key) or "")


# ---------- llm ----------

SYSTEM = """You translate IL2CPP native decompilation back into the original C# method bodies of a Unity game.
Write idiomatic, managed C# that compiles inside the given declaring type: no unsafe code, no pointers, no offsets.
IL2CPP noise to drop: il2cpp_init_metadata / runtime_class_init guards, MethodInfo* arguments, explicit null-reference
throws (C# throws them implicitly), GC write-barrier loops after stores (LOCK/UNLOCK bit sets), array bounds checks.
Idioms: rgctx get_Instance chains are Singleton<T>.Instance; il2cpp_object_new(TypeInfo_X)+ctor is `new X(...)`;
delegate ctor(obj, MethodInfo_M) is a method group; *(T*)(p+0xNN) is the field at that offset (see FIELD OFFSETS);
klass->static_fields->F is a static field; vtable calls (klass->vtable[n].methodPtr) are virtual/interface calls.
UnityEngine.Object null checks (op_Implicit / op_Inequality calls) must stay `obj != null` / `if (obj)` on the Unity type.
Float precision matters: float literals (3.1415927, 0.5) and single-precision C runtime calls (sinf, log10f, fmodf)
mean float arithmetic (Mathf.Sin, Mathf.Log10, %, float literals with f); the double versions (sin, log10) mean
double arithmetic. A C runtime call whose arguments Ghidra dropped still takes them: infer them from the names.
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


def run_llm(g, asm, keys_file, model="haiku", rounds=3, workers=8, tag=""):
    ctx = Context(g)
    nat, callees = native_index(g)
    loose_nat = loose_index(nat)
    keys = [k.strip() for k in Path(keys_file).read_text(encoding="utf-8").split("\n") if k.strip()]
    calls_of = {}
    for k in keys:
        r = nat.get(k) or nat.get(nat_key(k, loose_nat) or "")
        if r and r["calls"]:
            calls_of[k] = r["calls"]
    log_path = g.p(f"llm{tag}.{asm}.log.jsonl")
    # A key whose every attempt got no answer (the API was down or out of quota) is not done; it runs again.
    done = {r["key"] for r in jsonl(log_path) if r.get("final") and r.get("best_status") != "llm_fail"}
    keys = [k for k in keys if k not in done]
    print(f"llm{tag} {asm}: {len(keys)} methods to translate with {model}", flush=True)
    best, retry, pending = {}, {}, list(keys)
    for rnd in range(1, rounds + 1):
        if not pending:
            break
        wait_for_memory()
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
        if all(meta.get("error") for _, _, meta in results):
            # No prompt was answered: the API is down, not the methods hard. Stop before logging them as final.
            sys.exit(f"round {rnd}: all {len(results)} prompts failed ({results[0][2].get('error')}); stopping")
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
        verdict, summary = oracle_compile(g, asm, cands, f"llmround{tag}.{asm}") if cands else ({}, "no candidates")
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
                if own_name(k) in b["calls"]:
                    missing.append([f"(your body calls {own_name(k)} itself, the native code does not: "
                                    "that call is the base implementation, write base.{name}(...))".replace(
                                        "{name}", own_name(k).split("::")[1])])
            fixable = b["status"] in ("compile_error", "syntax_error", "llm_fail") or bool(missing)
            again = rnd < rounds and fixable
            if b["status"] == "llm_fail":
                b["errors"] = ["(no answer parsed; reply with a ### key line and one csharp block)"]
            logs.append({"key": k, "round": rnd, "status": st["status"], "fidelity": st.get("fidelity"),
                         "final": not again, "errors": st["errors"], "body": None if again else b["body"],
                         "best_status": b["status"], "best_fidelity": b.get("fidelity"),
                         # Kept even when it fails, so a later Oracle fix can re-score it without another LLM call.
                         "last_body": st.get("body")})
            if again:
                retry[k] = missing
                nxt.append(k)
        write_jsonl(log_path, logs, mode="a")
        write_jsonl(g.p(f"llm{tag}.{asm}.cost.jsonl"), [{"round": rnd, "prompts": len(jobs), "methods": len(pending),
                                                   "in": tin, "out": tout, "cost": round(cost, 3)}], mode="a")
        print(f"round {rnd}: {len(jobs)} prompts, in={tin} out={tout} cost=${cost:.2f}; {summary}", flush=True)
        pending = nxt
    merged = {r["key"]: r for r in jsonl(g.p(f"cand.llm{tag}.{asm}.jsonl"))}
    for r in jsonl(log_path):
        if r.get("final") and r.get("best_status", r["status"]) == "ok" and r.get("body") is not None:
            merged[r["key"]] = {"key": r["key"], "src": "llm" + tag, "body": r["body"]}
    write_jsonl(g.p(f"cand.llm{tag}.{asm}.jsonl"), merged.values())
    print(f"cand.llm{tag}.{asm}.jsonl: {len(merged)} compiling bodies so far", flush=True)


# ---------- score ----------

def state_machines(keys):
    """{method key: MoveNext key} for async/iterator methods, matched by the compiler's <Name>d__N naming."""
    by_owner = defaultdict(list)
    for k in keys:
        typ, rest = k.split("::", 1)
        if rest.startswith("MoveNext(") and "/" in typ:
            outer, inner = typ.rsplit("/", 1)
            m = re.match(r"^(?:_003C|<|_)([^<>]+?)(?:_003E|>|_)d__\d+$", inner)
            if m:
                by_owner[(loose(outer + "::x()").split("::")[0], m.group(1))].append(k)
    out = {}
    for k in keys:
        typ, rest = k.split("::", 1)
        name = re.sub(r"`\d+$", "", rest.split("(")[0])
        hit = by_owner.get((loose(typ + "::x()").split("::")[0], name))
        if hit and len(hit) == 1:
            out[k] = hit[0]
    return out


def native_index(g):
    nat = {r["key"]: r for r in jsonl(g.p("native_calls.jsonl"))}
    callees = json.loads(g.p("callees.json").read_text(encoding="utf-8")) if g.p("callees.json").exists() else {}
    # An async/iterator method's logic lives in its MoveNext; a body written back as await/yield must make those calls.
    for parent, mn in state_machines(list(nat)).items():
        nat[parent] = dict(nat[parent], calls=nat[parent]["calls"] + nat[mn]["calls"])
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


def own_name(key):
    typ, rest = key.split("::", 1)
    return simple_name(typ) + "::" + rest.split("(")[0]


def self_recursion(key, calls, native_row):
    me = own_name(key)
    return me in calls and not (native_row and any(me in alts for alts in native_row["calls"]))


def fidelity(key, calls, nat, callees, loose_nat):
    """Share of the native method's resolved direct calls that the C# body also makes (None: nothing to compare).

    A C# call counts for the native callees it was inlined into (one level), and an async builder's Start counts
    for the state machine's MoveNext it always runs. Name-only matches skip names too common to identify a callee.
    A body that calls itself when the native code does not scores 0: that is a base call turned into recursion
    (il2csharp writes base.OnValidate() as this.OnValidate()), and it stack-overflows at runtime.
    """
    r = nat.get(key) or nat.get(nat_key(key, loose_nat) or "")
    if self_recursion(key, calls, r):
        return 0.0
    if r is None or not r["calls"]:
        return None
    have = set(calls) - {own_name(key)}
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
        if kind.startswith("new") and nat_key(key, loose_nat) is None:
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
    loose_nat = loose_index(nat)
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


def same_value(a, b):
    a, b = str(a), str(b)
    if a.lower() == b.lower():
        return True
    try:
        fa, fb = float(a), float(b)
    except ValueError:
        return False
    return fa == fb or (math.isnan(fa) and math.isnan(fb))


def difftest(g, asm, prod, inputs, original, quiet=False):
    """Emit <asm>.dll with producer <prod>'s bodies, run them on the inputs the original game was probed with
    (tools/runtime-probe invoke mode), and compare every result with the original's.

    Returns {method key: {"ok": n, "total": n, "bad": [(args, expected, got)]}}."""
    emit = g.p(f"emit/{asm}.{prod}.dll")
    emit.parent.mkdir(exist_ok=True)
    oracle("compile", g.p(f"skel/{asm}"), asm, "--candidates", g.p(f"cand.{prod}.{asm}.jsonl"),
           "--out", g.p(f"res.{prod}.{asm}.jsonl"), "--emit", emit)
    ours_path = g.p(f"emit/invoke-out.{prod}.{asm}.jsonl")
    oracle_tool("invoke", "--dll", emit, "--inputs", inputs, "--out", ours_path, "--refs", g.cfg["plugins"],
                "--refs", Path(g.cfg["unity_data"]) / "Managed" / "UnityEngine")

    def load(p):
        out = {}
        for r in jsonl(p):
            if "ret" in r:
                args = tuple(repr(float(json.loads(a) if isinstance(a, str) else a)) for a in r["args"])
                out[(r["key"], args)] = r["ret"]
        return out
    orig, ours = load(original), load(ours_path)
    per = defaultdict(lambda: {"ok": 0, "total": 0, "bad": []})
    for k, v in orig.items():
        p = per[k[0]]
        p["total"] += 1
        if k in ours and same_value(ours[k], v):
            p["ok"] += 1
        else:
            p["bad"].append((k[1], v, ours.get(k)))
    calls_ok = sum(p["ok"] for p in per.values())
    methods_ok = sum(p["ok"] == p["total"] for p in per.values())
    if not quiet:
        lines = [f"difftest {asm} {prod}: {calls_ok}/{len(orig)} calls equal the original, "
                 f"{methods_ok}/{len(per)} methods on every input"]
        lines += [f"  {p['ok']}/{p['total']} {k}" for k, p in sorted(per.items()) if p["ok"] != p["total"]]
        print("\n".join(lines))
    return dict(per)


def testfix(g, asm, prod, inputs, original, model="haiku", rounds=2):
    """Repair bodies that differ from the original game on probed inputs: show the translator the failing
    calls, keep a new body only when it matches more calls. Writes cand.<prod>fix.<asm>.jsonl."""
    ctx = Context(g)
    nat, _ = native_index(g)
    loose_nat = loose_index(nat)
    fixed = f"{prod}fix"
    cands = {r["key"]: r for r in jsonl(g.p(f"cand.{prod}.{asm}.jsonl"))}
    write_jsonl(g.p(f"cand.{fixed}.{asm}.jsonl"), [dict(r, src=fixed) for r in cands.values()])
    per = difftest(g, asm, fixed, inputs, original)
    for rnd in range(1, rounds + 1):
        failing = [k for k, p in per.items() if p["ok"] < p["total"] and k in cands]
        if not failing:
            break
        jobs = []
        for k in failing:
            calls_of = {k: (nat.get(k) or nat.get(nat_key(k, loose_nat) or "", {})).get("calls", [])}
            ex = "\n".join(f"  {k.split('::')[1].split('(')[0]}({', '.join(a)}) -> expected {e}, yours {o}"
                           for a, e, o in per[k]["bad"][:12])
            jobs.append((k, ctx.pack([k], calls_of) + "\n\nYOUR CURRENT BODY FOR " + k + ":\n```csharp\n" + cands[k]["body"] +
                         "\n```\nIt compiles but differs from the original game on these calls (results recorded by running "
                         "the original binary):\n" + ex + "\nReply with a corrected body that reproduces the original results."))
        with cf.ThreadPoolExecutor(8) as pool:
            answers = list(pool.map(lambda j: (j[0], call_llm(j[1], model)), jobs))
        trial = dict(cands)
        for k, (text, meta) in answers:
            body = parse_bodies(text or "", [k]).get(k)
            if body:
                trial[k] = {"key": k, "src": fixed, "body": body}
        write_jsonl(g.p(f"cand.{fixed}.{asm}.jsonl"), trial.values())
        new = difftest(g, asm, fixed, inputs, original, quiet=True)
        res = {r["Key"]: r for r in jsonl(g.p(f"res.{fixed}.{asm}.jsonl"))}
        kept = 0
        for k in failing:
            if res.get(k, {}).get("Status") == "ok" and new.get(k, {}).get("ok", 0) > per[k]["ok"]:
                cands[k] = trial[k]
                kept += 1
        write_jsonl(g.p(f"cand.{fixed}.{asm}.jsonl"), [dict(r, src=fixed) for r in cands.values()])
        per = difftest(g, asm, fixed, inputs, original, quiet=rnd < rounds)
        print(f"testfix round {rnd}: {len(failing)} failing, {kept} improved")
    return per


def assemble(g, asm, producers, out_dir):
    """Pick each method's best compiling managed body across producers (highest fidelity, later producers win ties),
    then emit <out_dir>/<asm>.dll: the skeleton with every recovered body in it."""
    nat, callees = native_index(g)
    loose_nat = loose_index(nat)
    best = {}
    for prod in producers:
        if g.p(f"cand.{prod}.{asm}.jsonl").exists():
            oracle("compile", g.p(f"skel/{asm}"), asm, "--candidates", g.p(f"cand.{prod}.{asm}.jsonl"),
                   "--out", g.p(f"res.{prod}.{asm}.jsonl"))
        cands = {r["key"]: r for r in jsonl(g.p(f"cand.{prod}.{asm}.jsonl"))}
        for r in jsonl(g.p(f"res.{prod}.{asm}.jsonl")):
            if r["Status"] != "ok" or r["Unsafe"]:
                continue
            c = cands.get(r["Key"]) or next((v for k, v in cands.items() if loose(k) == loose(r["Key"])), None)
            if c is None:
                continue
            f = fidelity(r["Key"], r.get("Calls") or [], nat, callees, loose_nat)
            if f == 0.0 and self_recursion(r["Key"], r.get("Calls") or [], nat.get(r["Key"]) or nat.get(nat_key(r["Key"], loose_nat) or "")):
                continue
            score = -1.0 if f is None else f
            if r["Key"] not in best or score >= best[r["Key"]][0]:
                best[r["Key"]] = (score, {"key": r["Key"], "src": prod, "body": c["body"]})
    write_jsonl(g.p(f"cand.best.{asm}.jsonl"), [v for _, v in best.values()])
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    out = oracle("compile", g.p(f"skel/{asm}"), asm, "--candidates", g.p(f"cand.best.{asm}.jsonl"),
                 "--out", g.p(f"res.best.{asm}.jsonl"), "--emit", Path(out_dir) / f"{asm}.dll")
    print(f"assemble {asm}: {Counter(v['src'] for _, v in best.values())}; " + out.strip().split("\n")[-1])


UNITY_MESSAGES = {"Awake", "Start", "Update", "LateUpdate", "FixedUpdate", "OnEnable", "OnDisable", "OnDestroy", "OnGUI",
                  "OnApplicationFocus", "OnApplicationPause", "OnApplicationQuit", "OnValidate", "Reset", ".cctor"}


def closure(g, seed_cfg, out_dir):
    """Methods of this config's assemblies that the seed game's own code can reach: its direct and interface calls,
    then the libraries' callees transitively, plus what Unity or a vtable calls without a direct call site (messages,
    static constructors, overrides and implementations of a reached method). A paid library used through a small
    surface needs only these bodies to run."""
    seed = Game(seed_cfg)
    seed_nat, _ = native_index(seed)
    nat, callees = native_index(g)
    by_short, by_name = defaultdict(list), defaultdict(set)
    skel = {}
    for asm in g.cfg["assemblies"]:
        for k in skeleton_keys(g, asm, loose_index(nat)):
            typ, rest = k.split("::", 1)
            short = simple_name(typ) + "::" + rest.split("(")[0]
            by_short[short].append((asm, k))
            by_name[rest.split("(")[0]].add(short)
            skel[k] = asm
    reached = set()
    frontier = [x for r in seed_nat.values() for alts in r["calls"] for x in alts if x in by_short]
    frontier += [s for s in by_short if s.split("::")[1] in UNITY_MESSAGES]
    while frontier:
        s = frontier.pop()
        if s in reached:
            continue
        reached.add(s)
        frontier += [c for c in callees.get(s, []) if c in by_short and c not in reached]
        name = s.split("::")[1]
        # Same member name in few types: an override or interface implementation reached through dispatch.
        if name not in COMMON and len(by_name[name]) <= 8:
            frontier += [o for o in by_name[name] if o not in reached]
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    for asm in g.cfg["assemblies"]:
        keys = [k for s in sorted(reached) for a, k in by_short[s] if a == asm]
        # Unity's deserializer calls every component's and serialized class's parameterless constructor, where the
        # field initializers live; nothing in the binary calls it. Without them a VolumeComponent's parameters stay null.
        have = set(keys)
        keys += [k for k, a in skel.items() if a == asm and k.endswith("::.ctor()") and k not in have]
        total = sum(1 for a in skel.values() if a == asm)
        Path(out_dir, f"closure.{asm}.txt").write_text("\n".join(keys) + "\n", encoding="utf-8", newline="\n")
        print(f"closure {asm}: {len(keys)} of {total} bodies reachable from {seed.cfg['name']}")


def todo(g, asm, out_path):
    """Skeleton bodies that have native code but no faithful compiling body from any producer yet."""
    nat, callees = native_index(g)
    loose_nat = loose_index(nat)
    skel = skeleton_keys(g, asm, loose_nat)
    good = set()
    for prod in ("il2csharp", "llm"):
        for r in jsonl(g.p(f"res.{prod}.{asm}.jsonl")):
            if r["Status"] == "ok" and not r["Unsafe"]:
                f = fidelity(r["Key"], r.get("Calls") or [], nat, callees, loose_nat)
                if f is None or f >= FAITHFUL:
                    good.add(r["Key"])
    tried = {r["key"] for r in jsonl(g.p(f"llm.{asm}.log.jsonl")) if r.get("final")}
    keys = [k for k in skel if k not in good and k not in tried and nat_key(k, loose_nat) is not None]
    Path(out_path).write_text("\n".join(keys) + "\n", encoding="utf-8", newline="\n")
    print(f"todo {asm}: {len(keys)} of {len(skel)} bodies need translation")


def main(argv):
    g = Game(argv[1])
    cmd = argv[2]
    if cmd == "prep":
        prep(g)
    elif cmd == "closure":
        closure(g, argv[3], argv[4])
    elif cmd == "baseline":
        baseline(g)
    elif cmd == "difftest":
        difftest(g, argv[3], argv[4], argv[5], argv[6])
    elif cmd == "assemble":
        for asm in g.assemblies:
            if g.p(f"keys.{asm}.tsv").exists():
                assemble(g, asm, argv[3].split(","), argv[4])
    elif cmd == "testfix":
        testfix(g, argv[3], argv[4], argv[5], argv[6])
    elif cmd == "todo":
        todo(g, argv[3], argv[4])
    elif cmd == "score":
        score(g, argv[3].split(",") if len(argv) > 3 else ["il2csharp", "llm"])
    elif cmd == "pack":
        print(Context(g).pack([argv[3]]))
    elif cmd == "llm":
        kw = dict(a.split("=", 1) for a in argv[5:])
        run_llm(g, argv[3], argv[4], model=kw.get("model", "haiku"), rounds=int(kw.get("rounds", 3)),
                workers=int(kw.get("workers", 8)), tag=kw.get("tag", ""))
    else:
        sys.exit(f"unknown command '{cmd}'")


if __name__ == "__main__":
    main(sys.argv)
