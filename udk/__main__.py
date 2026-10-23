"""udk: query a decoded Unity game dump instead of watching clips.

  udk q <regex> [-k code|types|data|assets|audio|shaders] [-n N]   search everything, grouped by kind
  udk method <Type.Method | regex>                    print decompiled bodies
  udk type <Type>                                     print the type with fields, offsets, defaults
  udk refs <asset path or name regex>                 what an asset uses and what uses it
  udk trace <method regex>... -o trace.js [--log f]   Frida script logging calls + receiver fields
  udk build <game dir> <out dir> [--game-re RE]       run the whole pipeline (see udk/build.py)

The dump root comes from --dump or $UDK_DUMP (default: out/vd under the kit).
"""
import argparse
import csv
import json
import os
import re
import subprocess
import sys

KIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RG = os.path.join(KIT, "third_party", "rg")
KINDS = {
    "code": "code/decomp",
    "types": "code/types.cs",
    "data": "data",
    "assets": "assets/ExportedProject/Assets",
    "audio": "audio",
    "shaders": "shaders",
    "settings": "settings",
}
csv.field_size_limit(1 << 30)


def dump_root(a):
    return a.dump or os.environ.get("UDK_DUMP") or os.path.join(KIT, "out", "vd")


def cmd_q(a):
    root = dump_root(a)
    kinds = [a.kind] if a.kind else list(KINDS)
    for k in kinds:
        path = os.path.join(root, KINDS[k])
        if not os.path.exists(path):
            continue
        r = subprocess.run([RG, "-n", "-i", "-m", "3", "--max-columns", "220", "--max-columns-preview",
                            "-g", "!*.meta", "-g", "!*.png", "-g", "!wwnames.txt", a.pattern, path],
                           capture_output=True, text=True)
        lines = r.stdout.splitlines()
        print(f"== {k}: {len(lines)} hits" + (f" (showing {a.n})" if len(lines) > a.n else ""))
        for line in lines[: a.n]:
            print(line.replace(root + "/", ""))


def methods(root):
    with open(os.path.join(root, "code", "methods.tsv"), encoding="utf-8") as fh:
        yield from csv.DictReader(fh, delimiter="\t")


def cmd_method(a):
    root = dump_root(a)
    spec = a.spec
    def display(m):
        return m["file"].rsplit("/", 1)[-1][:-2] + "." + m["signature"].split("(")[0].split()[-1]

    if any(c in spec for c in "^$|*[\\"):
        rx = re.compile(spec)
        hits = [m for m in methods(root) if rx.search(display(m))]
    else:
        hits = [m for m in methods(root) if spec in display(m)]
    if not hits:
        sys.exit(f"no method matches {spec!r}")
    for m in hits[: a.n]:
        path = os.path.join(root, "code", "decomp", m["file"])
        with open(path, encoding="utf-8") as fh:
            lines = fh.read().split("\n")
        i = int(m["line"]) - 1
        j = i + 1
        while j < len(lines) and not (lines[j].startswith("// ") and "  @0x" in lines[j]):
            j += 1
        print(f"### code/decomp/{m['file']}:{m['line']}")
        print("\n".join(lines[i:j]).rstrip() + "\n")
    if len(hits) > a.n:
        print(f"... {len(hits) - a.n} more; raise -n")


def cmd_callers(a):
    """Methods that call Type.Method (or a property's get_/set_), or touch the field Type.field."""
    root = dump_root(a)
    typ, _, member = a.spec.rpartition(".")
    if not typ or not member:
        sys.exit("give Type.Method or Type.field")
    t = typ.replace(".", "_")
    own = {m["signature"].split("(")[0].split()[-1] for m in methods(root) if m["c_name"].startswith(t + "_")}
    names = [n for n in (member, "get_" + member, "set_" + member) if n in own]
    short = re.escape(typ.split(".")[-1])
    if not own:  # engine or library type: only its callers were decompiled, so try both shapes
        names, field = [member], member
    elif member in own:
        field = None
    else:  # field, or auto-property whose getter IL2CPP inlined into a backing-field read
        field = f"_{member}_k__BackingField" if names else member
    rxs = [rf"(\w+)->fields\)\.{re.escape(field)}\b|static_fields->{re.escape(field)}\b"] if field else []
    if names:
        rxs.append(rf"(?<![A-Za-z0-9]){re.escape(t)}__({'|'.join(map(re.escape, names))})(?!_b__\d)(_\w*)?\b")
    out = []
    for rx in rxs:
        out += subprocess.run([RG, "-n", "-P", rx, os.path.join(root, "code", "decomp")],
                              capture_output=True, text=True).stdout.splitlines()
    by_method, cache = {}, {}
    for line in out:
        path, no, text = line.split(":", 2)
        if path not in cache:
            with open(path, encoding="utf-8") as fh:
                cache[path] = fh.read().split("\n")
        lines = cache[path]
        no = int(no)
        k = max((i for i, h in enumerate(lines[:no]) if h.startswith("// ") and "  @0x" in h), default=0)
        caller = lines[k][3:].split("  @0x")[0]
        var = field and re.search(rf"(\w+)->fields\)\.{re.escape(field)}\b", text)
        if not var and (k == no - 1 or k + 1 < no <= k + 6 and "::" in text):
            continue  # the method's own header or definition line
        if var:
            body = "\n".join(lines[k:no])
            if var and not re.search(rf"\b{short}\s*\*\s*{re.escape(var.group(1))}\b", body):
                continue  # same field name on another type
        by_method.setdefault((os.path.relpath(path, root), k + 1, caller), []).append(text.strip())
    if names and own:  # machine-code references the decompiler did not name (delegates, tail jumps)
        from udk import xref
        binary = xref.binary_path(root)
        seen = {c for (_, _, c) in by_method}
        for m in methods(root):
            if m["c_name"].startswith(t + "_") and m["signature"].split("(")[0].split()[-1] in names and binary:
                n_shared = xref.shared_count(root, int(m["address"], 16))
                if n_shared > 1:
                    # Folded body: Ghidra names it after one of the methods sharing it, so calls are
                    # found by that name and kept when the receiver is declared as this type.
                    for key, texts in folded_callers(root, m, short).items():
                        by_method.setdefault(key, []).extend(texts)
                    print(f"note: {m['signature']} shares its code with {n_shared - 1} other methods; "
                          "callers found by receiver type, binary references omitted")
                    continue
                for site, how, label in xref.xrefs(root, binary, int(m["address"], 16)):
                    sig = label.split(": ", 1)[-1]
                    if sig not in seen:
                        by_method.setdefault(("binary", 0, sig), []).append(f"{how} at 0x{site:X} in {label}")
    # UnityEvent listeners wired in the editor (Button.onClick...) call by name from prefabs/scenes.
    assets_dir = os.path.join(root, "assets", "ExportedProject", "Assets")
    if names and os.path.isdir(assets_dir):
        r = subprocess.run([RG, "-n", "-g", "*.prefab", "-g", "*.unity", "-g", "*.asset",
                            rf"^\s+m_MethodName: ({'|'.join(map(re.escape, names))})$", assets_dir],
                           capture_output=True, text=True)
        for line in r.stdout.splitlines():
            p, no, text = line.split(":", 2)
            by_method.setdefault(("event", 0, os.path.relpath(p, assets_dir)), []).append(f"line {no}: {text.strip()}")
    kind = "calls or backing-field uses" if names else "field uses"
    print(f"{len(by_method)} methods with {kind} of {a.spec}")
    for (path, line, caller), texts in list(by_method.items())[: a.n]:
        print({"binary": f"### (binary only, not in decomp)  {caller}",
               "event": f"### (UnityEvent listener in asset)  {caller}"}.get(path, f"### {path}:{line}  {caller}"))
        for t_ in texts[:3]:
            print("    " + t_[:200])
    if len(by_method) > a.n:
        print(f"... {len(by_method) - a.n} more; raise -n")


def folded_callers(root, m, short):
    """Calls to a folded method body under the name Ghidra gave it, whose first argument is
    declared (or cast) as the method's own type."""
    path = os.path.join(root, "code", "decomp", m["file"])
    with open(path, encoding="utf-8") as fh:
        head = fh.read().split("\n")[int(m["line"]):int(m["line"]) + 8]
    names = [re.search(r"::(\w+)\s*$", h) or re.search(r"::(\w+)\s*\(", h) for h in head]
    name = next((n.group(1) for n in names if n), None)
    if not name:
        return {}
    rx = rf"\b{re.escape(name)}\s*\(\s*(?:\(([\w ]+)\*\)\s*)?(\w+)"
    r = subprocess.run([RG, "-n", "-P", rx, os.path.join(root, "code", "decomp")], capture_output=True, text=True)
    found, cache = {}, {}
    for line in r.stdout.splitlines():
        p, no, text = line.split(":", 2)
        mm = re.search(rx, text)
        if not mm:
            continue
        if p not in cache:
            with open(p, encoding="utf-8") as fh:
                cache[p] = fh.read().split("\n")
        lines, no = cache[p], int(no)
        k = max((i for i, h in enumerate(lines[:no]) if h.startswith("// ") and "  @0x" in h), default=0)
        cast, var = (mm.group(1) or "").strip(), mm.group(2)
        body = "\n".join(lines[k:no])
        if cast == short or (not cast and re.search(rf"\b{re.escape(short)}\s*\*\s*{re.escape(var)}\b", body)):
            found.setdefault((os.path.relpath(p, root), k + 1, lines[k][3:].split("  @0x")[0]), []).append(text.strip())
    return found


def cmd_settings(a):
    root = dump_root(a)
    path = os.path.join(root, "settings", a.name + ".json")
    if not os.path.exists(path):
        names = sorted(f[:-5] for f in os.listdir(os.path.join(root, "settings")))
        sys.exit(f"no settings object {a.name!r}; have: {', '.join(names)}")
    with open(path, encoding="utf-8") as fh:
        tree = json.load(fh)
    rx = re.compile(a.field or ".", re.I)
    for k, v in tree.items():
        if rx.search(k):
            print(f"{k} = {json.dumps(v, ensure_ascii=False)[:300]}")


def cmd_prefab(a):
    from udk import prefab
    prefab.print_prefab(dump_root(a), a.spec, a.n, a.v)


def cmd_type(a):
    root = dump_root(a)
    rx = re.compile(r"^(public|internal|private|protected)?[\w ]*\b(class|struct|enum|interface) " + re.escape(a.name) + r"\b")
    with open(os.path.join(root, "code", "types.cs"), encoding="utf-8") as fh:
        lines = fh.readlines()
    shown = 0
    for i, line in enumerate(lines):
        if rx.match(line.strip()):
            j = i
            while j < len(lines) and lines[j].rstrip() != "}":
                j += 1
            print(f"### code/types.cs:{i + 1}")
            print("".join(lines[i:j + 1]))
            shown += 1
    if not shown:
        sys.exit(f"no type named {a.name!r}")


def cmd_refs(a):
    from udk import assets
    assets.print_refs(dump_root(a), a.spec, a.n)


def cmd_trace(a):
    from udk import runtime
    hooks, cfg = runtime.generate(dump_root(a), a.patterns, a.o, a.log, winabi=not a.sysv)
    print(f"{len(hooks)} hooks -> {a.o}; gadget config {cfg}")


def cmd_build(a):
    from udk import build
    build.main(a.game, a.out, a.game_re, a.steps, a.types)


def main():
    ap = argparse.ArgumentParser(prog="udk", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dump")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("q")
    p.add_argument("pattern")
    p.add_argument("-k", "--kind", choices=list(KINDS))
    p.add_argument("-n", type=int, default=20)
    p.set_defaults(fn=cmd_q)
    p = sub.add_parser("method")
    p.add_argument("spec")
    p.add_argument("-n", type=int, default=5)
    p.set_defaults(fn=cmd_method)
    p = sub.add_parser("callers")
    p.add_argument("spec", help="Type.Method or Type.field")
    p.add_argument("-n", type=int, default=30)
    p.set_defaults(fn=cmd_callers)
    p = sub.add_parser("settings")
    p.add_argument("name", help="PlayerSettings, QualitySettings, TagManager, ...")
    p.add_argument("field", nargs="?", help="regex over top-level field names")
    p.set_defaults(fn=cmd_settings)
    p = sub.add_parser("prefab")
    p.add_argument("spec", help="regex over prefab/scene paths")
    p.add_argument("-n", type=int, default=1)
    p.add_argument("-v", action="store_true", help="also print short scalar fields")
    p.set_defaults(fn=cmd_prefab)
    p = sub.add_parser("type")
    p.add_argument("name")
    p.set_defaults(fn=cmd_type)
    p = sub.add_parser("refs")
    p.add_argument("spec")
    p.add_argument("-n", type=int, default=40)
    p.set_defaults(fn=cmd_refs)
    p = sub.add_parser("trace")
    p.add_argument("patterns", nargs="+")
    p.add_argument("-o", default="trace.js")
    p.add_argument("--log", help="write JSONL here instead of send() to the frida CLI")
    p.add_argument("--sysv", action="store_true", help="native Linux/Android binary (this in rdi/r0)")
    p.set_defaults(fn=cmd_trace)
    p = sub.add_parser("build")
    p.add_argument("game")
    p.add_argument("out")
    p.add_argument("--game-re", default=None)
    p.add_argument("--steps", default="inspector,settings,normalize,assets,data,audio,shaders,ghidra,index")
    p.add_argument("--types", help="ghidra step: decompile only types whose group matches this regex (default: the last run's scope; all: every type)")
    p.set_defaults(fn=cmd_build)
    a = ap.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
