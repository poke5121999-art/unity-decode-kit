"""udk: query a decoded Unity game dump instead of watching clips.

  udk q <regex> [-k code|types|data|assets] [-n N]   search everything, grouped by kind
  udk method <Type.Method | regex>                    print decompiled bodies
  udk type <Type>                                     print the type with fields, offsets, defaults
  udk refs <asset path or name regex>                 what an asset uses and what uses it
  udk trace <method regex>... -o trace.js [--log f]   Frida script logging calls + receiver fields
  udk build <game dir> <out dir> [--game-re RE]       run the whole pipeline (see udk/build.py)

The dump root comes from --dump or $UDK_DUMP (default: out/vd under the kit).
"""
import argparse
import csv
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
                            "-g", "!*.meta", "-g", "!*.png", "-g", "!*.asset.meta", a.pattern, path],
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
    build.main(a.game, a.out, a.game_re, a.steps)


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
    p.add_argument("--steps", default="inspector,assets,data,ghidra,index")
    p.set_defaults(fn=cmd_build)
    a = ap.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
