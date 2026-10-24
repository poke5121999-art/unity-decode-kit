"""Declaration coverage: does the skeleton declare every type, field and method the IL2CPP metadata has?

Metadata side: Il2CppInspector's types.cs, one image (assembly) at a time. Skeleton side: the C# the recompile
skeleton compiles from (work/skel/<asm>). Names are compared per type, so a count match cannot hide a swap.

Usage: python -m udk.declcov <config.json>
"""
import re
import sys
from collections import defaultdict

from .recompile import Game

TYPE = re.compile(r"^\s*(?:\[[^\]]*\]\s*)*(?:(?:public|internal|private|protected|sealed|abstract|static|readonly|ref|unsafe|partial)\s+)*"
                  r"(class|struct|enum|interface|delegate)\s+(?:[\w.<>,\[\] ]+\s+)?([A-Za-z_<][^\s:(<]*)")
FIELD = re.compile(r"^\s*(?:\[.*?\]\s*)*((?:public|private|protected|internal|static|readonly|const|volatile|\s)+)\s*(.+?)\s+(\S+?)(?: = .*)?;\s*//")
METHOD = re.compile(r"^\s*(?:\[.*?\]\s*)*(?:public|private|protected|internal|static|virtual|override|abstract|sealed|extern|new|unsafe|async|\s)+[^=;]*?\s([\w.<>,]+)\((.*)\)\s*(?:\{\}|=> default;|;)")


def norm(name):
    return re.sub(r"`\d+$", "", re.sub(r"_003C|_003E|[<>]", "_", name))


def metadata_images(types_cs):
    images, cur = defaultdict(lambda: {"types": set(), "fields": 0, "methods": 0}), None
    ranges = {}
    for line in open(types_cs, encoding="utf-8", errors="replace"):
        m = re.match(r"^// Image \d+: (\S+)\.dll - .* Types (\d+)-(\d+)", line)
        if m:
            ranges[(int(m.group(2)), int(m.group(3)))] = m.group(1)
            continue
        m = re.search(r"// TypeDefIndex: (\d+)", line)
        if m:
            idx = int(m.group(1))
            cur = next((a for (lo, hi), a in ranges.items() if lo <= idx <= hi), None)
            t = TYPE.match(line)
            if cur and t:
                images[cur]["types"].add(norm(t.group(2)))
            continue
        if cur is None:
            continue
        if FIELD.match(line) and "(" not in line.split("//")[0]:
            images[cur]["fields"] += 1
        elif re.search(r"\)\s*(\{\}|=> default;|;)\s*(//.*)?$", line) and "(" in line and "=" not in line.split("(")[0]:
            images[cur]["methods"] += 1
    return images


def skeleton(g, asm):
    types, fields, methods = set(), 0, 0
    for f in (g.p(f"skel/{asm}")).rglob("*.cs"):
        if "obj" in f.parts:
            continue
        for line in open(f, encoding="utf-8", errors="replace"):
            t = TYPE.match(line)
            if t:
                types.add(norm(t.group(2)))
    return types


def main(cfg_path):
    g = Game(cfg_path)
    images = metadata_images(g.dump / "inspector" / "types.cs")
    print("| asm | metadata types | skeleton types | missing in skeleton | metadata fields | metadata methods |")
    print("|---|---|---|---|---|---|")
    for asm in g.assemblies:
        meta = images.get(asm)
        if not meta or not g.p(f"skel/{asm}").exists():
            continue
        sk = skeleton(g, asm)
        missing = sorted(t for t in meta["types"] if t not in sk)
        print(f"| {asm} | {len(meta['types'])} | {len(sk)} | {len(missing)} {missing[:6]} | {meta['fields']} | {meta['methods']} |")


if __name__ == "__main__":
    main(sys.argv[1])
