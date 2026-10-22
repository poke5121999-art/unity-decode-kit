"""Write <out>/INDEX.md: what the dump holds, counts, and the commands to query it."""
import csv
import os
from collections import Counter

csv.field_size_limit(1 << 30)


def count_lines(path, skip_header=True):
    if not os.path.exists(path):
        return 0
    with open(path, encoding="utf-8") as fh:
        return sum(1 for _ in fh) - (1 if skip_header else 0)


def write(out, layout):
    code = os.path.join(out, "code")
    methods = count_lines(os.path.join(code, "methods.tsv"))
    failed = 0
    decomp = os.path.join(code, "decomp")
    for d, _, files in os.walk(decomp):
        for f in files:
            if f.endswith(".c"):
                with open(os.path.join(d, f), encoding="utf-8") as fh:
                    failed += fh.read().count("// decompile failed")
    data_kinds = Counter()
    rp = os.path.join(out, "data", "report.tsv")
    if os.path.exists(rp):
        with open(rp, encoding="utf-8") as fh:
            for r in csv.DictReader(fh, delimiter="\t"):
                data_kinds[(r["layers"], r["kind"])] += 1
    assets = Counter()
    ap = os.path.join(out, "assets", "ExportedProject", "Assets")
    for d, _, files in os.walk(ap):
        for f in files:
            if not f.endswith(".meta"):
                assets[os.path.relpath(d, ap).split(os.sep)[0]] += 1
    refs = count_lines(os.path.join(out, "assets", "refs.tsv"))
    lines = [
        f"# Dump: {os.path.basename(layout['data_dir'])}",
        "",
        f"Binary `{layout['binary']}`, metadata `{layout['metadata']}`.",
        "",
        "## Query",
        "",
        "```",
        f"export UDK_DUMP={out}",
        "udk q '<regex>'            # search code, types, data, assets at once",
        "udk method 'Type.Method'   # decompiled body",
        "udk type TypeName          # fields, offsets, constants",
        "udk refs '<asset regex>'   # what an asset uses / what uses it",
        "udk callers Type.Member    # methods that call a method or touch a field/property",
        "udk prefab '<regex>'       # prefab/scene hierarchy, components, what each field points at",
        "udk settings PlayerSettings [field regex]   # project settings as shipped",
        "```",
        "",
        "## Contents",
        "",
        f"- `code/types.cs`: every type, field (with offset), property, method address (Il2CppInspectorRedux).",
        f"- `code/decomp/`: {methods} game methods decompiled by Ghidra, one `.c` per type, {failed} failed. Index `code/methods.tsv`.",
        f"- `data/`: {sum(data_kinds.values())} loose data files; wrappers found: "
        + ", ".join(f"{k[0]} → {k[1]} ×{v}" for k, v in data_kinds.most_common()) + ". Per file: `data/report.tsv`.",
        f"- `assets/ExportedProject/`: AssetRipper Unity project; {sum(assets.values())} files. {refs} references in `assets/refs.tsv`.",
        "",
        "| Asset folder | Files |",
        "|---|---|",
    ] + [f"| {k} | {v} |" for k, v in assets.most_common()]
    with open(os.path.join(out, "INDEX.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
