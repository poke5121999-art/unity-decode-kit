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


def extras(out):
    """One line per optional output that exists: shaders, audio, settings, native plugins, normalized mirror."""
    rows = []
    for rel, f in (("shaders/", "summary.txt"), ("audio/", "summary.txt")):
        p = os.path.join(out, rel, f)
        if os.path.exists(p):
            with open(p, encoding="utf-8") as fh:
                rows.append((rel, fh.read().strip() + "."))
    s = os.path.join(out, "settings")
    if os.path.isdir(s):
        rows.append(("settings/", "project settings as shipped: " + ", ".join(sorted(f[:-5] for f in os.listdir(s))) + "."))
    p = os.path.join(out, "native", "plugins.tsv")
    if os.path.exists(p):
        with open(p, encoding="utf-8") as fh:
            libs = [line.split("\t") for line in fh.read().splitlines()[1:]]
        done = [r[0] for r in libs if r[2] == "decompiled"]
        rows.append(("native/", f"native plugins the game binds by P/Invoke: {len(libs)}; decompiled (one .c per class, "
                                f"`<lib>/functions.tsv`): {', '.join(done) or 'none'}; the rest listed in `plugins.tsv`."))
    h = os.path.join(out, "havok", "summary.tsv")
    if os.path.exists(h):
        with open(h, encoding="utf-8") as fh:
            hv = [line.split("\t") for line in fh.read().splitlines()[1:]]
        rows.append(("havok/", f"Havok collision meshes as OBJ (Unity axes): {sum(1 for r in hv if r[2] != '0')} of {len(hv)} "
                               f"assets, {sum(int(r[2]) for r in hv)} triangles; per asset `havok/summary.tsv`."))
    n = os.path.join(out, "normalized.log")
    if os.path.exists(n):
        with open(n, encoding="utf-8") as fh:
            k = sum(1 for line in fh if "\terror\t" not in line)
        rows.append(("normalized/", f"game files with engine-modified objects rewritten to the stock layout: {k} files (log `normalized.log`)."))
    return rows


def write(out, layout):
    code = os.path.join(out, "code")
    methods = count_lines(os.path.join(code, "methods.tsv"))
    failed = bad = retyped = 0
    decomp = os.path.join(code, "decomp")
    for d, _, files in os.walk(decomp):
        for f in files:
            if f.endswith(".c"):
                with open(os.path.join(d, f), encoding="utf-8") as fh:
                    text = fh.read()
                failed += text.count("// decompile failed")
                bad += text.count("Control flow encountered bad instruction data")
                retyped += text.count("/* retype: ")
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
        f"- `code/decomp/`: {methods} game methods decompiled by Ghidra, one `.c` per type, {failed} failed, {bad} with 'bad instruction data'. "
        f"{retyped} lines carry `/* retype: v: T; 0xNN = field */`, the real field behind a value typed by shared generic code. Index `code/methods.tsv`.",
        f"- `data/`: {sum(data_kinds.values())} loose data files; wrappers found: "
        + ", ".join(f"{k[0]} → {k[1]} ×{v}" for k, v in data_kinds.most_common()) + ". Per file: `data/report.tsv`.",
        f"- `assets/ExportedProject/`: AssetRipper Unity project; {sum(assets.values())} files. {refs} references in `assets/refs.tsv`.",
    ] + [f"- `{rel}`: {text}" for rel, text in extras(out)] + [
        "",
        "| Asset folder | Files |",
        "|---|---|",
    ] + [f"| {k} | {v} |" for k, v in assets.most_common()]
    with open(os.path.join(out, "INDEX.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
