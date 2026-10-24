"""Ground truth for "does this C# body do what the native method does": the direct calls in the machine code.

For every method in ghidra.jsonl, disassemble its native range in GameAssembly and resolve each `call rel32`
target to the managed methods at that address (several names when identical-code folding merged them).
Runtime helpers (il2cpp_*, unnamed thunks) are dropped. Writes native_calls.jsonl {key, calls:[[alt names]], indirect}.

Usage: python -m udk.nativecalls <config.json>   (config needs "binary": path to GameAssembly.dll / libil2cpp.so)
"""
import bisect
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

import capstone
import pefile

from .recompile import Game, jsonl, write_jsonl


# A target shared by more methods than this (Object..ctor, empty bodies) says nothing about which one was meant.
FOLD_LIMIT = 8


def simple_type(group):
    t = group.split("/", 1)[1] if "/" in group else group
    t = re.sub(r"\[[^\[\]]*(\[[^\[\]]*\][^\[\]]*)*\]", "", t)
    t = t.split("+")[-1].split("/")[-1].split(".")[-1]
    return re.sub(r"`\d+", "", t)


def method_name(sig):
    head = sig.split("(", 1)[0]
    if " " not in head.strip():
        return ".ctor"
    name = head.split(" ")[-1]
    name = re.sub(r"\[[^\[\]]*(\[[^\[\]]*\][^\[\]]*)*\]", "", name)
    return name.split(".")[-1] if not name.startswith(".") else name


def load_symbols(meta_path):
    names = defaultdict(set)
    starts = set()
    sec, cur = None, {}
    with open(meta_path, encoding="utf-8") as f:
        for line in f:
            m = re.match(r'^    "([a-zA-Z]+)": \[', line)
            if m:
                sec = m.group(1)
                continue
            if sec == "functionAddresses":
                m = re.match(r'^\s+"(0x[0-9A-Fa-f]+)"', line)
                if m:
                    starts.add(int(m.group(1), 16))
                continue
            if sec not in ("methodDefinitions", "constructedGenericMethods"):
                continue
            m = re.match(r'^\s+"(virtualAddress|dotNetSignature|group)": "(.*)",?$', line)
            if m:
                cur[m.group(1)] = json.loads('"' + m.group(2) + '"')
            elif line.strip().startswith("}"):
                if "virtualAddress" in cur and "group" in cur:
                    a = int(cur["virtualAddress"], 16)
                    starts.add(a)
                    name = method_name(cur.get("dotNetSignature", ""))
                    if name in ("ctor", "cctor"):
                        name = "." + name
                    names[a].add(simple_type(cur["group"]) + "::" + name)
                cur = {}
    return names, sorted(starts)


def main(cfg_path):
    g = Game(cfg_path)
    names, starts = load_symbols(g.dump / "inspector" / "metadata.json")
    pe = pefile.PE(g.cfg["binary"], fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase
    secs = [(base + s.VirtualAddress, s.get_data()) for s in pe.sections if s.Characteristics & 0x20000000]
    pdata = next(s for s in pe.sections if s.Name.rstrip(b"\0") == b".pdata").get_data()
    fend = {}
    for off in range(0, len(pdata) - 11, 12):
        b, e = int.from_bytes(pdata[off:off + 4], "little"), int.from_bytes(pdata[off + 4:off + 8], "little")
        if b:
            fend.setdefault(base + b, base + e)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

    def scan(a):
        i = bisect.bisect_right(starts, a)
        end = starts[i] if i < len(starts) else a + 0x4000
        end = min(fend.get(a, end), a + 0x10000)
        sec = next(((v, d) for v, d in secs if v <= a < v + len(d)), None)
        calls, indirect, unresolved, folded = [], 0, 0, 0
        if sec is None:
            return calls, indirect, unresolved, folded
        sva, sdata = sec
        for ins in md.disasm(sdata[a - sva:end - sva], a):
            if ins.mnemonic not in ("call", "jmp"):
                continue
            op = ins.op_str
            if ins.mnemonic == "jmp" and (not op.startswith("0x") or a <= int(op, 16) < end):
                continue
            if not op.startswith("0x"):
                indirect += 1
                continue
            t = int(op, 16)
            if t in names and len(names[t]) <= FOLD_LIMIT:
                calls.append(sorted(names[t]))
            elif t in names:
                folded += 1
            else:
                unresolved += 1
        return calls, indirect, unresolved, folded

    rows, unresolved_total = [], 0
    for r in jsonl(g.p("ghidra.jsonl")):
        calls, indirect, unresolved, folded = scan(int(r["addr"], 16))
        unresolved_total += unresolved
        rows.append({"key": r["key"], "calls": calls, "indirect": indirect, "helpers": unresolved, "folded": folded})
    write_jsonl(g.p("native_calls.jsonl"), rows)
    n = sum(len(r["calls"]) for r in rows)
    print(f"native_calls.jsonl: {len(rows)} methods, {n} resolved direct calls, {unresolved_total} helper calls")

    # Callees of every named function (BCL and plugins too), so a C# call that C++ inlined can be expanded one level.
    callees = defaultdict(set)
    for a, ns in names.items():
        if len(ns) > FOLD_LIMIT:
            continue
        flat = {x for alts in scan(a)[0] for x in alts}
        if flat:
            for nm in ns:
                callees[nm] |= flat
    g.p("callees.json").write_text(json.dumps({k: sorted(v) for k, v in callees.items()}), encoding="utf-8")
    print(f"callees.json: {len(callees)} functions with direct callees")


if __name__ == "__main__":
    main(sys.argv[1])
