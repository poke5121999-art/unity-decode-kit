# Headless PyGhidra script: decompile every method of the game assemblies into one C file per type.
# Args: <inspector_ghidra_dir> <game_assembly_regex> <out_dir> [workers]
# Output: <out_dir>/<Assembly>/<Namespace path>/<Type>.c and <out_dir>/methods.tsv
# (name, .NET signature, address, file, line) so `udk method` can jump straight to a body.
import json
import os
import re
import threading
import time
from collections import defaultdict

import java.lang
from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.util.task import ConsoleTaskMonitor

args = list(getScriptArgs())
inspector_dir, game_re, out_dir = args[:3]
workers = int(args[3]) if len(args) > 3 else 4
game_re = re.compile(game_re)
t0 = time.time()


def log(msg):
    print(f"[decompile {time.time() - t0:7.1f}s] {msg}", flush=True)


meta = json.load(open(os.path.join(inspector_dir, "metadata.json"), encoding="utf-8"))["addressMap"]
by_type = defaultdict(list)
for m in meta["methodDefinitions"]:
    group = m.get("group", "")
    if m["virtualAddress"] == "0x0000000000000000" or not game_re.match(group.split("/")[0]):
        continue
    by_type[group].append(m)
del meta
log(f"{sum(map(len, by_type.values()))} methods in {len(by_type)} types")

fm = currentProgram.getFunctionManager()
jobs = sorted(by_type.items())
lock = threading.Lock()
rows = []
done = [0]


def worker(chunk):
    ifc = DecompInterface()
    ifc.setOptions(DecompileOptions())
    ifc.toggleCCode(True)
    ifc.openProgram(currentProgram)
    mon = ConsoleTaskMonitor()
    for group, methods in chunk:
        rel = group.replace(".dll/", "/", 1).replace("<", "_").replace(">", "_") + ".c"
        path = os.path.join(out_dir, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        lines = []
        local_rows = []
        for m in sorted(methods, key=lambda m: m["dotNetSignature"]):
            fn = fm.getFunctionAt(toAddr(java.lang.Long(int(m["virtualAddress"], 16))))
            header = f"// {m['dotNetSignature']}  @{m['virtualAddress']}"
            local_rows.append((m["signature"].split("(")[0].split()[-1], m["dotNetSignature"], m["virtualAddress"], rel, len(lines) + 1))
            lines.append(header)
            if fn is None:
                lines.append("// (no function at this address)\n")
                continue
            res = ifc.decompileFunction(fn, 60, mon)
            if res is None or not res.decompileCompleted():
                lines.append(f"// decompile failed: {res.getErrorMessage() if res else 'none'}\n")
                continue
            lines.extend(res.getDecompiledFunction().getC().strip("\n").split("\n"))
            lines.append("")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        with lock:
            rows.extend(local_rows)
            done[0] += 1
            if done[0] % 200 == 0:
                log(f"{done[0]}/{len(jobs)} types")
    ifc.dispose()


chunks = [jobs[i::workers] for i in range(workers)]
threads = [threading.Thread(target=worker, args=(c,)) for c in chunks]
for t in threads:
    t.start()
for t in threads:
    t.join()

with open(os.path.join(out_dir, "methods.tsv"), "w", encoding="utf-8") as fh:
    fh.write("c_name\tsignature\taddress\tfile\tline\n")
    for r in sorted(rows):
        fh.write("\t".join(map(str, r)) + "\n")
log(f"done, {len(rows)} methods")
