# Headless PyGhidra script (run with analysis): decompile every function of a native plugin.
# Args: <out_dir> [workers]
# Output: <out_dir>/<group>.c, one file per C++ class or namespace, or per name prefix for C
# exports (PHY_Vehicle... -> PHY.c); unnamed functions go to _unnamed.c. <out_dir>/functions.tsv
# lists name, address, file and line so `udk q` and grep land on a body.
import os
import re
import threading
import time
from collections import defaultdict

from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.util.task import ConsoleTaskMonitor

args = list(getScriptArgs())
out_dir = args[0]
workers = int(args[1]) if len(args) > 1 else 4
t0 = time.time()


def log(msg):
    print(f"[native {time.time() - t0:7.1f}s] {msg}", flush=True)


def group_of(fn):
    ns = fn.getParentNamespace()
    if ns is not None and not ns.isGlobal():
        return ns.getName(True).replace("::", "/")
    name = fn.getName()
    if name.startswith("FUN_"):
        return "_unnamed"
    m = re.match(r"[A-Za-z0-9]+", name)
    return m.group(0) if m else "_misc"


groups = defaultdict(list)
for fn in currentProgram.getFunctionManager().getFunctions(True):
    if fn.isThunk() or fn.isExternal():
        continue
    groups[group_of(fn)].append(fn)
jobs = sorted(groups.items())
log(f"{sum(map(len, groups.values()))} functions in {len(jobs)} groups")

lock = threading.Lock()
rows = []
done = [0]


def worker(chunk):
    ifc = DecompInterface()
    ifc.setOptions(DecompileOptions())
    ifc.toggleCCode(True)
    ifc.openProgram(currentProgram)
    mon = ConsoleTaskMonitor()
    for group, fns in chunk:
        rel = re.sub(r"[<>:*?\"|]", "_", group) + ".c"
        path = os.path.join(out_dir, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        lines, local = [], []
        for fn in sorted(fns, key=lambda f: f.getEntryPoint().getOffset()):
            addr = f"0x{fn.getEntryPoint().getOffset():X}"
            local.append((fn.getName(True), addr, rel, len(lines) + 1))
            lines.append(f"// {fn.getName(True)}  @{addr}")
            res = ifc.decompileFunction(fn, 60, mon)
            if res is None or not res.decompileCompleted():
                lines.append(f"// decompile failed: {res.getErrorMessage() if res else 'none'}\n")
                continue
            lines.extend(res.getDecompiledFunction().getC().strip("\n").split("\n"))
            lines.append("")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        with lock:
            rows.extend(local)
            done[0] += 1
            if done[0] % 100 == 0:
                log(f"{done[0]}/{len(jobs)} groups")
    ifc.dispose()


threads = [threading.Thread(target=worker, args=(jobs[i::workers],)) for i in range(workers)]
for t in threads:
    t.start()
for t in threads:
    t.join()
with open(os.path.join(out_dir, "functions.tsv"), "w", encoding="utf-8") as fh:
    fh.write("name\taddress\tfile\tline\n")
    for r in sorted(rows):
        fh.write("\t".join(r[:3]) + f"\t{r[3]}\n")
log(f"done, {len(rows)} functions")
