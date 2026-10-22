# Headless PyGhidra script: load Il2CppInspector types and names into a GameAssembly/libil2cpp program.
# Args: <inspector_ghidra_dir> <game_assembly_regex>
# The inspector dir holds metadata.json, il2cpp_ghidra.py and cpp/appdata/il2cpp-types.h
# (Il2CppInspector -t Ghidra). Only methods of assemblies matching the regex get full C
# signatures; the rest get a function + name, which is what callers need to read well.
import json
import os
import re
import time

import java.io
import java.lang
from ghidra.app.util.cparser.C import CParserUtils
from ghidra.program.model.symbol import SourceType, SymbolUtilities

inspector_dir, game_re = getScriptArgs()
game_re = re.compile(game_re)
t0 = time.time()


def log(msg):
    print(f"[prepare {time.time() - t0:7.1f}s] {msg}", flush=True)


if not getDataTypes("Il2CppObject"):
    header = os.path.join(inspector_dir, "cpp", "appdata", "il2cpp-types.h")
    log(f"parsing {header}")
    dtm = currentProgram.getDataTypeManager()
    res = CParserUtils.parseHeaderFiles(
        [], [header], [], ["-D_GHIDRA_"], dtm, monitor)
    log(f"header parsed, ok={res.successful()} types={dtm.getDataTypeCount(True)}")
    if not res.successful():
        print(res.getFormattedParseMessage(None))

src = open(os.path.join(inspector_dir, "il2cpp_ghidra.py"), encoding="utf-8").read()
src = src[: src.rindex("status = GhidraStatusHandler()")]
exec(compile(src, "il2cpp_ghidra.py", "exec"), globals())
getSourceFile = lambda: java.io.File(os.path.join(inspector_dir, "il2cpp_ghidra.py"))  # noqa: E731

backend = GhidraDisassemblerInterface()
context = ScriptContext(backend, GhidraStatusHandler())
backend.on_start()

meta = json.load(open(os.path.join(inspector_dir, "metadata.json"), encoding="utf-8"))["addressMap"]
log("metadata loaded")


def is_game(m):
    return bool(game_re.match(m.get("group", "").split("/")[0]))


game = [m for m in meta["methodDefinitions"] if is_game(m)]
rest = [m for m in meta["methodDefinitions"] if not is_game(m)]
log(f"methods: game={len(game)} other={len(rest)} generic={len(meta['constructedGenericMethods'])}")

symtab = currentProgram.getSymbolTable()
seen = set()


def name_only(m):
    a = int(m["virtualAddress"], 16)
    if a == 0 or a in seen:
        return
    seen.add(a)
    addr = toAddr(java.lang.Long(a))
    if getFunctionAt(addr) is None:
        createFunction(addr, None)
    label = backend._demangle_symbol(m["name"]) if m["name"].startswith("_ZN") else m["name"]
    if label and len(label) < 2000:
        createLabel(addr, SymbolUtilities.replaceInvalidChars(label, True), True)


for m in game:
    a = int(m["virtualAddress"], 16)
    if a == 0:
        continue
    seen.add(a)
    backend.define_function(a)
    context.define_il_method(m)
log("game methods typed")
for m in rest:
    name_only(m)
log("other methods named")
for m in meta["constructedGenericMethods"]:
    name_only(m)
log("generic instances named")

for d in meta["stringLiterals"]:
    context.define_string(d)
for d in meta["typeInfoPointers"]:
    context.define_field_from_json(d)
for d in meta["methodInfoPointers"]:
    context.define_il_method_info(d)
for d in meta["fields"]:
    context.define_field_with_value(d)
log("strings, TypeInfo, MethodInfo, fields labelled")
for d in meta["apis"]:
    context.define_cpp_function(d)
log("done")
