"""Name the IL2CPP runtime helpers Ghidra leaves as FUN_xxx / func_0x..., by how they are called.

Every game method calls the same handful of runtime helpers. Each has a call shape no other
function has, so the most frequent callee in that shape is the helper. The table lands in
code/helpers.tsv and the names are substituted into code/decomp/**/*.c (safe to rerun).
"""
import os
import re
from collections import Counter

CALLEE = r"(FUN_[0-9a-f]+|func_0x[0-9a-f]+)"
SHAPES = {
    "il2cpp_init_metadata": re.compile(CALLEE + r"\(&(MethodInfo__|TypeInfo__|StringLiteral_|FieldInfo|_ZN)"),
    "il2cpp_object_new": re.compile(r"= \([\w ]+\*\)\s*" + CALLEE + r"\(\s*TypeInfo__"),
    "il2cpp_write_barrier": re.compile(CALLEE + r"\(&\(\w+->fields\)"),
    "il2cpp_runtime_class_init": re.compile(r"field_0x1c == 0\) \{\s*\n\s*" + CALLEE + r"\("),
    "il2cpp_throw_null_reference": re.compile(CALLEE + r"\(\);\s*\n\s*pcVar\d+ = \(code \*\)swi\(3\);"),
}
HEADER = re.compile(r"^// .*  @(0x[0-9a-fA-F]+)$")
NOISE = re.compile(r"^/\* WARNING: Unknown calling convention -- yet parameter storage is locked \*/\n", re.M)
# Compiler-inserted IL2CPP lazy-init guards: pure boilerplate before the real body, present in
# almost every method. Drop them so a reader sees the logic. Both blocks are brace-balanced.
GUARD_RTC = re.compile(
    r"[ \t]*if \(\*\(int \*\)&\(TypeInfo__\w+->_1\)\.field_0x1c == 0\) \{\n"
    r"[ \t]*il2cpp_runtime_class_init\(\);\n[ \t]*\}\n")
GUARD_META = re.compile(
    r"[ \t]*if \(DAT_[0-9a-f]+ == '\\0'\) \{\n[ \t]*il2cpp_init_metadata\([^\n]*\);\n"
    r"[ \t]*DAT_[0-9a-f]+ = '\\x01';\n[ \t]*\}\n")


def addr(token):
    return int(token.split("_", 1)[1].replace("0x", ""), 16)


def c_files(decomp):
    for d, _, files in os.walk(decomp):
        for f in files:
            if f.endswith(".c"):
                yield os.path.join(d, f)


def find_helpers(decomp):
    counts = {name: Counter() for name in SHAPES}
    for p in c_files(decomp):
        text = open(p, encoding="utf-8").read()
        for name, rx in SHAPES.items():
            for m in rx.finditer(text):
                counts[name][addr(m.group(1))] += 1
    found = {}
    for name, c in counts.items():
        for a, n in c.most_common():
            if a not in found:
                found[a] = (name, n)
                break
    return found


def name_helpers(root):
    decomp = os.path.join(root, "code", "decomp")
    found = find_helpers(decomp)
    with open(os.path.join(root, "code", "helpers.tsv"), "w", encoding="utf-8") as fh:
        fh.write("address\tname\tcalls_in_shape\n")
        for a, (name, n) in sorted(found.items(), key=lambda x: x[1][0]):
            fh.write(f"0x{a:x}\t{name}\t{n}\n")
    tokens = re.compile(CALLEE)
    by_addr = {a: name for a, (name, _) in found.items()}

    def sub(m):
        return by_addr.get(addr(m.group(1)), m.group(1))

    header_line = {}
    for p in c_files(decomp):
        text = open(p, encoding="utf-8").read()
        new = GUARD_META.sub("", GUARD_RTC.sub("", NOISE.sub("", tokens.sub(sub, text))))
        if new != text:
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(new)
        rel = os.path.relpath(p, decomp)
        for i, line in enumerate(new.split("\n"), 1):
            m = HEADER.match(line)
            if m:
                header_line[(rel, int(m.group(1), 16))] = i
    fix_method_lines(os.path.join(root, "code", "methods.tsv"), header_line)
    return found


def fix_method_lines(path, header_line):
    """Point methods.tsv at each method's header line in the rewritten files."""
    with open(path, encoding="utf-8") as fh:
        rows = [line.rstrip("\n").split("\t") for line in fh]
    head, body = rows[0], rows[1:]
    for r in body:
        r[4] = str(header_line.get((r[3], int(r[2], 16)), r[4]))
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join("\t".join(r) for r in [head] + body) + "\n")
