"""Name the fields of values returned by shared generic code.

IL2CPP compiles Table<int, TItem>.get_Item once for every reference type argument, so Ghidra types its
result as the shared instantiation's (Object__Array*, Il2CppObject*...). A read of TItem's field at
0x18 then prints as `item->max_length`. The call still passes the closed method's MethodInfo
(`MethodInfo__..Table<int,_GameCommon::Table::TItem>__get_Item_int_`), whose .NET signature in
Il2CppInspector's metadata gives the real return type. This pass finds variables assigned from such a
call and appends, to each line that reads them, the real field at that offset:
    SetActive(questMark, (int)item->max_length == 1)  /* item: TItem; 0x18 = _Category_k__BackingField */
Comments only; the decompiled text is unchanged otherwise. A rerun replaces earlier notes.
Usage: python -m udk.retype <dump>
"""
import json
import os
import re
import subprocess
import sys

MARK = "/* retype: "
OLD = re.compile(r"  /\* retype: [^\n]*? \*/$", re.M)
ALNUM = re.compile(r"[^A-Za-z0-9]")
FIELD_LINE = re.compile(r"^\s*(?:\[[^\]]*\]\s*)*((?:public|private|protected|internal|static|readonly|const|volatile|new)\s+)*"
                        r"[\w.<>\[\], ]+?\s+(\w+);\s*//\s*0x([0-9A-Fa-f]+)")
CLASS_LINE = re.compile(r"^(\t*)(?:\[[^\]]*\]\s*)*(?:public|private|protected|internal)?\s*(?:sealed |abstract |static |readonly |ref )*"
                        r"(?:class|struct) (\w+)")


def type_fields(types_cs):
    """{qualified type name: {offset: field}} for instance fields, from Il2CppInspector's types.cs."""
    out, stack, ns = {}, [], ""
    with open(types_cs, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.startswith("namespace "):
                ns = line.split()[1].strip("{ \n")
                continue
            m = CLASS_LINE.match(line)
            if m and "(" not in line:
                depth = len(m.group(1)) - (1 if ns else 0)
                stack = stack[:max(depth, 0)] + [m.group(2)]
                out[".".join(([ns] if ns else []) + stack)] = cur = {}
                continue
            f = FIELD_LINE.match(line)
            if f and stack and " static " not in f" {line.strip()} " and " const " not in f" {line.strip()} ":
                cur.setdefault(int(f.group(3), 16), f.group(2))
    return out


def closed_returns(metadata_json):
    """{alphanumeric key of the MethodInfo label: .NET return type, qualified when the label names it}."""
    with open(metadata_json, encoding="utf-8") as fh:
        infos = json.load(fh)["addressMap"]["methodInfoPointers"]
    names = [m["name"] for m in infos]
    r = subprocess.run(["c++filt"], input="\n".join(names), capture_output=True, text=True)
    out = {}
    for m, dem in zip(infos, r.stdout.split("\n")):
        sig = m.get("dotNetSignature", "")
        ret = sig.split(" ", 1)[0] if " " in sig else ""
        if not ret or ret in ("Void", "Boolean", "Int32", "Single", "String", "Object") or "<" not in dem:
            continue
        q = re.search(rf"([\w:]+::{re.escape(ret)})\b", dem)
        out[ALNUM.sub("", dem)] = q.group(1).replace("::", ".") if q else ret
    return out


# Members of the shared types Ghidra picks, by offset in pointer-size units of the object header.
HEADER = {"klass": 0, "monitor": 1, "bounds": 2, "max_length": 3}
ASSIGN = re.compile(r"(\w+) = (?:(?!\b\w+ = )[^;])*?(MethodInfo__(?:[^\s,()<>]|<(?:[^<>]|<[^<>]*>)*>)+)", re.S)


_PREFIX = {}


def lookup(returns, key):
    """Return type for a MethodInfo label; Ghidra cuts very long labels at the line end, so a label
    that is a prefix of known ones resolves when they all return the same type."""
    if key in returns:
        return returns[key]
    if len(key) < 40:
        return None
    if id(returns) not in _PREFIX:
        _PREFIX.clear()
        _PREFIX[id(returns)] = sorted(returns)
    import bisect
    keys = _PREFIX[id(returns)]
    i = bisect.bisect_left(keys, key)
    found = set()
    while i < len(keys) and keys[i].startswith(key):
        found.add(returns[keys[i]])
        i += 1
    return found.pop() if len(found) == 1 else None


def annotate(text, returns, fields, ptr):
    """Return text with retype comments, and the number of lines annotated. A variable is retyped
    only when every assignment to it in the function is a call returning the same closed type."""
    text = OLD.sub("", text)  # recompute, so a rerun after a fix replaces old notes
    by_short = {}
    for q in fields:
        by_short.setdefault(q.rsplit(".", 1)[-1], []).append(q)
    heads = [m.start() for m in re.finditer(r"^// .*  @0x", text, re.M)] or [0]
    chunks = [text[:heads[0]]] + [text[a:b] for a, b in zip(heads, heads[1:] + [len(text)])]
    out, n = [], 0
    for chunk in chunks:
        seen = {}
        for m in ASSIGN.finditer(chunk):
            ret = lookup(returns, ALNUM.sub("", m.group(2)))
            q = None
            if ret:
                q = ret if ret in fields else (by_short.get(ret.rsplit(".", 1)[-1]) or [None])[0]
            seen.setdefault(m.group(1), set()).add(q)
        var_type = {}
        for var, qs in seen.items():
            if len(qs) == 1 and None not in qs and len(re.findall(rf"(?<![\w.>]){re.escape(var)} = ", chunk)) == \
                    len([m for m in ASSIGN.finditer(chunk) if m.group(1) == var]):
                var_type[var] = next(iter(qs))
        lines = chunk.split("\n")
        for i, line in enumerate(lines):
            notes = []
            if MARK not in line:
                for var, q in var_type.items():
                    v = re.escape(var)
                    for mm in re.finditer(rf"\(\(\w+\)&{v}(?:->|\[(\d+)\]\.)(\w+) \+ (0x[0-9a-fA-F]+|\d+)\)|"
                                          rf"\b{v}\[(\d+)\]\.(klass|monitor)\b|"
                                          rf"\b{v}->(\w+)\b(?!\[)|\b{v}->vector\[(\d+)\]|"
                                          rf"\([\w ]+\*\)\((?:\(\w+\))?{v} \+ (0x[0-9a-fA-F]+|\d+)\)", line):
                        g = mm.groups()
                        # Il2CppObject* indexed as an array: p[k].monitor is k objects of (klass, monitor) in
                        obj = lambda k: 2 * ptr * int(k) if k else 0
                        if g[1] in HEADER:
                            off = obj(g[0]) + HEADER[g[1]] * ptr + int(g[2], 0)
                        elif g[4]:
                            off = obj(g[3]) + HEADER[g[4]] * ptr
                        elif g[5] in HEADER:
                            off = HEADER[g[5]] * ptr
                        elif g[6]:
                            off = (4 + int(g[6])) * ptr  # Object__Array.vector after the header
                        elif g[7]:
                            off = int(g[7], 0)
                        else:
                            continue
                        f = fields[q].get(off)
                        if f:
                            notes.append(f"{var}: {q.rsplit('.', 1)[-1]}; 0x{off:x} = {f}")
            if notes:
                lines[i] = f"{line}  {MARK}{'; '.join(dict.fromkeys(notes))} */"
                n += 1
        out.append("\n".join(lines))
    return "".join(out), n


def run(root):
    fields = type_fields(os.path.join(root, "code", "types.cs"))
    returns = closed_returns(os.path.join(root, "inspector", "metadata.json"))
    with open(os.path.join(root, "INDEX.md"), encoding="utf-8") as fh:
        binary = re.search(r"Binary `([^`]+)`", fh.read()).group(1)
    with open(binary, "rb") as fh:
        head = fh.read(5)
    ptr = 4 if head[:4] == b"\x7fELF" and head[4] == 1 else 8
    total = files = 0
    for d, _, fs in os.walk(os.path.join(root, "code", "decomp")):
        for f in fs:
            if not f.endswith(".c"):
                continue
            p = os.path.join(d, f)
            with open(p, encoding="utf-8") as fh:
                text = fh.read()
            if "MethodInfo__" not in text:
                continue
            new, n = annotate(text, returns, fields, ptr)
            if new != text:
                with open(p, "w", encoding="utf-8") as fh:
                    fh.write(new)
            total += n
            files += bool(n)
    return total, files


if __name__ == "__main__":
    n, f = run(sys.argv[1])
    print(f"[retype] {n} lines annotated in {f} files")
