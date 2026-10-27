"""Turn post-build patches (methoddiff rows where the deployed body differs and is not a stub) into cand.manual rows,
so a fresh assemble reproduces the DLL that is actually running. Helpers xplant added to the type (UdkNew*) travel as
local functions inside the body that calls them. Constructor initializer changes (`: base(...)`) ride in the row's
"init" field; Oracle puts it on the constructor in place of the skeleton's default-argument initializer.
Usage: python migrate_rows.py <mdiff.jsonl> <keys.<asm>.tsv> <out cand.jsonl> <out report.tsv>"""
import io, json, re, sys
from pathlib import Path
sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, str(Path(__file__).parent))
from migrate_plan import stub

KW = {"int": "Int32", "uint": "UInt32", "long": "Int64", "ulong": "UInt64", "short": "Int16", "ushort": "UInt16",
      "byte": "Byte", "sbyte": "SByte", "float": "Single", "double": "Double", "decimal": "Decimal", "bool": "Boolean",
      "string": "String", "object": "Object", "char": "Char", "void": "Void"}


def split_params(s):
    out, depth, cur = [], 0, ""
    for ch in s:
        if ch in "<([":
            depth += 1
        elif ch in ">)]":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur)
    return out


def param_type(p):
    p = re.sub(r"\[[^\]]*\]\s*", "", p.strip()) if p.strip().startswith("[") else p.strip()
    p = re.sub(r"\s*=.*$", "", p)
    byref = "&" if re.match(r"^(?:ref|out|in)\s", p) else ""
    p = re.sub(r"^(?:this|ref|out|in|params)\s+", "", p)
    return _type_name(p.rsplit(" ", 1)[0].strip()) + byref


OPS = {"+": "op_Addition", "-": "op_Subtraction", "*": "op_Multiply", "/": "op_Division", "%": "op_Modulus",
       "==": "op_Equality", "!=": "op_Inequality", "<": "op_LessThan", ">": "op_GreaterThan", "<=": "op_LessThanOrEqual",
       ">=": "op_GreaterThanOrEqual", "!": "op_LogicalNot", "true": "op_True", "false": "op_False"}


def _type_name(t):
    arr = "[]" if t.endswith("[]") else ""
    t = t[:-2] if arr else t
    if t.endswith("?"):
        return "Nullable" + arr
    if t.startswith("("):
        return "ValueTuple" + arr
    t = re.sub(r"<.*>$", "", t).split(".")[-1]
    return KW.get(t, t) + arr


def split_member(raw):
    """(header, initializer, body) from an ilspy member; body without the outer braces."""
    i, depth = 0, 0
    while i < len(raw):
        ch = raw[i]
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        elif depth == 0 and (ch == "{" or raw.startswith("=>", i)):
            break
        i += 1
    head = raw[:i].strip()
    rest = raw[i:].strip()
    init = ""
    m = re.search(r"\)\s*:\s*((?:base|this)\s*\(.*\))\s*$", head, re.S)
    if m:
        init = m.group(1)
        head = head[:m.start() + 1]
    if rest.startswith("=>"):
        expr = rest[2:].strip().rstrip(";")
        return head, init, None, expr
    return head, init, rest[1:rest.rstrip().rfind("}")].strip("\n"), None


def main():
    mdiff, keys_tsv, out_cand, out_rep = sys.argv[1:5]
    keys = [l.split("\t")[0] for l in io.open(keys_tsv, encoding="utf-8").read().splitlines()[1:] if l]
    keyset = set(keys)
    rows = list(map(json.loads, io.open(mdiff, encoding="utf-8")))
    helpers = {}
    for r in rows:
        if r["kind"] == "only_deployed" and re.search(r"\bUdkNew\w+\s*\(", r["member"]):
            name = re.search(r"\b(UdkNew\w+)\s*\(", r["member"]).group(1)
            text = re.sub(r"^\s*(?:private|public|internal|protected)\s+", "", r["deployed_raw"].strip())
            helpers[(r["type"], name)] = text
    cands, report = [], []
    for r in rows:
        if r["kind"] != "changed":
            continue
        # An empty constructor body looks like a stub, but its initializer may be the whole fix (base(baseWeight)).
        if stub(r["deployed"]) and not re.search(r"\)\s*:\s*(?:base|this)\s*\(", r["deployed"].split("{", 1)[0]):
            continue
        raw = r["deployed_raw"]
        head, init, body, expr = split_member(raw)
        m = re.search(r"\b(?!(?:public|private|protected|internal|static|override|virtual|unsafe)\b)([A-Za-z_]\w*)"
                      r"(?:<[\w\s,]*>)?\((.*)\)\s*$", head, re.S)
        typ = r["type"]
        ns_type = typ
        if not m:
            report.append(("skip:not_a_method", typ, r["member"][:120], ""))
            continue
        name, params = m.group(1), m.group(2)
        simple = re.sub(r"`[0-9]+$", "", typ.split(".")[-1])
        suffix = ""
        op = re.search(r"\b(implicit|explicit)\s+operator\s+([\w.<>\[\]?]+)\s*\(|\boperator\s*([^\s(]+)\s*\(", head)
        if op and op.group(1):
            name, suffix = "op_" + op.group(1).capitalize(), ":" + _type_name(op.group(2))
        elif op:
            name = OPS.get(op.group(3), op.group(3))
        elif name == simple:
            name = ".cctor" if re.search(r"\bstatic\b", head) else ".ctor"
        sig = ",".join(param_type(p) for p in split_params(params))
        # Nested types: the key uses '/' after the outermost type and `N for generic arity.
        tail = f"::{name}({sig}){suffix}"
        cands_k = [k for k in keyset if k.endswith(tail) and k.split("::")[0].replace("/", ".") == ns_type]
        if len(cands_k) == 2 and re.search(r"\(\s*\S", init) and sum("`" in k for k in cands_k) == 1:
            # Foo and Foo<T> decompile into one name here; a base call with arguments cannot target object, so the
            # generic subclass is the one that owns it.
            cands_k = [k for k in cands_k if "`" in k]
        if len(cands_k) != 1:
            report.append(("skip:no_key" if not cands_k else "skip:ambiguous_key", typ, f"{name}({sig})", ";".join(cands_k[:3])))
            continue
        key = cands_k[0]
        if expr is not None:
            void = re.search(r"\bvoid\s+\w+\s*\(", head) or name in (".ctor", ".cctor")
            body = f"{expr};" if void else f"return {expr};"
        used = sorted({h for (t, h) in helpers if t == typ and re.search(rf"\b{h}\b", body)})
        if used:
            body = body + "\n" + "\n".join(helpers[(typ, h)] for h in used)
        ours_init = re.search(r"\)\s*:\s*((?:base|this)\s*\(.*?\))\s*\{", r["ours"] or "")
        ours_init = ours_init.group(1) if ours_init else ""
        row = {"key": key, "src": "manual", "native": "migrated from deployed pc24-release Runtime.dll 916c0695 (Cecil/xplant patch)",
               "body": body}
        if name == ".ctor" and re.sub(r"\s+", "", init) != re.sub(r"\s+", "", ours_init):
            row["init"] = init
            report.append(("init:ctor_initializer", typ, key, f"ours `{ours_init}` deployed `{init}`"))
        cands.append(row)
        report.append(("manual" + (":with_helpers" if used else ""), typ, key, ",".join(used)))
    with io.open(out_cand, "w", encoding="utf-8", newline="\n") as w:
        w.writelines(json.dumps(c) + "\n" for c in cands)
    with io.open(out_rep, "w", encoding="utf-8", newline="\n") as w:
        w.write("class\ttype\tkey\tdetail\n")
        w.writelines("\t".join(x) + "\n" for x in report)
    from collections import Counter
    for k, v in sorted(Counter(x[0] for x in report).items()):
        print(f"{v:5}  {k}")


if __name__ == "__main__":
    main()
