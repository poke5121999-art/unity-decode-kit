"""Deterministic bodies for stubbed accessors whose native code only returns or stores one field.
The 3p closure seeded what the game calls, so plain property getters (JSkyProfile.FogSyncOption, EnableSun,
SunLightIntensity) stayed `return default;` and silently switched features off. No LLM: the native shape is exact.
Writes cand.trivial.<asm>.jsonl. Usage: python trivial.py <work dir> <asm>..."""
import io, json, re, sys
sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, "D:/walking-trade-ref/udk")
from udk.recompile import loose
sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent))
from recovered import recovered

GET = re.compile(r"^\s*return\s+(?:\(\s*\w+\s*\*?\s*\)\s*)?\(?(this->fields\)?|TypeInfo__[\w]+->static_fields)\s*(?:\.|->)\s*(\w+)\s*;\s*$")
SET = re.compile(r"^\s*\(?(this->fields\)?|TypeInfo__[\w]+->static_fields)\s*(?:\.|->)\s*(\w+)\s*=\s*value\s*;\s*$")


def code_lines(c):
    body = c.split("\n{", 1)[-1].rsplit("}", 1)[0]
    out = []
    for l in body.splitlines():
        s = l.strip()
        if not s or s.startswith(("il2cpp_", "//", "/*", "if (DAT_", "DAT_", "}", "return;")) or "write_barrier" in s:
            continue
        # Static class-init guard il2cpp puts before any static field access.
        if re.match(r"^if \(\*\(int \*\)&\(TypeInfo__\w+->_1\)\.field_0x1c == 0\) \{$", s):
            continue
        if re.match(r"^[\w\s\*]+ \*?\w+;$", s) and "=" not in s:
            continue
        out.append(s)
    return out


def main(W, asms):
  nat = {}
  for l in io.open(f"{W}/ghidra.jsonl", encoding="utf-8"):
    r = json.loads(l)
    nat.setdefault(loose(r["key"]), r["c"])

  for asm in asms:
    ok = recovered(W, asm, "trivial")
    keys = [l.split("\t")[0] for l in io.open(f"{W}/keys.{asm}.tsv", encoding="utf-8").read().splitlines()[1:] if l]
    out = []
    for k in keys:
        name = k.split("::", 1)[1]
        if loose(k) in ok or not re.match(r"(get|set)_\w+\(", name):
            continue
        c = nat.get(loose(k))
        if not c or "folded" in c[:200]:
            continue
        typ = re.sub(r"`\d+", "", k.split("::", 1)[0].split("/")[-1].split(".")[-1])
        if typ not in c.split("\n{", 1)[0].split("*/", 1)[-1]:
            continue
        lines = code_lines(c)
        if name.startswith("get_") and len(lines) == 1 and (m := GET.match(lines[0])):
            body = f"return {m.group(2)};"
        elif name.startswith("set_") and len(lines) == 1 and (m := SET.match(lines[0])):
            body = f"{m.group(2)} = value;"
        else:
            continue
        if "k__BackingField" in body:
            continue
        out.append({"key": k, "src": "trivial", "body": body})
    with io.open(f"{W}/cand.trivial.{asm}.jsonl", "w", encoding="utf-8", newline="\n") as w:
        w.writelines(json.dumps(r) + "\n" for r in out)
    print(f"{asm}: {len(out)} trivial accessors")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2:])
