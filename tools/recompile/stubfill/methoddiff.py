"""Per-member diff of two `ilspycmd -p` trees: the pipeline's assembled DLL against the DLL actually deployed. Two
compiles of the same source decompile identically, so every difference is a post-build patch (Cecil, xplant) or a
recovered body the deployed DLL lacks. Writes a TSV: kind (changed / only_deployed / only_ours), type, member header.
Usage: python methoddiff.py <ours dir> <deployed dir> <out.tsv> [--bodies <out.jsonl>]"""
import io, json, re, sys
from pathlib import Path
sys.stdout.reconfigure(encoding="utf-8")

TYPE = re.compile(r"\b(class|struct|interface|enum|record)\s+([A-Za-z_]\w*)")


def members(path):
    """{(type path, header): body text} for one file; header is the declaration line(s) before the body."""
    lines = io.open(path, encoding="utf-8-sig", errors="replace").read().splitlines()
    out = {}
    stack = []  # (type name, depth at which its members sit)
    depth = 0
    i = 0
    pending = []
    while i < len(lines):
        s = lines[i].strip()
        opens, closes = s.count("{"), s.count("}")
        if stack and depth == stack[-1][1] and s and not s.startswith(("[", "//", "#")) and s not in ("{", "}"):
            m = TYPE.search(s)
            if m and "(" not in s.split(m.group(0))[0]:
                stack.append((m.group(2), depth + 1))
                depth += opens - closes
                if opens == 0 and i + 1 < len(lines) and lines[i + 1].strip() == "{":
                    depth += 1
                    i += 1
                pending = []
                i += 1
                continue
            header = " ".join(pending + [s])
            pending = []
            body = [s]
            d = opens - closes
            j = i
            if d == 0 and not s.endswith(";") and j + 1 < len(lines) and lines[j + 1].strip().startswith(("{", "=>", ":", "where")):
                while True:
                    j += 1
                    t = lines[j].strip()
                    body.append(t)
                    d += t.count("{") - t.count("}")
                    if d <= 0 and (t.endswith("}") or t.endswith(";")):
                        break
            else:
                while d > 0:
                    j += 1
                    t = lines[j].strip()
                    body.append(t)
                    d += t.count("{") - t.count("}")
            key = (".".join(n for n, _ in stack), re.sub(r"\s*(=>|\{).*$", "", header).strip())
            out[key] = (re.sub(r"\s+", " ", " ".join(body)), "\n".join(lines[i:j + 1]))
            i = j + 1
            continue
        if stack and depth == stack[-1][1] and s.startswith("["):
            pending.append(s)
        if not stack or depth != stack[-1][1] or s in ("{", "}"):
            if not stack and s and not s.startswith(("using", "namespace", "//", "[", "#")):
                m = TYPE.search(s)
                if m:
                    stack.append((m.group(2), depth + 1))
                    depth += opens - closes
                    if opens == 0 and i + 1 < len(lines) and lines[i + 1].strip() == "{":
                        depth += 1
                        i += 1
                    i += 1
                    continue
            depth += opens - closes
            while stack and depth < stack[-1][1]:
                stack.pop()
        i += 1
    return out


RAW = {}
SM_ATTR = re.compile(r"\[(?:IteratorStateMachine|AsyncStateMachine)\([^\]]*\)\]\s*|\[DebuggerStepThrough\]\s*")


def norm_header(hdr):
    """Attribute order differs between compiles; state-machine attributes only appear when ilspy did not fold the
    iterator/async body back into the method."""
    attrs = re.findall(r"\[[^\[\]]*(?:\[[^\]]*\][^\[\]]*)*\]", re.match(r"^((?:\[[^\[\]]*(?:\[[^\]]*\][^\[\]]*)*\]\s*)*)", hdr).group(1))
    decl = re.sub(r"^((?:\[[^\[\]]*(?:\[[^\]]*\][^\[\]]*)*\]\s*)*)", "", hdr).strip()
    attrs = sorted(a for a in attrs if not SM_ATTR.match(a + " "))
    is_async = bool(re.search(r"\basync\s", decl))
    decl = re.sub(r"\basync\s+", "", decl)
    return " ".join(attrs + [decl]), is_async or bool(SM_ATTR.search(hdr))


def tree(root):
    """{(type, header): body}; state-machine methods map to None (their body lives in a generated type)."""
    root = Path(root)
    res = {}
    raw = RAW.setdefault(str(root), {})
    for p in root.rglob("*.cs"):
        rel = p.relative_to(root).as_posix()
        if rel.startswith(("Properties/", "obj/")):
            continue
        ns = rel.rsplit("/", 1)[0] if "/" in rel else ""
        for (typ, hdr), (body, text) in members(p).items():
            if "_003C" in typ or "<>" in typ:
                continue
            h, sm = norm_header(hdr)
            res[(f"{ns}.{typ}" if ns else typ, h)] = None if sm else body
            raw[(f"{ns}.{typ}" if ns else typ, h)] = text
    return res


def main():
    ours, dep, out = tree(sys.argv[1]), tree(sys.argv[2]), sys.argv[3]
    bodies_out = sys.argv[sys.argv.index("--bodies") + 1] if "--bodies" in sys.argv else None
    rows = []
    for k in sorted(set(ours) | set(dep)):
        if k not in ours:
            rows.append(("only_deployed",) + k)
        elif k not in dep:
            rows.append(("only_ours",) + k)
        elif ours[k] is None or dep[k] is None:
            rows.append(("state_machine",) + k)
        elif ours[k] != dep[k]:
            # The deploy step instruments still-stubbed bodies with UdkStubLog.Hit; that is not a fix to migrate.
            if "UdkStubLog.Hit" in dep[k]:
                rows.append(("stub_logged" if re.sub(r"global::UdkStubLog\.Hit\(\"[^\"]*\"\);\s*", "", dep[k]) == ours[k]
                             else "deployed_stub_ours_real",) + k)
            else:
                rows.append(("changed",) + k)
    with io.open(out, "w", encoding="utf-8", newline="\n") as w:
        w.write("kind\ttype\tmember\n")
        w.writelines("\t".join(r) + "\n" for r in rows)
    if bodies_out:
        with io.open(bodies_out, "w", encoding="utf-8", newline="\n") as w:
            for kind, typ, hdr in rows:
                w.write(json.dumps({"kind": kind, "type": typ, "member": hdr, "ours": ours.get((typ, hdr)), "deployed": dep.get((typ, hdr)),
                                    "deployed_raw": RAW[str(Path(sys.argv[2]))].get((typ, hdr))}) + "\n")
    from collections import Counter
    print(f"{len(ours)} members ours, {len(dep)} deployed; " + ", ".join(f"{k}={v}" for k, v in Counter(r[0] for r in rows).items()))


if __name__ == "__main__":
    main()
