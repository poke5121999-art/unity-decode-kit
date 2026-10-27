"""Make migrated rows compile inside skeleton files that import fewer namespaces than the decompile they came from.
Driven by the Oracle errors of the previous round: an unknown name (CS0246/CS0103) gets the namespace the deployed
file imports for it (global::NS.Name), an ambiguous one (CS0104) the candidate the deployed file imports, and LINQ
extension calls (CS1061 'does not contain a definition for Where') become System.Linq.Enumerable static calls,
which is how the pipeline's own bodies spell them.
Usage: python qualify_rows.py <cand.jsonl> <res.jsonl> <dump.cs> <deployed ilspy dir> <out cand.jsonl>"""
import io, json, re, sys
from pathlib import Path
sys.stdout.reconfigure(encoding="utf-8")

LINQ = {"Where", "Select", "SelectMany", "Any", "All", "First", "FirstOrDefault", "Last", "LastOrDefault", "Single",
        "SingleOrDefault", "OrderBy", "OrderByDescending", "ThenBy", "ThenByDescending", "ToList", "ToArray",
        "ToDictionary", "ToHashSet", "Count", "Sum", "Min", "Max", "Average", "Concat", "Distinct", "Skip", "Take",
        "Contains", "GroupBy", "Cast", "OfType", "Reverse", "Aggregate", "Except", "Intersect", "Union", "Zip",
        "DefaultIfEmpty", "ElementAt", "ElementAtOrDefault", "SequenceEqual", "TakeWhile", "SkipWhile", "MinBy", "MaxBy"}


def type_namespaces(dump):
    ns, out = "", {}
    for line in io.open(dump, encoding="utf-8", errors="replace"):
        if line.startswith("// Namespace:"):
            ns = line.split(":", 1)[1].strip()
        elif "// TypeDefIndex:" in line and ns:
            # Nested types print as Outer.Inner; only top-level names can be qualified as NS.Name.
            m = re.search(r"\b(?:class|struct|enum|interface)\s+([A-Za-z_][\w.]*)", line)
            if m and "." not in m.group(1):
                out.setdefault(m.group(1), set()).add(ns)
    return out


def deployed_usings(ddir, key):
    typ = key.split("::")[0].split("/")[0]
    ns, _, name = re.sub(r"`\d+", "", typ).rpartition(".")
    p = Path(ddir) / ns / f"{name}.cs"
    if not p.exists():
        return set()
    return set(re.findall(r"^using\s+([\w.]+);", p.read_text(encoding="utf-8-sig", errors="replace"), re.M))


def qualify_name(body, name, full):
    # Not after '.', '::' or inside a string literal (good enough for decompiled code: strings rarely hold type names).
    parts = re.split(r'("(?:[^"\\]|\\.)*")', body)
    for i in range(0, len(parts), 2):
        parts[i] = re.sub(rf"(?<![\w.:]){re.escape(name)}\b(?!\s*:(?!:))", f"global::{full}", parts[i])
    return "".join(parts)


def receiver_start(s, end):
    """Index where the receiver expression ending at s[end-1] starts (identifiers, member access, calls, indexers)."""
    i = end - 1
    while i >= 0:
        ch = s[i]
        if ch in ")]>":
            close, open_ = ch, {")": "(", "]": "[", ">": "<"}[ch]
            depth = 0
            while i >= 0:
                if s[i] == close:
                    depth += 1
                elif s[i] == open_:
                    depth -= 1
                    if depth == 0:
                        break
                i -= 1
            i -= 1
            continue
        if ch.isalnum() or ch in "_.":
            i -= 1
            continue
        if ch == ":" and i > 0 and s[i - 1] == ":":
            i -= 2
            continue
        break
    start = i + 1
    while start < end and s[start] == ".":
        start += 1
    return start


def linq_static(body, methods):
    for m in methods:
        pat = re.compile(rf"(?<!System\.Linq\.Enumerable)(?<=[\w)\]>])\.{m}\s*(<[^()]*?>)?\s*\(")
        pos = 0
        for _ in range(100):
            hit = pat.search(body, pos)
            if not hit:
                break
            start = receiver_start(body, hit.start())
            recv = body[start:hit.start()]
            if not recv.strip() or re.fullmatch(r"(?:global::)?(?:UnityEngine\.|System\.)?(?:Math|Mathf|string|String|Enumerable|Array)", recv):
                pos = hit.end()
                continue
            targs = hit.group(1) or ""
            after = body[hit.end():]
            sep = "" if after.lstrip().startswith(")") else ", "
            body = body[:start] + f"global::System.Linq.Enumerable.{m}{targs}({recv}{sep}" + after
            pos = start
    return body


def main():
    cand_p, res_p, dump, ddir, out_p = sys.argv[1:6]
    tns = type_namespaces(dump)
    res = {r["Key"]: r for r in map(json.loads, io.open(res_p, encoding="utf-8"))}
    stats = {"names": 0, "ambiguous": 0, "linq": 0, "unresolved": 0}
    out = []
    for c in map(json.loads, io.open(cand_p, encoding="utf-8")):
        r = res.get(c["key"])
        if r is None or r["Status"] == "ok":
            out.append(c)
            continue
        body, usings = c["body"], deployed_usings(ddir, c["key"])
        for e in r["Errors"]:
            m = re.match(r"CS0(?:246|103): The (?:type or namespace )?name '(\w+)(?:<[,\s]*>)?'", e)
            if m:
                name = m.group(1)
                nss = [n for n in tns.get(name, ()) if n in usings] or sorted(tns.get(name, ()))
                if len(nss) == 1:
                    body = qualify_name(body, name, f"{nss[0]}.{name}")
                    stats["names"] += 1
                elif len(nss) != 1:
                    stats["unresolved"] += 1
                continue
            m = re.match(r"CS0104: '(\w+)' is an ambiguous reference between '([\w.]+)' and '([\w.]+)'", e)
            if m:
                pick = [f for f in (m.group(2), m.group(3)) if f.rsplit(".", 1)[0] in usings]
                if len(pick) == 1:
                    body = qualify_name(body, m.group(1), pick[0])
                    stats["ambiguous"] += 1
                continue
            m = re.match(r"CS0117: 'Debug' does not contain a definition for 'Log", e)
            if m:
                # The skeleton imports System.Diagnostics, whose Debug has no LogWarning/LogError.
                body = qualify_name(body, "Debug", "UnityEngine.Debug")
                stats["ambiguous"] += 1
                continue
            m = re.match(r"CS1061: .* does not contain a definition for '(\w+)'", e)
            if m and m.group(1) in LINQ:
                # Oracle reports only the first errors of a member: convert every LINQ call now, not one per round.
                # List.Reverse() is an in-place instance method; turning it into Enumerable.Reverse changes behaviour.
                body = linq_static(body, sorted(n for n in LINQ - {"Reverse"} if re.search(rf"\.{n}\s*(?:<[^()]*?>)?\s*\(", body)))
                stats["linq"] += 1
        out.append(dict(c, body=body))
    with io.open(out_p, "w", encoding="utf-8", newline="\n") as w:
        w.writelines(json.dumps(c) + "\n" for c in out)
    print(stats)


if __name__ == "__main__":
    main()
