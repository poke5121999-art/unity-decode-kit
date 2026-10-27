"""Candidates that failed only because a BCL type name is unqualified (the 3p skeletons lack `using System;`).
Writes cand.qual.<asm>.jsonl with those names prefixed by their namespace, for assemble to try as another producer."""
import io, json, re, sys
sys.stdout.reconfigure(encoding="utf-8")

W = sys.argv[1]
asms = sys.argv[2:]
NS = {
    "System": ["ArgumentException", "ArgumentNullException", "ArgumentOutOfRangeException", "InvalidOperationException",
               "NotSupportedException", "NotImplementedException", "IndexOutOfRangeException", "Exception",
               "NullReferenceException", "FormatException", "Delegate", "Action", "Func", "Predicate", "Comparison",
               "Math", "MathF", "Array", "Convert", "Enum", "Guid", "DateTime", "TimeSpan", "Type", "Activator",
               "BitConverter", "StringComparison", "IDisposable", "EventArgs", "EventHandler", "Lazy", "Tuple",
               "Environment", "GC", "Attribute", "Uri", "Version", "Buffer", "StringSplitOptions", "IntPtr",
               "IComparable", "IEquatable", "ICloneable", "Nullable", "Object", "String"],
    "System.Collections.Generic": ["List", "Dictionary", "HashSet", "Queue", "Stack", "KeyValuePair", "IEnumerable",
                                   "IEnumerator", "IList", "IDictionary", "ICollection", "IReadOnlyList",
                                   "IReadOnlyDictionary", "IReadOnlyCollection", "Comparer", "EqualityComparer",
                                   "LinkedList", "SortedDictionary", "SortedList", "IComparer", "KeyNotFoundException"],
    "System.Text": ["StringBuilder", "Encoding"],
    "System.IO": ["Path", "File", "Directory", "StreamReader", "StreamWriter", "MemoryStream", "Stream"],
    "System.Linq": [],
    "System.Reflection": ["BindingFlags", "MethodInfo", "FieldInfo", "PropertyInfo"],
    "System.Globalization": ["CultureInfo", "NumberStyles"],
    "System.Text.RegularExpressions": ["Regex", "Match", "MatchCollection", "RegexOptions"],
}
FULL = {n: f"{ns}.{n}" for ns, names in NS.items() for n in names}
MISSING = re.compile(r"CS0(?:246|103): The (?:type or namespace )?name '(\w+)(?:<[,\s]*>)?'")

total = fixable = 0
for asm in asms:
    cands = {}
    for prod in ("llm", "llmround", "llmfix"):
        try:
            for l in io.open(f"{W}/cand.{prod}.{asm}.jsonl", encoding="utf-8"):
                r = json.loads(l)
                cands[r["key"]] = r
        except FileNotFoundError:
            pass
    best_ok = set()
    try:
        best_ok = {json.loads(l)["Key"] for l in io.open(f"{W}/res.best.{asm}.jsonl", encoding="utf-8")
                   if json.loads(l)["Status"] == "ok"}
    except FileNotFoundError:
        pass
    fails = {}
    for prod in ("llm", "llmround", "llmfix"):
        try:
            for l in io.open(f"{W}/res.{prod}.{asm}.jsonl", encoding="utf-8"):
                r = json.loads(l)
                if r["Status"] == "compile_error" and r["Key"] not in best_ok:
                    fails[r["Key"]] = r["Errors"]
        except FileNotFoundError:
            pass
    out = []
    for key, errs in fails.items():
        total += 1
        names = [MISSING.search(e) for e in errs]
        if not errs or not all(names) or any(m.group(1) not in FULL for m in names) or key not in cands:
            continue
        body = cands[key]["body"]
        for m in names:
            n = m.group(1)
            body = re.sub(rf"(?<![\w.]){n}(?=\s*[<(.\s])", FULL[n], body)
        out.append({"key": key, "src": "qual", "body": body})
    fixable += len(out)
    with io.open(f"{W}/cand.qual.{asm}.jsonl", "w", encoding="utf-8", newline="\n") as w:
        w.writelines(json.dumps(r) + "\n" for r in out)
    print(f"{asm}: {len(fails)} failed bodies not recovered, {len(out)} fail only on unqualified BCL names")
print(f"total {total}, qualifiable {fixable}")
