"""Sort methoddiff rows into a migration plan: which deployed bodies become cand.manual rows, which need a Cecil
post-step (type-level), and which are representation noise. Usage: python migrate_plan.py <mdiff.jsonl> <plan.tsv>"""
import io, json, re, sys
from collections import Counter

STUB = re.compile(r"^[^{]*\{\s*(?:global::UdkStubLog\.Hit\(\"[^\"]*\"\);\s*)?"
                  r"(?:(?:\w+\s*=\s*(?:default(?:\([^)]*\))?|null|false|0[fdmul]?|0\.0f?);\s*)*)"
                  r"(?:return(?:\s+(?:null|default(?:\([^)]*\))?|0[fdmul]?|0\.0f?|false))?;\s*)?\}\s*$", re.I)


def stub(body):
    return body is not None and bool(STUB.match(body))


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    rows = []
    for r in map(json.loads, io.open(sys.argv[1], encoding="utf-8")):
        kind, ours, dep = r["kind"], r["ours"], r["deployed"]
        helpers = sorted(set(re.findall(r"\bUdk\w+", dep or "")) - {"UdkStubLog"})
        if kind == "changed":
            if stub(ours) and not stub(dep):
                cls = "manual:recovered_in_deployed"
            elif not stub(ours) and stub(dep):
                cls = "keep_ours:deployed_is_stub"
            else:
                cls = "manual:patched_over_real"
        elif kind == "only_deployed":
            cls = "inline:xplant_helper" if re.search(r"\bUdkNew\w+\s*\(", r["member"]) else "cecil:added_member"
        elif kind == "only_ours":
            cls = "check:only_ours"
        else:
            cls = kind
        rows.append((cls, r["type"], r["member"][:160], ",".join(helpers)))

    with io.open(sys.argv[2], "w", encoding="utf-8", newline="\n") as w:
        w.write("class\ttype\tmember\tudk_helpers\n")
        w.writelines("\t".join(x) + "\n" for x in sorted(rows))
    for k, v in sorted(Counter(r[0] for r in rows).items()):
        print(f"{v:5}  {k}")
    print(f"{sum(1 for r in rows if r[3]):5}  rows whose deployed body calls Udk* helpers")


if __name__ == "__main__":
    main()
