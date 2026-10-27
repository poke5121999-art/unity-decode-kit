"""Gate before handing over an assembled DLL: every method still stubbed in ours must also be stubbed in the DLL it
replaces. A member diff can miss a recovered body when two names collide (Foo vs Foo<T>, Random vs System.Random);
the stub sets cannot. Reads UdkStubLog.Hit keys (assemble with UDK_MARK_STUBS=1) from two ilspycmd -p trees.

With --dump, async and iterator methods count too. A method the original compiled to a state machine but that
decompiles here as a plain body is hollow: it has a candidate, so it carries no Hit, yet the work of its MoveNext
is not there (a `return UniTask.CompletedTask` guess, or a sync rewrite). Hollow keys join the stub set.
Usage: python stubgate.py <ours dir> <deployed dir> [--dump <dump.cs> [--image-end <TypeDefIndex>]]
  (exit 1 when ours stubs something deployed implements)"""
import io, re, sys
from collections import Counter
from pathlib import Path
sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, str(Path(__file__).parent))


def hits(root):
    pat = re.compile(r'UdkStubLog\.Hit\("([^"]*)"')
    return {k for p in Path(root).rglob("*.cs") for k in pat.findall(p.read_text(encoding="utf-8-sig", errors="replace"))}


def arity(t):
    """Foo<T, U>.Bar -> Foo`2.Bar, the way methoddiff names types."""
    return re.sub(r"<([^<>]*)>", lambda m: f"`{m.group(1).count(',') + 1}", t)


NS = re.compile(r"^// Namespace: (.*)$")
TYPE = re.compile(r"^(?:\w+ )*(?:struct|class|interface|enum) (\S+?)(?:\s*:[^/]*)?\s*// TypeDefIndex: (\d+)")
ATTR = re.compile(r"^\s*\[(?:Async|Iterator)StateMachine\(typeof\((.+)\.<([A-Za-z_]\w*)>d__\d+(?:<[^>]*>)?\)\)\]")


def state_machines(dump, image_end):
    """Counter of "Ns.Type::Method" -> state machines the original compiled for that name (one per overload).
    dump.cs prints nested types under an empty namespace, so the namespace is the last top-level type's."""
    out, pending, ns, idx = Counter(), "", "", 0
    for line in io.open(dump, encoding="utf-8", errors="replace"):
        m = NS.match(line)
        if m:
            pending = m.group(1)
            continue
        m = TYPE.match(line)
        if m:
            idx = int(m.group(2))
            if pending or "." not in m.group(1):
                ns = pending
            continue
        m = ATTR.match(line)
        if m and idx < image_end and not m.group(2).startswith("<"):
            typ = arity(m.group(1))
            out[f"{ns}.{typ}::{m.group(2)}" if ns else f"{typ}::{m.group(2)}"] += 1
    return out


def hollow(root, sms):
    """Keys whose original state machines outnumber the async/iterator overloads that decompile here."""
    import methoddiff
    real, seen = Counter(), set()
    methoddiff.tree(root)
    # Not the attribute: a sync rewrite keeps [AsyncStateMachine] (MoveToHoldableAsync, served=0). A body that ilspy
    # could not fold back still starts its builder.
    for (typ, hdr), body in methoddiff.RAW[str(Path(root))].items():
        m = re.search(r"\b([A-Za-z_]\w*)\s*(?:<[^()]*>)?\s*\(", re.sub(r"\[[^\]]*\]\s*", "", hdr))
        if not m:
            continue
        key = f"{typ}::{m.group(1)}"
        seen.add(key)
        if re.search(r"\basync\s[^(]*\(|\bawait\b|\byield\s+(?:return|break)\b|<>t__builder|\.Start\(ref\b", body):
            real[key] += 1
    return {k for k, n in sms.items() if k in seen and real[k] < n}, {k for k in sms if k not in seen}


def main():
    args = sys.argv[1:]
    dump = args[args.index("--dump") + 1] if "--dump" in args else None
    image_end = int(args[args.index("--image-end") + 1]) if "--image-end" in args else 2235
    ours_dir, dep_dir = [a for i, a in enumerate(args) if not a.startswith("--") and (i == 0 or not args[i - 1].startswith("--"))][:2]
    ours, dep = hits(ours_dir), hits(dep_dir)
    print(f"stubs: ours {len(ours)}, deployed {len(dep)}")
    if dump:
        sms = state_machines(dump, image_end)
        h_ours, missing = hollow(ours_dir, sms)
        h_dep, _ = hollow(dep_dir, sms)
        print(f"state-machine methods in the original: {len(sms)} names ({sum(sms.values())} overloads); "
              f"hollow: ours {len(h_ours)}, deployed {len(h_dep)}; not found in ours: {len(missing)}")
        ours |= {"HOLLOW " + k for k in h_ours}
        dep |= {"HOLLOW " + k for k in h_dep}
    lost = sorted(ours - dep)
    print(f"gate set: ours {len(ours)}, deployed {len(dep)}, recovered by ours {len(dep - ours)}, lost by ours {len(lost)}")
    for k in lost:
        print("  LOST", k)
    if "--list" in args:
        for k in sorted(ours):
            print("  STUB", k)
    sys.exit(1 if lost else 0)


if __name__ == "__main__":
    main()
