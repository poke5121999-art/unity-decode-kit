"""Verify recovered methods by running both games: the original (IL2CPP, BepInEx 6) and ours (Mono, BepInEx 5),
each with the same MethodProbe, then diff how often every hooked method fires per in-game day. A method the original
calls that ours never calls is dead behaviour (a stub, a hollow async, a pruned branch), which call-set fidelity
cannot see. Most gated methods live on MonoBehaviours and touch NavMesh or transforms, so they cannot be replayed
outside Unity; a call profile still sees them.

  python -m udk.verify hooks <dump.cs> <script.json> <native_calls.jsonl> <stubgate --list output> <out methodprobe.txt>
      hook list: each gated method plus the Runtime methods its native code calls (one level), async state
      machines folded onto the method that owns them. Methods whose native body is COMDAT-folded with another
      method are left out: Harmony detours the shared address, the other method then enters the patch with the
      wrong MethodInfo, and the game dies with an AccessViolation in il2cpp_runtime_invoke (seen on
      SteamLeaderboardPlatform::get_IsAvailable, ZombieMobObject::AddNewGoal, SerializableGuid::op_Implicit)."""
import io, json, re, sys
from collections import defaultdict
sys.stdout.reconfigure(encoding="utf-8")

NS = re.compile(r"^// Namespace: (.*)$")
TYPE = re.compile(r"^(?:\w+ )*(?:struct|class|interface|enum) (\S+?)(?:\s*:[^/]*)?\s*// TypeDefIndex: (\d+)")
METHOD = re.compile(r"^\t(?:[\w\[\]<>,.]+ )*?([A-Za-z_]\w*)(?:<[^()]*>)?\(")


def runtime_types(dump, image_end=2235):
    """{short type name: {MethodProbe type name}} and {MethodProbe type name: {method names}} for one image.
    MethodProbe names nested types with '+'; dump.cs prints them as Outer.Inner under an empty namespace."""
    by_short, methods = defaultdict(set), defaultdict(set)
    pending, ns, cur = "", "", None
    for line in io.open(dump, encoding="utf-8", errors="replace"):
        m = NS.match(line)
        if m:
            pending = m.group(1)
            continue
        m = TYPE.match(line)
        if m:
            name = m.group(1)
            if pending or "." not in name:
                ns = pending
            cur = None
            if int(m.group(2)) < image_end and "<" not in name:
                cur = (ns + "." if ns else "") + name.replace(".", "+")
                by_short[name.split(".")[-1]].add(cur)
            continue
        if cur:
            m = METHOD.match(line)
            if m and m.group(1) not in (cur.split("+")[-1].split(".")[-1],):
                methods[cur].add(m.group(1))
    return by_short, methods


def owner(key):
    """MethodProbe line for a census key: 'Ns.Type/_Name_d__5::MoveNext()' -> 'Ns.Type::Name'."""
    typ, meth = key.split("(")[0].split("::", 1)
    parts = typ.replace("_003C", "<").replace("_003E", ">").split("/")
    outer = [parts[0]]
    for p in parts[1:]:
        m = re.match(r"^<+([A-Za-z_]\w*)>", p) or re.match(r"^_([A-Za-z_][A-Za-z0-9]*)_d__\d+$", p)
        if m:
            return "+".join(outer) + "::" + m.group(1)
        if p.startswith(("<", "_")):
            return None
        outer.append(p)
    meth = meth.split(".")[-1]
    return None if meth.startswith((".", "<")) or meth in ("ctor", "cctor") else "+".join(outer) + "::" + meth


def folded_names(script):
    """MethodProbe lines, dotted ("Ns.Type.Inner::M"), with at least one overload sharing its native address."""
    sj = json.load(io.open(script, encoding="utf-8"))
    count = defaultdict(int)
    for m in sj["ScriptMethod"]:
        count[m["Address"]] += 1
    return {m["Name"].replace("$$", "::") for m in sj["ScriptMethod"] if count[m["Address"]] > 1}


def hooks(dump, script, calls_p, gate_p, out):
    by_short, methods = runtime_types(dump)
    folded = folded_names(script)
    gate = [l.strip()[5:].replace("HOLLOW ", "") for l in io.open(gate_p, encoding="utf-8") if l.strip().startswith("STUB ")]
    native = defaultdict(list)
    for l in io.open(calls_p, encoding="utf-8"):
        r = json.loads(l)
        native[owner(r["key"])].append(r["calls"])
    lines, unresolved = set(), 0
    for k in gate:
        o = owner(k)
        if not o:
            continue
        lines.add(o)
        for calls in native.get(o, []):
            for alts in calls:
                for c in alts:
                    t, _, m = c.partition("::")
                    full = [f for f in by_short.get(t, ()) if m in methods.get(f, ())]
                    unresolved += not full
                    lines.update(f"{f}::{m}" for f in full)
    dropped = {l for l in lines if l.replace("+", ".") in folded}
    lines -= dropped
    with io.open(out, "w", encoding="utf-8", newline="\n") as w:
        w.write("# udk.verify hooks: gated methods + Runtime callees (one level), COMDAT-folded ones left out\n")
        w.writelines(l + "\n" for l in sorted(lines))
        w.writelines(f"# folded: {l}\n" for l in sorted(dropped))
    print(f"{len(gate)} gated keys -> {len(lines)} hook lines, {len(dropped)} folded left out "
          f"({unresolved} callee refs outside Runtime or unresolved) -> {out}")


if __name__ == "__main__":
    cmd, *a = sys.argv[1:]
    {"hooks": hooks}[cmd](*a)
