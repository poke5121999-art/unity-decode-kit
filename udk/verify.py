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
      SteamLeaderboardPlatform::get_IsAvailable, ZombieMobObject::AddNewGoal, SerializableGuid::op_Implicit).

  python -m udk.verify hooks-types <dump.cs> <script.json> <type regex> <method regex> <out methodprobe.txt>
      hook list: every Runtime method whose type and name match, COMDAT-folded ones left out. For walking up a
      DEAD chain (who should have called it) one layer at a time.

  python -m udk.verify hooks-divergence <divergence.tsv> <script.json> <max score> <batch size> <out prefix>
      hook lists, in batches, for the recovered Runtime methods udk.divergence scores below max score: one
      original-side run per batch tells which divergent hand-recovered bodies the original actually runs.

  python -m udk.verify divergence-fired <divergence.tsv> <out.tsv> <original methodprobe.jsonl>...
      the divergent recovered methods those runs saw fire, ranked: the work queue for hand-recovered bodies.

  python -m udk.verify diff<original methodprobe.jsonl> <original days> <ours methodprobe.jsonl> <ours days> <out.tsv>
                            [<original until s> <ours until s>]
      calls per in-game day, side by side. DEAD = the original calls it and ours never does (the served=0 class);
      LOW / HIGH = off by more than 4x; EXTRA = only ours calls it; THROWS = more calls end in an exception in
      ours (columns are then exception counts). Methods the bot forces are left out, since both
      sides call them because the bot does. Exit 1 when anything is DEAD."""
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


def hooks_types(dump, script, type_re, method_re, out):
    _, methods = runtime_types(dump)
    folded = folded_names(script)
    lines = {f"{t}::{m}" for t, ms in methods.items() if re.search(type_re, t) for m in ms if re.search(method_re, m)}
    dropped = {l for l in lines if l.replace("+", ".") in folded}
    lines -= dropped
    with io.open(out, "w", encoding="utf-8", newline="\n") as w:
        w.write(f"# udk.verify hooks-types {type_re} {method_re}, COMDAT-folded ones left out\n")
        w.writelines(l + "\n" for l in sorted(lines))
    print(f"{len(lines)} hook lines, {len(dropped)} folded left out -> {out}")


def hooks_divergence(divergence_p, script, max_score, batch, out_prefix):
    """Hook lists for the recovered (non-stub) Runtime methods that udk.divergence scores below max_score, split
    into batches of `batch` lines (out_prefix-1.txt, -2.txt, ...), so one original-side run per batch shows which
    divergent bodies the original actually executes. Highest rank first; COMDAT-folded methods left out."""
    folded = folded_names(script)
    ranked, seen = [], set()
    for row in io.open(divergence_p, encoding="utf-8"):
        f = row.rstrip("\n").split("\t")
        if f[0] == "rank" or f[1] != "Runtime" or f[5] == "stub" or float(f[4]) >= float(max_score):
            continue
        o = owner(f[2])
        if o and o not in seen and o.replace("+", ".") not in folded:
            seen.add(o)
            ranked.append(o)
    n = int(batch)
    for i in range(0, len(ranked), n):
        path = f"{out_prefix}-{i // n + 1}.txt"
        with io.open(path, "w", encoding="utf-8", newline="\n") as w:
            w.write(f"# udk.verify hooks-divergence score<{max_score}, batch {i // n + 1}\n")
            w.writelines(l + "\n" for l in ranked[i:i + n])
    print(f"{len(ranked)} divergent methods -> {(len(ranked) + n - 1) // n} batches of <= {n} ({out_prefix}-N.txt)")


def divergence_fired(divergence_p, out, *runs):
    """The divergent recovered methods the original actually ran: udk.divergence rows (non-stub, Runtime) whose
    method fired in any of the original-side probe runs over the hooks-divergence batches, highest rank first."""
    calls, hooked = {}, set()
    for r in runs:
        for l in io.open(r, encoding="utf-8"):
            try:
                o = json.loads(l)
            except ValueError:
                continue
            if "calls" in o:
                m = o["method"].split("(")[0]
                hooked.add(m)
                calls[m] = max(calls.get(m, 0), o["calls"], o.get("entered", 0))
    rows = []
    for row in io.open(divergence_p, encoding="utf-8"):
        f = row.rstrip("\n").split("\t")
        if f[0] == "rank" or f[1] != "Runtime" or f[5] == "stub":
            continue
        o = owner(f[2])
        k = next((x for x in (o, o and o.replace("+", ".")) if x in hooked), None)
        if k and calls[k] > 0:
            rows.append((float(f[0]), calls[k], f[4], f[2], f[5], f[7]))
    rows.sort(reverse=True)
    with io.open(out, "w", encoding="utf-8", newline="\n") as w:
        w.write("rank\toriginal_calls\tscore\tkey\tsrc\tmissing\n")
        w.writelines("%.2f\t%d\t%s\t%s\t%s\t%s\n" % r for r in rows)
    print(f"{len(hooked)} hooked, {sum(1 for v in calls.values() if v)} fired in the original, "
          f"{len(rows)} divergent rows -> {out}")


# Called directly by the autoplay bot (D:/walking-trade-ref/SCENARIO-driver.md [FORCE]); identical on both sides.
FORCED = {
    "Runtime.Game.GameController::OnCutscenesCompleted", "Runtime.Item.ItemObject::Initialize",
    "Runtime.Item.Shelving.ShelfObject::TryPlaceShelvable", "Runtime.Item.ItemObject::ApplyChangesToShopGrid",
    "Runtime.Game.StoreManager::TryToggleStoreOpen", "Runtime.Events.CustomerEventsManager::SpawnCustomerAtRandomPoint",
    "Runtime.Player.CheckoutCurrencyObject::SetValidity", "Runtime.Player.StashCheckoutCurrencyDepot::TryDeposit",
    "Runtime.Item.CheckoutObject::Interact", "Runtime.Player.States.ServingPlayerState::OnViewAccepted",
    "Runtime.Player.States.ServingPlayerState::StopServing", "Runtime.Day.TimeManager::SetTime",
    "Runtime.Game.StoreManager::CloseStore", "Runtime.Item.BedObject::Interact",
    "Runtime.Player.States.SleepingPlayerState::SleepViewCompleted", "Runtime.Day.TimeManager::Sleep",
    "Runtime.Menu.MenuController::OnSaveCreated", "Runtime.Menu.MenuController::OnSaveSelected",
}


def profile(path, until=None):
    """{method line: calls}, from the last record per method (records are cumulative). until: seconds since load;
    the original keeps running after the bot finishes while ours quits, so both are cut at the bot's end."""
    last, threw = {}, {}
    for l in io.open(path, encoding="utf-8"):
        r = json.loads(l)
        if "calls" in r:
            if until is None or r["t"] <= until:
                last[r["method"]] = r["calls"]
                # entered - returned: calls that ended in an exception (a postfix never sees those)
                threw[r["method"]] = r.get("entered", r["calls"]) - r["calls"]
            else:
                last.setdefault(r["method"], 0)
        elif "error" in r:
            last.setdefault(r["method"], None)
    profile.threw = threw
    return last


# Divergences already found and waiting on a decision: reported as KNOWN with the reason, not as DEAD, so the gate
# keeps failing only on new ones. Remove an entry once it is fixed or accepted for good.
KNOWN = {
    "Runtime.Achievements.SteamAchievementPlatform::GetIntStat": "ours runs NullAchievementPlatform (no Steam)",
    "Runtime.Achievements.NullAchievementPlatform::GetIntStat": "ours runs NullAchievementPlatform (no Steam)",
}


def diff(orig_p, orig_days, ours_p, ours_days, out, orig_until=None, ours_until=None):
    orig = profile(orig_p, orig_until and float(orig_until))
    orig_threw = profile.threw
    ours = profile(ours_p, ours_until and float(ours_until))
    ours_threw = profile.threw
    od, wd = float(orig_days), float(ours_days)
    rows = []
    for k in sorted(set(orig) | set(ours)):
        if k.split("(")[0] in FORCED:
            continue
        o, w = orig.get(k), ours.get(k)
        if ours_threw.get(k, 0) > orig_threw.get(k, 0):
            rows.append(("THROWS", k, orig_threw.get(k, 0), ours_threw.get(k, 0)))
            continue
        if o is None or w is None:
            verdict = "UNHOOKED"  # missing or not patchable on one side: no evidence either way
        else:
            o_rate, w_rate = o / od, w / wd
            if o == 0 and w == 0:
                verdict = "SILENT"
            elif w == 0:
                verdict = "DEAD"
            elif o == 0:
                verdict = "EXTRA"
            elif w_rate * 4 < o_rate:
                verdict = "LOW"
            elif w_rate > o_rate * 4:
                verdict = "HIGH"
            else:
                verdict = "OK"
        if verdict in ("DEAD", "LOW", "HIGH", "EXTRA") and k.split("(")[0] in KNOWN:
            verdict = "KNOWN"
        rows.append((verdict, k, o, w))
    with io.open(out, "w", encoding="utf-8", newline="\n") as f:
        f.write(f"verdict\tmethod\toriginal calls ({orig_days} days)\tours calls ({ours_days} days)\n")
        f.writelines(f"{v}\t{k}\t{o}\t{w}\n" for v, k, o, w in sorted(rows))
    from collections import Counter
    print(", ".join(f"{k}={n}" for k, n in sorted(Counter(r[0] for r in rows).items())) + f" -> {out}")
    for v, k, o, w in rows:
        if v in ("DEAD", "LOW", "THROWS"):
            print(f"  {v:5} {k}  original {o}, ours {w}")
        elif v == "KNOWN":
            print(f"  KNOWN {k}  original {o}, ours {w}: {KNOWN[k.split('(')[0]]}")
    sys.exit(1 if any(r[0] in ("DEAD", "THROWS") for r in rows) else 0)


if __name__ == "__main__":
    cmd, *a = sys.argv[1:]
    {"hooks": hooks, "hooks-types": hooks_types, "hooks-divergence": hooks_divergence,
     "divergence-fired": divergence_fired, "diff": diff}[cmd](*a)
