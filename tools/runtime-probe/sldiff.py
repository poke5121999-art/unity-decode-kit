import json, os, subprocess, sys

# usage: sldiff.py <run dir> [slot]
# Decrypts <run dir>/save_slot_<slot>.save.json with survivor-web-hub-12's decrypttest, then diffs the snapshot saved
# before the load (Snapshots[0], phase a) against the one saved after it (Snapshots[1], phase b), entry by entry
# keyed on (SaveId, Type). An entry that changes across a load is state the load lost or rebuilt differently.
sys.stdout.reconfigure(encoding="utf-8")
DECRYPT = r"C:\Users\tamph\AppData\Local\Temp\claude\D--survivor-web-hub\13ab5b03-bfbc-43d5-83c0-7a3c13401058\scratchpad\decrypttest\bin\Release\net8.0\decrypttest.dll"
run = sys.argv[1]
slot = sys.argv[2] if len(sys.argv) > 2 else "3"
# Physics settles items between the two saves; drift under this is noise, not a lost field.
TOL = float(sys.argv[3]) if len(sys.argv) > 3 else 0.05
src = os.path.join(run, "save_slot_%s.save.json" % slot)
out = os.path.join(run, "payload.json")
r = subprocess.run(["dotnet", DECRYPT, src, slot, out], capture_output=True, text=True, timeout=120)
print(r.stdout.strip())
if r.returncode or not os.path.exists(out):
    sys.exit("decrypt failed: " + r.stderr.strip()[:300])
p = json.load(open(out, encoding="utf-8"))
snaps = p.get("Snapshots") or []
print("snapshots", len(snaps), [s.get("MiniSummary", {}).get("Day") for s in snaps])
if len(snaps) < 2:
    sys.exit("fewer than two snapshots: phase b did not save")


def load(v):
    if isinstance(v, str):
        try:
            return json.loads(v)
        except ValueError:
            return v
    return v


def diff(a, b, path, acc):
    if len(acc) > 2000:
        return
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b)):
            if k not in a:
                acc.append((path + "/" + k, "<none>", b[k]))
            elif k not in b:
                acc.append((path + "/" + k, a[k], "<none>"))
            else:
                diff(a[k], b[k], path + "/" + k, acc)
    elif isinstance(a, list) and isinstance(b, list):
        # Record lists are unordered across a load (the game rebuilds them from scene objects): align by identity.
        key = next((k for k in ("Id", "InstanceId", "SaveId") if a and all(isinstance(x, dict) and k in x for x in a + b)), None)
        if key:
            ma, mb = {x[key]: x for x in a}, {x[key]: x for x in b}
            for k in sorted(set(ma) | set(mb), key=str):
                if k not in mb:
                    acc.append(("%s[%s=%s]" % (path, key, k), "<record>", "<none>"))
                elif k not in ma:
                    acc.append(("%s[%s=%s]" % (path, key, k), "<none>", "<record>"))
                else:
                    diff(ma[k], mb[k], "%s[%s]" % (path, str(k)[:8]), acc)
            return
        if len(a) != len(b):
            acc.append((path + "[len]", len(a), len(b)))
        for i, (x, y) in enumerate(zip(a, b)):
            diff(x, y, "%s[%d]" % (path, i), acc)
    elif isinstance(a, float) and isinstance(b, float) and abs(a - b) <= TOL:
        return
    elif a != b:
        acc.append((path, a, b))


def entries(s):
    return {(e.get("SaveId"), e.get("Type")): load(e.get("Payload")) for e in s.get("Entries") or []}


before, after = entries(snaps[0]), entries(snaps[1])
same = changed = 0
for key in sorted(set(before) | set(after), key=lambda k: (str(k[1]), str(k[0]))):
    sid, typ = key
    if key not in after:
        print("LOST    %s %s" % (typ, sid))
        continue
    if key not in before:
        print("NEW     %s %s" % (typ, sid))
        continue
    acc = []
    diff(before[key], after[key], "", acc)
    if not acc:
        same += 1
        continue
    changed += 1
    print("CHANGED %s %s: %d field(s)" % (typ, sid, len(acc)))
    for path, x, y in acc[:6]:
        print("          %s: %s -> %s" % (path, json.dumps(x, ensure_ascii=False)[:70], json.dumps(y, ensure_ascii=False)[:70]))
print("entries same %d, changed %d, lost %d, new %d" % (same, changed, len(set(before) - set(after)), len(set(after) - set(before))))
