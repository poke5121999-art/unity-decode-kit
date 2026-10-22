"""Compare udk's decoded VOID DIVER tables and Lua with the hand-decoded copies in vd-ref."""
import os
import sys

out, ref = sys.argv[1], sys.argv[2]
for sub, refsub, ext in (("StreamingAssets/TableEncrypted", "tables", ".csv"), ("StreamingAssets/LuaEncrypted", "lua", ".lua")):
    same = diff = missing = 0
    for d, _, files in os.walk(os.path.join(ref, refsub)):
        for f in files:
            r = os.path.join(d, f)
            rel = os.path.relpath(r, os.path.join(ref, refsub))
            o = os.path.join(out, sub, os.path.splitext(rel)[0] + ext)
            if not os.path.exists(o):
                missing += 1
                print("missing", o)
            elif open(o, "rb").read() == open(r, "rb").read():
                same += 1
            else:
                diff += 1
                print("differs", rel)
    print(f"{refsub}: identical={same} differ={diff} missing={missing}")
