"""Gate before handing over an assembled DLL: every method still stubbed in ours must also be stubbed in the DLL it
replaces. A member diff can miss a recovered body when two names collide (Foo vs Foo<T>, Random vs System.Random);
the stub sets cannot. Reads UdkStubLog.Hit keys (assemble with UDK_MARK_STUBS=1) from two ilspycmd -p trees.
Usage: python stubgate.py <ours dir> <deployed dir>   (exit 1 when ours stubs something deployed implements)"""
import re, sys
from pathlib import Path
sys.stdout.reconfigure(encoding="utf-8")


def hits(root):
    pat = re.compile(r'UdkStubLog\.Hit\("([^"]*)"')
    return {k for p in Path(root).rglob("*.cs") for k in pat.findall(p.read_text(encoding="utf-8-sig", errors="replace"))}


ours, dep = hits(sys.argv[1]), hits(sys.argv[2])
lost = sorted(ours - dep)
print(f"stubs: ours {len(ours)}, deployed {len(dep)}, recovered by ours {len(dep - ours)}, lost by ours {len(lost)}")
for k in lost:
    print("  LOST", k)
sys.exit(1 if lost else 0)
