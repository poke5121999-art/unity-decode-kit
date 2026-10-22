# Headless PyGhidra script: print function body ranges and owner for addresses (debug aid).
# Args: <hex address>...
import java.lang
fm = currentProgram.getFunctionManager()
for a in getScriptArgs():
    addr = toAddr(java.lang.Long(int(a, 16)))
    at, owner = fm.getFunctionAt(addr), fm.getFunctionContaining(addr)
    print(f"[probe] {a}: at={at} containing={owner}")
    if owner:
        print(f"[probe]   body={owner.getBody()} thunk={owner.isThunk()}")
