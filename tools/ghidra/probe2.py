# Debug aid: disassemble + fix bodies, mark jmp-to-function-entry as tail calls, decompile the first.
import java.lang
from ghidra.app.cmd.function import CreateFunctionCmd
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.listing import FlowOverride
from ghidra.util.task import ConsoleTaskMonitor
fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()
addrs = [toAddr(java.lang.Long(int(a, 16))) for a in getScriptArgs()]
for a in addrs:
    disassemble(a)
for a in addrs:
    f = fm.getFunctionAt(a)
    CreateFunctionCmd.fixupFunctionBody(currentProgram, f, monitor)
    for ins in listing.getInstructions(f.getBody(), True):
        if ins.getFlowType().isJump() and not ins.getFlowType().isConditional():
            for t in ins.getFlows():
                if fm.getFunctionAt(t) is not None:
                    ins.setFlowOverride(FlowOverride.CALL_RETURN)
                    print(f"[probe] tail call {ins.getAddress()} -> {fm.getFunctionAt(t)}")
ifc = DecompInterface(); ifc.openProgram(currentProgram)
print("[probe]\n" + ifc.decompileFunction(fm.getFunctionAt(addrs[0]), 60, ConsoleTaskMonitor()).getDecompiledFunction().getC())
