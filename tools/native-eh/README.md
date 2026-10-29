# native-eh: catch clauses Ghidra does not show

IL2CPP compiles a C# `try/catch` into an MSVC C++ `try/catch`. MSVC moves each catch body into a separate
function (a funclet) that only the exception tables of the parent point at. Ghidra decompiles the parent body
and never shows the funclets, so a method recovered from Ghidra output silently loses its catch clauses.

In The Walking Trade this hid three catch clauses in `RigidbodyNavigator.SetDestinationCore`
(`OperationCanceledException`, `TimeoutException`, `Exception`) and the `OperationCanceledException` handling of
eleven mob and skill-view async methods.

All scripts take the original `GameAssembly.dll` and Il2CppDumper's `script.json`. They need Python 3.8 with
capstone 5. Run them with `python -I`, and keep them out of directories holding a `dis.py` (it shadows the stdlib
module that capstone imports).

## ehaudit.py: which methods have typed catches

    python -I ehaudit.py GameAssembly.dll script.json "Runtime." out.tsv

Writes one row per native method whose name starts with the prefix and whose exception tables have a catch
funclet, with the exception types each funclet tests (`IsInst` against `<Type>_TypeInfo`). Every async
`MoveNext` has an outer `System.Exception` catch that only forwards to the builder's `SetException`. Rows that
list anything else are the ones to compare with the recovered C#.

## ehscan.py: what each catch does

    python -I ehscan.py GameAssembly.dll script.json <function va hex> [instructions per continuation]

Prints the FH4 try map of one function. For each try block it prints the try-state range, the funclet's
disassembly (which type checks pick which continuation), and the start of each continuation in the parent, which
is the C# catch body. Calls are named from `script.json` methods, RIP-relative operands from metadata and string
literals. Reading a continuation:

- `mov dword [sm], 0xfffffffe` then a builder `SetResult` call means `return`.
- A store of a constant into the result slot means `result = <enum value>`.
- Getting the saved exception and calling the raise helper means `throw;`.
- An empty continuation list means the funclet returns the continuation itself: `lea rax, [rip+X]` before its
  `ret` gives one address per matched type (`SetDestinationCore`, va `182467FD0`).
- Exception `get_Message` is vtable slot 5 (`[klass+0x188]`), and `get_StackTrace` is slot 9 (`+0x1c8`).

## fh4.py

Decoder for `__CxxFrameHandler4` FuncInfo: compressed integers, try-block map, handler map. Continuations come out
as offsets from the function start.

## disx.py

    python -I disx.py GameAssembly.dll <va hex> <length>

Plain capstone disassembly of a virtual address range. Use it when Ghidra merges a call's argument struct and the
argument slots have to be read off the registers and stack.
