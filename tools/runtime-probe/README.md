# MethodProbe (BepInEx 6 IL2CPP method probe)

Game-agnostic plugin: Harmony-postfixes every method listed in a config file and logs call counts plus the first N argument/return samples as JSONL.

## Build
Needs a game dir that already has BepInEx 6 (be.791 or newer) installed and has run once (so `BepInEx/interop` exists).

    dotnet build -c Release -o out -p:GameDir=D:\walking-trade-ref\runtime\game

## Install
Copy `out/MethodProbe.dll` to `<game>/BepInEx/plugins/`.

## Configure
- `<game>/BepInEx/config/methodprobe.txt`: one `Namespace.Type::Method` per line (`#` comments). All overloads are patched. Type is looked up by full name in the loaded interop assemblies (names as in the interop DLLs / il2cpp dump; nested types use `+`).
- `<game>/BepInEx/config/local.methodprobe.cfg` (generated on first run): `MethodList`, `OutputFile` (default `BepInEx/methodprobe.jsonl`), `FlushSeconds` (5), `MaxSamples` (5).

## Output
JSONL, appended every flush for methods whose count changed. The LAST line per `method` is the cumulative state:

    {"method":"Runtime.Save.SaveService::GetSlotPath","calls":1,"samples":[{"args":["0"],"ret":"C:/.../save_slot_0.save.json"}]}

Args/ret: string, bool, enum, primitive rendered as strings; any other object as `"<Full.TypeName>"`. Lines with `"error"` mean type/method not found or patch failed. Instance (`this`) is not logged.

## Known limits
- Postfix only: no pre-call state, no exceptions. Calls are counted even past MaxSamples.
- Methods inlined by IL2CPP/compiler never fire; async state-machine methods (UniTask) may show 0 (see notes in STATUS).
- Very hot methods (per frame) are cheap but still cost a Harmony postfix each call.

## Invoke mode
Calls STATIC methods with primitive params once per arg set and records the returns.
- Input `BepInEx/config/methodprobe-invoke.jsonl` (absent = mode off), one line per method:
  `{"key":"Ns.Type::Method(Int32,Single)","params":["int","float"],"args":[[1,0.5],[2,1.5]],"skip":[[-7]]}`
  Methods are resolved by type full name + method name + parameter type names (public or private static). `skip` (optional) lists arg sets that must not be invoked (e.g. known infinite loops); they are written with `"ret":"timeout"`.
- Config section `[Invoke]` in `local.methodprobe.cfg`: `InputFile`, `OutputFile` (default `BepInEx/methodprobe-invoke-out.jsonl`), `DelaySeconds` (10), `TriggerMethod`.
- Run on the main thread: set `TriggerMethod` to a no-arg method that runs every frame (e.g. a MonoBehaviour `Update`); the first call after the delay runs everything. With it empty the plugin uses a background thread, which did NOT work on this game (no output, no error), so always set a trigger.
- Output: one line per call `{"key","args","ret"}` (floats via `ToString("R")`; NaN/Infinity quoted) or `{"key","error"}` (exception type + message). Written line by line, so a hang still leaves partial output. There is no watchdog: a method that never returns freezes the main thread.
