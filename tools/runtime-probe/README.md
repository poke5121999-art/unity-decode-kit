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
