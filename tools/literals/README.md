# literals

String literals per method: the original's machine code against our recompiled IL.

## Why

Il2CppDumper names a string literal `StringLiteral_<sanitized text, cut at 32 chars>`, and Ghidra's C shows only
that name. Different strings get the same name (`"_"`, `"."`, `" "` and `""` are all `StringLiteral__`; `"_name"`
and `"@name"` are both `StringLiteral__name`; `..._died_inside` and `..._died_outside` share one). `udk/recompile.py`
keys `strings.tsv` by that name, so the last string parsed wins and the translator emits it for all of them.
On The Walking Trade: 614 colliding names, 1247 strings lost; 112 Runtime methods took a wrong literal
(localization keys like `item_..._` built with `" "`, `"{0} | {1}"` for `"{0} / {1}"`, `"@name"` for `"_name"`).

## Tools

| Step | Command | Output |
|---|---|---|
| dump our ldstr | `ldstr/bin/ldstr.exe <Runtime.dll> ldstr.tsv` | method, param count, literals |
| diff | `python -I litdiff.py <GameAssembly.dll> <script.json> ldstr.tsv litdiff.tsv [ns]` | per method: native-only, ours-only |
| explain by collision | `python -I litimpact.py <inspector/metadata.json> litdiff.tsv litimpact.tsv` | `unique` rows: one native candidate per wrong literal |
| collapsed collisions | `python -I litcollapse.py <metadata.json> litdiff.tsv ldstr.tsv` | native picks between two colliding literals, ours kept one; fix by hand in `litcond.tsv` |
| where else | `python -I litwhere.py <rows.tsv> ldstr.tsv` | `elsewhere` (native inlined a callee) or `LOST` |
| bucket | `python -I litclass.py litdiff.tsv` | STUB / LOG / REVIEW files next to it |
| fix | `litfix/bin/litfix.exe <in.dll> litimpact.tsv <out.dll> [litcond.tsv]` | rewrites ldstr in `unique` rows; `litcond.tsv` restores `cond ? a : b` |

Build the two C# tools with `dotnet build -c Release -o bin` in each folder (Unity.Cecil from the Unity 6 editor).

`litfix` is idempotent: a fixed method no longer differs, so a second `litimpact` run lists 0 `unique` rows. Run it
last on a merged head, then rerun `ldstr` + `litdiff` + `litimpact` to show the rows are gone.

## Traps

- Native literal sets include inlined callees, and lambda numbers (`b__40_1`) can differ between the two builds,
  so a lone missing literal is a lead, not a bug. `litwhere` separates inlining from loss.
- `python -I` ignores `PYTHONIOENCODING`; the scripts that print non-ASCII reconfigure stdout themselves.
- A method stubbed in our build (`UdkStubLog.Hit("T::M(...)")`) shows its signature as an extra literal.
