"""Keys a generator must not regenerate: bodies the oracle compiled, except the generator's own.
Every candidate generator reads res.best to skip what is already recovered, and res.best contains the generator's
previous output, so without the exclusion a rerun writes an empty cand file and assemble drops those bodies
(qualify lost 24 bodies this way, trivial would have lost 91)."""
import io, json, sys

sys.path.insert(0, "D:/walking-trade-ref/udk")
from udk.recompile import loose


def recovered(work, asm, own_src):
    try:
        rows = [json.loads(l) for l in io.open(f"{work}/res.best.{asm}.jsonl", encoding="utf-8")]
    except FileNotFoundError:
        return set()
    return {loose(r["Key"]) for r in rows if r["Status"] == "ok" and r.get("Src") != own_src}
