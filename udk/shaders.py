"""Shaders: readable programs for every variant, which AssetRipper Free replaces with dummies.

For each Shader asset: the platform blobs are LZ4 chunks holding one entry per sub-program;
the parsed form says which (pass, stage, keywords) each blob entry is and names the uniforms.
  D3D11 entries carry DXBC: 3Dmigoto's cmd_Decompiler (under wine on Linux) turns it into HLSL,
    then cbN[i] references are renamed to the uniform names Unity stored (_MainTex_ST, ...).
  GLES/GLCore entries are GLSL text and are written as is.
Output: shaders/<Shader name>/<pass>.<stage>.<variant>.{hlsl,glsl} and shaders/<Shader name>/shader.json
(properties, render state, tags, keywords per variant). Run as `python -m udk.shaders <out> <files...>`.
"""
import glob
import json
import os
import re
import struct
import subprocess
import sys

import lz4.block

KIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DECOMPILER = os.path.join(KIT, "third_party", "cmd_decompiler", "cmd_Decompiler.exe")
STAGES = ["progVertex", "progFragment", "progGeometry", "progHull", "progDomain"]
SAFE = re.compile(r"[^\w.-]+")


def blob_entries(t, platform_i):
    """Decompressed sub-program entries of one platform, as a list of bytes."""
    def pick(a):
        v = a[platform_i]
        return v[0] if isinstance(v, list) else v

    blob = bytes(t["compressedBlob"])
    off, clen, dlen = pick(t["offsets"]), pick(t["compressedLengths"]), pick(t["decompressedLengths"])
    data = lz4.block.decompress(blob[off:off + clen], uncompressed_size=dlen)
    count = struct.unpack_from("<i", data, 0)[0]
    stride = (len(data) and 12) if count and 4 + count * 12 <= len(data) and _plausible(data, count, 12) else 8
    out = []
    for i in range(count):
        o, n = struct.unpack_from("<ii", data, 4 + i * stride)
        out.append(data[o:o + n])
    return out


def _plausible(data, count, stride):
    for i in range(min(count, 8)):
        o, n = struct.unpack_from("<ii", data, 4 + i * stride)
        if not (0 < o <= len(data) and 0 <= n and o + n <= len(data)):
            return False
    return True


def program_code(entry):
    i = entry.find(b"DXBC")
    if i >= 0:
        size = struct.unpack_from("<I", entry, i + 24)[0]
        return "dxbc", entry[i:i + size]
    j = entry.find(b"#version")
    if j >= 0:
        end = entry.find(b"\0", j)
        return "glsl", entry[j:end if end > 0 else len(entry)]
    return None, None


def names_of(pass_):
    ni = pass_.get("m_NameIndices") or []
    return {idx: name for name, idx in ni}


def uniform_map(params, names):
    """cbuffer bind index -> {16-byte row: (name, kind)} from Unity's stored reflection."""
    rows = {}
    cb_names = {cb["m_NameIndex"]: cb for cb in params.get("m_ConstantBuffers", [])}
    for bind in params.get("m_ConstantBufferBindings", []):
        cb = cb_names.get(bind["m_NameIndex"])
        if cb is None:
            continue
        r = rows.setdefault(bind["m_Index"], {})
        for v in cb.get("m_VectorParams", []):
            if v["m_Index"] % 16 == 0:
                r[v["m_Index"] // 16] = (names.get(v["m_NameIndex"], f"n{v['m_NameIndex']}"), "vec")
        for m in cb.get("m_MatrixParams", []):
            for k in range(m.get("m_RowCount", 4)):
                r[m["m_Index"] // 16 + k] = (names.get(m["m_NameIndex"], f"n{m['m_NameIndex']}") + f"[{k}]", "mat")
    return rows


def rename(hlsl, rows):
    def sub(m):
        cb, row = int(m.group(1)), int(m.group(2))
        hit = rows.get(cb, {}).get(row)
        return f"{hit[0]}/*cb{cb}[{row}]*/" if hit else m.group(0)
    return re.sub(r"\bcb(\d+)\[(\d+)\]", sub, hlsl)


def dump_shader(t, out_dir, taken):
    pf = t["m_ParsedForm"]
    base = SAFE.sub("_", pf["m_Name"])
    sdir, k = os.path.join(out_dir, base), 1
    while sdir in taken:  # two Shader objects with one name (copies in different bundles)
        k += 1
        sdir = os.path.join(out_dir, f"{base}~{k}")
    taken.add(sdir)
    os.makedirs(sdir, exist_ok=True)
    keywords = pf.get("m_KeywordNames") or []
    summary = {"name": pf["m_Name"], "properties": pf["m_PropInfo"]["m_Props"], "fallback": pf.get("m_FallbackName"),
               "platforms": t["platforms"], "subshaders": []}
    entries = {}
    for pi in range(len(t["platforms"])):
        try:
            entries[pi] = blob_entries(t, pi)
        except Exception as e:  # noqa: BLE001 - one bad platform blob should not hide the others
            summary.setdefault("errors", []).append(f"platform {t['platforms'][pi]}: {e}")
    pending, used = [], set()
    for si, ss in enumerate(pf["m_SubShaders"]):
        sub = {"tags": ss.get("m_Tags"), "lod": ss.get("m_LOD"), "passes": []}
        for pj, ps in enumerate(ss["m_Passes"]):
            names = names_of(ps)
            pname = SAFE.sub("_", ps.get("m_Name") or ps.get("m_UseName") or f"pass{pj}")
            pinfo = {"name": ps.get("m_Name"), "state": ps.get("m_State"), "tags": ps.get("m_Tags"), "variants": []}
            for stage in STAGES:
                prog = ps.get(stage) or {}
                lists = prog.get("m_PlayerSubPrograms") or []
                flat = [sp for lst in lists for sp in lst] or prog.get("m_SubPrograms") or []
                common = prog.get("m_CommonParameters") or {}
                rows = uniform_map(common, names)
                for sp in flat:
                    kws = [keywords[k] for k in sp.get("m_KeywordIndices", []) if k < len(keywords)]
                    for pi, ent in entries.items():
                        bi = sp["m_BlobIndex"]
                        if bi >= len(ent):
                            continue
                        kind, code = program_code(ent[bi])
                        if not kind:
                            continue
                        var = "_".join(kws) or "base"
                        stem = f"s{si}.{pname}.{stage[4:].lower()}.{SAFE.sub('_', var)}"[:180]
                        if (stem, kind) in used:  # same pass/stage/keywords on another platform or blob
                            stem = f"{stem}.b{bi}.p{pi}"
                        used.add((stem, kind))
                        path = os.path.join(sdir, stem + "." + kind)
                        with open(path, "wb") as fh:
                            fh.write(code)
                        pinfo["variants"].append({"stage": stage[4:], "keywords": kws, "file": os.path.basename(path)})
                        if kind == "dxbc":
                            pending.append((path, rows))
            sub["passes"].append(pinfo)
        summary["subshaders"].append(sub)
    with open(os.path.join(sdir, "shader.json"), "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=1, default=str)
    return pending


def decompile(pending, batch=100):
    """cmd_Decompiler writes <file>.hlsl next to each .dxbc. It runs per folder with relative names:
    a batch of absolute paths overflows the 32 KB Windows command line."""
    ok = 0
    env = dict(os.environ, WINEDEBUG="-all")
    by_dir = {}
    for p, rows in pending:
        by_dir.setdefault(os.path.dirname(p), []).append((os.path.basename(p), rows))
    for d, items in by_dir.items():
        for i in range(0, len(items), batch):
            chunk = items[i:i + batch]
            subprocess.run(["wine", DECOMPILER, "-D"] + [n for n, _ in chunk], cwd=d, capture_output=True,
                           env=env, timeout=3600)
            for n, rows in chunk:
                h = os.path.join(d, n[:-5] + ".hlsl")
                if os.path.exists(h):
                    with open(h, encoding="utf-8", errors="replace") as fh:
                        text = fh.read()
                    with open(h, "w", encoding="utf-8") as fh:
                        fh.write(rename(text, rows))
                    os.remove(os.path.join(d, n))
                    ok += 1
    return ok


def run(out, files):
    import UnityPy
    sdir = os.path.join(out, "shaders")
    os.makedirs(sdir, exist_ok=True)
    pending, n, taken = [], 0, set()
    for f in files:
        try:
            env = UnityPy.load(f)
        except Exception:  # noqa: BLE001 - not a Unity file
            continue
        for o in env.objects:
            if o.type.name != "Shader":
                continue
            try:
                t = o.read_typetree()
            except Exception:  # noqa: BLE001
                continue
            if "m_ParsedForm" not in t:
                continue
            pending += dump_shader(t, sdir, taken)
            n += 1
    ok = decompile(pending) if pending else 0
    summary = f"{n} shaders, {len(pending)} DXBC programs, {ok} decompiled to HLSL"
    with open(os.path.join(sdir, "summary.txt"), "w") as fh:
        fh.write(summary + "\n")
    print(f"[shaders] {summary}", flush=True)


if __name__ == "__main__":
    out = sys.argv[1]
    files = []
    for a in sys.argv[2:]:
        files += [p for p in glob.glob(os.path.join(a, "**", "*"), recursive=True) if os.path.isfile(p)] if os.path.isdir(a) else [a]
    run(out, files)
