"""Run the whole pipeline on one Unity build: udk build <game dir> <out dir>.

Steps (each reruns cleanly and skips if its output exists; delete the output to redo):
  inspector  Il2CppInspectorRedux: types.cs, metadata.json, C header, Ghidra script
  data       peel XOR/gzip/LZ4 off loose files and TextAssets, keys from code literals
  ghidra     load header + names into Ghidra, decompile game assemblies per type
  assets     AssetRipper export as a Unity project, then refs.tsv/guids.tsv
  index      INDEX.md with counts and how to query
Layout is found by find_layout(): Windows/Linux standalone or an unpacked Android APK.
"""
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import time

KIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TP = os.path.join(KIT, "third_party")
INSPECTOR = os.path.join(TP, "inspector-legacy", "Il2CppInspectorRedux.Legacy.CLI-linux-x64", "Il2CppInspector")
ASSETRIPPER = os.path.join(TP, "assetripper", "AssetRipper.GUI.Free")
LIB_RE = (r"^(mscorlib|System|Mono\.|Microsoft\.|Unity\.|UnityEngine|netstandard|Newtonsoft|DOTween|UniTask|UniRx|"
          r"spine-|Sirenix|Cinemachine|protobuf|Google\.|Firebase|MoonSharp|XLua|Serilog|MasterAudio|ACTk|VContainer|"
          r"Zenject|Febucci|ChocDino|InputIcons|StompyRobot|com\.rlabrecque|Facepunch|Rewired|I2\.|PlayFab|AppsFlyer|"
          r"Photon|Mirror|FMOD|Wwise|AK\.|Ionic|ICSharpCode|SharpZipLib|BouncyCastle|LitJson|Purchasing|Assembly-CSharp-firstpass)")


def env():
    e = dict(os.environ)
    e["DOTNET_ROOT"] = os.path.join(TP, "dotnet")
    e["DOTNET_ROLL_FORWARD"] = "Major"
    e["JAVA_HOME"] = glob.glob(os.path.join(TP, "jdk-25*"))[0]
    e["GHIDRA_INSTALL_DIR"] = glob.glob(os.path.join(TP, "ghidra_*_PUBLIC"))[0]
    e["PATH"] = os.path.join(e["JAVA_HOME"], "bin") + os.pathsep + os.path.join(KIT, ".venv", "bin") + os.pathsep + e["PATH"]
    return e


def log(msg):
    print(f"[udk {time.strftime('%H:%M:%S')}] {msg}", flush=True)


def find_layout(game):
    """Return dict: binary, metadata, data_dir (Unity data folder), loose (dirs with loose data files)."""
    meta = glob.glob(os.path.join(game, "**", "global-metadata.dat"), recursive=True)
    if not meta:
        sys.exit(f"global-metadata.dat not found under {game}")
    meta = meta[0]
    for pat in ("GameAssembly.dll", "**/arm64-v8a/libil2cpp.so", "**/libil2cpp.so", "GameAssembly.so"):
        hits = glob.glob(os.path.join(game, pat), recursive=True)
        if hits:
            binary = hits[0]
            break
    else:
        sys.exit(f"no IL2CPP binary found under {game}")
    data_dir = os.path.dirname(os.path.dirname(os.path.dirname(meta)))
    if data_dir.endswith(os.path.join("assets", "bin")):
        data_dir = os.path.dirname(data_dir)
    loose = [p for p in glob.glob(os.path.join(data_dir, "StreamingAssets")) if os.path.isdir(p)]
    return {"binary": binary, "metadata": meta, "data_dir": data_dir, "loose": loose}


def run(cmd, timeout, logfile):
    log(" ".join(cmd[:3]) + " ...")
    with open(logfile, "w") as fh:
        r = subprocess.run(cmd, stdout=fh, stderr=subprocess.STDOUT, env=env(), timeout=timeout)
    if r.returncode:
        sys.exit(f"{cmd[0]} exited {r.returncode}; see {logfile}")


def step_inspector(L, out, game_re):
    d = os.path.join(out, "inspector")
    if os.path.exists(os.path.join(d, "metadata.json")):
        return
    os.makedirs(d, exist_ok=True)
    run([INSPECTOR, "-i", L["binary"], "-m", L["metadata"], "-e", "none", "--select-outputs",
         "-c", os.path.join(d, "types.cs"), "-p", os.path.join(d, "il2cpp_ghidra.py"), "-t", "Ghidra",
         "-o", os.path.join(d, "metadata.json"), "-h", os.path.join(d, "cpp")],
        1800, os.path.join(d, "log.txt"))
    os.makedirs(os.path.join(out, "code"), exist_ok=True)
    shutil.copy(os.path.join(d, "types.cs"), os.path.join(out, "code", "types.cs"))


def literals(out):
    with open(os.path.join(out, "inspector", "metadata.json"), encoding="utf-8") as fh:
        return [s["string"] for s in json.load(fh)["addressMap"]["stringLiterals"]]


def step_data(L, out, game_re):
    from udk import data
    d = os.path.join(out, "data")
    if os.path.exists(os.path.join(d, "report.tsv")):
        return
    items = list(data.files_under(L["loose"]))
    text_assets = os.path.join(out, "assets", "ExportedProject", "Assets")
    if os.path.isdir(text_assets):
        for p in glob.glob(os.path.join(text_assets, "**", "*.bytes"), recursive=True) + \
                glob.glob(os.path.join(text_assets, "TextAsset", "**", "*.txt"), recursive=True):
            items.append((os.path.join("TextAsset", os.path.relpath(p, text_assets)), open(p, "rb").read()))
    rows = data.run(items, d, literals(out))
    log(f"data: {len(rows)} files, {sum(1 for r in rows if r[1] != '-')} unwrapped")


def game_assemblies(out):
    with open(os.path.join(out, "inspector", "metadata.json"), encoding="utf-8") as fh:
        groups = {m["group"].split("/")[0] for m in json.load(fh)["addressMap"]["methodDefinitions"]}
    lib = re.compile(LIB_RE)
    return sorted(g for g in groups if g and not lib.match(g))


def step_ghidra(L, out, game_re):
    code = os.path.join(out, "code", "decomp")
    if os.path.exists(os.path.join(out, "code", "methods.tsv")):
        return
    if not game_re:
        names = game_assemblies(out)
        log(f"game assemblies: {', '.join(names)}")
        game_re = "^(" + "|".join(re.escape(n) for n in names) + ")$"
    proj = os.path.join(out, "ghidra")
    os.makedirs(proj, exist_ok=True)
    py = os.path.join(KIT, ".venv", "bin", "pyghidra")
    base = [py, "-X", "mx14g", "--skip-analysis", "--project-path", proj, "--project-name", "p", L["binary"]]
    if not os.path.exists(os.path.join(proj, "prepared")):
        run(base + [os.path.join(KIT, "tools", "ghidra", "prepare.py"), os.path.join(out, "inspector"), game_re],
            4 * 3600, os.path.join(proj, "prepare.log"))
        open(os.path.join(proj, "prepared"), "w").close()
    run(base + [os.path.join(KIT, "tools", "ghidra", "decompile.py"), os.path.join(out, "inspector"), game_re, code, "6"],
        6 * 3600, os.path.join(proj, "decompile.log"))
    shutil.move(os.path.join(code, "methods.tsv"), os.path.join(out, "code", "methods.tsv"))
    from udk import code as code_mod
    found = code_mod.name_helpers(out)
    log(f"named runtime helpers: {', '.join(n for n, _ in found.values())}")


def step_assets(L, out, game_re):
    from udk import assets, assetripper
    d = os.path.join(out, "assets")
    if not os.path.isdir(os.path.join(d, "ExportedProject")):
        assetripper.export(ASSETRIPPER, L["data_dir"], d)
    if not os.path.exists(os.path.join(d, "refs.tsv")):
        n_guid, n_ref = assets.build_refs(out)
        log(f"assets: {n_guid} assets with guids, {n_ref} references")


def step_index(L, out, game_re):
    from udk import index
    index.write(out, L)


STEPS = {"inspector": step_inspector, "data": step_data, "ghidra": step_ghidra, "assets": step_assets, "index": step_index}


def main(game, out, game_re=None, steps="inspector,assets,data,ghidra,index"):
    L = find_layout(os.path.abspath(game))
    out = os.path.abspath(out)
    os.makedirs(out, exist_ok=True)
    log(f"binary {L['binary']}")
    for s in steps.split(","):
        t = time.time()
        STEPS[s](L, out, game_re)
        log(f"{s} done in {time.time() - t:.0f}s")
