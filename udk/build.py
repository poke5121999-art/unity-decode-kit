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
# Il2CppInspectorRedux 2026.2 built from source with tools/inspector/tolerant.patch (see setup.sh)
INSPECTOR = [os.path.join(TP, "dotnet", "dotnet"), os.path.join(TP, "inspector-tolerant", "Il2CppInspector.dll")]
ASSETRIPPER = os.path.join(TP, "assetripper", "AssetRipper.GUI.Free")
# Libraries with public source: their bodies are not worth decompiling. Closed or paid
# libraries (MasterAudio, DOTweenPro, Febucci TextAnimator, InputIcons...) stay in, because a
# remake has no other way to read them.
OPEN_SOURCE_LIBS = (r"^(mscorlib|System|Mono\.|Microsoft\.|Unity\.|UnityEngine|netstandard|Newtonsoft|UniTask|UniRx|"
                    r"spine-|Cinemachine|protobuf|Google\.|Firebase|MoonSharp|XLua|Serilog|ACTk|VContainer|Zenject|"
                    r"com\.rlabrecque|Facepunch|Mirror|ICSharpCode|SharpZipLib|BouncyCastle|LitJson|Purchasing|"
                    r"Assembly-CSharp-firstpass|Sirenix\.Serialization|Sirenix\.Utilities)")
HEAVY = os.environ.get("UDK_HEAVY", os.path.expanduser("~/handoff/heavy.sh"))


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
    """Return dict: game, binary, metadata, data_dir (Unity data folder), loose (dirs with loose data files).
    For an APK, point game at a folder holding the unpacked base APK, asset packs and lib/."""
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
    if not loose:
        # Android: StreamingAssets are the APK's (and asset packs') assets/ folders.
        loose = sorted(os.path.dirname(b) for b in glob.glob(os.path.join(game, "**", "assets", "bin"), recursive=True))
    return {"game": game, "binary": binary, "game_binary": binary, "metadata": meta, "data_dir": data_dir, "loose": loose}


def run(cmd, timeout, logfile, min_free_gb=0):
    """Run a tool. Heavy ones (min_free_gb > 0) go through the host's job queue when it has one,
    so they wait for their turn and for free memory instead of failing."""
    if min_free_gb and os.path.exists(HEAVY):
        cmd = ["sh", HEAVY, str(timeout), str(min_free_gb)] + cmd
        timeout = None
    log(" ".join(cmd[:5]) + " ...")
    os.makedirs(os.path.dirname(logfile), exist_ok=True)
    with open(logfile, "w") as fh:
        r = subprocess.run(cmd, stdout=fh, stderr=subprocess.STDOUT, env=env(), timeout=timeout)
    if r.returncode:
        sys.exit(f"{cmd[0]} exited {r.returncode}; see {logfile}")


BINARY_FORMAT = "2: xor windows undone, moved windows put back"


def read_text(path):
    if not os.path.exists(path):
        return ""
    with open(path, encoding="utf-8") as fh:
        return fh.read().strip()


def step_inspector(L, out, game_re):
    d = os.path.join(out, "inspector")
    have = os.path.exists(os.path.join(d, "metadata.json"))
    marker = os.path.join(d, "binary.format")
    repaired = os.path.join(d, os.path.basename(L["game_binary"]))
    if have and not (os.path.exists(repaired) and read_text(marker) != BINARY_FORMAT):
        return
    os.makedirs(d, exist_ok=True)
    from udk import metadata
    meta = L["metadata"]
    fixed = os.path.join(d, "global-metadata.dat")
    how = metadata.repair(meta, fixed, L["game"])
    if how != "plain":
        log(f"metadata repaired: {how}")
        meta = fixed
    binary, meta = fix_binary(L, d, meta)
    if binary != L["game_binary"]:
        with open(marker, "w") as fh:
            fh.write(BINARY_FORMAT + "\n")
    if have:
        log("inspector: repaired binary rewritten; Il2CppInspector output kept (it reads tables, not code)")
        return
    run(INSPECTOR + ["-i", binary, "-m", meta, "-e", "none", "--select-outputs",
         "-c", os.path.join(d, "types.cs"), "-p", os.path.join(d, "il2cpp_ghidra.py"), "-t", "Ghidra",
         "-o", os.path.join(d, "metadata.json"), "-h", os.path.join(d, "cpp")],
        1800, os.path.join(d, "log.txt"), min_free_gb=7)
    os.makedirs(os.path.join(out, "code"), exist_ok=True)
    shutil.copy(os.path.join(d, "types.cs"), os.path.join(out, "code", "types.cs"))


def fix_binary(L, d, meta):
    """Undo at-rest protection of an ELF libil2cpp.so (see udk/elf.py); later steps use the copy."""
    from udk import elf
    with open(L["game_binary"], "rb") as fh:  # always repair from the shipped file
        b = bytearray(fh.read())
    if b[:4] != b"\x7fELF":
        return L["game_binary"], meta
    windows = elf.unxor_sections(b)
    moved = elf.unshuffle_windows(b, windows)
    with open(meta, "rb") as fh:
        m = fh.read()
    import struct
    img_off, img_size = struct.unpack_from("<II", m, 8 + 8 * 20)
    owned = max(sum(struct.unpack_from("<II", m, img_off + i + 8)) for i in range(0, img_size, 40))
    n_params = struct.unpack_from("<I", m, 8 + 8 * 12 + 4)[0] // 16  # genericParameters, 16 bytes each in v24
    version = struct.unpack_from("<i", m, 4)[0]
    # The registration and Il2CppType layouts below are those of metadata v24 (Unity 2018.4-2019.4);
    # on another version they would locate the wrong tables and write over unrelated bytes.
    neutral = elf.neutralize_types(b, owned, n_params) if version == 24 else None
    if version != 24:
        log(f"metadata v{version}: XOR windows undone; type/registration repairs are v24-only and were skipped")
    if neutral:
        reg_meta = int(neutral[0], 16)
        neutral = neutral + (elf.restore_typedef_types(b, reg_meta, m),
                             elf.fix_enums_and_generic_args(b, reg_meta, m, n_params))
        m, unset = elf.drop_corrupt_defaults(m, b, reg_meta)
        if unset:
            meta = os.path.join(d, "global-metadata.dat")  # never write into the game folder
            with open(meta, "wb") as fh:
                fh.write(m)
        log(f"default values with unreadable types retyped as Int32: {unset}")
    if not windows and not (neutral and neutral[2]):
        return L["game_binary"], meta
    fixed = os.path.join(d, os.path.basename(L["game_binary"]))
    with open(fixed, "wb") as fh:
        fh.write(b)
    dropped = elf.sanitize(fixed, fixed)
    with open(fixed, "rb") as fh:
        b = bytearray(fh.read())
    reg = elf.find_code_registration(b) if version == 24 else None
    invokers = elf.clamp_invoker_indices(b, reg[1], reg[0], reg[2]) if reg else 0
    mods = elf.find_modules(b) if version in elf.TYPEDEF_LAYOUT else None
    names = elf.repair_module_names(b, mods[1], mods[0], m, version) if mods else []
    if reg and neutral:
        specs, rows, ranges = elf.repair_generic_tables(b, int(neutral[0], 16), reg[2], reg[1], reg[0], m)
        log(f"generic tables repaired: {specs} method specs rewritten, {rows} generic method rows and "
            f"{ranges} rgctx ranges dropped")
    with open(fixed, "wb") as fh:
        fh.write(b)
    log(f"module names repaired: {names}; invoker indices cleared: {invokers}")
    log(f"binary repaired: xor windows {windows}; windows moved back (section, group, permutation, groups, votes) {moved}; registration/types/neutralized {neutral}; null segments {dropped}")
    L["binary"] = fixed
    return fixed, meta


def literals(out):
    with open(os.path.join(out, "inspector", "metadata.json"), encoding="utf-8") as fh:
        return [s["string"] for s in json.load(fh)["addressMap"]["stringLiterals"]]


TEXT_ASSET_EXT = (".bytes", ".txt", ".json", ".xml", ".csv", ".lua", ".yaml", ".html")


def step_data(L, out, game_re):
    from udk import data
    d = os.path.join(out, "data")
    report, marker = os.path.join(d, "report.tsv"), os.path.join(d, "format")
    done = os.path.join(out, "logs", "assets.done")
    if os.path.exists(report) and read_text(marker) == data.FORMAT and \
            not (os.path.exists(done) and os.path.getmtime(done) > os.path.getmtime(report)):
        return
    items = list(data.files_under(L["loose"]))
    text_assets = os.path.join(out, "assets", "ExportedProject", "Assets")
    if os.path.isdir(text_assets):
        # AssetRipper names a TextAsset by its detected content: .bytes, .txt, .json, .xml, .csv...
        for p in [q for ext in TEXT_ASSET_EXT for q in glob.glob(os.path.join(text_assets, "**", "*" + ext), recursive=True)]:
            if not os.path.isfile(p):
                continue  # AssetRipper names a folder after a bundle path ending in .bytes
            items.append((os.path.join("TextAsset", os.path.relpath(p, text_assets)), open(p, "rb").read()))
    rows = data.run(items, d, literals(out))
    with open(marker, "w") as fh:
        fh.write(data.FORMAT + "\n")
    log(f"data: {len(rows)} files, {sum(1 for r in rows if r[1] != '-')} unwrapped")


def game_assemblies(out):
    with open(os.path.join(out, "inspector", "metadata.json"), encoding="utf-8") as fh:
        groups = {m["group"].split("/")[0] for m in json.load(fh)["addressMap"]["methodDefinitions"]}
    lib = re.compile(OPEN_SOURCE_LIBS)
    return sorted(g for g in groups if g and not lib.match(g))


def main_assembly(out):
    """The game assembly with the most methods."""
    with open(os.path.join(out, "inspector", "metadata.json"), encoding="utf-8") as fh:
        groups = [m["group"].split("/")[0] for m in json.load(fh)["addressMap"]["methodDefinitions"]]
    game = set(game_assemblies(out))
    from collections import Counter
    return Counter(g for g in groups if g in game).most_common(1)[0][0]


DECOMP_FORMAT = "2: game methods + game generic instances"


def step_ghidra(L, out, game_re):
    final = os.path.join(out, "code", "decomp")
    marker = os.path.join(out, "code", "decomp.format")
    if L.get("types") is None:
        # A rerun keeps the scope of the last one; a whole-binary pass is hours longer than a slice.
        m = re.search(r"; types (.*?)(; binary |$)", read_text(marker))
        if m:
            L["types"] = m.group(1)
            log(f"ghidra: keeping the last run's type scope {L['types']} (--types all for every type)")
    if L.get("types") == "all":
        L["types"] = None
    bin_format = read_text(os.path.join(out, "inspector", "binary.format"))  # empty: no repair needed
    # What the Ghidra project's copy of the bytes came from: the repair format and the file. Empty when
    # the shipped binary needed no repair, which keeps older unrepaired dumps current.
    imported = f"{bin_format} {L['binary']}" if bin_format else ""
    want = DECOMP_FORMAT + (f"; types {L['types']}" if L.get("types") else "") + \
        (f"; binary {imported}" if imported else "")
    if os.path.exists(os.path.join(out, "code", "methods.tsv")) and os.path.exists(marker) and \
            open(marker).read().strip() == want:
        return
    code = final + ".next"  # the old output stays readable until the new one is complete
    shutil.rmtree(code, ignore_errors=True)
    if not game_re:
        names = game_assemblies(out)
        log(f"game assemblies: {', '.join(names)}")
        game_re = "^(" + "|".join(re.escape(n) for n in names) + ")$"
    proj = os.path.join(out, "ghidra")
    os.makedirs(proj, exist_ok=True)
    py = os.path.join(KIT, ".venv", "bin", "pyghidra")
    base = [py, "-X", "mx14g", "--skip-analysis", "--project-path", proj, "--project-name", "p", L["binary"]]
    prepared = os.path.join(proj, "prepared")
    if os.path.exists(prepared) and read_text(prepared) != imported:
        shutil.rmtree(proj)  # the project holds a copy of the binary's bytes; an older repair is stale
        os.makedirs(proj)
    if not os.path.exists(prepared):
        run(base + [os.path.join(KIT, "tools", "ghidra", "prepare.py"), os.path.join(out, "inspector"), game_re],
            4 * 3600, os.path.join(proj, "prepare.log"), min_free_gb=8)
        with open(prepared, "w") as fh:
            fh.write(imported + "\n")
    run(base + [os.path.join(KIT, "tools", "ghidra", "decompile.py"), os.path.join(out, "inspector"), game_re, code, "6"]
        + ([L["types"]] if L.get("types") else []),
        6 * 3600, os.path.join(proj, "decompile.log"), min_free_gb=6)
    shutil.move(os.path.join(code, "methods.tsv"), os.path.join(out, "code", "methods.tsv.next"))
    if os.path.isdir(final):
        os.rename(final, final + ".old")
    os.rename(code, final)
    os.replace(os.path.join(out, "code", "methods.tsv.next"), os.path.join(out, "code", "methods.tsv"))
    shutil.rmtree(final + ".old", ignore_errors=True)
    with open(marker, "w") as fh:
        fh.write(want + "\n")
    from udk import code as code_mod
    found = code_mod.name_helpers(out)
    log(f"named runtime helpers: {', '.join(n for n, _ in found.values())}")


def step_retype(L, out, game_re):
    """Name fields read from values that shared generic code returns (udk/retype.py); comments only."""
    from udk import retype
    if os.path.isdir(os.path.join(out, "code", "decomp")):
        n, files = retype.run(out)
        log(f"retype: {n} lines annotated in {files} files")


def step_native(L, out, game_re):
    """Decompile the game's own native plugins (udk/native.py). SDK plugins bound by P/Invoke too are
    listed in native/plugins.tsv but not decompiled unless L["native"] (a regex over file names) says so."""
    from udk import native
    d = os.path.join(out, "native")
    if os.path.exists(os.path.join(d, "plugins.tsv")):
        return
    dirs = {os.path.dirname(L["game_binary"])}
    dirs.update(p for p in glob.glob(os.path.join(L["game"], "**", "Plugins", "**"), recursive=True) if os.path.isdir(p))
    found = native.plugins(sorted(dirs), os.path.join(out, "code", "types.cs"), skip={os.path.realpath(L["game_binary"])})
    # A plugin is the game's own when its name carries the leading word of the biggest game assembly
    # (NssMain -> libNssPhysicsPlugin). Assembly-CSharp names no studio, so such games pick none by default.
    word = re.match(r"[A-Z]+[a-z0-9]*|[a-z0-9]*", main_assembly(out)).group(0).lower()
    words = {word} - {"assembly", "unity"}
    pick = re.compile(L["native"]) if L.get("native") else None
    os.makedirs(d, exist_ok=True)
    rows = []
    for path, hits in found:
        name = os.path.basename(path)
        own = pick.search(name) if pick else any(w in name.lower() for w in words if len(w) >= 3)
        rows.append((name, len(hits), "decompiled" if own else "listed", path))
        if not own:
            continue
        lib = os.path.splitext(name)[0]
        proj = os.path.join(out, "ghidra-native")
        os.makedirs(proj, exist_ok=True)
        run([os.path.join(KIT, ".venv", "bin", "pyghidra"), "-X", "mx8g", "--project-path", proj, "--project-name", lib,
             path, os.path.join(KIT, "tools", "ghidra", "native.py"), os.path.join(d, lib), "4"],
            3 * 3600, os.path.join(d, lib + ".log"), min_free_gb=6)
        thunks = native.add_export_thunks(path, os.path.join(d, lib))
        log(f"native: {name}: {thunks} one-instruction exports mapped to their bodies")
    with open(os.path.join(d, "plugins.tsv"), "w", encoding="utf-8") as fh:
        fh.write("library	bound_externs	state	path\n")
        for r in rows:
            fh.write("\t".join(map(str, r)) + "\n")
    log(f"native: {sum(r[2] == 'decompiled' for r in rows)} plugins decompiled, {len(rows)} bound by P/Invoke")


def step_normalize(L, out, game_re):
    """Mirror the game for AssetRipper: engine-modified objects rewritten to the stock layout
    (udk/normalize.py), and the repaired IL2CPP pair placed where a standard build keeps it."""
    d = os.path.join(out, "normalized")
    if not os.path.exists(d + ".log"):
        run([os.path.join(KIT, ".venv", "bin", "python"), "-m", "udk.normalize", L["game"], d],
            12 * 3600, os.path.join(out, "logs", "normalize.log"), min_free_gb=10)
    places = il2cpp_places(L, out)
    for src, rel in places:
        dst = os.path.join(d, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        if os.path.lexists(dst):
            os.remove(dst)
        shutil.copy2(src, dst)
        log(f"normalized: {rel} <- {os.path.relpath(src, out) if src.startswith(out) else src}")
    root = merge_splits(d, places[0][1])
    if root:
        with open(d + ".root", "w") as fh:
            fh.write(root)


def merge_splits(mirror, meta_rel):
    """Fold a split package (xapk: base apk, config apks, asset packs) into the base apk's tree, the
    way a device sees it after install: every split's assets/ and lib/ go under the base. AssetRipper
    reports a "Mixed game structure" (and no scripting backend) for the unmerged folders. Returns the
    base folder, or None for a package that is not split."""
    marker = os.path.join("assets", "bin", "Data")
    if marker not in meta_rel:
        return None
    base = meta_rel.split(marker)[0].strip(os.sep)
    tops = [t for t in os.listdir(mirror) if t != base and os.path.isdir(os.path.join(mirror, t))]
    if not base or not tops:
        return None
    clashes = 0
    for t in tops:
        for sub in ("assets", "lib"):
            src_root = os.path.join(mirror, t, sub)
            for d, _, fs in os.walk(src_root):
                for f in fs:
                    src = os.path.join(d, f)
                    dst = os.path.join(mirror, base, sub, os.path.relpath(src, src_root))
                    if os.path.lexists(dst):
                        clashes += 1
                        continue
                    os.makedirs(os.path.dirname(dst), exist_ok=True)
                    os.rename(src, dst)
        shutil.rmtree(os.path.join(mirror, t))
    log(f"normalized: merged {len(tops)} split folders into {base} ({clashes} duplicate paths kept from the base)")
    return os.path.join(mirror, base)


def il2cpp_places(L, out):
    """(file, path in the mirror) for metadata and binary. A protected build gets the repaired copies
    from out/inspector; a split Android package (xapk) keeps libil2cpp.so in a config apk, so it is
    placed under the base apk's lib/<abi>/, where AssetRipper's IL2CPP detection looks."""
    fixed_meta = os.path.join(out, "inspector", "global-metadata.dat")
    original = L["game_binary"]  # L["binary"] may already point at the repaired copy in out/inspector
    fixed_bin = os.path.join(out, "inspector", os.path.basename(original))
    meta_rel = os.path.relpath(L["metadata"], L["game"])
    places = [(fixed_meta if os.path.exists(fixed_meta) else L["metadata"], meta_rel)]
    binary = fixed_bin if os.path.exists(fixed_bin) else original
    marker = os.path.join("assets", "bin", "Data")
    if marker in meta_rel:
        base = meta_rel.split(marker)[0]
        abi = os.path.basename(os.path.dirname(original))
        places.append((binary, os.path.join(base, "lib", abi, os.path.basename(original))))
        places.append((binary, os.path.relpath(original, L["game"])))  # no protected copy left behind
    else:
        places.append((binary, os.path.relpath(original, L["game"])))
    return places


def step_assets(L, out, game_re):
    from udk import assets
    d = os.path.join(out, "assets")
    done = os.path.join(out, "logs", "assets.done")  # an interrupted export leaves a partial folder
    if not os.path.exists(done):
        for x in ("ExportedProject", "refs.tsv", "guids.tsv"):
            p = os.path.join(d, x)
            shutil.rmtree(p, ignore_errors=True) if os.path.isdir(p) else (os.path.exists(p) and os.remove(p))
        os.makedirs(d, exist_ok=True)
        normalized = os.path.join(out, "normalized")
        src = normalized if os.path.exists(normalized + ".log") else L["game"]
        if os.path.exists(normalized + ".root"):
            with open(normalized + ".root") as fh:
                src = fh.read().strip()
        # AssetRipper empties its target folder first, so its logs live in out/logs.
        run([os.path.join(KIT, ".venv", "bin", "python"), "-m", "udk.assetripper", ASSETRIPPER, src, d,
             os.path.join(out, "logs")], 8 * 3600, os.path.join(out, "logs", "assetripper-run.log"), min_free_gb=9)
        open(done, "w").close()
    spine_dir = os.path.join(KIT, "tools", "spine")
    if not os.path.isdir(os.path.join(spine_dir, "node_modules")):
        subprocess.run(["npm", "install", "--silent", "--no-audit", "--no-fund"], cwd=spine_dir, timeout=600, check=True)
    r = subprocess.run(["node", os.path.join(spine_dir, "summarize.mjs"), os.path.join(d, "ExportedProject", "Assets")],
                       capture_output=True, text=True, timeout=3600)
    log(r.stdout.strip() or r.stderr.strip()[-300:])
    if not os.path.exists(os.path.join(d, "refs.tsv")):
        n_guid, n_ref = assets.build_refs(out)
        log(f"assets: {n_guid} assets with guids, {n_ref} references")


def step_audio(L, out, game_re):
    from udk import audio
    if os.path.exists(os.path.join(out, "audio", "events.tsv")):
        return
    roots = [L["game"], os.path.join(out, "assets", "ExportedProject", "Assets")]
    text = [os.path.join(out, "data"), os.path.join(out, "assets", "ExportedProject", "Assets")]
    n_banks, n_events = audio.run(out, [r for r in roots if os.path.isdir(r)], literals(out), [t for t in text if os.path.isdir(t)])
    log(f"audio: {n_banks} banks, {n_events} events rendered")


def step_shaders(L, out, game_re):
    if os.path.exists(os.path.join(out, "shaders", "summary.txt")):
        return
    shutil.rmtree(os.path.join(out, "shaders"), ignore_errors=True)
    run([os.path.join(KIT, ".venv", "bin", "python"), "-m", "udk.shaders", out, L["game"]],
        6 * 3600, os.path.join(out, "logs", "shaders.log"), min_free_gb=6)


def step_settings(L, out, game_re):
    from udk import settings
    found = settings.run(out, L["data_dir"])
    log(f"settings: {', '.join(found) or 'none found'}")


def step_index(L, out, game_re):
    from udk import index
    index.write(out, L)


STEPS = {"inspector": step_inspector, "data": step_data, "audio": step_audio, "ghidra": step_ghidra,
         "assets": step_assets, "shaders": step_shaders, "settings": step_settings, "normalize": step_normalize,
         "native": step_native, "retype": step_retype, "index": step_index}


def main(game, out, game_re=None, steps="inspector,settings,normalize,assets,data,audio,shaders,ghidra,retype,native,index", types=None,
         native=None):
    out = os.path.abspath(out)
    os.makedirs(out, exist_ok=True)
    if os.path.isfile(game):
        from udk import unpack
        log(f"unpacking {game}")
        game = unpack.unpack(game, os.path.join(out, "input"))
    L = find_layout(os.path.abspath(game))
    L["types"] = types
    # A repaired copy from an earlier run is what every later step reads (Ghidra once read the
    # protected file because only an inspector step in the same run switched over).
    fixed = os.path.join(out, "inspector", os.path.basename(L["game_binary"]))
    if os.path.exists(fixed) and os.path.exists(os.path.join(out, "inspector", "binary.format")):
        L["binary"] = fixed
    L["native"] = native
    log(f"binary {L['binary']}")
    for s in steps.split(","):
        t = time.time()
        STEPS[s](L, out, game_re)
        log(f"{s} done in {time.time() - t:.0f}s")
