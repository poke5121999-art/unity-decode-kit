"""Swap AssetRipper's dummy shaders for the real shaders of the same name.

The free AssetRipper exports every shader as a "DummyShaderTextExporter" stub: properties intact, one flat pass.
Shaders that ship as source elsewhere (the URP package, TextMesh Pro's essential resources .unitypackage) can
replace them exactly: find the real shader with the same `Shader "Name"`, point every reference in the project at
its guid, and move the dummy out. A .unitypackage source is installed under its own pathname and guid, with its
include files, so the shader compiles and later imports of the same package line up.

Usage: python -m udk.shaderremap <project Assets dir> <moved-dummies dir> <source>...
  source, first match wins: a package root inside the project (referenced in place), an unpacked .unitypackage
  (guid dirs with `pathname`), or a source checkout outside the project (copied under Assets/_shaders/)
"""
import os
import re
import shutil
import sys
from pathlib import Path

NAME = re.compile(r'^\s*Shader\s+"([^"]+)"', re.M)
GUID = re.compile(r"^guid: ([0-9a-f]{32})", re.M)
REFS = (".mat", ".asset", ".prefab", ".unity", ".controller", ".overrideController", ".shadervariants", ".preset")


def read(p):
    return open(p, encoding="utf-8", errors="replace").read()


def shader_name(p):
    m = NAME.search(read(p))
    return m.group(1) if m else None


def dummies(assets):
    out = {}
    for dirpath, _, files in os.walk(assets):
        for f in files:
            p = os.path.join(dirpath, f)
            if f.endswith(".shader") and os.path.exists(p + ".meta") and "DummyShaderTextExporter" in read(p):
                out[shader_name(p)] = (p, GUID.search(read(p + ".meta")).group(1))
    return out


def real_shaders(sources, project):
    """name -> (guid, install): install is None for a shader already in the project (an installed package),
    ("pkg", unitypackage dir, guid dir) or ("dir", source root, shader path) for one to copy in."""
    out = {}
    for src in sources:
        if any(os.path.exists(os.path.join(src, d, "pathname")) for d in os.listdir(src)):
            for d in os.listdir(src):
                asset = os.path.join(src, d, "asset")
                if os.path.exists(asset) and read(os.path.join(src, d, "pathname")).strip().endswith(".shader"):
                    out.setdefault(shader_name(asset), (d, ("pkg", src, d)))
            continue
        for dirpath, _, files in os.walk(src):
            for f in files:
                p = os.path.join(dirpath, f)
                if f.endswith(".shader") and os.path.exists(p + ".meta"):
                    inside = os.path.abspath(p).startswith(os.path.abspath(project) + os.sep)
                    out.setdefault(shader_name(p), (GUID.search(read(p + ".meta")).group(1), None if inside else ("dir", src, p)))
    return out


def install(project, kind, src, item, installed):
    """Copy one shader into the project with its guid, and once per source every include file it may need:
    all includes of a .unitypackage, or the shader's own directory for a source checkout."""
    if kind == "dir":
        repo = os.path.basename(src.rstrip("/\\"))
        dst_root = os.path.join(project, "Assets", "_shaders", repo)
        # The checkout's shaders include each other as Packages/<package name>/...; once copied under Assets that
        # path no longer exists, so point it at the copy.
        moved = {}
        for dirpath, _, files in os.walk(src):
            if "package.json" in files:
                m = re.search(r'"name"\s*:\s*"([^"]+)"', read(os.path.join(dirpath, "package.json")))
                if m:
                    rel_pkg = os.path.relpath(dirpath, src).replace("\\", "/")
                    moved["Packages/" + m.group(1) + "/"] = f"Assets/_shaders/{repo}/{rel_pkg}/"
        here = os.path.dirname(item)
        for f in os.listdir(here):
            if f.endswith((".shader", ".cginc", ".hlsl")) and (f.endswith((".cginc", ".hlsl")) or os.path.join(here, f) == item):
                # Unity skips folders ending in ~ (a package's Samples~), so the copy drops the tilde.
                rel = os.path.relpath(os.path.join(here, f), src).replace("~" + os.sep, os.sep)
                dst = os.path.join(dst_root, rel)
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                text = read(os.path.join(here, f))
                for old, new in moved.items():
                    text = text.replace(old, new)
                open(dst, "w", encoding="utf-8", newline="").write(text)
                if os.path.exists(os.path.join(here, f) + ".meta"):
                    shutil.copyfile(os.path.join(here, f) + ".meta", dst + ".meta")
        return
    pkg, guid_dir = src, item

    def copy(d):
        rel = read(os.path.join(pkg, d, "pathname")).strip().splitlines()[0]
        dst = os.path.join(project, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copyfile(os.path.join(pkg, d, "asset"), dst)
        shutil.copyfile(os.path.join(pkg, d, "asset.meta"), dst + ".meta")
    copy(guid_dir)
    if pkg not in installed:
        installed.add(pkg)
        for d in os.listdir(pkg):
            pn = os.path.join(pkg, d, "pathname")
            if os.path.exists(pn) and read(pn).strip().endswith((".cginc", ".hlsl")):
                copy(d)


def main(assets, moved, sources):
    project = str(Path(assets).parent)
    dum, real = dummies(assets), real_shaders(sources, project)
    swap, installed = {}, set()
    for name, (path, guid) in dum.items():
        if name not in real:
            continue
        new_guid, src = real[name]
        if src:
            install(project, *src, installed)
        swap[guid] = new_guid
        os.makedirs(moved, exist_ok=True)
        for ext in ("", ".meta"):
            shutil.move(path + ext, os.path.join(moved, os.path.basename(path) + ext))
    pat = re.compile(r"guid: (" + "|".join(swap) + ")") if swap else None
    refs = files = 0
    for dirpath, _, fs in os.walk(assets):
        for f in fs:
            if not pat or not f.endswith(REFS):
                continue
            p = os.path.join(dirpath, f)
            text = read(p)
            new, n = pat.subn(lambda m: "guid: " + swap[m.group(1)], text)
            if n:
                open(p, "w", encoding="utf-8", newline="").write(new)
                refs += n
                files += 1
    left = sorted(n for n in dum if n not in real)
    print(f"shaderremap: {len(swap)} of {len(dum)} dummy shaders replaced by the real shader; {refs} references "
          f"re-pointed in {files} files; {len(left)} have no source: {left}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2], sys.argv[3:])
