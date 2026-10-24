"""Turn an AssetRipper-exported compute shader (a ComputeShader .asset: bindings plus DXBC, no source) back into a
.compute file Unity can build.

AssetRipper keeps each kernel's compiled DXBC and its binding table, but Unity cannot import the .asset as a compute
shader ("was not imported correctly"), so every Dispatch on it fails in the build. `skel` writes a .compute with the
declarations recovered exactly (kernels, thread group size, $Globals params with their types, textures, buffers) and
each kernel's DXBC disassembly as a comment; the bodies are translated from that by hand or by the LLM. `install`
swaps the .asset for the finished .compute under the same guid, so every reference keeps pointing at it.

Usage: python -m udk.computeshader skel <asset> <out.compute>
       python -m udk.computeshader install <asset> <done.compute> <moved-dir>
Disassembly uses d3dcompiler_47.dll (Windows).
"""
import ctypes
import os
import re
import shutil
import struct
import sys

# Unity ShaderParamType
PARAM_TYPE = {0: "float", 1: "int", 2: "bool", 3: "half", 4: "short", 5: "uint"}


def disassemble(code):
    d3d = ctypes.WinDLL("d3dcompiler_47.dll")
    out = ctypes.c_void_p()
    if d3d.D3DDisassemble(code, len(code), 0, None, ctypes.byref(out)) != 0:
        return "(D3DDisassemble failed)"
    vt = ctypes.cast(ctypes.cast(out, ctypes.POINTER(ctypes.c_void_p))[0], ctypes.POINTER(ctypes.c_void_p))
    ptr = ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p)(vt[3])(out)
    size = ctypes.CFUNCTYPE(ctypes.c_size_t, ctypes.c_void_p)(vt[4])(out)
    text = ctypes.string_at(ptr, size).decode(errors="replace").replace("\0", "")
    return "\n".join(l for l in text.splitlines() if l.strip() and not l.startswith("//"))


def parse(asset_text):
    """Kernels of the first variant (one per kernel name), with their bindings, and every $Globals param."""
    variant = asset_text.split("  - serializedVersion: 2\n    targetRenderer:")[1]
    kernels = []
    for block in re.split(r"\n    - serializedVersion: 3\n", variant)[1:]:
        name = re.search(r"name: (\S+)", block).group(1)
        def names(section):
            m = re.search(section + r":\n((?:        [- ].*\n)*)", block)
            return re.findall(r"^        - name: (\S+)", m.group(1), re.M) if m else []
        code = bytes.fromhex(re.search(r"code: ([0-9a-f]+)", block).group(1))
        tgs = struct.unpack("<3I", bytes.fromhex(re.search(r"threadGroupSize: ([0-9a-f]+)", block).group(1)))
        kernels.append({"name": name, "textures": names("textures"), "in": names("inBuffers"),
                        "out": names("outBuffers"), "tgs": tgs, "code": code})
    params = {}
    for m in re.finditer(r"- name: (\S+)\n\s+type: (\d+)\n\s+offset: \d+\n\s+arraySize: (\d+)\n\s+rowCount: (\d+)\n\s+colCount: (\d+)", variant):
        name, typ, arr, rows, cols = m.group(1), int(m.group(2)), int(m.group(3)), int(m.group(4)), int(m.group(5))
        t = PARAM_TYPE.get(typ, "float") + (f"{rows}x{cols}" if rows > 1 else str(cols) if cols > 1 else "")
        params[name] = t + " " + name + (f"[{arr}]" if arr else "")
    return kernels, params


def skel(asset, out):
    text = open(asset, encoding="utf-8").read()
    kernels, params = parse(text)
    lines = [f"// Recovered from {os.path.basename(asset)} by udk.computeshader: declarations are exact, kernel bodies",
             "// are translated from the DXBC disassembly under each one."]
    lines += [f"#pragma kernel {k['name']}" for k in kernels]
    lines.append("")
    lines += [p + ";" for p in params.values()]
    textures = sorted({t for k in kernels for t in k["textures"]})
    buffers = sorted({b for k in kernels for b in k["out"]})
    inbuf = sorted({b for k in kernels for b in k["in"]})
    lines += [f"Texture2D {t}; // check dimension against dcl_resource" for t in textures]
    lines += [f"StructuredBuffer<float> {b}; // check stride against dcl_resource_structured" for b in inbuf]
    lines += [f"RWStructuredBuffer<float> {b}; // check stride against dcl_uav_structured" for b in buffers]
    for k in kernels:
        lines += ["", "/*", disassemble(k["code"]), "*/", f"[numthreads({k['tgs'][0]}, {k['tgs'][1]}, {k['tgs'][2]})]",
                  f"void {k['name']}(uint3 id : SV_DispatchThreadID)", "{", "}"]
    open(out, "w", encoding="utf-8", newline="\n").write("\n".join(lines) + "\n")
    print(f"computeshader: {len(kernels)} kernels, {len(params)} params -> {out}")


def compile_kernel(source, kernel):
    d3d = ctypes.WinDLL("d3dcompiler_47.dll")
    src = source.replace("#pragma kernel", "// kernel").encode()
    code, err = ctypes.c_void_p(), ctypes.c_void_p()
    hr = d3d.D3DCompile(src, len(src), None, None, None, kernel.encode(), b"cs_5_0", 0, 0,
                        ctypes.byref(code), ctypes.byref(err))
    blob = code if hr == 0 else err
    vt = ctypes.cast(ctypes.cast(blob, ctypes.POINTER(ctypes.c_void_p))[0], ctypes.POINTER(ctypes.c_void_p))
    data = ctypes.string_at(ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p)(vt[3])(blob),
                            ctypes.CFUNCTYPE(ctypes.c_size_t, ctypes.c_void_p)(vt[4])(blob))
    return (data, None) if hr == 0 else (None, data.decode(errors="replace"))


def check(asset, done):
    """Compile each kernel of the translation with fxc (cs_5_0) and diff its disassembly against the shipped DXBC.
    Identical instruction lists mean the body is the original up to names and formatting."""
    kernels, _ = parse(open(asset, encoding="utf-8").read())
    source = open(done, encoding="utf-8").read()
    same = 0
    for k in kernels:
        code, err = compile_kernel(source, k["name"])
        if err:
            print(f"{k['name']}: compile error\n{err}")
            continue
        a, b = disassemble(k["code"]).splitlines(), disassemble(code).splitlines()
        if a == b:
            same += 1
            print(f"{k['name']}: identical ({len(a)} instructions)")
        else:
            import difflib
            print(f"{k['name']}: differs\n" + "\n".join(difflib.unified_diff(a, b, "shipped", "translation", lineterm="")))
    print(f"computeshader check: {same}/{len(kernels)} kernels identical to the shipped DXBC")


def install(asset, done, moved):
    guid = re.search(r"^guid: (\S+)", open(asset + ".meta", encoding="utf-8").read(), re.M).group(1)
    dst = os.path.splitext(asset)[0] + ".compute"
    os.makedirs(moved, exist_ok=True)
    for ext in ("", ".meta"):
        shutil.move(asset + ext, os.path.join(moved, os.path.basename(asset) + ext))
    shutil.copyfile(done, dst)
    # Main object of an imported compute shader is fileID 7200000, as in the exported .asset, so references hold.
    open(dst + ".meta", "w", encoding="utf-8", newline="\n").write(
        f"fileFormatVersion: 2\nguid: {guid}\nComputeShaderImporter:\n  externalObjects: {{}}\n  preprocessorOverride: 0\n"
        "  userData: \n  assetBundleName: \n  assetBundleVariant: \n")
    # A reference to a native .asset says type: 2, to an imported file type: 3.
    assets_dir = asset[:asset.replace("\\", "/").rfind("/Assets/") + 7]
    old, new, n = f"guid: {guid}, type: 2", f"guid: {guid}, type: 3", 0
    for dirpath, _, files in os.walk(assets_dir):
        for f in files:
            if f.endswith((".unity", ".prefab", ".asset", ".mat")):
                p = os.path.join(dirpath, f)
                text = open(p, encoding="utf-8", errors="replace").read()
                if old in text:
                    open(p, "w", encoding="utf-8", newline="").write(text.replace(old, new))
                    n += 1
    print(f"computeshader: {asset} -> {dst} (guid {guid}); {n} referencing files updated")


if __name__ == "__main__":
    if sys.argv[1] == "skel":
        skel(sys.argv[2], sys.argv[3])
    elif sys.argv[1] == "check":
        check(sys.argv[2], sys.argv[3])
    elif sys.argv[1] == "install":
        install(sys.argv[2], sys.argv[3], sys.argv[4])
    else:
        sys.exit(f"unknown command '{sys.argv[1]}'")
