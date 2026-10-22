"""Turn an AssetRipper export into a project for a newer Unity editor (e.g. 2019.4 -> 6000.3).

AssetRipper writes every managed assembly as script stubs, Unity's own packages included
(UnityEngine.UI, Unity.TextMeshPro, Unity.Timeline...). Stubs have no method bodies, so those
assemblies are swapped for the real packages the target editor ships with, and every scene,
prefab and asset that pointed at a stub script is repointed to the package script with the same
namespace and class name. What changed is written to <project>/UpgradeReport.tsv.

Package sources: <editor>/Data/Resources/PackageManager/BuiltInPackages/<name>/ (folders) and
<editor>/Data/Resources/PackageManager/Editor/<name>-<version>.tgz; versions and deprecations
from <editor>/Data/Resources/PackageManager/Editor/manifest.json.
"""
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile

NAMESPACE = re.compile(rb"^\s*namespace\s+([\w.]+)", re.M)
GUID = re.compile(r"^guid:\s*([0-9a-f]{32})", re.M)
YAML_EXT = {".unity", ".prefab", ".asset", ".mat", ".controller", ".overrideController", ".anim", ".playable",
            ".mask", ".signal", ".lighting", ".spriteatlas", ".guiskin", ".fontsettings", ".physicMaterial",
            ".physicsMaterial2D", ".renderTexture", ".cubemap", ".flare", ".preset", ".mixer", ".shadervariants"}


def editor_root(version):
    return os.path.expanduser(f"~/Unity/Hub/Editor/{version}/Editor")


class Package:
    """One package the editor ships: its name, version and a way to read its files."""

    def __init__(self, name, version, folder=None, tgz=None):
        self.name, self.version, self.folder, self.tgz = name, version, folder, tgz

    def files(self):
        """(relative path, bytes) for every .cs, .cs.meta and .asmdef file."""
        want = (".cs", ".cs.meta", ".asmdef")
        if self.folder:
            for d, _, fs in os.walk(self.folder):
                for f in fs:
                    if f.endswith(want):
                        p = os.path.join(d, f)
                        with open(p, "rb") as fh:
                            yield os.path.relpath(p, self.folder), fh.read()
        else:
            with tarfile.open(self.tgz) as t:
                for m in t.getmembers():
                    if m.isfile() and m.name.endswith(want):
                        yield m.name.split("/", 1)[1], t.extractfile(m).read()


def editor_packages(editor):
    """name -> Package for every package the editor carries, plus the editor manifest rules."""
    pm = os.path.join(editor, "Data", "Resources", "PackageManager")
    with open(os.path.join(pm, "Editor", "manifest.json"), encoding="utf-8") as fh:
        rules = json.load(fh)["packages"]
    pkgs = {}
    for d in glob.glob(os.path.join(pm, "BuiltInPackages", "*")):
        pj = os.path.join(d, "package.json")
        if os.path.isfile(pj):
            with open(pj, encoding="utf-8") as fh:
                meta = json.load(fh)
            pkgs[meta["name"]] = Package(meta["name"], meta["version"], folder=d)
    for t in glob.glob(os.path.join(pm, "Editor", "*.tgz")):
        name, version = re.match(r"(.+)-(\d[^-]*(?:-[\w.]+)?)\.tgz$", os.path.basename(t)).groups()
        pkgs.setdefault(name, Package(name, version, tgz=t))
    return pkgs, rules


def runtime_assemblies(pkg):
    """asmdef name -> {(namespace, class): script guid} for the package's non-test, non-editor code."""
    files = dict(pkg.files())
    asm_dirs = {}
    for rel, raw in files.items():
        if rel.endswith(".asmdef") and "Tests" not in rel and "Samples~" not in rel:
            meta = json.loads(raw.decode("utf-8-sig"))
            if meta.get("includePlatforms") == ["Editor"]:
                continue
            asm_dirs[os.path.dirname(rel)] = meta["name"]
    out = {}
    for rel, raw in files.items():
        if not rel.endswith(".cs"):
            continue
        owner = max((d for d in asm_dirs if rel.startswith(d + "/") or d == ""), key=len, default=None)
        if owner is None:
            continue
        meta = files.get(rel + ".meta")
        if not meta:
            continue
        g = GUID.search(meta.decode("utf-8", "replace"))
        ns = NAMESPACE.search(raw)
        key = (ns.group(1).decode() if ns else "", os.path.splitext(os.path.basename(rel))[0])
        if g:
            out.setdefault(asm_dirs[owner], {})[key] = g.group(1)
    return out


def exported_scripts(asm_dir):
    """{(namespace, class): guid} for an exported assembly folder."""
    out = {}
    for p in glob.glob(os.path.join(asm_dir, "**", "*.cs"), recursive=True):
        meta = p + ".meta"
        if not os.path.exists(meta):
            continue
        with open(meta, encoding="utf-8", errors="replace") as fh:
            g = GUID.search(fh.read())
        with open(p, "rb") as fh:
            ns = NAMESPACE.search(fh.read())
        if g:
            out[(ns.group(1).decode() if ns else "", os.path.splitext(os.path.basename(p))[0])] = g.group(1)
    return out


def plan(export, editor):
    """Which exported assemblies become packages, and the script guid remap that goes with it."""
    pkgs, rules = editor_packages(editor)
    by_asm = {}
    for pkg in pkgs.values():
        if rules.get(pkg.name, {}).get("deprecated"):
            continue
        for asm, scripts in runtime_assemblies(pkg).items():
            by_asm.setdefault(asm, (pkg, scripts))
    scripts_root = os.path.join(export, "Assets", "Scripts")
    swaps, remap, missing = [], {}, []
    for asm in sorted(os.listdir(scripts_root)) if os.path.isdir(scripts_root) else []:
        if asm not in by_asm:
            continue
        pkg, new = by_asm[asm]
        old = exported_scripts(os.path.join(scripts_root, asm))
        hit = 0
        for key, g in old.items():
            if key in new:
                remap[g] = new[key]
                hit += 1
            else:
                missing.append((asm, ".".join(filter(None, key))))
        swaps.append((asm, pkg.name, pkg.version, hit, len(old)))
    return swaps, remap, missing, pkgs, rules


def write_manifest(export, project, swaps, pkgs, rules):
    """Keep built-in modules, add the packages that replace exported assemblies, drop the rest."""
    src = os.path.join(export, "Packages", "manifest.json")
    deps = {}
    if os.path.exists(src):
        with open(src, encoding="utf-8") as fh:
            deps = json.load(fh).get("dependencies", {})
    rows = []
    out = {}
    for name, ver in deps.items():
        r = rules.get(name, {})
        if r.get("deprecated") or r.get("removeOnProjectUpgrade"):
            rows.append(("package-dropped", name, f"{ver}: {r.get('deprecated', 'removed on upgrade')[:120]}"))
        elif name in pkgs:
            out[name] = pkgs[name].version
            if pkgs[name].version != ver:
                rows.append(("package-bumped", name, f"{ver} -> {pkgs[name].version}"))
        elif name.startswith("com.unity.modules."):
            out[name] = "1.0.0"
        else:
            out[name] = ver
    for _, name, version, _, _ in swaps:
        if name not in out:
            out[name] = version
            rows.append(("package-added", name, version))
    os.makedirs(os.path.join(project, "Packages"), exist_ok=True)
    with open(os.path.join(project, "Packages", "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump({"dependencies": dict(sorted(out.items()))}, fh, indent=2)
    return rows


def remap_guids(root, remap):
    """Rewrite script guids in every text YAML file under root. Returns files changed."""
    if not remap:
        return 0
    pat = re.compile(r"guid: (" + "|".join(remap) + r")\b")
    changed = 0
    for d, _, fs in os.walk(root):
        for f in fs:
            if os.path.splitext(f)[1] not in YAML_EXT:
                continue
            p = os.path.join(d, f)
            with open(p, "rb") as fh:
                head = fh.read(5)
                if head != b"%YAML":
                    continue
                text = head.decode() + fh.read().decode("utf-8", "replace")
            new, n = pat.subn(lambda m: "guid: " + remap[m.group(1)], text)
            if n:
                with open(p, "w", encoding="utf-8") as fh:
                    fh.write(new)
                changed += 1
    return changed


def upgrade(export, project, version):
    """Copy the export into project, upgraded for editor `version`. Returns report rows."""
    editor = editor_root(version)
    swaps, remap, missing, pkgs, rules = plan(export, editor)
    replaced = {asm for asm, *_ in swaps}
    if os.path.isdir(project):
        for x in ("Assets", "Packages", "ProjectSettings"):
            shutil.rmtree(os.path.join(project, x), ignore_errors=True)
    os.makedirs(project, exist_ok=True)

    def skip(d, names):
        if os.path.normpath(d) == os.path.normpath(os.path.join(export, "Assets", "Scripts")):
            return [n for n in names if n in replaced or n in (r + ".meta" for r in replaced)]
        return []

    shutil.copytree(os.path.join(export, "Assets"), os.path.join(project, "Assets"), ignore=skip)
    shutil.copytree(os.path.join(export, "ProjectSettings"), os.path.join(project, "ProjectSettings"))
    with open(os.path.join(project, "ProjectSettings", "ProjectVersion.txt"), "w") as fh:
        fh.write(f"m_EditorVersion: {version}\n")
    rows = [("assembly-to-package", asm, f"{name} {ver}: {hit}/{total} scripts remapped")
            for asm, name, ver, hit, total in swaps]
    rows += [("script-not-in-package", asm, cls) for asm, cls in missing]
    rows += write_manifest(export, project, swaps, pkgs, rules)
    rows.append(("guid-remap", "files", str(remap_guids(os.path.join(project, "Assets"), remap))))
    with open(os.path.join(project, "UpgradeReport.tsv"), "w", encoding="utf-8") as fh:
        fh.write("kind\tsubject\tdetail\n")
        for r in rows:
            fh.write("\t".join(r) + "\n")
    return rows


def compile_errors(log):
    """Distinct compiler errors in an editor log, as (file, code, message)."""
    seen = []
    with open(log, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = re.match(r"(.+?)\(\d+,\d+\): error (CS\d+): (.*)", line.strip())
            if m and m.groups() not in seen:
                seen.append(m.groups())
    return seen


def import_project(project, version, log, timeout=7200, min_free_gb=10):
    """Open the project once in batchmode so Unity imports assets, runs the API updater and compiles."""
    unity = os.path.join(editor_root(version), "Unity")
    cmd = [unity, "-batchmode", "-nographics", "-quit", "-accept-apiupdate", "-projectPath", project, "-logFile", log]
    queue = os.path.expanduser("~/handoff/heavy.sh")
    if os.path.exists(queue):
        cmd = ["sh", queue, str(timeout), str(min_free_gb)] + cmd
    subprocess.run(cmd, timeout=timeout + 600)
    return compile_errors(log)


if __name__ == "__main__":
    export, project, version = sys.argv[1:4]
    for r in upgrade(export, project, version):
        if r[0] != "script-not-in-package":
            print("\t".join(r))
