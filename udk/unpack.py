"""Turn a mobile package into a folder the rest of the kit can read.

  .xapk / .apks / .zip  ->  every inner .apk (and .ap asset pack) extracted to <dest>/<stem>/
  .apk                  ->  extracted to <dest>/<stem>/
  anything else         ->  left as is under <dest>/_outer/
Uses Python's zipfile: the system unzip on this host mangles some names (drops the last
character), which silently breaks paths like manifest.json.
"""
import os
import zipfile

INNER = (".apk", ".ap", ".obb")


def extract(zpath, dest):
    with zipfile.ZipFile(zpath) as z:
        z.extractall(dest)


def unpack(package, dest):
    os.makedirs(dest, exist_ok=True)
    done = os.path.join(dest, ".unpacked")
    if os.path.exists(done):
        return dest
    stem = os.path.splitext(os.path.basename(package))[0]
    if package.lower().endswith(".apk"):
        extract(package, os.path.join(dest, stem))
    else:
        tmp = os.path.join(dest, ".outer")
        extract(package, tmp)
        for d, _, files in os.walk(tmp):
            for f in files:
                p = os.path.join(d, f)
                if f.lower().endswith(INNER) and zipfile.is_zipfile(p):
                    extract(p, os.path.join(dest, os.path.splitext(f)[0]))
                    os.remove(p)
        os.rename(tmp, os.path.join(dest, "_outer"))
    open(done, "w").close()
    return dest

