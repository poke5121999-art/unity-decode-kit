"""Lua bytecode -> source with unluac, after undoing header tweaks some engines make.

Seen: xLua builds (Zing Speed) write Lua 5.3 chunks with format byte 1 and only four type-size
bytes (the Instruction size is dropped). normalize() finds the LUAC_INT marker to count the size
bytes and rebuilds a standard header; unluac does the rest.
"""
import glob
import os
import subprocess
from concurrent.futures import ThreadPoolExecutor

KIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UNLUAC = os.path.join(KIT, "third_party", "unluac.jar")
LUAC_DATA = b"\x19\x93\r\n\x1a\n"
LUAC_INT = (0x5678).to_bytes(8, "little")


def java():
    return glob.glob(os.path.join(KIT, "third_party", "jdk-25*", "bin", "java"))[0]


def normalize(b):
    """Return a chunk unluac accepts, or b unchanged when it is already standard."""
    if b[4] == 0x53 and b[6:12] == LUAC_DATA:
        marker = b.find(LUAC_INT, 12, 24)
        sizes = b[12:marker]
        if len(sizes) == 4:  # int, size_t, lua_Integer, lua_Number: Instruction size missing
            sizes = sizes[:2] + b"\x04" + sizes[2:]
        return b[:5] + b"\x00" + LUAC_DATA + sizes + b[marker:]
    return b


def decompile_files(paths, workers=6):
    """Write <path minus .luac>.lua next to each bytecode file. Returns (ok, failed) counts."""
    jv = java()

    def one(p):
        src = p[:-5] if p.endswith(".luac") else p
        fixed = src + ".norm.luac"
        with open(p, "rb") as fh:
            data = normalize(fh.read())
        with open(fixed, "wb") as fh:
            fh.write(data)
        r = subprocess.run([jv, "-jar", UNLUAC, fixed], capture_output=True, timeout=300)
        os.remove(fixed)
        if r.returncode == 0:  # an empty chunk decompiles to empty output
            with open(src + ".lua", "wb") as fh:
                fh.write(r.stdout)
            return True
        with open(src + ".lua.error", "wb") as fh:
            fh.write(r.stderr[-2000:])
        return False

    with ThreadPoolExecutor(workers) as ex:
        res = list(ex.map(one, paths))
    return sum(res), len(res) - sum(res)
