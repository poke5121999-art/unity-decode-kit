"""Name the C runtime math functions a stripped IL2CPP binary calls (Ghidra shows them as FUN_xxx with no args).

Each unnamed callee of the game's methods runs in a CPU emulator on sample inputs, once as float(float[,float])
and once as double(double[,double]); a callee whose outputs match a libm function on every input gets its name.
Writes mathnames.json {"0x...": "sinf"} for recompile.Context to annotate the decompilation it shows a translator.

Usage: python -m udk.mathnames <config.json>
"""
import json
import math
import re
import struct
import sys

import pefile
from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_64, UC_PROT_ALL
from unicorn.x86_const import UC_X86_REG_RIP, UC_X86_REG_RSP, UC_X86_REG_XMM0, UC_X86_REG_XMM1

from .recompile import Game, jsonl

ONE = {"sin": math.sin, "cos": math.cos, "tan": math.tan, "asin": math.asin, "acos": math.acos, "atan": math.atan,
       "exp": math.exp, "log": math.log, "log10": math.log10, "log2": math.log2, "sqrt": math.sqrt,
       "floor": math.floor, "ceil": math.ceil, "fabs": math.fabs, "sinh": math.sinh, "cosh": math.cosh,
       "tanh": math.tanh, "exp2": lambda x: 2.0 ** x, "round": lambda x: math.floor(x + 0.5) if x >= 0 else -math.floor(-x + 0.5)}
TWO = {"atan2": math.atan2, "pow": math.pow, "fmod": math.fmod, "hypot": math.hypot}
XS = [0.3, 0.7, 0.9, 1.7, 2.5, 10.25]
YS = [(0.3, 0.7), (1.7, 2.0), (2.5, 0.9), (10.25, 3.0), (0.9, 1.7)]
SENTINEL = 0x70000000
STACK = 0x7FF00000


def f32(x):
    return struct.unpack("<f", struct.pack("<f", x))[0]


class Emu:
    def __init__(self, binary):
        pe = pefile.PE(binary, fast_load=True)
        base = pe.OPTIONAL_HEADER.ImageBase
        self.uc = Uc(UC_ARCH_X86, UC_MODE_64)
        size = (pe.OPTIONAL_HEADER.SizeOfImage + 0xFFF) & ~0xFFF
        self.uc.mem_map(base, size, UC_PROT_ALL)
        for s in pe.sections:
            data = s.get_data()
            self.uc.mem_write(base + s.VirtualAddress, data[:max(0, min(len(data), size - s.VirtualAddress))])
        self.uc.mem_map(STACK, 0x100000, UC_PROT_ALL)
        self.uc.mem_map(SENTINEL, 0x1000, UC_PROT_ALL)
        self.uc.mem_write(SENTINEL, b"\xf4")

    def call(self, addr, xmm, width):
        rsp = STACK + 0x80000
        self.uc.mem_write(rsp, struct.pack("<Q", SENTINEL))
        self.uc.reg_write(UC_X86_REG_RSP, rsp)
        for reg, v in zip((UC_X86_REG_XMM0, UC_X86_REG_XMM1), xmm):
            raw = struct.pack("<f", v) if width == 4 else struct.pack("<d", v)
            self.uc.reg_write(reg, int.from_bytes(raw.ljust(16, b"\0"), "little"))
        self.uc.emu_start(addr, SENTINEL, count=50000)
        if self.uc.reg_read(UC_X86_REG_RIP) != SENTINEL:
            return None
        out = self.uc.reg_read(UC_X86_REG_XMM0).to_bytes(16, "little")
        return struct.unpack("<f", out[:4])[0] if width == 4 else struct.unpack("<d", out[:8])[0]


def close(a, b, width):
    if a is None or b is None or math.isnan(a) or math.isnan(b):
        return False
    tol = 2e-6 if width == 4 else 1e-12
    return abs(a - b) <= tol * max(1.0, abs(b))


def identify(emu, addr):
    for width, suffix in ((4, "f"), (8, "")):
        conv = f32 if width == 4 else (lambda v: v)
        for name, fn in ONE.items():
            try:
                if all(close(emu.call(addr, [conv(x)], width), conv(fn(conv(x))), width) for x in XS):
                    return name + suffix
            except (UcError, ValueError, OverflowError):
                break
        for name, fn in TWO.items():
            try:
                if all(close(emu.call(addr, [conv(x), conv(y)], width), conv(fn(conv(x), conv(y))), width) for x, y in YS):
                    return name + suffix
            except (UcError, ValueError, OverflowError):
                break
    return None


def main(cfg_path):
    g = Game(cfg_path)
    targets = set()
    for r in jsonl(g.p("ghidra.jsonl")):
        for m in re.finditer(r"\b(?:FUN_|func_0x0*)([0-9a-f]{8,})\b", r["c"]):
            targets.add(int(m.group(1), 16))
    emu = Emu(g.cfg["binary"])
    names = {}
    for a in sorted(targets):
        try:
            n = identify(emu, a)
        except UcError:
            n = None
        if n:
            names[f"0x{a:x}"] = n
    g.p("mathnames.json").write_text(json.dumps(names, indent=1), encoding="utf-8")
    print(f"mathnames.json: {len(names)} of {len(targets)} unnamed callees identified: {sorted(set(names.values()))}")


if __name__ == "__main__":
    main(sys.argv[1])
