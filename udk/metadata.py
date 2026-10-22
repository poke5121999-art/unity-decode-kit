"""Repair an obfuscated global-metadata.dat before Il2CppInspector reads it.

Seen so far (Zing Speed, Unity 2019.4): magic and version scrambled, header XOR'd with one byte,
and bytes 0x1000-0x5000 of every 64 KB block XOR'd with the same byte. The repair is found, not
hardcoded:
  1. the header key is the byte that turns the header into ascending (offset, size) pairs that
     fit the file, the first offset being the header size;
  2. the block pattern is found by block_mask() from byte statistics;
  3. the magic is restored and the version set from the Unity version found in the build.
"""
import glob
import os
import re
import struct

MAGIC = 0xFAB11BAF
VERSION_BY_UNITY = [  # (first Unity version, metadata version); Il2CppInspector finds the sub-version
    ((2017, 1), 24), ((2018, 3), 24), ((2020, 2), 27), ((2021, 2), 29), ((2022, 3), 31),
    ((2023, 2), 31), ((6000, 2), 38), ((6000, 3), 39),
]
UNITY_RE = re.compile(rb"(20[12]\d|6000)\.(\d+)\.(\d+)[abfp]\d+")


def unity_version(game_dir):
    for pat in ("**/globalgamemanagers", "**/data.unity3d", "**/unity default resources", "**/*.unity3d", "**/level0"):
        for p in glob.glob(os.path.join(game_dir, pat), recursive=True)[:5]:
            with open(p, "rb") as fh:
                m = UNITY_RE.search(fh.read(4096))
            if m:
                return m.group(0).decode()
    return None


def metadata_version(unity):
    major, minor = (int(x) for x in unity.split(".")[:2])
    best = 24
    for (ma, mi), v in VERSION_BY_UNITY:
        if (major, minor) >= (ma, mi):
            best = v
    return best


def header_pairs(b, key):
    first = struct.unpack_from("<I", bytes(x ^ key for x in b[8:12]))[0]
    if not (64 <= first <= 2048 and first % 8 == 0):
        return None
    count = (first - 8) // 8
    h = bytes(x ^ key for x in b[8:first])
    pairs = [struct.unpack_from("<II", h, 8 * i) for i in range(count)]
    n = len(b)
    if any(o + s > n or (s and o < first) for o, s in pairs):
        return None
    nonempty = [o for o, s in pairs if s]
    if nonempty != sorted(nonempty):
        return None
    return pairs


GRAIN = 256


def block_mask(b, key):
    """Find which GRAIN-sized slots of a repeating period are XOR'd: int tables are mostly zero
    bytes, so a slot is XOR'd when the key byte outnumbers 0x00 there across the whole file.
    The period kept is the one that leaves the most zero bytes."""
    cells = [(b[i:i + GRAIN].count(0), b[i:i + GRAIN].count(key)) for i in range(0, len(b), GRAIN)]
    best = None
    for period in (1 << p for p in range(12, 21)):
        slots = period // GRAIN
        agg = [[0, 0] for _ in range(slots)]
        for i, (z, k) in enumerate(cells):
            agg[i % slots][0] += z
            agg[i % slots][1] += k
        mask = [k > z for z, k in agg]
        zeros = sum(max(z, k) for z, k in agg)
        if best is None or zeros > best[0] or (zeros == best[0] and period < best[1]):
            best = (zeros, period, mask)
    return best[1], best[2]


def repair(src, dst, game_dir):
    """Write a readable copy of src to dst. Returns a description of what was done."""
    b = bytearray(open(src, "rb").read())
    if struct.unpack_from("<I", b)[0] == MAGIC:
        return "plain"
    key = next((k for k in range(256) if header_pairs(b, k)), None)
    if key is None:
        raise ValueError(f"{src}: unknown metadata obfuscation (no single-byte header key)")
    pairs = header_pairs(b, key)
    first = pairs[0][0] if pairs[0][1] else 8 + 8 * len(pairs)
    table = bytes(x ^ key for x in range(256))
    period, mask = block_mask(b, key)
    for start in range(0, len(b), period):
        for j, on in enumerate(mask):
            lo = start + j * GRAIN
            if start == 0 and not on:
                # The first period is laid out differently (the region after the header, before
                # the first masked slot, is XOR'd too), so decide its cells one by one.
                lo = max(lo, first)
                cell = b[lo:start + (j + 1) * GRAIN]
                on = len(cell) > 0 and cell.count(key) > cell.count(0)
            if on:
                hi = start + (j + 1) * GRAIN
                b[lo:hi] = bytes(b[lo:hi]).translate(table)
    b[8:first] = bytes(b[8:first]).translate(table)
    xored = f"{sum(mask) * GRAIN} of every {period} bytes"
    unity = unity_version(game_dir) or "2019.4.0f1"
    version = metadata_version(unity)
    struct.pack_into("<Ii", b, 0, MAGIC, version)
    with open(dst, "wb") as fh:
        fh.write(b)
    return f"header xor 0x{key:02X}; blocks xor'd: {xored}; magic restored; version {version} (Unity {unity})"
