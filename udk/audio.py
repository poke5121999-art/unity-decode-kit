"""Wwise audio: banks -> named events -> the sounds each event plays.

wwiser (bnnm) parses every .bnk together and writes a TXTP per event; vgmstream renders a TXTP
to WAV and ffmpeg compresses it. Wwise stores only FNV-1 hashes of names, so the names come from
the game itself: every identifier-like word in the code's string literals and the decoded data
(Lua, tables) goes into wwnames.txt, and wwiser keeps the ones whose hash matches.
Output: audio/banks/banks.txt (bank dumps), audio/txtp/<event>.txtp (play with vgmstream),
audio/wem/<wem id>.ogg (every embedded sound), audio/events.tsv (event -> banks, wem ids, seconds).
"""
import glob
import os
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor

KIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WWISER = os.path.join(KIT, "third_party", "wwiser", "wwiser.pyz")
VGM = os.path.join(KIT, "third_party", "vgmstream", "vgmstream-cli")
PY = os.path.join(KIT, ".venv", "bin", "python")
WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_]{2,63}")


def find_banks(roots):
    out = []
    for root in roots:
        for ext in ("bnk", "wem", "pck", "bnk.bytes", "wem.bytes", "pck.bytes"):
            out += glob.glob(os.path.join(root, "**", f"*.{ext}"), recursive=True)
    return out


def names(literals, text_dirs):
    words = set()
    for s in literals:
        words.update(WORD.findall(s))
    for d in text_dirs:
        for p in glob.glob(os.path.join(d, "**", "*"), recursive=True):
            if p.endswith((".lua", ".csv", ".json", ".txt", ".xml", ".tsv", ".asset", ".prefab")) and os.path.isfile(p):
                with open(p, encoding="utf-8", errors="replace") as fh:
                    words.update(WORD.findall(fh.read()))
    return sorted(words)


def run(out, roots, literals, text_dirs, workers=4):
    adir = os.path.join(out, "audio")
    bdir = os.path.join(adir, "banks")
    os.makedirs(bdir, exist_ok=True)
    files = find_banks(roots)
    if not files:
        return 0, 0
    for f in files:
        dst = os.path.join(bdir, os.path.basename(f).removesuffix(".bytes"))
        if not os.path.exists(dst):
            os.symlink(os.path.abspath(f), dst)
    with open(os.path.join(bdir, "wwnames.txt"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(names(literals, text_dirs)))
    banks = sorted(os.path.basename(f).removesuffix(".bytes") for f in files if f.endswith((".bnk", ".bnk.bytes")))
    subprocess.run([PY, WWISER, "-d", "txt", "-dn", "banks", "-g", "-go", "../txtp", "-gw", "../banks/"] + banks,
                   cwd=bdir, capture_output=True, timeout=3600)
    tdir = os.path.join(adir, "txtp")
    wdir = os.path.join(adir, "wem")
    os.makedirs(wdir, exist_ok=True)
    durations = {}

    def bank_media(bank):
        # Every embedded wem of a bank, named by its id; state-muted TXTP branches would hide some.
        r = subprocess.run([VGM, "-S", "0", "-o", os.path.join(wdir, "?n.wav"), os.path.join(bdir, bank)],
                           capture_output=True, text=True, timeout=1800)
        return r.stdout

    with ThreadPoolExecutor(workers) as ex:
        list(ex.map(bank_media, banks))
    def to_ogg(wav):
        r = subprocess.run(["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", wav],
                           capture_output=True, text=True)
        subprocess.run(["ffmpeg", "-loglevel", "error", "-y", "-i", wav, "-c:a", "libvorbis", "-q:a", "4",
                        wav[:-4] + ".ogg"], timeout=600)
        os.remove(wav)
        return os.path.basename(wav)[:-4], r.stdout.strip()

    with ThreadPoolExecutor(workers) as ex:
        durations.update(ex.map(to_ogg, glob.glob(os.path.join(wdir, "*.wav"))))
    with open(os.path.join(adir, "events.tsv"), "w", encoding="utf-8") as fh:
        fh.write("event\tbanks\twems\twem_seconds\n")
        n = 0
        for t in sorted(glob.glob(os.path.join(tdir, "*.txtp"))):
            text = open(t, encoding="utf-8", errors="replace").read()
            name = re.sub(r" \{[^}]*\}", "", os.path.splitext(os.path.basename(t))[0])
            wems = list(dict.fromkeys(re.findall(r"##(\d+)\.wem", text)))
            bnks = sorted(set(re.findall(r"([^/\s?]+)\.bnk", text)))
            fh.write(f"{name}\t{','.join(bnks)}\t{','.join(wems)}\t{','.join(durations.get(w, '?') for w in wems)}\n")
            n += 1
    return len(banks), len(durations)
