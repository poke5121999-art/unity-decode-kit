"""Runtime facts: generate a Frida script that logs chosen methods with the fields of `this`.

  udk trace <method regex> [...] -o trace.js [--log path.jsonl]

Each hook records time, method, call depth and, after the call returns, every primitive field
of the receiver (offsets from types.cs), so a log line reads like
{"t": 12.41, "m": "PlayerUnit.TakeDamage", "this": {"_hp": 73, "_isDead": false}}.
The same script runs on Windows (`frida -f "Game.exe" -l trace.js`) and under wine on Linux
(LD_PRELOAD=frida-gadget.so with the gadget config udk writes next to the script).
"""
import csv
import json
import os
import re

KIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PRIM = {"int": "s32", "uint": "u32", "float": "float", "double": "double", "bool": "u8", "byte": "u8",
        "sbyte": "s8", "short": "s16", "ushort": "u16", "long": "s64", "ulong": "u64", "char": "u16",
        "string": "str"}
FIELD_RE = re.compile(r"^\s*(?:\[[^\]]*\]\s*)*(?:(?:public|private|protected|internal)\s+)*"
                      r"(static\s+|const\s+)?(?:readonly\s+)?([\w.<>,\[\] ]+?)\s+(\w+);\s*// 0x([0-9A-Fa-f]+)")
CLASS_RE = re.compile(r"^(?:\[.*\]\s*)?(?:public|internal|private|protected)?[\w ]*\b(class|struct) (\w+)(?:<[^>]*>)?(?:\s*:\s*([\w.]+))?")
ENUM_RE = re.compile(r"\benum (\w+)\b")
csv.field_size_limit(1 << 30)


class TypeTable:
    """Instance fields per class name, parsed once from types.cs."""

    def __init__(self, types_cs):
        self.fields, self.base, self.enums = {}, {}, set()
        cur = None
        with open(types_cs, encoding="utf-8") as fh:
            for line in fh:
                s = line.strip()
                m = CLASS_RE.match(s)
                if m and not s.endswith(";"):
                    cur = m.group(2)
                    self.fields.setdefault(cur, [])
                    if m.group(3):
                        self.base[cur] = m.group(3).split(".")[-1]
                    continue
                e = ENUM_RE.search(s)
                if e and not s.endswith(";") and "(" not in s:
                    self.enums.add(e.group(1))
                    cur = None
                    continue
                if cur:
                    f = FIELD_RE.match(line)
                    if f and not f.group(1):
                        self.fields[cur].append((f.group(3), int(f.group(4), 16), f.group(2).split(".")[-1]))

    def instance_fields(self, cls, depth=0):
        out = []
        if depth < 8 and cls in self.base:
            out += self.instance_fields(self.base[cls], depth + 1)
        for name, off, t in self.fields.get(cls, []):
            kind = PRIM.get(t) or ("s32" if t in self.enums else None)
            if kind:
                out.append([name, off, kind])
        return out


def pick_methods(root, patterns):
    rxs = [re.compile(p) for p in patterns]
    with open(os.path.join(root, "code", "methods.tsv"), encoding="utf-8") as fh:
        for m in csv.DictReader(fh, delimiter="\t"):
            cls = m["file"].rsplit("/", 1)[-1][:-2].split("+")[-1]
            name = cls + "." + m["signature"].split("(")[0].split()[-1]
            if any(r.search(name) for r in rxs):
                yield name, cls, int(m["address"], 16)


JS = r"""
const HOOKS = __HOOKS__;
const IMAGE_BASE = ptr('__IMAGE_BASE__');
const LOG = '__LOG__';
const t0 = Date.now();
let out = null;
function emit(o) {
  const line = JSON.stringify(o);
  if (LOG) { if (!out) out = new File(LOG, 'a'); out.write(line + '\n'); out.flush(); } else { send(o); }
}
function readStr(p) {
  if (p.isNull()) return null;
  const n = p.add(0x10).readS32();
  return n >= 0 && n < 4096 ? p.add(0x14).readUtf16String(n) : null;
}
function readField(base, off, kind) {
  const a = base.add(off);
  switch (kind) {
    case 'str': return readStr(a.readPointer());
    case 'float': return a.readFloat();
    case 'double': return a.readDouble();
    case 'u8': return a.readU8();
    case 's8': return a.readS8();
    case 's16': return a.readS16();
    case 'u16': return a.readU16();
    case 's32': return a.readS32();
    case 'u32': return a.readU32();
    case 's64': return a.readS64().toNumber();
    case 'u64': return a.readU64().toNumber();
  }
}
function snapshot(self, fields) {
  const o = {};
  if (self.isNull()) return o;
  for (const [name, off, kind] of fields) { try { o[name] = readField(self, off, kind); } catch (e) {} }
  return o;
}
function gameAssemblyBase() {
  const m = Process.findModuleByName('GameAssembly.dll') || Process.findModuleByName('libil2cpp.so');
  if (m) return m.base;
  for (const r of Process.enumerateRanges('r--')) {
    if (r.file && /gameassembly\.dll$/i.test(r.file.path) && r.file.offset === 0) return r.base;
  }
  return null;
}
function install(base) {
  let depth = 0;
  for (const h of HOOKS) {
    const addr = base.add(ptr(h.addr).sub(IMAGE_BASE));
    try {
      Interceptor.attach(addr, {
        onEnter() { this.self = Process.arch === 'x64' ? (Process.platform === 'windows' || h.winabi ? this.context.rcx : this.context.rdi) : this.context.r0; depth++; },
        onLeave() { depth--; emit({ t: (Date.now() - t0) / 1000, m: h.name, d: depth, this: snapshot(this.self, h.fields) }); }
      });
    } catch (e) { emit({ t: 0, m: h.name, error: String(e) }); }
  }
  emit({ t: (Date.now() - t0) / 1000, m: '<installed>', hooks: HOOKS.length, base: base.toString() });
}
const timer = setInterval(() => { const b = gameAssemblyBase(); if (b) { clearInterval(timer); install(b); } }, 200);
"""


def generate(root, patterns, out_js, log_path=None, image_base=0x180000000, winabi=True, limit=400):
    tt = TypeTable(os.path.join(root, "code", "types.cs"))
    hooks = []
    for name, cls, addr in pick_methods(root, patterns):
        hooks.append({"name": name, "addr": hex(addr), "fields": tt.instance_fields(cls), "winabi": winabi})
        if len(hooks) >= limit:
            break
    js = (JS.replace("__HOOKS__", json.dumps(hooks)).replace("__IMAGE_BASE__", hex(image_base))
          .replace("__LOG__", log_path or ""))
    with open(out_js, "w", encoding="utf-8") as fh:
        fh.write(js)
    cfg = os.path.splitext(out_js)[0] + ".gadget.config"
    with open(cfg, "w", encoding="utf-8") as fh:
        json.dump({"interaction": {"type": "script", "path": os.path.abspath(out_js)}}, fh)
    return hooks, cfg
