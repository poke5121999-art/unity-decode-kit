"""Havok binary tagfiles (magic 0xCAB00D1E 0xD011FACE, format version 5 as written by hk_2014.2.0-r1).

parse(data)  -> HkFile: the type table (class, version, parent, members with types) and the objects.
meshes(data) -> triangle meshes [{"name", "class", "vertices": [(x, y, z)], "triangles": [(a, b, c)], ...}]
               from the collision shapes found. Vertices are in shape space, which is world space
               when the file holds a bare shape (no rigid body), as the Zing Speed NssHKXData files do.
Usage: python -m udk.havok <in.json|in.bin> <out.obj>
       (.json: a ScriptableObject export with fields.HKXData as a hex string; anything else is raw bytes)

Stream layout, as observed in these files (field names and type codes are the file's own):
  * Integers are variable length: byte 0 holds the sign in bit 0, 6 value bits in bits 1-6 and a
    continuation flag in bit 7; each further byte adds 7 value bits. Sign-magnitude, so a uint32 or
    uint64 field written from a negative value is read back by masking.
  * Strings: a length > 0 is followed by that many bytes and appends the string to a table; a
    length <= 0 refers to table entry -length. The table starts as ["", None].
  * Tags: 1 file info (version, SDK string, 4 unknown bytes), 2 class metadata, 3 object,
    4 object kept for back references, 5 back reference, 6 null object, 7 end of file.
  * Metadata: name, version, parent class index (0 = none), member count, then per member a name,
    a type code (low nibble: 0 void, 1 byte, 2 int, 3 real, 4 vec4, 5 vec8, 6 vec12, 7 vec16,
    8 object, 9 struct, 10 cstring; 0x10 array, 0x20 tuple), a tuple size if 0x20, a class name if
    object or struct.
  * An object is its class index, then a bitmap (LSB first, one bit per member including inherited
    and void members) of the members present, then each present non-void member.
  * Arrays are a count followed by the elements. Inside an array an int column is preceded by its
    width in bytes (4 or 8, the values stay variable length) and a vecN column by the number of
    floats written per vector. An array of structs is written by column: one presence bitmap for
    the struct, then every present member for all elements in turn (nested structs recurse the same
    way; nested arrays are written whole, element by element).
Read but not exercised by any file seen so far: object references, cstrings, byte arrays outside
tuples, vectors outside arrays of structs. Those code paths follow the same rules and may be wrong.
"""
import json
import struct
import sys

MAGIC = b"\x1e\x0d\xb0\xca\xce\xfa\x11\xd0"
TAG_FILE_INFO, TAG_METADATA, TAG_OBJECT, TAG_OBJECT_REMEMBER, TAG_BACKREF, TAG_NULL, TAG_END = 1, 2, 3, 4, 5, 6, 7
BASE = {0: "void", 1: "byte", 2: "int", 3: "real", 4: "vec4", 5: "vec8", 6: "vec12", 7: "vec16",
        8: "object", 9: "struct", 10: "cstring"}
VEC_WIDTH = {4: 4, 5: 8, 6: 12, 7: 16}
ARRAY, TUPLE = 0x10, 0x20


class HkType:
    def __init__(self, name, version, parent, members):
        self.name, self.version, self.parent, self.members = name, version, parent, members

    def __repr__(self):
        return "HkType(%s v%d : %s, %s)" % (self.name, self.version, self.parent.name if self.parent else "-",
                                            ", ".join("%s %s" % (type_name(t, n, c), m) for m, t, n, c in self.members))

    def all_members(self):
        return (self.parent.all_members() if self.parent else []) + self.members

    def is_a(self, name):
        return self.name == name or (self.parent is not None and self.parent.is_a(name))


def type_name(code, tup, cls):
    s = BASE.get(code & 0xF, "?%d" % (code & 0xF))
    if cls:
        s += " " + cls
    if code & TUPLE:
        s = "%s[%d]" % (s, tup)
    if code & ARRAY:
        s = "array<%s>" % s
    return s


class HkFile:
    def __init__(self):
        self.version = None
        self.sdk = None
        self.header_extra = None
        self.types = []      # HkType, in file order
        self.objects = []    # top-level objects, dicts with "_class"

    def type(self, name):
        return next((t for t in self.types if t.name == name), None)


class Reader:
    def __init__(self, data):
        if data[:8] != MAGIC:
            raise ValueError("no Havok binary tagfile magic: got %s" % data[:8].hex())
        self.b, self.p = data, 8
        self.strings = ["", None]
        self.classes = [None]
        self.remembered = []
        self.f = HkFile()

    def int(self):
        b, p = self.b, self.p
        c = b[p]
        p += 1
        v, sh = (c >> 1) & 0x3F, 6
        neg = c & 1
        while c & 0x80:
            c = b[p]
            p += 1
            v |= (c & 0x7F) << sh
            sh += 7
        self.p = p
        return -v if neg else v

    def string(self):
        n = self.int()
        if n <= 0:
            return self.strings[-n]
        s = self.b[self.p:self.p + n].decode("utf-8", "replace")
        self.p += n
        self.strings.append(s)
        return s

    def bitmap(self, n):
        nb = (n + 7) // 8
        bits = int.from_bytes(self.b[self.p:self.p + nb], "little")
        self.p += nb
        return [(bits >> i) & 1 for i in range(n)]

    def metadata(self):
        name, version, parent, count = self.string(), self.int(), self.int(), self.int()
        members = []
        for _ in range(count):
            mname, code = self.string(), self.int()
            tup = self.int() if code & TUPLE else 0
            cls = self.string() if code & 0xF in (8, 9) else None
            members.append((mname, code, tup, cls))
        t = HkType(name, version, self.classes[parent], members)
        self.classes.append(t)
        self.f.types.append(t)

    def type_by_name(self, name):
        for t in self.classes[1:]:
            if t.name == name:
                return t
        raise ValueError("class %r used at offset 0x%x has no metadata" % (name, self.p))

    def object_ref(self):
        tag = self.int()
        if tag == TAG_NULL:
            return None
        if tag == TAG_BACKREF:
            return self.remembered[self.int()]
        if tag in (TAG_OBJECT, TAG_OBJECT_REMEMBER):
            return self.object(tag)
        raise ValueError("object reference with tag %d at offset 0x%x" % (tag, self.p))

    def object(self, tag):
        t = self.classes[self.int()]
        o = {"_class": t.name}
        if tag == TAG_OBJECT_REMEMBER:
            self.remembered.append(o)
        o.update({m: c[0] for m, c in self.columns(t.all_members(), 1, False).items()})
        return o

    def columns(self, members, n, in_array):
        """Present members of n structs or objects, one list of n values per member."""
        out = {}
        for (mname, code, tup, cls), present in zip(members, self.bitmap(len(members))):
            if present and code & 0xF:
                out[mname] = self.values(code, tup, cls, n, in_array)
        return out

    def array(self, code, tup, cls):
        return self.values(code & ~ARRAY, tup, cls, self.int(), True)

    def values(self, code, tup, cls, n, in_array):
        """n values of one type, as a list. Struct values come back as a list of dicts."""
        if code & ARRAY:
            return [self.array(code, tup, cls) for _ in range(n)]
        base, k = code & 0xF, (tup if code & TUPLE else 1)
        total = n * k
        if base == 1:
            r = list(self.b[self.p:self.p + total])
            self.p += total
        elif base == 2:
            if in_array:
                self.int()  # width in bytes of the source field (4 or 8)
            r = [self.int() for _ in range(total)]
        elif base == 3:
            r = list(struct.unpack_from("<%df" % total, self.b, self.p))
            self.p += 4 * total
        elif base in VEC_WIDTH:
            w = VEC_WIDTH[base]
            nc = self.int() if in_array else w
            flat = struct.unpack_from("<%df" % (total * nc), self.b, self.p)
            self.p += 4 * total * nc
            r = [tuple(flat[i * nc:(i + 1) * nc]) + (0.0,) * (w - nc) for i in range(total)]
        elif base == 8:
            r = [self.object_ref() for _ in range(total)]
        elif base == 9:
            t = self.type_by_name(cls)
            cols = self.columns(t.all_members(), total, in_array)
            r = [dict({"_class": t.name}, **{m: c[i] for m, c in cols.items()}) for i in range(total)]
        elif base == 10:
            r = [self.string() for _ in range(total)]
        else:
            raise ValueError("member type code 0x%x at offset 0x%x is not handled" % (code, self.p))
        if k > 1:
            r = [r[i * k:(i + 1) * k] for i in range(n)]
        return r

    def run(self):
        while self.p < len(self.b):
            start = self.p
            tag = self.int()
            if tag == TAG_FILE_INFO:
                self.f.version = self.int()
                self.f.sdk = self.string()
                self.f.header_extra = self.b[self.p:self.p + 4]
                self.p += 4
            elif tag == TAG_METADATA:
                self.metadata()
            elif tag in (TAG_OBJECT, TAG_OBJECT_REMEMBER):
                self.f.objects.append(self.object(tag))
            elif tag == TAG_NULL:
                pass
            elif tag == TAG_END:
                return self.f
            else:
                raise ValueError("tag %d at offset 0x%x is not a top-level tag" % (tag, start))
        raise ValueError("stream ended at 0x%x without an end-of-file tag" % self.p)


def parse(data):
    return Reader(bytes(data)).run()


def walk(o, seen=None):
    """Every object dict reachable from o (objects and struct values)."""
    seen = set() if seen is None else seen
    if isinstance(o, dict):
        if id(o) in seen:
            return
        seen.add(id(o))
        yield o
        for v in o.values():
            yield from walk(v, seen)
    elif isinstance(o, list):
        for v in o:
            yield from walk(v, seen)


# hkcdStaticMeshTree: per-section 11:11:10 packed vertices scaled by codecParms (offset xyz, scale
# xyz), plus 21:21:22 shared vertices quantised over the whole tree's domain. Primitive indices
# below numPackedVertices are packed vertices of the section, the rest index the section's slice of
# sharedVerticesIndex. Section.primitives/sharedVertices/dataRuns pack (offset << 8) | count.
def static_mesh_tree(tree):
    U32, U64 = 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF
    packed = [v & U32 for v in tree.get("packedVertices", [])]
    shared = [v & U64 for v in tree.get("sharedVertices", [])]
    shared_index = tree.get("sharedVerticesIndex", [])
    prims = tree.get("primitives", [])
    runs = tree.get("primitiveDataRuns", [])
    dmin, dmax = tree["domain"]["min"][:3], tree["domain"]["max"][:3]
    dscale = [(dmax[i] - dmin[i]) / ((1 << bits) - 1) for i, bits in enumerate((21, 21, 22))]
    verts, tris, tri_user, kinds = [], [], [], {"triangle": 0, "quad": 0, "custom": 0}
    for s in tree.get("sections", []):
        cp = s["codecParms"]
        base = len(verts)
        first = s.get("firstPackedVertex", 0)
        for i in range(s.get("numPackedVertices", 0)):
            v = packed[first + i]
            q = (v & 0x7FF, (v >> 11) & 0x7FF, v >> 22)
            verts.append(tuple(cp[j] + cp[3 + j] * q[j] for j in range(3)))
        soff = s.get("sharedVertices", {}).get("data", 0) >> 8
        for i in range(s.get("numSharedIndices", 0)):
            v = shared[shared_index[soff + i]]
            q = (v & 0x1FFFFF, (v >> 21) & 0x1FFFFF, v >> 42)
            verts.append(tuple(dmin[j] + dscale[j] * q[j] for j in range(3)))
        pdata = s.get("primitives", {}).get("data", 0)
        poff, pcount = pdata >> 8, pdata & 0xFF
        user = [None] * pcount
        rdata = s.get("dataRuns", {}).get("data", 0)
        for r in runs[rdata >> 8:(rdata >> 8) + (rdata & 0xFF)]:
            for i in range(r.get("index", 0), r.get("index", 0) + r.get("count", 0)):
                if i < pcount:
                    user[i] = r.get("value", 0) & U32
        for i in range(pcount):
            a, b, c, d = prims[poff + i]["indices"]
            if a == b:
                kinds["custom"] += 1
                continue
            tris.append((base + a, base + b, base + c))
            tri_user.append(user[i])
            if c == d:
                kinds["triangle"] += 1
            else:
                kinds["quad"] += 1
                tris.append((base + a, base + c, base + d))
                tri_user.append(user[i])
    return verts, tris, tri_user, kinds


def box_mesh(o):
    hx, hy, hz = o["halfExtents"][:3]
    verts = [(sx * hx, sy * hy, sz * hz) for sx in (-1, 1) for sy in (-1, 1) for sz in (-1, 1)]
    quads = [(0, 1, 3, 2), (4, 6, 7, 5), (0, 4, 5, 1), (2, 3, 7, 6), (0, 2, 6, 4), (1, 5, 7, 3)]
    return verts, [t for a, b, c, d in quads for t in ((a, b, c), (a, c, d))]


MESH_SHAPES = ("hkpBvCompressedMeshShape", "hkcdStaticMeshTree", "hkpBoxShape")


def meshes(data, report=None):
    """Triangle meshes of the collision shapes in a tagfile. Shapes of classes this reader cannot turn
    into triangles are counted in report["skipped"] (class -> count) when report is a dict."""
    f = parse(data)
    out, skipped = [], {}
    for n, o in enumerate(x for top in f.objects for x in walk(top)):
        cls = o.get("_class", "")
        if cls == "hkpBvCompressedMeshShape" and "tree" in o:
            v, t, u, kinds = static_mesh_tree(o["tree"])
            out.append({"name": "%s_%d" % (cls, n), "class": cls, "vertices": v, "triangles": t,
                        "user_data": u, "primitives": kinds, "convex_radius": o.get("convexRadius", 0.0)})
        elif cls == "hkpBoxShape" and "halfExtents" in o:
            v, t = box_mesh(o)
            out.append({"name": "%s_%d" % (cls, n), "class": cls, "vertices": v, "triangles": t,
                        "convex_radius": o.get("radius", 0.0)})
        elif cls.endswith("Shape") or cls in ("hkpRigidBody", "hkpPhysicsSystem"):
            skipped[cls] = skipped.get(cls, 0) + 1
    if report is not None:
        report["skipped"] = skipped
        report["sdk"] = f.sdk
        report["types"] = [t.name for t in f.types]
    return out


def load(path):
    """Raw tagfile bytes from a .bin or a ScriptableObject JSON export with fields.HKXData."""
    if path.endswith(".json"):
        with open(path, encoding="utf-8") as fh:
            fields = json.load(fh)["fields"]
        if "HKXData" not in fields:
            raise ValueError("%s: fields has no HKXData (fields: %s)" % (path, ", ".join(fields)))
        return bytes.fromhex(fields["HKXData"])
    with open(path, "rb") as fh:
        return fh.read()


def write_obj(ms, path):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("# udk.havok: Havok collision, shape space, Y up\n")
        base = 1
        for m in ms:
            fh.write("o %s\n" % m["name"])
            fh.writelines("v %.5f %.5f %.5f\n" % v for v in m["vertices"])
            fh.writelines("f %d %d %d\n" % (a + base, b + base, c + base) for a, b, c in m["triangles"])
            base += len(m["vertices"])


def main(argv):
    if len(argv) != 2:
        sys.exit(__doc__)
    report = {}
    ms = meshes(load(argv[0]), report)
    write_obj(ms, argv[1])
    print("%s: %d types" % (report["sdk"], len(report["types"])))
    for m in ms:
        print("%s: %d vertices, %d triangles %s" % (m["name"], len(m["vertices"]), len(m["triangles"]),
                                                   m.get("primitives", "")))
    if report["skipped"]:
        print("skipped (no mesh decoder): %s" % report["skipped"])
    if not ms:
        sys.exit("no triangle mesh found in %s" % argv[0])


if __name__ == "__main__":
    main(sys.argv[1:])
