"""Decode behaviac behavior trees (*.bson.bytes) and agent metadata (*.meta.bson.bytes).

Format reference: behaviac C# runtime, BsonDeserizer (BehaviorTree.cs), BehaviorTree.load_bson,
BehaviorNode.load_properties_pars_attachments_children, AgentMeta.load_bson (Meta.cs).

Wire format (little endian, USE_STRING_COUNT_HEAD build):
  document  = int32 size (counts itself and the final 0) ... 0x00
  string    = uint16 count (includes trailing NUL) + utf8 bytes + NUL
  element   = type byte + payload (see below); a 0x00 type byte ends the enclosing document

File: wrapper document {0x16 | 0x1d element, then 0x00}.
Tree file: 0x16 behavior doc {name, agenttype, bool fsm, version, elements...}
  elements: 0x17 properties doc {(0x02 name value)*}, 0x18 pars doc {(0x19 doc{name,type,value})*},
            0x1b attachments doc {(0x1c doc{class,id,bool pre,bool eff,bool trans,elements...})*},
            0x22 custom doc {0x1a node}, 0x1a node doc {class,id,elements...}
Meta file: 0x1d agents doc {version, signature, (0x1e agent doc {name, base, signature,
            0x17 props doc {(0x1f doc{name,type,ismember,isstatic,value|member})*}, 0x20 methods doc})*}

Tree returned by decode(): {"tag", "attrs", "children"} dicts mirroring behaviac's XML.
"""
import struct
import sys

BT_NONE, BT_STRING = 0, 2
BT_BEHAVIOR, BT_PROPERTIES, BT_PARS, BT_PAR, BT_NODE = 22, 23, 24, 25, 26
BT_ATTACHMENTS, BT_ATTACHMENT, BT_AGENTS, BT_AGENT, BT_PROPERTY = 27, 28, 29, 30, 31
BT_METHODS, BT_METHOD, BT_CUSTOM, BT_PARAMETER = 32, 33, 34, 35


class BsonError(ValueError):
    pass


def el(tag, attrs=None, children=None):
    return {"tag": tag, "attrs": attrs if attrs is not None else {}, "children": children if children is not None else []}


class Reader:
    def __init__(self, data):
        self.d = data
        self.p = 0
        self.warnings = []

    def _need(self, n):
        if self.p + n > len(self.d):
            raise BsonError("truncated at %d (need %d bytes)" % (self.p, n))

    def byte(self):
        self._need(1)
        b = self.d[self.p]
        self.p += 1
        return b

    def int32(self):
        self._need(4)
        v = struct.unpack_from("<i", self.d, self.p)[0]
        self.p += 4
        return v

    def string(self):
        self._need(2)
        n = struct.unpack_from("<H", self.d, self.p)[0]
        self.p += 2
        self._need(n)
        raw = self.d[self.p:self.p + n]
        self.p += n
        if n == 0 or raw[-1] != 0:
            raise BsonError("string at %d lacks NUL terminator" % (self.p - n))
        return raw[:-1].decode("utf-8", "replace")

    def boolean(self):
        return self.byte() != 0

    def open_doc(self):
        start = self.p
        size = self.int32()
        end = start + size
        if size < 5 or end > len(self.d) or self.d[end - 1] != 0:
            raise BsonError("bad document size %d at %d" % (size, start))
        return end

    def close_doc(self, end):
        """The document's terminating 0 has been consumed; the cursor must sit at its end."""
        if self.p != end:
            raise BsonError("document ends at %d but parser is at %d" % (end, self.p))


def _node_body(r, node, bar_version=None):
    """Read elements until the 0x00 terminator, filling `node` (a node or attachment element)."""
    while True:
        t = r.byte()
        if t == BT_NONE:
            return
        if t == BT_PROPERTIES:
            end = r.open_doc()
            attrs = {}
            while True:
                tt = r.byte()
                if tt == BT_NONE:
                    break
                if tt != BT_STRING:
                    raise BsonError("unexpected type %d in properties at %d" % (tt, r.p - 1))
                k = r.string()
                attrs[k] = r.string()
            r.close_doc(end)
            node["children"].append(el("property", attrs))
        elif t == BT_PARS:
            node["children"].append(_pars(r))
        elif t == BT_ATTACHMENTS:
            _attachments(r, node)
        elif t == BT_CUSTOM:
            end = r.open_doc()
            tt = r.byte()
            if tt != BT_NODE:
                raise BsonError("custom element without node at %d" % (r.p - 1))
            c = el("custom")
            c["children"].append(_node(r))
            if r.byte() != BT_NONE:
                raise BsonError("custom document not terminated at %d" % (r.p - 1))
            r.close_doc(end)
            node["children"].append(c)
        elif t == BT_NODE:
            node["children"].append(_node(r))
        else:
            raise BsonError("unknown element type %d at %d" % (t, r.p - 1))


def _node(r):
    end = r.open_doc()
    cls = r.string()
    nid = r.string()
    n = el("node", {"class": cls, "id": nid})
    _node_body(r, n)
    r.close_doc(end)
    return n


def _pars(r):
    end = r.open_doc()
    pars = el("pars")
    while True:
        t = r.byte()
        if t == BT_NONE:
            break
        if t != BT_PAR:
            raise BsonError("unexpected type %d in pars at %d" % (t, r.p - 1))
        pend = r.open_doc()
        name = r.string()
        typ = r.string()
        val = r.string()
        # load_local uses CloseDocument(true): the document's own 0 byte is consumed here
        if r.byte() != 0:
            raise BsonError("par document not terminated at %d" % (r.p - 1))
        r.close_doc(pend)
        pars["children"].append(el("par", {"name": name, "type": typ, "value": val}))
    r.close_doc(end)
    return pars


def _attachments(r, owner):
    end = r.open_doc()
    holder = el("attachments")
    while True:
        t = r.byte()
        if t == BT_NONE:
            break
        if t == BT_ATTACHMENT:
            aend = r.open_doc()
            cls = r.string()
            aid = r.string()
            pre, eff, trans = r.boolean(), r.boolean(), r.boolean()
            a = el("attachment", {"class": cls, "id": aid})
            if pre:
                a["attrs"]["flag"] = "precondition"
            elif eff:
                a["attrs"]["flag"] = "effector"
            elif trans:
                a["attrs"]["flag"] = "transition"
            _node_body(r, a)
            r.close_doc(aend)
            owner["children"].append(a)
        elif t == BT_PARS:
            owner["children"].append(_pars(r))
        elif t == BT_ATTACHMENTS:
            _attachments(r, owner)
        else:
            raise BsonError("unexpected type %d in attachments at %d" % (t, r.p - 1))
    r.close_doc(end)


def _tree(r):
    end = r.open_doc()
    name = r.string()
    agent = r.string()
    fsm = r.boolean()
    version = r.string()
    attrs = {"name": name, "agenttype": agent}
    if fsm:
        attrs["fsm"] = "true"
    attrs["version"] = version
    b = el("behavior", attrs)
    _node_body(r, b)
    r.close_doc(end)
    return b


def _meta(r):
    end = r.open_doc()
    root = el("agents", {"version": r.string(), "signature": r.string()})
    while True:
        t = r.byte()
        if t == BT_NONE:
            break
        if t != BT_AGENT:
            raise BsonError("unexpected type %d in agents at %d" % (t, r.p - 1))
        aend = r.open_doc()
        a = el("agent", {"type": r.string(), "base": r.string(), "signature": r.string()})
        while True:
            t2 = r.byte()
            if t2 == BT_NONE:
                break
            if t2 == BT_PROPERTIES:
                pend = r.open_doc()
                while True:
                    t3 = r.byte()
                    if t3 == BT_NONE:
                        break
                    if t3 != BT_PROPERTY:
                        raise BsonError("unexpected type %d in agent properties at %d" % (t3, r.p - 1))
                    qend = r.open_doc()
                    p = el("property", {"name": r.string(), "type": r.string()})
                    ismember = r.string() == "true"
                    p["attrs"]["ismember"] = "true" if ismember else "false"
                    p["attrs"]["isstatic"] = r.string()
                    p["attrs"]["member" if ismember else "value"] = r.string()
                    if r.byte() != 0:
                        raise BsonError("property document not terminated at %d" % (r.p - 1))
                    r.close_doc(qend)
                    a["children"].append(p)
                r.close_doc(pend)
            elif t2 == BT_METHODS:
                mend = r.open_doc()
                while True:
                    t3 = r.byte()
                    if t3 == BT_NONE:
                        break
                    if t3 != BT_METHOD:
                        raise BsonError("unexpected type %d in methods at %d" % (t3, r.p - 1))
                    qend = r.open_doc()
                    m = el("method", {"name": r.string(), "agent": r.string()})
                    while True:
                        t4 = r.byte()
                        if t4 == BT_NONE:
                            break
                        if t4 != BT_PARAMETER:
                            raise BsonError("unexpected type %d in method at %d" % (t4, r.p - 1))
                        send = r.open_doc()
                        m["children"].append(el("parameter", {"name": r.string(), "type": r.string()}))
                        if r.byte() != 0:
                            raise BsonError("parameter document not terminated at %d" % (r.p - 1))
                        r.close_doc(send)
                    r.close_doc(qend)
                    a["children"].append(m)
                r.close_doc(mend)
            else:
                raise BsonError("unknown agent element type %d at %d" % (t2, r.p - 1))
        r.close_doc(aend)
        root["children"].append(a)
    r.close_doc(end)
    return root


def decode(data, strict=False):
    """Decode a behaviac .bson.bytes buffer into a nested {"tag","attrs","children"} tree.

    The returned root also carries "consumed" (bytes read) and "size" (buffer length) keys;
    decode is fully consumed when they are equal.  strict=True raises on trailing bytes.
    """
    data = bytes(data)
    r = Reader(data)
    if len(data) < 6:
        raise BsonError("buffer too short (%d bytes)" % len(data))
    outer = r.open_doc()  # Init() -> OpenDocument(): the file is one wrapper document
    t = r.byte()
    if t == BT_BEHAVIOR:
        root = _tree(r)
    elif t == BT_AGENTS:
        root = _meta(r)
    else:
        raise BsonError("not a behaviac bson buffer (first type byte %d)" % t)
    if r.byte() != BT_NONE:
        raise BsonError("wrapper document not terminated at %d" % (r.p - 1))
    r.close_doc(outer)
    root["consumed"] = r.p
    root["size"] = len(data)
    if strict and r.p != len(data):
        raise BsonError("%d trailing bytes after document" % (len(data) - r.p))
    return root


def _esc(s):
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;").replace("\n", "&#10;"))


def to_xml(tree, indent="  "):
    """Render a decode() tree as behaviac-style XML text."""
    out = ['<?xml version="1.0" encoding="utf-8"?>']

    def emit(e, depth):
        pad = indent * depth
        attrs = "".join(' %s="%s"' % (k, _esc(str(v))) for k, v in e["attrs"].items())
        if e["children"]:
            out.append("%s<%s%s>" % (pad, e["tag"], attrs))
            for c in e["children"]:
                emit(c, depth + 1)
            out.append("%s</%s>" % (pad, e["tag"]))
        else:
            out.append("%s<%s%s />" % (pad, e["tag"], attrs))

    emit(tree, 0)
    return "\n".join(out) + "\n"


def outline(tree):
    """Compact text outline: node classes with their property values."""
    out = []

    def walk(e, depth):
        pad = "  " * depth
        a = e["attrs"]
        if e["tag"] in ("node", "attachment"):
            head = "%s%s#%s" % (pad, a.get("class"), a.get("id"))
            if e["tag"] == "attachment":
                head = pad + "@" + head.strip() + (" [%s]" % a["flag"] if "flag" in a else "")
            out.append(head)
            for c in e["children"]:
                if c["tag"] == "property":
                    for k, v in c["attrs"].items():
                        out.append("%s    %s = %s" % (pad, k, v))
        elif e["tag"] == "behavior":
            out.append("behavior %s agent=%s v%s" % (a["name"], a["agenttype"], a["version"]))
        elif e["tag"] == "par":
            out.append("%s  par %s %s = %s" % (pad, a["type"], a["name"], a["value"]))
        elif e["tag"] == "custom":
            out.append(pad + "custom:")
        for c in e["children"]:
            if c["tag"] != "property":
                walk(c, depth + 1 if e["tag"] != "pars" else depth)

    walk(tree, 0)
    return "\n".join(out)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if not argv or argv[0] in ("-h", "--help"):
        print("usage: python -m udk.behaviac <in.bson.bytes> [out.xml]")
        return 2
    with open(argv[0], "rb") as f:
        tree = decode(f.read())
    xml = to_xml(tree)
    if len(argv) > 1:
        with open(argv[1], "w", encoding="utf-8") as f:
            f.write(xml)
    else:
        sys.stdout.write(xml)
    if tree["consumed"] != tree["size"]:
        sys.stderr.write("warning: %d of %d bytes consumed\n" % (tree["consumed"], tree["size"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
