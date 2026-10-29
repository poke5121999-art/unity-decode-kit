import struct
NEG = [-1,-2,-1,-3,-1,-2,-1,-4,-1,-2,-1,-3,-1,-2,-1,-5]
SH = [25,18,25,11,25,18,25,4,25,18,25,11,25,18,25,0]

def ru(data, p):
    lb = data[p] & 0x0F
    n = -NEG[lb]
    v = struct.unpack_from("<I", data, p + n - 4)[0] >> SH[lb]
    return v, p + n

def handlers(data, off, fi):
    """FH4 FuncInfo at file offset of rva fi -> list of (tryLow, tryHigh, handler rva, cont list)."""
    p = off(fi)
    h = data[p]; p += 1
    if h & 4: _, p = ru(data, p)
    if h & 8: p += 4
    if not h & 16: return []
    tbm = struct.unpack_from("<i", data, p)[0]; p += 4
    q = off(tbm)
    n, q = ru(data, q)
    out = []
    for _ in range(n):
        lo, q = ru(data, q); hi, q = ru(data, q); ch, q = ru(data, q)
        ha = struct.unpack_from("<i", data, q)[0]; q += 4
        r = off(ha)
        m, r = ru(data, r)
        for _ in range(m):
            hh = data[r]; r += 1
            if hh & 1: _, r = ru(data, r)
            if hh & 2: r += 4
            if hh & 4: _, r = ru(data, r)
            disp = struct.unpack_from("<i", data, r)[0]; r += 4
            conts = []
            for _ in range((hh >> 4) & 3):
                if hh & 8: conts.append(struct.unpack_from("<i", data, r)[0]); r += 4
                else:
                    c, r = ru(data, r); conts.append(c)
            out.append((lo, hi, disp, conts))
    return out
