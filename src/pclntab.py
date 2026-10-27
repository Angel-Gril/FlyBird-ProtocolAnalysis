"""pclntab2.py — 稳健版 Go pclntab 解析（多候选校验），可用于剥符号二进制。"""
import struct
import sys
from pathlib import Path

MAGICS = [
    (b"\xf1\xff\xff\xff", 1),  # go1.20+
    (b"\xf0\xff\xff\xff", 1),  # go1.18/1.19
    (b"\xfa\xff\xff\xff", 0),  # go1.16/1.17
]


def candidates(data: bytes):
    for magic, _ in MAGICS:
        start = 0
        while True:
            i = data.find(magic, start)
            if i < 0:
                break
            start = i + 1
            if data[i + 4:i + 6] != b"\x00\x00":
                continue
            minLC = data[i + 6]
            ptrSize = data[i + 7]
            if minLC not in (1, 2, 4) or ptrSize not in (4, 8):
                continue
            yield i, ptrSize


def parse_at(data: bytes, off: int, ptr: int):
    fmt = "<Q" if ptr == 8 else "<I"
    p = off + 8

    def up(p):
        return struct.unpack_from(fmt, data, p)[0]

    try:
        nfunc = up(p); p += ptr
        nfiles = up(p); p += ptr
        text_start = up(p); p += ptr
        funcname_off = up(p); p += ptr
        cu_off = up(p); p += ptr
        filetab_off = up(p); p += ptr
        pctab_off = up(p); p += ptr
        pcln_off = up(p); p += ptr
    except struct.error:
        return None
    if not (1000 < nfunc < 400000 and 0 < nfiles < 50000):
        return None
    if not (0 < text_start < len(data)):
        return None
    if not (0 < funcname_off < len(data) and 0 < pcln_off < len(data)):
        return None
    functab = off + pcln_off
    if functab + nfunc * 8 > len(data):
        return None
    return dict(nfunc=nfunc, nfiles=nfiles, text_start=text_start,
                funcname_base=off + funcname_off, functab=functab, base=off)


def build(data: bytes, hdr: dict):
    out = {}
    for i in range(hdr["nfunc"]):
        try:
            entry_off, func_off = struct.unpack_from("<II", data, hdr["functab"] + i * 8)
            fptr = hdr["base"] + hdr["pcln_off"] + func_off if "pcln_off" in hdr else hdr["functab"] + func_off
            name_off = struct.unpack_from("<i", data, fptr + 4)[0]
        except struct.error:
            continue
        if name_off <= 0:
            continue
        ns = hdr["funcname_base"] + name_off
        ne = data.find(b"\x00", ns, ns + 300)
        if ne < 0:
            continue
        name = data[ns:ne].decode("utf-8", "replace")
        if "/" in name or "." in name:
            out[name] = hdr["text_start"] + entry_off
    return out


def main():
    path = Path(sys.argv[1])
    data = path.read_bytes()
    best = None
    for off, ptr in candidates(data):
        hdr = parse_at(data, off, ptr)
        if not hdr:
            continue
        tbl = build(data, hdr)
        if len(tbl) > 1000:
            print(f"[+] pclntab @0x{off:x} ptr={ptr} nfunc={hdr['nfunc']} parsed={len(tbl)} textStart=0x{hdr['text_start']:x}")
            best = tbl
            break
    if not best:
        print("pclntab not found")
        return 1
    for k in sys.argv[2:]:
        hits = [(n, a) for n, a in best.items() if k in n]
        print(f"\n=== '{k}': {len(hits)} ===")
        for n, a in hits[:15]:
            print(f"  0x{a:x}  {n}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
