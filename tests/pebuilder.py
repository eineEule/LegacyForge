"""Build small synthetic PE files for tests: real section, import, delay-import,
resource and signature layouts, but no runnable code. No proprietary binaries."""

from __future__ import annotations

import struct

FILE_ALIGN = 0x200
SECT_ALIGN = 0x1000


def _align(n: int, a: int) -> int:
    return (n + a - 1) // a * a


def _u16s(s: str) -> bytes:
    return s.encode("utf-16-le") + b"\0\0"


def _pad4(b: bytes) -> bytes:
    return b + b"\0" * ((-len(b)) % 4)


def version_blob(strings: dict[str, str], fixed=(1, 0, 0, 0)) -> bytes:
    def node(key: str, value: bytes, vtype: int, children: list[bytes], vlen: int) -> bytes:
        body = _pad4(struct.pack("<HHH", 0, vlen, vtype) + _u16s(key)) + _pad4(value)
        body += b"".join(children)
        body = struct.pack("<H", len(body)) + body[2:]
        return _pad4(body)

    strs = [node(k, _u16s(v), 1, [], len(v) + 1) for k, v in strings.items()]
    table = node("040904b0", b"", 1, strs, 0)
    sfi = node("StringFileInfo", b"", 1, [table], 0)
    a, b, c, d = fixed
    ffi = struct.pack("<13I", 0xFEEF04BD, 0x10000, (a << 16) | b, (c << 16) | d,
                      (a << 16) | b, (c << 16) | d, 0x3F, 0, 4, 1, 0, 0, 0)
    return node("VS_VERSION_INFO", ffi, 0, [sfi], len(ffi))


def build_pe(*, pe32: bool = True, characteristics: int = 0x0102, checksum: int = 0,
             imports: dict[str, list[str]] | None = None,
             delay_imports: dict[str, list[str]] | None = None,
             version: dict[str, str] | None = None, manifest: str | None = None,
             section_names=(".text",), text_bytes: bytes = b"\xc3" * 64,
             signature: bytes | None = None, subsystem: int = 2,
             dll_characteristics: int = 0x0000, overlay: bytes = b"") -> bytes:
    sections: list[tuple[str, bytes, int]] = []  # name, data, characteristics
    rva = SECT_ALIGN
    layout = []

    def add(name: str, builder, chars: int):
        nonlocal rva
        data = builder(rva)
        layout.append((name, rva, data, chars))
        rva += _align(max(len(data), 1), SECT_ALIGN)
        return layout[-1][1]

    for name in section_names:
        add(name, lambda base: text_bytes, 0x60000020)
    text_rva = layout[0][1]
    import_dir = delay_dir = res_dir = (0, 0)

    if imports or delay_imports:
        def build_idata(base: int) -> bytes:
            nonlocal import_dir, delay_dir
            blob = bytearray()
            imp = imports or {}
            dly = delay_imports or {}
            desc_size = 20 * (len(imp) + 1)
            ddesc_size = 32 * (len(dly) + 1)
            blob += b"\0" * (desc_size + ddesc_size)
            ptr = 8 if not pe32 else 4

            def put(b: bytes) -> int:
                off = len(blob)
                blob.extend(_pad4(b))
                return base + off

            def thunks(funcs: list[str]) -> int:
                rvas = [put(struct.pack("<H", 0) + f.encode() + b"\0") for f in funcs]
                fmt = "<Q" if not pe32 else "<I"
                return put(b"".join(struct.pack(fmt, r) for r in rvas) + b"\0" * ptr)

            for i, (dll, funcs) in enumerate(imp.items()):
                name = put(dll.encode() + b"\0")
                t = thunks(funcs)
                struct.pack_into("<5I", blob, i * 20, t, 0, 0, name, t)
            for i, (dll, funcs) in enumerate(dly.items()):
                name = put(dll.encode() + b"\0")
                t = thunks(funcs)
                struct.pack_into("<8I", blob, desc_size + i * 32, 1, name, 0, t, t, 0, 0, 0)
            if imp:
                import_dir = (base, desc_size)
            if dly:
                delay_dir = (base + desc_size, ddesc_size)
            return bytes(blob)

        add(".idata", build_idata, 0xC0000040)

    if version or manifest:
        items = []
        if version:
            items.append((16, version_blob(version)))
        if manifest:
            items.append((24, manifest.encode()))

        def build_rsrc(base: int) -> bytes:
            nonlocal res_dir
            n = len(items)
            # root dir + n type entries, then per type: name dir(1 entry) + lang dir(1 entry) + data entry
            root = 16 + 8 * n
            per = (16 + 8) * 2 + 16
            blob = bytearray(root + per * n)
            struct.pack_into("<IIHHHH", blob, 0, 0, 0, 0, 0, 0, n)
            for i, (tid, data) in enumerate(items):
                sub = root + per * i
                struct.pack_into("<II", blob, 16 + 8 * i, tid, 0x80000000 | sub)
                struct.pack_into("<IIHHHH", blob, sub, 0, 0, 0, 0, 0, 1)
                lang = sub + 24
                struct.pack_into("<II", blob, sub + 16, 1, 0x80000000 | lang)
                struct.pack_into("<IIHHHH", blob, lang, 0, 0, 0, 0, 0, 1)
                entry = lang + 24
                struct.pack_into("<II", blob, lang + 16, 0x409, entry)
                data_rva = base + len(blob)
                blob += _pad4(data)
                struct.pack_into("<IIII", blob, entry, data_rva, len(data), 0, 0)
            res_dir = (base, len(blob))
            return bytes(blob)

        add(".rsrc", build_rsrc, 0x40000040)

    opt_size = 224 if pe32 else 240
    headers_size = _align(0x80 + 4 + 20 + opt_size + 40 * len(layout), FILE_ALIGN)
    raw = headers_size
    sec_headers = b""
    body = b""
    for name, srva, data, chars in layout:
        raw_size = _align(len(data), FILE_ALIGN)
        sec_headers += struct.pack("<8sIIIIIIHHI", name.encode()[:8], len(data), srva, raw_size,
                                   raw, 0, 0, 0, 0, chars)
        body += data + b"\0" * (raw_size - len(data))
        raw += raw_size
    size_of_image = rva

    dirs = [(0, 0)] * 16
    dirs[1], dirs[2], dirs[13] = import_dir, res_dir, delay_dir
    sig_offset = headers_size + len(body) + len(overlay)
    if signature:
        dirs[4] = (sig_offset, len(signature))

    machine = 0x14C if pe32 else 0x8664
    coff = struct.pack("<HHIIIHH", machine, len(layout), 0x3A000000, 0, 0, opt_size, characteristics)
    if pe32:
        opt = struct.pack("<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII", 0x10B, 6, 0, 0, 0, 0, text_rva, text_rva, 0,
                          0x400000, SECT_ALIGN, FILE_ALIGN, 4, 0, 0, 0, 4, 0, 0, size_of_image,
                          headers_size, checksum, subsystem, dll_characteristics,
                          0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    else:
        opt = struct.pack("<HBBIIIIIQIIHHHHHHIIIIHHQQQQII", 0x20B, 14, 0, 0, 0, 0, text_rva, text_rva,
                          0x140000000, SECT_ALIGN, FILE_ALIGN, 6, 0, 0, 0, 6, 0, 0, size_of_image,
                          headers_size, checksum, subsystem, dll_characteristics,
                          0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    opt += b"".join(struct.pack("<II", *d) for d in dirs)
    assert len(opt) == opt_size, (len(opt), opt_size)

    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    hdr = bytes(dos) + b"PE\0\0" + coff + opt + sec_headers
    hdr += b"\0" * (headers_size - len(hdr))
    out = hdr + body + overlay + (signature or b"")
    return out
