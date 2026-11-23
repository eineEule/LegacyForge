"""Bounds-checked, dependency-free PE (Windows executable) parser.

Every offset read from the file is checked before use: a malformed or
hostile executable raises PEError, it never produces silent garbage.
Static analysis only; nothing here executes or loads the file.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from pathlib import Path

IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020
MACHINE_I386 = 0x014C
MACHINE_AMD64 = 0x8664
PE32_MAGIC = 0x10B
PE32_PLUS_MAGIC = 0x20B

MAX_SECTIONS = 96
MAX_IMPORT_DLLS = 2048
MAX_FUNCS_PER_DLL = 8192
MAX_ANALYZE_BYTES = 1 << 30  # 1 GiB
HEADER_READ = 8192

DIR_EXPORT, DIR_IMPORT, DIR_RESOURCE, DIR_SECURITY = 0, 1, 2, 4
DIR_DELAY_IMPORT, DIR_COM = 13, 14
RT_VERSION, RT_MANIFEST = 16, 24

SUBSYSTEMS = {1: "native", 2: "windows-gui", 3: "windows-console", 9: "windows-ce-gui",
              10: "efi-application"}
DLL_CHARACTERISTICS = {
    0x0020: "HIGH_ENTROPY_VA", 0x0040: "DYNAMIC_BASE", 0x0080: "FORCE_INTEGRITY",
    0x0100: "NX_COMPAT", 0x0200: "NO_ISOLATION", 0x0400: "NO_SEH", 0x0800: "NO_BIND",
    0x1000: "APPCONTAINER", 0x2000: "WDM_DRIVER", 0x4000: "GUARD_CF",
    0x8000: "TERMINAL_SERVER_AWARE",
}


class PEError(Exception):
    pass


@dataclass(frozen=True)
class PEInfo:
    machine: int
    characteristics: int
    magic: int

    @property
    def is_32bit(self) -> bool:
        return self.magic == PE32_MAGIC

    @property
    def arch(self) -> str:
        return "x32" if self.is_32bit else "x64"

    @property
    def large_address_aware(self) -> bool:
        return bool(self.characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE)


@dataclass
class Section:
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    characteristics: int
    entropy: float = 0.0

    @property
    def executable(self) -> bool:
        return bool(self.characteristics & 0x20000000)


@dataclass
class ImportedDll:
    name: str
    delay: bool = False
    functions: list[str] = field(default_factory=list)


class _Reader:
    def __init__(self, data: bytes):
        self.data = data

    def need(self, off: int, n: int, what: str) -> None:
        if off < 0 or n < 0 or off + n > len(self.data):
            raise PEError(f"truncated or invalid file: {what} at 0x{off:x} runs past end of file")

    def u16(self, off: int, what: str = "field") -> int:
        self.need(off, 2, what)
        return int.from_bytes(self.data[off:off + 2], "little")

    def u32(self, off: int, what: str = "field") -> int:
        self.need(off, 4, what)
        return int.from_bytes(self.data[off:off + 4], "little")

    def u64(self, off: int, what: str = "field") -> int:
        self.need(off, 8, what)
        return int.from_bytes(self.data[off:off + 8], "little")

    def cstr(self, off: int, limit: int = 512) -> str:
        self.need(off, 1, "string")
        end = self.data.find(b"\0", off, min(len(self.data), off + limit))
        if end == -1:
            raise PEError(f"unterminated string at 0x{off:x}")
        return self.data[off:end].decode("latin-1")


def _entropy(buf: bytes) -> float:
    if not buf:
        return 0.0
    counts = [0] * 256
    for b in buf:
        counts[b] += 1
    n = len(buf)
    return -sum(c / n * math.log2(c / n) for c in counts if c)


class PEFile:
    """Parsed headers plus lazily parsed imports and resources."""

    def __init__(self, data: bytes, *, full: bool = True):
        if len(data) > MAX_ANALYZE_BYTES:
            raise PEError("file too large to analyze")
        self.data = data
        r = self.r = _Reader(data)
        r.need(0, 0x40, "DOS header")
        if data[:2] != b"MZ":
            raise PEError("not a Windows executable (missing MZ header)")
        self.pe_offset = pe = r.u32(0x3C, "e_lfanew")
        r.need(pe, 4, "PE signature")
        if data[pe:pe + 4] != b"PE\0\0":
            raise PEError("not a PE executable (missing PE signature)")
        coff = pe + 4
        self.machine = r.u16(coff, "machine")
        self.num_sections = r.u16(coff + 2, "section count")
        self.timestamp = r.u32(coff + 4, "timestamp")
        self.size_of_optional_header = r.u16(coff + 16, "optional header size")
        self.characteristics_offset = coff + 18
        self.characteristics = r.u16(coff + 18, "characteristics")
        opt = self.opt_offset = coff + 20
        self.magic = r.u16(opt, "optional header magic")
        if self.magic not in (PE32_MAGIC, PE32_PLUS_MAGIC):
            raise PEError(f"unknown optional header magic 0x{self.magic:x}")
        is32 = self.magic == PE32_MAGIC
        min_opt = 96 if is32 else 112
        if self.size_of_optional_header < min_opt:
            raise PEError("optional header too small")
        self.entry_rva = r.u32(opt + 16, "entry point")
        self.image_base = r.u32(opt + 28, "image base") if is32 else r.u64(opt + 24, "image base")
        self.subsystem_version = (r.u16(opt + 48), r.u16(opt + 50))
        self.size_of_image = r.u32(opt + 56, "size of image")
        self.size_of_headers = r.u32(opt + 60, "size of headers")
        self.checksum_offset = opt + 64
        self.checksum = r.u32(opt + 64, "checksum")
        self.subsystem = r.u16(opt + 68, "subsystem")
        self.dll_characteristics = r.u16(opt + 70, "dll characteristics")
        nd_off = opt + (92 if is32 else 108)
        self.num_data_dirs = r.u32(nd_off, "data directory count")
        dirs_off = nd_off + 4
        n_dirs = min(self.num_data_dirs, 16)
        if dirs_off + n_dirs * 8 > opt + self.size_of_optional_header:
            n_dirs = max(0, (opt + self.size_of_optional_header - dirs_off) // 8)
        self.data_dirs = [(r.u32(dirs_off + i * 8), r.u32(dirs_off + i * 8 + 4)) for i in range(n_dirs)]

        if self.num_sections > MAX_SECTIONS:
            raise PEError(f"{self.num_sections} sections exceeds the PE limit")
        sec_off = opt + self.size_of_optional_header
        self.sections: list[Section] = []
        for i in range(self.num_sections):
            o = sec_off + i * 40
            r.need(o, 40, "section header")
            name = data[o:o + 8].rstrip(b"\0").decode("latin-1")
            self.sections.append(Section(name, r.u32(o + 12), r.u32(o + 8), r.u32(o + 20),
                                         r.u32(o + 16), r.u32(o + 36)))
        if full:
            for s in self.sections:
                start = s.raw_offset
                end = min(len(data), start + s.raw_size, start + (16 << 20))
                s.entropy = round(_entropy(data[start:end]), 2) if start < len(data) else 0.0

    # basic facts -------------------------------------------------------
    @property
    def info(self) -> PEInfo:
        return PEInfo(self.machine, self.characteristics, self.magic)

    @property
    def is_32bit(self) -> bool:
        return self.magic == PE32_MAGIC

    def data_dir(self, idx: int) -> tuple[int, int]:
        return self.data_dirs[idx] if idx < len(self.data_dirs) else (0, 0)

    def rva_to_offset(self, rva: int) -> int:
        if rva < self.size_of_headers and rva < len(self.data):
            return rva
        for s in self.sections:
            size = max(s.virtual_size, s.raw_size)
            if s.virtual_address <= rva < s.virtual_address + size:
                off = rva - s.virtual_address
                if off >= s.raw_size:
                    raise PEError(f"RVA 0x{rva:x} points into uninitialised section data")
                return s.raw_offset + off
        raise PEError(f"RVA 0x{rva:x} is not inside any section")

    @property
    def dll_flags(self) -> list[str]:
        return [n for bit, n in DLL_CHARACTERISTICS.items() if self.dll_characteristics & bit]

    @property
    def subsystem_name(self) -> str:
        return SUBSYSTEMS.get(self.subsystem, f"unknown ({self.subsystem})")

    @property
    def has_signature(self) -> bool:
        off, size = self.data_dir(DIR_SECURITY)
        return size > 0 and off > 0 and off + size <= len(self.data)

    @property
    def is_dotnet(self) -> bool:
        return self.data_dir(DIR_COM)[1] > 0

    @property
    def overlay_size(self) -> int:
        end = max((s.raw_offset + s.raw_size for s in self.sections if s.raw_size), default=0)
        sig_off, sig_size = self.data_dir(DIR_SECURITY)
        tail = len(self.data) - end
        if sig_size and sig_off >= end:
            tail -= sig_size
        return max(0, tail)

    # integrity ---------------------------------------------------------
    def integrity_issues(self) -> list[str]:
        issues = []
        for s in self.sections:
            if s.raw_size and s.raw_offset + s.raw_size > len(self.data):
                issues.append(f"section {s.name or '?'} data runs past end of file")
        if self.entry_rva and not any(
            s.virtual_address <= self.entry_rva < s.virtual_address + max(s.virtual_size, s.raw_size)
            for s in self.sections
        ):
            issues.append("entry point is outside every section")
        if self.num_data_dirs > 16:
            issues.append(f"declares {self.num_data_dirs} data directories (max 16)")
        if self.checksum and self.checksum != pe_checksum(self.data, self.checksum_offset):
            issues.append("header checksum does not match (common in games; Windows ignores it for .exe)")
        sig_off, sig_size = self.data_dir(DIR_SECURITY)
        if sig_size and sig_off + sig_size > len(self.data):
            issues.append("signature directory points past end of file")
        return issues

    # imports -----------------------------------------------------------
    def imports(self) -> list[ImportedDll]:
        out: list[ImportedDll] = []
        r = self.r
        rva, size = self.data_dir(DIR_IMPORT)
        if rva and size:
            off = self.rva_to_offset(rva)
            for i in range(MAX_IMPORT_DLLS):
                d = off + i * 20
                r.need(d, 20, "import descriptor")
                oft, name_rva, ft = r.u32(d), r.u32(d + 12), r.u32(d + 16)
                if not (oft or name_rva or ft):
                    break
                name = r.cstr(self.rva_to_offset(name_rva)).lower()
                funcs = self._thunks(oft or ft)
                if not funcs and oft and ft and ft != oft:
                    funcs = self._thunks(ft)  # empty lookup table (some Delphi/FPC linkers): use the IAT
                out.append(ImportedDll(name, False, funcs))
        rva, size = self.data_dir(DIR_DELAY_IMPORT)
        if rva and size:
            off = self.rva_to_offset(rva)
            for i in range(MAX_IMPORT_DLLS):
                d = off + i * 32
                r.need(d, 32, "delay import descriptor")
                attrs, name_ptr, int_ptr = r.u32(d), r.u32(d + 4), r.u32(d + 16)
                if not name_ptr:
                    break
                fix = 0 if attrs & 1 else self.image_base  # old VC6 style stored VAs
                name = r.cstr(self.rva_to_offset(name_ptr - fix)).lower()
                funcs = self._thunks(int_ptr - fix, va_base=fix) if int_ptr else []
                out.append(ImportedDll(name, True, funcs))
        return out

    def _thunks(self, rva: int, va_base: int = 0) -> list[str]:
        if not rva:
            return []
        r = self.r
        names: list[str] = []
        try:
            off = self.rva_to_offset(rva)
        except PEError:
            return names
        step = 4 if self.is_32bit else 8
        flag = 1 << (31 if self.is_32bit else 63)
        for i in range(MAX_FUNCS_PER_DLL):
            v = r.u32(off + i * step) if step == 4 else r.u64(off + i * step)
            if v == 0:
                break
            if v & flag:
                names.append(f"#{v & 0xFFFF}")
                continue
            try:
                names.append(r.cstr(self.rva_to_offset((v - va_base) + 2), 256))
            except PEError:
                names.append("?")
        return names

    # resources ---------------------------------------------------------
    def _resource_leaves(self, wanted: set[int]) -> dict[int, bytes]:
        rva, size = self.data_dir(DIR_RESOURCE)
        if not (rva and size):
            return {}
        r = self.r
        base = self.rva_to_offset(rva)
        found: dict[int, bytes] = {}
        seen: set[int] = set()

        def entries(dir_off: int):
            r.need(dir_off, 16, "resource directory")
            n = r.u16(dir_off + 12) + r.u16(dir_off + 14)
            for i in range(min(n, 4096)):
                e = dir_off + 16 + i * 8
                yield r.u32(e), r.u32(e + 4)

        def first_leaf(off_field: int, depth: int) -> bytes | None:
            if depth > 3:
                return None
            target = base + (off_field & 0x7FFFFFFF)
            if target in seen:
                return None
            seen.add(target)
            if off_field & 0x80000000:
                for _, child in entries(target):
                    leaf = first_leaf(child, depth + 1)
                    if leaf is not None:
                        return leaf
                return None
            r.need(target, 16, "resource data entry")
            data_rva, data_size = r.u32(target), r.u32(target + 4)
            if data_size > (8 << 20):
                return None
            o = self.rva_to_offset(data_rva)
            r.need(o, data_size, "resource data")
            return self.data[o:o + data_size]

        for type_id, off_field in entries(base):
            if type_id & 0x80000000 or type_id not in wanted or type_id in found:
                continue
            leaf = first_leaf(off_field, 1)
            if leaf is not None:
                found[type_id] = leaf
        return found

    def resources(self) -> tuple[dict, str | None]:
        """(version_info, manifest_text)."""
        leaves = self._resource_leaves({RT_VERSION, RT_MANIFEST})
        version = parse_version_info(leaves[RT_VERSION]) if RT_VERSION in leaves else {}
        manifest = None
        if RT_MANIFEST in leaves:
            raw = leaves[RT_MANIFEST]
            manifest = raw.decode("utf-16" if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else "utf-8",
                                  errors="replace")
        return version, manifest


def parse_version_info(blob: bytes) -> dict:
    """Parse VS_VERSIONINFO into {FileVersion, ProductVersion, CompanyName, ...}."""
    out: dict[str, str] = {}

    def node(off: int, end: int, depth: int) -> int:
        if depth > 6 or off + 6 > end:
            return end
        length = int.from_bytes(blob[off:off + 2], "little")
        value_len = int.from_bytes(blob[off + 2:off + 4], "little")
        vtype = int.from_bytes(blob[off + 4:off + 6], "little")
        if length < 6:
            return end
        nend = min(end, off + length)
        k = off + 6
        kend = k
        while kend + 1 < nend and blob[kend:kend + 2] != b"\0\0":
            kend += 2
        key = blob[k:kend].decode("utf-16-le", errors="replace")
        v = (kend + 2 + 3) & ~3
        if key == "VS_VERSION_INFO" and value_len >= 52 and \
                int.from_bytes(blob[v:v + 4], "little") == 0xFEEF04BD:
            ms, ls = int.from_bytes(blob[v + 8:v + 12], "little"), int.from_bytes(blob[v + 12:v + 16], "little")
            out.setdefault("FixedFileVersion", f"{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}")
        vbytes = value_len * 2 if vtype == 1 else value_len
        if depth >= 3 and vtype == 1 and value_len:
            val = blob[v:v + vbytes].decode("utf-16-le", errors="replace").rstrip("\0")
            if key and len(out) < 64:
                out.setdefault(key, val[:256])
        child = (v + vbytes + 3) & ~3
        while child < nend:
            nxt = node(child, nend, depth + 1)
            if nxt <= child:
                break
            child = (nxt + 3) & ~3
        return nend

    try:
        node(0, len(blob), 0)
    except Exception:
        pass
    return out


def manifest_facts(text: str | None) -> dict:
    """Pull the compatibility-relevant parts out of an application manifest.
    Regex, not an XML parser: manifests are untrusted (no entity expansion)."""
    if not text:
        return {}
    facts: dict = {}
    m = re.search(r"requestedExecutionLevel[^>]*level\s*=\s*[\"']([^\"']+)", text)
    if m:
        facts["execution_level"] = m.group(1)
    m = re.search(r"<(?:\w+:)?dpiAware[^>]*>\s*([^<]+)", text)
    if m:
        facts["dpi_aware"] = m.group(1).strip()
    m = re.search(r"<(?:\w+:)?dpiAwareness[^>]*>\s*([^<]+)", text)
    if m:
        facts["dpi_awareness"] = m.group(1).strip()
    os_ids = re.findall(r"supportedOS\s+Id\s*=\s*[\"']\{([0-9a-fA-F-]+)\}", text)
    if os_ids:
        facts["supported_os_ids"] = [i.lower() for i in os_ids]
    if "Microsoft.Windows.Common-Controls" in text:
        facts["common_controls_v6"] = True
    return facts


# header-only fast path --------------------------------------------------

def read_info_bytes(data: bytes | bytearray) -> PEInfo:
    return PEFile(bytes(data), full=False).info


def read_info(path: Path) -> PEInfo:
    return PEFile(read_headers(path), full=False).info


def read_headers(path: Path) -> bytes:
    """Enough of the file for header parsing, wherever the PE header sits."""
    with open(path, "rb") as f:
        dos = f.read(0x40)
        if len(dos) < 0x40 or dos[:2] != b"MZ":
            raise PEError("not a Windows executable (missing MZ header)")
        e_lfanew = int.from_bytes(dos[0x3C:0x40], "little")
        if e_lfanew > (16 << 20):
            raise PEError("PE header offset is implausibly large")
        f.seek(0)
        return f.read(e_lfanew + HEADER_READ)


def load(path: Path) -> PEFile:
    size = Path(path).stat().st_size
    if size > MAX_ANALYZE_BYTES:
        raise PEError("file too large to analyze")
    return PEFile(Path(path).read_bytes())


# checksum + LAA ---------------------------------------------------------

def _offsets(data: bytes | bytearray) -> tuple[int, int, int]:
    p = PEFile(bytes(data), full=False)
    return p.characteristics_offset, p.opt_offset, p.checksum_offset


def pe_checksum(data: bytes | bytearray, checksum_offset: int) -> int:
    """Standard PE checksum (same algorithm as imagehlp's CheckSumMappedFile)."""
    checksum = 0
    length = len(data)
    padded = bytes(data) + b"\0" * ((-length) % 4)
    skip = checksum_offset // 4
    for i in range(len(padded) // 4):
        if i == skip:
            continue
        dword = int.from_bytes(padded[i * 4:i * 4 + 4], "little")
        checksum = (checksum & 0xFFFFFFFF) + dword + (checksum >> 32)
        if checksum > 2 ** 32:
            checksum = (checksum & 0xFFFFFFFF) + (checksum >> 32)
    checksum = (checksum & 0xFFFF) + (checksum >> 16)
    checksum = checksum + (checksum >> 16)
    checksum &= 0xFFFF
    return (checksum + length) & 0xFFFFFFFF


def set_laa_bytes(data: bytearray) -> bool:
    """Set the LAA flag in-place. Returns True if the data changed."""
    p = PEFile(bytes(data), full=False)
    if not p.is_32bit:
        raise PEError("64-bit executable; LAA flag is irrelevant")
    if p.info.large_address_aware:
        return False
    new_chars = p.characteristics | IMAGE_FILE_LARGE_ADDRESS_AWARE
    data[p.characteristics_offset:p.characteristics_offset + 2] = new_chars.to_bytes(2, "little")
    if p.checksum != 0:  # games usually ship 0 (unchecked); only fix a real one
        data[p.checksum_offset:p.checksum_offset + 4] = \
            pe_checksum(data, p.checksum_offset).to_bytes(4, "little")
    return True


def verify_laa_patch(before: bytes, after: bytes) -> None:
    """Post-patch validation: LAA now set, file still parses, and nothing but
    the characteristics and checksum fields changed."""
    if len(before) != len(after):
        raise PEError("patched file changed size")
    p = PEFile(after, full=False)
    if not p.info.large_address_aware:
        raise PEError("LAA flag not set after patch")
    allowed = set(range(p.characteristics_offset, p.characteristics_offset + 2)) | \
        set(range(p.checksum_offset, p.checksum_offset + 4))
    diff = [i for i in range(len(before)) if before[i] != after[i]] if before != after else []
    stray = [i for i in diff if i not in allowed]
    if stray:
        raise PEError(f"patch changed unexpected bytes at 0x{stray[0]:x}")


def set_laa(path: Path) -> bool:
    data = bytearray(Path(path).read_bytes())
    before = bytes(data)
    changed = set_laa_bytes(data)
    if changed:
        verify_laa_patch(before, bytes(data))
        from .fsutil import atomic_write

        atomic_write(Path(path), bytes(data))
    return changed


GRAPHICS_DLLS = {
    "ddraw.dll": "DirectDraw",
    "d3dim.dll": "Direct3D immediate mode (5-7)",
    "d3dim700.dll": "Direct3D 7",
    "d3d8.dll": "Direct3D 8",
    "d3d9.dll": "Direct3D 9",
    "d3d10.dll": "Direct3D 10",
    "d3d10_1.dll": "Direct3D 10.1",
    "d3d11.dll": "Direct3D 11",
    "dxgi.dll": "DXGI (D3D10/11)",
    "opengl32.dll": "OpenGL",
    "glide.dll": "3dfx Glide",
    "glide2x.dll": "3dfx Glide 2",
    "glide3x.dll": "3dfx Glide 3",
    "dinput.dll": "DirectInput",
    "dinput8.dll": "DirectInput 8",
    "dsound.dll": "DirectSound",
}


def imported_dlls(path: Path) -> list[str]:
    """Back-compat helper: names of all imported DLLs."""
    return [d.name for d in load(path).imports()]
