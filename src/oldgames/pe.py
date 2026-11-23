"""Minimal, dependency-free PE header helpers.

Only what the engine needs: architecture, the Large Address Aware (LAA) flag,
and the optional-header checksum. Import inspection uses `pefile` lazily.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020
MACHINE_I386 = 0x014C
MACHINE_AMD64 = 0x8664
PE32_MAGIC = 0x10B
PE32_PLUS_MAGIC = 0x20B


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


def _pe_offset(data: bytes | bytearray) -> int:
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise PEError("not a Windows executable (missing MZ header)")
    off = int.from_bytes(data[0x3C:0x40], "little")
    if data[off : off + 4] != b"PE\0\0":
        raise PEError("not a PE executable (missing PE signature)")
    return off


def _offsets(data: bytes | bytearray) -> tuple[int, int, int]:
    """Return (characteristics_offset, magic_offset, checksum_offset)."""
    pe = _pe_offset(data)
    coff = pe + 4
    opt = coff + 20
    return coff + 18, opt, opt + 64


def read_info_bytes(data: bytes | bytearray) -> PEInfo:
    char_off, magic_off, _ = _offsets(data)
    pe = _pe_offset(data)
    return PEInfo(
        machine=int.from_bytes(data[pe + 4 : pe + 6], "little"),
        characteristics=int.from_bytes(data[char_off : char_off + 2], "little"),
        magic=int.from_bytes(data[magic_off : magic_off + 2], "little"),
    )


def read_info(path: Path) -> PEInfo:
    with open(path, "rb") as f:
        head = f.read(4096)
    return read_info_bytes(head)


def pe_checksum(data: bytes | bytearray, checksum_offset: int) -> int:
    """Standard PE checksum (same algorithm as imagehlp's CheckSumMappedFile)."""
    checksum = 0
    length = len(data)
    padded = bytes(data) + b"\0" * ((-length) % 4)
    skip = checksum_offset // 4
    for i in range(len(padded) // 4):
        if i == skip:
            continue
        dword = int.from_bytes(padded[i * 4 : i * 4 + 4], "little")
        checksum = (checksum & 0xFFFFFFFF) + dword + (checksum >> 32)
        if checksum > 2**32:
            checksum = (checksum & 0xFFFFFFFF) + (checksum >> 32)
    checksum = (checksum & 0xFFFF) + (checksum >> 16)
    checksum = checksum + (checksum >> 16)
    checksum &= 0xFFFF
    return (checksum + length) & 0xFFFFFFFF


def set_laa_bytes(data: bytearray) -> bool:
    """Set the LAA flag in-place. Returns True if the data changed."""
    info = read_info_bytes(data)
    if not info.is_32bit:
        raise PEError("64-bit executable; LAA flag is irrelevant")
    if info.large_address_aware:
        return False
    char_off, _, sum_off = _offsets(data)
    new_chars = info.characteristics | IMAGE_FILE_LARGE_ADDRESS_AWARE
    data[char_off : char_off + 2] = new_chars.to_bytes(2, "little")
    # Games usually ship with checksum 0 (unchecked); only fix a real one.
    if int.from_bytes(data[sum_off : sum_off + 4], "little") != 0:
        data[sum_off : sum_off + 4] = pe_checksum(data, sum_off).to_bytes(4, "little")
    return True


def set_laa(path: Path) -> bool:
    data = bytearray(Path(path).read_bytes())
    changed = set_laa_bytes(data)
    if changed:
        Path(path).write_bytes(data)
    return changed


GRAPHICS_DLLS = {
    "d3d8.dll": "Direct3D 8",
    "d3d9.dll": "Direct3D 9",
    "d3d10.dll": "Direct3D 10",
    "d3d10_1.dll": "Direct3D 10.1",
    "d3d11.dll": "Direct3D 11",
    "dxgi.dll": "DXGI (D3D10/11)",
    "ddraw.dll": "DirectDraw",
    "opengl32.dll": "OpenGL",
    "glide2x.dll": "3dfx Glide",
    "glide3x.dll": "3dfx Glide",
    "dinput8.dll": "DirectInput 8",
    "dsound.dll": "DirectSound",
}


def imported_dlls(path: Path) -> list[str]:
    """List DLLs the executable imports (requires `pefile`)."""
    import pefile  # lazy: only `inspect` needs it

    pe = pefile.PE(str(path), fast_load=True)
    pe.parse_data_directories(
        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
    )
    names = [e.dll.decode(errors="replace").lower() for e in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])]
    pe.close()
    return names
