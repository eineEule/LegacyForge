from pathlib import Path

import pytest


def make_pe(characteristics: int = 0x0102, magic: int = 0x10B, checksum: int = 0,
            size: int = 1024) -> bytes:
    """A minimal PE header: enough for oldgames.pe, not a runnable program."""
    data = bytearray(size)
    data[0:2] = b"MZ"
    data[0x3C:0x40] = (0x80).to_bytes(4, "little")
    data[0x80:0x84] = b"PE\0\0"
    coff = 0x84
    machine = 0x014C if magic == 0x10B else 0x8664
    data[coff : coff + 2] = machine.to_bytes(2, "little")
    data[coff + 16 : coff + 18] = (224 if magic == 0x10B else 240).to_bytes(2, "little")
    data[coff + 18 : coff + 20] = characteristics.to_bytes(2, "little")
    opt = coff + 20
    data[opt : opt + 2] = magic.to_bytes(2, "little")
    data[opt + 64 : opt + 68] = checksum.to_bytes(4, "little")
    for i in range(0x200, size):  # some body bytes so checksums are non-trivial
        data[i] = (i * 7) & 0xFF
    return bytes(data)


@pytest.fixture
def game(tmp_path: Path) -> Path:
    d = tmp_path / "Game"
    d.mkdir()
    (d / "game.exe").write_bytes(make_pe())
    (d / "settings.ini").write_text(
        "; comment stays\n[Video]\nMSAA = 8\nVSync = 1\n\n[Debug]\nLogging = 0\n", encoding="utf-8"
    )
    return d


@pytest.fixture(autouse=True)
def _isolated_cache(tmp_path, monkeypatch):
    monkeypatch.setenv("OLDGAMES_CACHE", str(tmp_path / "cache"))
