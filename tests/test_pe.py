import pytest

from legacyforge import pe
from conftest import make_pe


def test_reads_32bit_without_laa():
    info = pe.read_info_bytes(make_pe())
    assert info.is_32bit and info.arch == "x32" and not info.large_address_aware


def test_set_laa_flips_only_that_bit():
    data = bytearray(make_pe(characteristics=0x0102))
    assert pe.set_laa_bytes(data) is True
    info = pe.read_info_bytes(data)
    assert info.characteristics == 0x0122
    assert pe.set_laa_bytes(data) is False  # idempotent


def test_zero_checksum_left_alone():
    data = bytearray(make_pe(checksum=0))
    pe.set_laa_bytes(data)
    _, _, off = pe._offsets(data)
    assert data[off : off + 4] == b"\0\0\0\0"


def test_nonzero_checksum_recomputed():
    data = bytearray(make_pe(checksum=0x1234))
    pe.set_laa_bytes(data)
    _, _, off = pe._offsets(data)
    stored = int.from_bytes(data[off : off + 4], "little")
    assert stored == pe.pe_checksum(data, off) != 0x1234


def test_checksum_matches_pefile():
    pefile = pytest.importorskip("pefile")
    data = bytearray(make_pe(checksum=1))
    _, _, off = pe._offsets(data)
    ours = pe.pe_checksum(data, off)
    p = pefile.PE(data=bytes(data), fast_load=True)
    assert ours == p.generate_checksum()


def test_64bit_rejected():
    with pytest.raises(pe.PEError):
        pe.set_laa_bytes(bytearray(make_pe(magic=0x20B)))


def test_not_an_exe():
    with pytest.raises(pe.PEError):
        pe.read_info_bytes(b"hello world" * 10)
