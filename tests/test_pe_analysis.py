import random

import pytest

from legacyforge import analysis, pe
from pebuilder import build_pe

IMPORTS = {"KERNEL32.dll": ["CreateFileA", "ReadFile", "CloseHandle", "GetTickCount", "Sleep"],
           "d3d9.dll": ["Direct3DCreate9"], "msvcr80.dll": ["malloc"]}


def rich(**kw):
    base = dict(imports=IMPORTS, delay_imports={"dsound.dll": ["DirectSoundCreate8"]},
                version={"CompanyName": "Acme", "FileVersion": "1.2.3", "ProductName": "Test Game"},
                manifest="<assembly><requestedExecutionLevel level='asInvoker'/><dpiAware>true</dpiAware>"
                         "<supportedOS Id='{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}'/></assembly>")
    base.update(kw)
    return build_pe(**base)


@pytest.mark.parametrize("pe32", [True, False])
def test_full_parse(pe32):
    p = pe.PEFile(rich(pe32=pe32))
    assert p.info.arch == ("x32" if pe32 else "x64")
    imps = {d.name: d for d in p.imports()}
    assert imps["d3d9.dll"].functions == ["Direct3DCreate9"]
    assert imps["dsound.dll"].delay
    ver, man = p.resources()
    assert ver["ProductName"] == "Test Game" and ver["FixedFileVersion"] == "1.0.0.0"
    facts = pe.manifest_facts(man)
    assert facts["execution_level"] == "asInvoker" and facts["dpi_aware"] == "true"
    assert facts["supported_os_ids"] == ["8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a"]
    assert p.subsystem_name == "windows-gui" and not p.integrity_issues()


def test_matches_pefile_where_available():
    pefile = pytest.importorskip("pefile")
    data = rich()
    ours = [d.name for d in pe.PEFile(data).imports() if not d.delay]
    theirs = [e.dll.decode().lower() for e in pefile.PE(data=data).DIRECTORY_ENTRY_IMPORT]
    assert ours == theirs


def test_truncation_never_misparses():
    data = rich()
    for n in list(range(0, 0x200, 7)) + list(range(0x200, len(data), 97)):
        try:
            p = pe.PEFile(data[:n])
            p.imports()
            p.resources()
        except pe.PEError:
            pass  # the only acceptable failure


def test_random_corruption_only_raises_peerror():
    rng = random.Random(1234)
    data = rich()
    for _ in range(400):
        buf = bytearray(data)
        for _ in range(rng.randint(1, 12)):
            buf[rng.randrange(len(buf))] = rng.randrange(256)
        try:
            p = pe.PEFile(bytes(buf))
            p.imports()
            p.resources()
            p.integrity_issues()
        except pe.PEError:
            pass


def test_header_beyond_4k(tmp_path):
    data = bytearray(rich())
    # move the PE header to 0x2000 by inserting padding after the DOS stub
    pad = 0x2000 - 0x80
    moved = data[:0x80] + b"\0" * pad + data[0x80:]
    moved[0x3C:0x40] = (0x2000).to_bytes(4, "little")
    f = tmp_path / "far.exe"
    f.write_bytes(bytes(moved))
    assert pe.read_info(f).arch == "x32"


def test_implausible_header_offset(tmp_path):
    data = bytearray(rich())
    data[0x3C:0x40] = (0x7FFFFFF0).to_bytes(4, "little")
    f = tmp_path / "bad.exe"
    f.write_bytes(bytes(data))
    with pytest.raises(pe.PEError):
        pe.read_info(f)


def test_laa_verification_catches_stray_bytes():
    before = rich()
    after = bytearray(before)
    pe.set_laa_bytes(after)
    pe.verify_laa_patch(before, bytes(after))
    after[-1] ^= 0xFF
    with pytest.raises(pe.PEError, match="unexpected bytes"):
        pe.verify_laa_patch(before, bytes(after))


def write(tmp_path, data, name="game.exe"):
    d = tmp_path / "Game"
    d.mkdir(exist_ok=True)
    (d / name).write_bytes(data)
    return d / name


def test_analysis_graphics_and_folder(tmp_path):
    exe = write(tmp_path, rich(text_bytes=b"\xc3" * 32 + b"opengl32.dll\0"))
    (exe.parent / "d3d9.dll").write_bytes(build_pe(characteristics=0x2102))
    (exe.parent / "binkw32.dll").write_bytes(b"x")
    a = analysis.analyze(exe, check_signature=False)
    g = {x.api: x for x in a.graphics}
    assert g["d3d9"].strength == "strong"
    assert g["opengl"].strength == "weak"  # string only: possible runtime load
    assert a.apis() == {"d3d9"}
    assert a.folder["proxy_dlls"][0]["name"] == "d3d9.dll"
    assert a.folder["bundled_libraries"][0]["library"] == "Bink video"
    assert a.large_address_aware is False and "2 GiB" in a.address_space
    assert a.signature["status"] == "unsigned"


def test_analysis_protection_and_signature(tmp_path):
    exe = write(tmp_path, build_pe(section_names=("UPX0", ".text"), imports={"kernel32.dll": ["LoadLibraryA", "GetProcAddress"]},
                                   signature=b"\x10\0\0\0\0\x02\x02\0" + b"s" * 8))
    a = analysis.analyze(exe, check_signature=False)
    assert any("UPX" in p.detail for p in a.protection)
    assert any("tiny import table" in p.detail for p in a.protection)
    assert a.signature["present"] and a.signature["status"] == "unknown"


def test_directdraw_and_software(tmp_path):
    exe = write(tmp_path, build_pe(imports={"ddraw.dll": ["DirectDrawCreate"], "gdi32.dll": ["BitBlt"]}))
    assert analysis.analyze(exe, check_signature=False).apis() == {"directdraw"}
    exe2 = write(tmp_path, build_pe(imports={"gdi32.dll": ["BitBlt"]}), "two.exe")
    assert [g.api for g in analysis.analyze(exe2, check_signature=False).graphics] == ["software"]


def test_address_space_text():
    assert "4 GiB" in analysis.address_space(True, True, True)
    assert "32-bit Windows" in analysis.address_space(True, True, False)
    assert "64-bit process" in analysis.address_space(False, False)


def test_vc2008_side_by_side(tmp_path):
    from legacyforge import deps

    sxs = tmp_path / "WinSxS"
    crt = sxs / "x86_microsoft.vc90.crt_1fc8b3b9a1e18e3b_9.0.30729.9635_none_508ddc384bcb6798"
    crt.mkdir(parents=True)
    (crt / "msvcr90.dll").write_bytes(b"x")
    game = tmp_path / "G"
    game.mkdir()
    reqs = {r.dll: r for r in deps.check(["msvcr90.dll", "msvcp80.dll"], game, True, winsxs=sxs)}
    assert reqs["msvcr90.dll"].status == "present-on-system"
    assert reqs["msvcp80.dll"].status == "missing"
    assert deps.sxs_present("msvcr90.dll", False, sxs) is False  # x64 store is separate


def test_renderer_in_game_dll(tmp_path):
    d = tmp_path / "RoN"
    d.mkdir()
    (d / "game.exe").write_bytes(build_pe(imports={"engine.dll": ["Init"], "kernel32.dll": ["Sleep"]}))
    (d / "engine.dll").write_bytes(build_pe(characteristics=0x2102, imports={"d3d9.dll": ["Direct3DCreate9"]}))
    (d / "extra.dll").write_bytes(build_pe(characteristics=0x2102, imports={"opengl32.dll": ["glBegin"]}))
    a = analysis.analyze(d / "game.exe", check_signature=False)
    g = {x.api: x for x in a.graphics}
    assert g["d3d9"].strength == "strong" and "engine.dll" in g["d3d9"].evidence[0].detail
    assert g["opengl"].strength == "medium"
    assert {x["dll"] for x in a.folder["game_dlls"]} == {"engine.dll", "extra.dll"}


def test_launcher_detection(tmp_path):
    from legacyforge import recommend

    d = tmp_path / "L"
    d.mkdir()
    (d / "patriots.exe").write_bytes(build_pe(imports={"kernel32.dll": ["CreateProcessA"], "gdi32.dll": ["BitBlt"]}))
    a = analysis.analyze(d / "patriots.exe", check_signature=False)
    assert a.looks_like_launcher
    ids = [r.id for r in recommend.recommend(recommend.Context(exe=a))]
    assert "info.launcher" in ids and "memory.laa" not in ids


def test_runtime_loaded_dll_named_in_exe_is_strong(tmp_path):
    d = tmp_path / "R"
    d.mkdir()
    (d / "game.exe").write_bytes(build_pe(imports={"kernel32.dll": ["LoadLibraryA"]},
                                          text_bytes=b"\xc3" * 16 + b"d3dgl.dll\0"))
    (d / "d3dgl.dll").write_bytes(build_pe(characteristics=0x2102, imports={"d3d11.dll": ["D3D11CreateDevice"]}))
    a = analysis.analyze(d / "game.exe", check_signature=False)
    assert {g.api: g.strength for g in a.graphics}["d3d11"] == "strong"
    assert not a.looks_like_launcher


def test_mfc_dialog_launcher(tmp_path):
    d = tmp_path / "P"
    d.mkdir()
    (d / "patriots.exe").write_bytes(build_pe(imports={"steam_api.dll": ["SteamAPI_Init"], "mfc140.dll": ["#1"],
                                                       "gdiplus.dll": ["GdiplusStartup"], "gdi32.dll": ["BitBlt"]}))
    (d / "d3dgl.dll").write_bytes(build_pe(characteristics=0x2102, imports={"d3d11.dll": ["D3D11CreateDevice"]}))
    a = analysis.analyze(d / "patriots.exe", check_signature=False)
    assert a.looks_like_launcher and "MFC / GDI+ dialog application" in a.launcher_reasons
    assert not any("CreateProcess" in r for r in a.launcher_reasons)
