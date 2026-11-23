import io
import tarfile
import zipfile

import pytest

from legacyforge import engine, tools, transaction
from legacyforge.archive import ArchiveError, SafeArchive
from legacyforge.fixes import FixError
from legacyforge.recipe import RecipeError, parse
from pebuilder import build_pe

DLL32 = build_pe(characteristics=0x2102)
DLL64 = build_pe(pe32=False, characteristics=0x2022)


def make_zip(path, files: dict, *, symlink: str | None = None):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in files.items():
            z.writestr(name, data)
        if symlink:
            info = zipfile.ZipInfo(symlink)
            info.external_attr = (0o120777 << 16)
            z.writestr(info, "/etc/passwd")
    return path


@pytest.mark.parametrize("bad", ["../evil.dll", "/abs/evil.dll", "a/../../evil.dll", "C:/evil.dll", "..\\evil.dll"])
def test_zip_slip_rejected(tmp_path, bad):
    with pytest.raises(ArchiveError):
        SafeArchive(make_zip(tmp_path / "a.zip", {bad: b"x"}))


def test_zip_symlink_rejected(tmp_path):
    with pytest.raises(ArchiveError, match="symlink"):
        SafeArchive(make_zip(tmp_path / "a.zip", {"ok.txt": b"x"}, symlink="link"))


def test_tar_link_rejected(tmp_path):
    p = tmp_path / "a.tar.gz"
    with tarfile.open(p, "w:gz") as t:
        info = tarfile.TarInfo("x32/d3d9.dll")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
        t.addfile(info)
    with pytest.raises(ArchiveError, match="link"):
        SafeArchive(p)


def test_zip_bomb_ratio_rejected(tmp_path):
    with pytest.raises(ArchiveError, match="ratio"):
        SafeArchive(make_zip(tmp_path / "a.zip", {"big.bin": b"\0" * (8 << 20)}))


def test_find_under(tmp_path):
    with SafeArchive(make_zip(tmp_path / "a.zip", {"MS/x86/DDraw.dll": DLL32, "MS/x64/DDraw.dll": DLL64})) as ar:
        assert ar.find(filename="ddraw.dll", under="ms/x64").name == "MS/x64/DDraw.dll"
        assert ar.read(ar.find(filename="ddraw.dll", under="x86")) == DLL32


@pytest.fixture
def game(tmp_path):
    d = tmp_path / "Game"
    d.mkdir()
    (d / "game.exe").write_bytes(build_pe(imports={"ddraw.dll": ["DirectDrawCreate"]}))
    return d


def recipe(*fixes):
    return parse({"game": "t", "name": "T", "detect": {"exe": "game.exe"}, "fixes": list(fixes)})


def cnc_zip(tmp_path, dll=DLL32):
    return make_zip(tmp_path / "cnc.zip", {"ddraw.dll": dll, "ddraw.ini": "[ddraw]\nwindowed=false\nmaintas=false\n",
                                          "Shaders/nearest.glsl": "x", "Shaders/pkg.zip": "skip"})


def test_cnc_ddraw_install_settings_and_revert(game, tmp_path, monkeypatch):
    monkeypatch.setattr(tools, "fetch", lambda name, allow=False: cnc_zip(tmp_path))
    r = recipe({"cnc-ddraw": {"settings": {"windowed": True, "maintas": True, "renderer": "auto"}}})
    engine.apply(engine.make_plan(r, game))
    ini = (game / "ddraw.ini").read_text()
    assert "windowed=true" in ini and "maintas=true" in ini and "renderer = auto" in ini
    assert (game / "Shaders" / "nearest.glsl").exists() and not (game / "Shaders" / "pkg.zip").exists()
    assert transaction.owner_of(game / "ddraw.dll", game) == "t"
    engine.revert(r, game)
    assert not (game / "ddraw.dll").exists() and not (game / "Shaders" / "nearest.glsl").exists()


def test_wrong_architecture_dll_refused(game, tmp_path, monkeypatch):
    monkeypatch.setattr(tools, "fetch", lambda name, allow=False: cnc_zip(tmp_path, DLL64))
    with pytest.raises(FixError, match="x64 but the game is x32"):
        engine.apply(engine.make_plan(recipe({"cnc-ddraw": {}}), game))
    assert not (game / "ddraw.dll").exists()  # rolled back


def test_foreign_proxy_needs_approval(game, tmp_path, monkeypatch):
    monkeypatch.setattr(tools, "fetch", lambda name, allow=False: cnc_zip(tmp_path))
    (game / "ddraw.dll").write_bytes(b"someone else's wrapper")
    p = engine.make_plan(recipe({"cnc-ddraw": {}}), game)
    assert [t for t, _ in p.missing_approvals] == ["replace-foreign"]
    with pytest.raises(engine.ApprovalError):
        engine.apply(p)
    engine.apply(engine.make_plan(recipe({"cnc-ddraw": {}}), game, approvals={"replace-foreign"}))
    engine.revert(recipe({"cnc-ddraw": {}}), game)
    assert (game / "ddraw.dll").read_bytes() == b"someone else's wrapper"


def test_cnc_setting_allowlist():
    with pytest.raises(RecipeError, match="not allowed"):
        recipe({"cnc-ddraw": {"settings": {"injectdll": "evil.dll"}}})


def test_dgvoodoo2_user_archive(game, tmp_path):
    z = make_zip(tmp_path / "dgv.zip", {"MS/x86/DDraw.dll": DLL32, "MS/x86/D3DImm.dll": DLL32,
                                       "MS/x64/DDraw.dll": DLL64, "dgVoodoo.conf": "[General]\n"})
    r = recipe({"dgvoodoo2": {"api": "ddraw"}})
    p = engine.make_plan(r, game, params={"dgvoodoo2": {"archive": str(z)}})
    assert "dgvoodoo2-unpinned" in [t for t, _ in p.missing_approvals]
    p = engine.make_plan(r, game, params={"dgvoodoo2": {"archive": str(z)}}, approvals={"dgvoodoo2-unpinned"})
    engine.apply(p)
    assert (game / "DDraw.dll").read_bytes() == DLL32 and (game / "dgVoodoo.conf").exists()
    engine.revert(r, game)
    with pytest.raises(FixError, match="hash does not match"):
        engine.apply(engine.make_plan(r, game, params={"dgvoodoo2": {"archive": str(z), "sha256": "0" * 64}}))


def test_dxvk_validates_real_dlls(game, tmp_path, monkeypatch):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for arch, data in (("x32", DLL32), ("x64", DLL64)):
            for dll in ("d3d9.dll",):
                info = tarfile.TarInfo(f"dxvk-9/{arch}/{dll}")
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
    (tmp_path / "dxvk.tgz").write_bytes(buf.getvalue())
    monkeypatch.setattr(tools, "fetch", lambda name, allow=False: tmp_path / "dxvk.tgz")
    r = recipe({"dxvk": {"api": "d3d9", "config": {"d3d9.maxFrameRate": 60, "dxgi.syncInterval": 1}}})
    engine.apply(engine.make_plan(r, game))
    assert (game / "d3d9.dll").read_bytes() == DLL32
    assert "d3d9.maxFrameRate = 60" in (game / "dxvk.conf").read_text()


def test_dxvk_config_key_validation():
    with pytest.raises(RecipeError):
        recipe({"dxvk": {"api": "d3d9", "config": {"$(rm -rf)": 1}}})


def test_laa_refuses_protected_exe(tmp_path):
    d = tmp_path / "P"
    d.mkdir()
    (d / "game.exe").write_bytes(build_pe(section_names=(".text", ".securom")))
    with pytest.raises(FixError, match="protection"):
        engine.apply(engine.make_plan(recipe({"laa": {}}), d, approvals={"laa"}))


def test_laa_signed_needs_extra_approval(tmp_path):
    d = tmp_path / "S"
    d.mkdir()
    (d / "game.exe").write_bytes(build_pe(signature=b"\x10\0\0\0\0\x02\x02\0" + b"s" * 8))
    p = engine.make_plan(recipe({"laa": {}}), d, approvals={"laa"})
    assert [t for t, _ in p.missing_approvals] == ["laa-signed"]


def test_laa_hash_match_needs_no_approval(tmp_path):
    from legacyforge.fsutil import sha256_file

    d = tmp_path / "H"
    d.mkdir()
    (d / "game.exe").write_bytes(build_pe())
    r = parse({"schema_version": 2, "game": "t", "name": "T", "detect": {"exe": "game.exe"},
               "editions": [{"id": "v1", "name": "1.0", "sha256": [sha256_file(d / "game.exe")]}],
               "fixes": [{"laa": {}, "status": "known"}]})
    p = engine.make_plan(r, d)
    assert p.edition.id == "v1" and not p.missing_approvals


def test_nested_install_owner_and_dir_cleanup(tmp_path, monkeypatch):
    d = tmp_path / "AoE2"
    (d / "age2_x1").mkdir(parents=True)
    (d / "age2_x1" / "age2_x1.exe").write_bytes(build_pe(imports={"ddraw.dll": ["DirectDrawCreate"]}))
    monkeypatch.setattr(tools, "fetch", lambda name, allow=False: cnc_zip(tmp_path))
    r = parse({"game": "aoe", "name": "A", "detect": {"exe": "age2_x1/age2_x1.exe"}, "fixes": [{"cnc-ddraw": {}}]})
    engine.apply(engine.make_plan(r, d))
    assert transaction.owner_of(d / "age2_x1" / "ddraw.dll", d / "age2_x1") == "aoe"
    engine.revert(r, d)
    assert sorted(p.name for p in (d / "age2_x1").iterdir()) == ["age2_x1.exe"]  # Shaders/ removed too


def test_laa_hash_match_must_cover_every_target(tmp_path):
    from legacyforge.fsutil import sha256_file

    d = tmp_path / "M"
    d.mkdir()
    (d / "game.exe").write_bytes(build_pe())
    (d / "other.exe").write_bytes(build_pe(text_bytes=b"\x90" * 64))
    r = parse({"schema_version": 2, "game": "t", "name": "T", "detect": {"exe": "game.exe"},
               "editions": [{"id": "v1", "name": "1.0", "sha256": [sha256_file(d / "game.exe")]}],
               "fixes": [{"laa": ["game.exe", "other.exe"]}]})
    p = engine.make_plan(r, d)
    assert p.edition.id == "v1"
    assert [t for t, _ in p.missing_approvals] == ["laa"] and "other.exe" in p.missing_approvals[0][1]
