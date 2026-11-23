import io
import tarfile

import pytest

from oldgames import engine, pe, tools
from oldgames.fixes import FixError
from oldgames.fixes.ini import edit_ini
from oldgames.recipe import RecipeError, bundled, parse


def recipe(*fixes, exe="game.exe"):
    return parse({"game": "test", "name": "Test", "detect": {"exe": exe}, "fixes": list(fixes)})


def test_bundled_recipes_are_valid():
    r = bundled()
    assert {"civ5", "rise-of-nations-ee"} <= set(r)


def test_unknown_fix_type():
    with pytest.raises(RecipeError, match="unknown fix type"):
        recipe({"teleport": {}})


def test_bad_params():
    with pytest.raises(RecipeError, match="api"):
        recipe({"dxvk": {"api": "glide"}})


def test_conflict_detected(game):
    r = recipe({"dxvk": {"api": "d3d9"}}, {"reshade": {"api": "d3d9"}})
    with pytest.raises(RecipeError, match="conflict"):
        engine.make_plan(r, game)


def test_missing_exe(game):
    with pytest.raises(RecipeError, match="not found"):
        engine.make_plan(recipe({"laa": {}}, exe="other.exe"), game)


def test_apply_and_revert_roundtrip(game):
    original_exe = (game / "game.exe").read_bytes()
    original_ini = (game / "settings.ini").read_text()
    r = recipe({"laa": {}}, {"ini": {"file": "settings.ini", "set": {"Video": {"MSAA": 2}}}})
    out = engine.apply(engine.make_plan(r, game))
    assert any("LAA flag set" in line for line in out)
    assert pe.read_info(game / "game.exe").large_address_aware
    assert "MSAA = 2" in (game / "settings.ini").read_text()
    assert engine.status(r, game) is not None

    with pytest.raises(Exception, match="already applied"):
        engine.apply(engine.make_plan(r, game))

    engine.revert(r, game)
    assert (game / "game.exe").read_bytes() == original_exe
    assert (game / "settings.ini").read_text() == original_ini
    assert not (game / ".oldgames").exists()


def test_failure_rolls_back(game):
    original = (game / "game.exe").read_bytes()
    r = recipe({"laa": {}}, {"ini": {"file": "missing.ini", "set": {"A": {"b": 1}}}})
    with pytest.raises(FixError, match="Rolled back"):
        engine.apply(engine.make_plan(r, game))
    assert (game / "game.exe").read_bytes() == original
    assert engine.status(r, game) is None


def test_no_changes_leaves_no_snapshot(game):
    pe.set_laa(game / "game.exe")
    r = recipe({"laa": {}})
    out = engine.apply(engine.make_plan(r, game))
    assert "nothing needed changing" in out
    assert engine.status(r, game) is None


def test_optional_requires_with(game):
    r = recipe({"laa": {}}, {"dxvk": {"api": "d3d9"}, "optional": True})
    assert [e.fix.type for e in engine.make_plan(r, game).entries] == ["laa"]
    assert len(engine.make_plan(r, game, {"dxvk"}).entries) == 2
    with pytest.raises(RecipeError):
        engine.make_plan(r, game, {"reshade"})


def test_dxvk_with_fake_release(game, tmp_path, monkeypatch):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for arch in ("x32", "x64"):
            for dll in ("d3d9.dll", "d3d11.dll", "dxgi.dll"):
                payload = f"{arch}/{dll}".encode()
                info = tarfile.TarInfo(f"dxvk-9.9/{arch}/{dll}")
                info.size = len(payload)
                tar.addfile(info, io.BytesIO(payload))
    archive = tmp_path / "dxvk.tar.gz"
    archive.write_bytes(buf.getvalue())
    monkeypatch.setattr(tools, "fetch", lambda name, allow=False: archive)

    (game / "d3d9.dll").write_bytes(b"original system-ish dll")
    r = recipe({"dxvk": {"api": "d3d11"}}, {"dxvk": {"api": "d3d9"}})
    engine.apply(engine.make_plan(r, game))
    assert (game / "dxgi.dll").read_bytes() == b"x32/dxgi.dll"
    assert (game / "d3d9.dll").read_bytes() == b"x32/d3d9.dll"
    engine.revert(r, game)
    assert not (game / "dxgi.dll").exists()
    assert (game / "d3d9.dll").read_bytes() == b"original system-ish dll"


def test_unpinned_tool_refused(monkeypatch, tmp_path):
    monkeypatch.setattr(tools, "load_pins", lambda: {"x": {"version": "1", "url": "https://example.invalid/x.zip", "sha256": None}})
    cached = tools.cache_dir() / "x-1-x.zip"
    cached.parent.mkdir(parents=True)
    cached.write_bytes(b"data")
    with pytest.raises(tools.ToolError, match="no pinned sha256"):
        tools.fetch("x")
    assert tools.fetch("x", allow_unpinned=True) == cached


def test_hash_mismatch_deletes_download(monkeypatch):
    monkeypatch.setattr(tools, "load_pins", lambda: {"x": {"version": "1", "url": "https://example.invalid/x.zip", "sha256": "00" * 32}})
    cached = tools.cache_dir() / "x-1-x.zip"
    cached.parent.mkdir(parents=True)
    cached.write_bytes(b"tampered")
    with pytest.raises(tools.ToolError, match="mismatch"):
        tools.fetch("x")
    assert not cached.exists()


def test_ini_preserves_layout():
    text = "; top\n[Video]\nMSAA = 8\r\n[Debug]\nLogging=0\n"
    new, _ = edit_ini(text, {"Video": {"MSAA": 2}, None: {"logging": 1}, "Audio": {"Vol": 5}})
    assert new == "; top\n[Video]\nMSAA = 2\r\n[Debug]\nLogging=1\n[Audio]\nVol = 5\n"


def test_ini_keeps_encoding_bytes(game):
    raw = b"[Video]\r\nName = Caf\xe9\r\nMSAA = 8\r\n"  # ANSI byte, no BOM
    (game / "settings.ini").write_bytes(raw)
    r = recipe({"ini": {"file": "settings.ini", "set": {"Video": {"MSAA": 2}}}})
    engine.apply(engine.make_plan(r, game))
    assert (game / "settings.ini").read_bytes() == raw.replace(b"MSAA = 8", b"MSAA = 2")


def test_ini_adds_key_to_existing_section():
    new, _ = edit_ini("[A]\nx = 1\n[B]\ny = 2\n", {"A": {"z": 3}})
    assert new == "[A]\nx = 1\nz = 3\n[B]\ny = 2\n"
