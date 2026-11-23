import json
import os

import pytest

from legacyforge import engine, transaction, winapi
from legacyforge.recipe import parse
from legacyforge.system import LAYERS_KEY
from pebuilder import build_pe


@pytest.fixture
def game(tmp_path):
    d = tmp_path / "Game"
    d.mkdir()
    (d / "game.exe").write_bytes(build_pe())
    (d / "s.ini").write_text("[A]\nx = 1\n")
    return d


def ini_recipe():
    return parse({"game": "t", "name": "T", "detect": {"exe": "game.exe"},
                  "fixes": [{"ini": {"file": "s.ini", "set": {"A": {"x": 2}}}}]})


def test_revert_refuses_to_clobber_independent_edits(game):
    r = ini_recipe()
    engine.apply(engine.make_plan(r, game))
    (game / "s.ini").write_text("[A]\nx = 2\nuser_edit = yes\n")
    with pytest.raises(transaction.ConflictError) as e:
        engine.revert(r, game)
    assert "s.ini" in str(e.value)
    assert "user_edit" in (game / "s.ini").read_text()  # nothing restored
    assert engine.status(r, game)["conflicts"]


def test_keep_current_and_force(game):
    r = ini_recipe()
    engine.apply(engine.make_plan(r, game))
    (game / "s.ini").write_text("edited")
    log = engine.revert(r, game, keep_current=True)
    assert any("kept" in line for line in log) and (game / "s.ini").read_text() == "edited"

    (game / "s.ini").write_text("[A]\nx = 1\n")
    engine.apply(engine.make_plan(r, game))
    (game / "s.ini").write_text("edited again")
    engine.revert(r, game, force=True)
    assert (game / "s.ini").read_text() == "[A]\nx = 1\n"


def test_deleted_file_is_a_conflict(game):
    r = ini_recipe()
    engine.apply(engine.make_plan(r, game))
    (game / "s.ini").unlink()
    with pytest.raises(transaction.ConflictError, match="missing"):
        engine.revert(r, game)


def test_interrupted_apply_recovery(game):
    r = ini_recipe()
    tx = engine.snapshot_for(r, game)
    tx.begin("t", ["ini"])
    tx.track(game / "s.ini")
    (game / "s.ini").write_text("half written")
    tx.track(game / "new.dll")
    (game / "new.dll").write_bytes(b"x")
    # process "crashes" here: no commit
    with pytest.raises(transaction.TransactionError, match="interrupted"):
        engine.apply(engine.make_plan(r, game))
    with pytest.raises(transaction.TransactionError, match="recover"):
        engine.revert(r, game)
    engine.recover(r, game)
    assert (game / "s.ini").read_text() == "[A]\nx = 1\n" and not (game / "new.dll").exists()


def test_corrupt_backup_is_not_restored(game):
    r = ini_recipe()
    engine.apply(engine.make_plan(r, game))
    tx = engine.snapshot_for(r, game)
    (tx.root / "files" / "0").write_text("tampered")
    with pytest.raises(transaction.TransactionError, match="corrupt"):
        engine.revert(r, game)


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks unsupported")
def test_refuses_to_write_through_symlink(game, tmp_path):
    outside = tmp_path / "outside.ini"
    outside.write_text("[A]\nx = 1\n")
    (game / "s.ini").unlink()
    try:
        (game / "s.ini").symlink_to(outside)
    except OSError:
        pytest.skip("creating symlinks needs admin or Developer Mode on Windows")
    with pytest.raises(Exception, match="link"):
        engine.apply(engine.make_plan(ini_recipe(), game))
    assert outside.read_text() == "[A]\nx = 1\n"


def test_v01_snapshot_still_reverts(game):
    snap = game / ".oldgames" / "t"
    (snap / "files").mkdir(parents=True)
    (snap / "files" / "0").write_bytes(b"[A]\nx = 1\n")  # bytes: text mode would add \r on Windows
    (game / "s.ini").write_bytes(b"[A]\nx = 2\n")
    (game / "added.dll").write_bytes(b"x")
    (snap / "manifest.json").write_text(json.dumps({
        "recipe": "t", "created": "2026-11-22T22:59:32", "fixes": ["ini"],
        "backed_up": [{"path": str((game / "s.ini").resolve()), "stored": "files/0", "sha256":
                       __import__("hashlib").sha256(b"[A]\nx = 1\n").hexdigest()}],
        "added": [str((game / "added.dll").resolve())]}))
    engine.revert(ini_recipe(), game)
    assert (game / "s.ini").read_bytes() == b"[A]\nx = 1\n" and not (game / "added.dll").exists()
    assert not (game / ".oldgames").exists()


def test_registry_compat_roundtrip_and_conflict(game):
    reg = winapi.MemoryRegistry()
    exe = str((game / "game.exe").resolve())
    reg.set(winapi.HKCU, LAYERS_KEY, exe, "~ HIGHDPIAWARE")
    r = parse({"game": "t", "name": "T", "detect": {"exe": "game.exe"},
               "fixes": [{"compat": {"mode": "winxpsp3", "disable_fullscreen_optimizations": True}}]})
    engine.apply(engine.make_plan(r, game, registry=reg))
    assert reg.get(winapi.HKCU, LAYERS_KEY, exe) == "~ HIGHDPIAWARE WINXPSP3 DISABLEDXMAXIMIZEDWINDOWEDMODE"
    engine.revert(r, game, registry=reg)
    assert reg.get(winapi.HKCU, LAYERS_KEY, exe) == "~ HIGHDPIAWARE"

    engine.apply(engine.make_plan(r, game, registry=reg))
    reg.set(winapi.HKCU, LAYERS_KEY, exe, "~ RUNASADMIN")  # someone else changed it
    with pytest.raises(transaction.ConflictError):
        engine.revert(r, game, registry=reg)


def test_hklm_writes_refused():
    with pytest.raises(PermissionError):
        winapi.MemoryRegistry().set(winapi.HKLM, "x", "y", "z")
