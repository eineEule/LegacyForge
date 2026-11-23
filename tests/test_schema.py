import pytest
import yaml

from legacyforge import engine
from legacyforge.fsutil import UnsafePathError
from legacyforge.recipe import RecipeError, bundled, load_file, parse
from pebuilder import build_pe

BASE = {"game": "t", "name": "T", "detect": {"exe": "game.exe"}, "fixes": []}


def p(**kw):
    return parse({**BASE, **kw})


def test_v1_recipe_still_loads():
    r = p(fixes=[{"laa": "game.exe"}], notes="hello")
    assert r.schema_version == 1 and r.notes == ["hello"]


def test_unknown_top_level_key():
    with pytest.raises(RecipeError, match="unknown top-level"):
        p(run="calc.exe")


def test_unknown_fix_param():
    with pytest.raises(RecipeError, match="unknown parameter"):
        p(fixes=[{"dxvk": {"api": "d3d9", "command": "calc.exe"}}])


def test_bad_hash_and_unknown_edition():
    with pytest.raises(RecipeError, match="SHA-256"):
        p(schema_version=2, editions=[{"id": "a", "name": "A", "sha256": ["nothex"]}])
    with pytest.raises(RecipeError, match="unknown edition"):
        p(schema_version=2, editions=[{"id": "a", "name": "A"}], fixes=[{"laa": {}, "editions": ["b"]}])


def test_known_issue_requires_evidence():
    with pytest.raises(RecipeError, match="evidence"):
        p(schema_version=2, known_issues=[{"id": "x", "summary": "crashes"}])


def test_python_tags_rejected(tmp_path):
    f = tmp_path / "evil.yaml"
    f.write_text("game: !!python/object/apply:os.system ['calc.exe']\nname: x\nfixes: []\n")
    with pytest.raises(RecipeError, match="invalid YAML"):
        load_file(f)


def test_oversized_recipe(tmp_path):
    f = tmp_path / "big.yaml"
    f.write_text("notes: '" + "x" * 300_000 + "'\n")
    with pytest.raises(RecipeError, match="too large"):
        load_file(f)


def test_bad_game_id():
    with pytest.raises(RecipeError):
        parse({**BASE, "game": "../../etc"})


def test_path_traversal_in_fix_paths(tmp_path):
    d = tmp_path / "G"
    d.mkdir()
    (d / "game.exe").write_bytes(build_pe())
    r = p(fixes=[{"ini": {"file": "../outside.ini", "set": {"A": {"x": 1}}}}])
    with pytest.raises(UnsafePathError):
        engine.make_plan(r, d)


def test_incompatible_fixes(tmp_path):
    d = tmp_path / "G"
    d.mkdir()
    (d / "game.exe").write_bytes(build_pe())
    r = p(schema_version=2, fixes=[{"laa": {}}, {"compat": {"mode": "win98"}}],
          incompatible_fixes=[{"fixes": ["laa", "compat"], "reason": "test"}])
    with pytest.raises(RecipeError, match="incompatible"):
        engine.make_plan(r, d, approvals={"laa"})


def test_order_and_edition_filter():
    r = p(schema_version=2, editions=[{"id": "a", "name": "A"}, {"id": "b", "name": "B"}],
          fixes=[{"compat": {"mode": "win98"}, "order": 2},
                 {"laa": {}, "order": 1, "editions": ["a"]}])
    assert [e.fix.type for e in r.active(set(), "a")] == ["laa", "compat"]
    assert [e.fix.type for e in r.active(set(), "b")] == ["compat"]


def test_bundled_recipes_valid_and_honest():
    rs = bundled()
    assert {"civ4", "civ5", "aoe2-1999", "rise-of-nations-ee", "rise-of-nations-2003"} <= set(rs)
    for r in rs.values():
        for e in r.evidence:
            assert e["outcome"] != "verified-stable", "no bundled recipe may claim verified stability"
        for f in r.fixes:
            assert f.status != "verified"
