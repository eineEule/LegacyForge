from legacyforge import analysis, recommend
from legacyforge.recipe import parse
from pebuilder import build_pe


def analyze(tmp_path, **kw):
    d = tmp_path / "G"
    d.mkdir(exist_ok=True)
    (d / "g.exe").write_bytes(build_pe(**kw))
    return analysis.analyze(d / "g.exe", check_signature=False)


def recs(a, **ctx):
    return {r.id: r for r in recommend.recommend(recommend.Context(exe=a, **ctx))}


def test_unknown_32bit_game_gets_only_experimental_laa(tmp_path):
    r = recs(analyze(tmp_path, imports={"kernel32.dll": ["Sleep"]}))
    laa = r["memory.laa"]
    assert laa.category == recommend.EXPERIMENTAL and laa.confidence == "low"
    assert laa.modifies_executable and laa.rollback and not laa.needs_admin


def test_memory_crash_evidence_raises_category(tmp_path):
    r = recs(analyze(tmp_path, imports={"kernel32.dll": ["Sleep"]}), observed={"memory_crash": True})
    assert r["memory.laa"].category == recommend.SUGGESTED


def test_64bit_or_laa_gets_no_memory_fix(tmp_path):
    assert "memory.laa" not in recs(analyze(tmp_path, pe32=False))
    assert "memory.laa" not in recs(analyze(tmp_path, characteristics=0x0122))


def test_signed_and_protected_are_blocked(tmp_path):
    a = analyze(tmp_path, section_names=(".text", ".securom"), signature=b"\x10\0\0\0\0\x02\x02\0" + b"s" * 8)
    r = recs(a)
    blocked = " ".join(r["memory.laa"].blocked_by)
    assert "signed" in blocked and "SecuROM" in blocked
    assert "info.protection" in r


def test_directdraw_only_suggests_cnc_ddraw(tmp_path):
    r = recs(analyze(tmp_path, imports={"ddraw.dll": ["DirectDrawCreate"]}))
    assert r["graphics.cnc-ddraw"].category == recommend.SUGGESTED
    r2 = recs(analyze(tmp_path, imports={"ddraw.dll": ["DirectDrawCreate"], "d3d9.dll": ["Direct3DCreate9"]}))
    assert "graphics.cnc-ddraw" not in r2  # cnc-ddraw does not support Direct3D games


def test_dxvk_blocked_without_32bit_vulkan(tmp_path):
    a = analyze(tmp_path, imports={"d3d9.dll": ["Direct3DCreate9"]})
    r = recs(a, system={"vulkan": {"loader_32bit": False}})
    assert r["graphics.dxvk-d3d9"].category == recommend.EXPERIMENTAL
    assert any("Vulkan" in b for b in r["graphics.dxvk-d3d9"].blocked_by)


def test_missing_runtime(tmp_path):
    a = analyze(tmp_path)
    r = recs(a, deps=[{"dll": "d3dx9_43.dll", "runtime": "DirectX End-User Runtimes (June 2010)",
                       "status": "missing", "source": "Microsoft"}])
    rec = next(v for k, v in r.items() if k.startswith("runtime."))
    assert rec.needs_admin and not rec.modifies_executable


def test_recipe_hash_match_is_known_fix(tmp_path):
    a = analyze(tmp_path)
    recipe = parse({"game": "g", "name": "G", "detect": {"exe": "g.exe"}, "fixes": [{"laa": {}}]})
    assert recs(a, recipe=recipe, recipe_hash_match=True)["memory.laa"].category == recommend.KNOWN_GAME
    assert recs(a, recipe=recipe, recipe_hash_match=False)["memory.laa"].category == recommend.SUGGESTED


def test_every_recommendation_has_required_fields(tmp_path):
    a = analyze(tmp_path, imports={"ddraw.dll": ["x"], "d3d9.dll": ["y"]})
    for r in recommend.recommend(recommend.Context(exe=a)):
        d = r.to_dict()
        for k in ("problem", "evidence", "benefit", "risk", "needs_admin", "modifies_executable",
                  "rollback", "verification", "confidence", "category"):
            assert d[k] is not None and d[k] != ""


def test_recipe_and_generic_rule_merge(tmp_path):
    a = analyze(tmp_path, imports={"ddraw.dll": ["DirectDrawCreate"]})
    r = parse({"game": "g", "name": "G", "detect": {"exe": "g.exe"}, "fixes": [{"cnc-ddraw": {}, "status": "known"}]})
    out = recommend.recommend(recommend.Context(exe=a, recipe=r))
    cnc = [x for x in out if x.fix_type == "cnc-ddraw"]
    assert len(cnc) == 1 and cnc[0].category == recommend.KNOWN_GAME
    assert any("imports ddraw.dll" in e for e in cnc[0].evidence) and any("recipe" in e for e in cnc[0].evidence)
