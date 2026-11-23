import json
import sys

import pytest

from legacyforge import diagnostics as d
from legacyforge import monitor, registry, sessions, services
from pebuilder import build_pe


def test_exit_classification():
    assert d.classify_exit(0).kind == "normal"
    assert d.classify_exit(1).kind == "error-code"  # not by itself a crash
    av = d.classify_exit(-1073741819)  # 0xC0000005 as a signed int
    assert av.kind == "exception" and av.name == "EXCEPTION_ACCESS_VIOLATION"
    assert d.classify_exit(0xC0000017).meaning == "out of memory"
    assert d.classify_exit(0xC0000123).kind == "exception"
    assert d.classify_exit(5, killed_by_user=True).kind == "terminated"
    assert d.classify_exit(None).kind == "unknown"


NAMED = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>
<Provider Name='Application Error'/><EventID Qualifiers='0'>1000</EventID>
<TimeCreated SystemTime='2026-11-22T03:12:00.000Z'/></System><EventData>
<Data Name='AppName'>CivilizationV_DX11.exe</Data><Data Name='AppVersion'>1.0.3.279</Data>
<Data Name='ModuleName'>nvwgf2um.dll</Data><Data Name='ExceptionCode'>c0000005</Data>
<Data Name='FaultingOffset'>0x0012ab34</Data></EventData></Event>"""
POSITIONAL = """<Event><System><Provider Name="Application Error"/><EventID>1000</EventID>
<TimeCreated SystemTime="2026-11-22T03:12:00Z"/></System><EventData><Data>age2_x1.exe</Data><Data>1.0</Data>
<Data>0</Data><Data>ddraw.dll</Data><Data>7.1</Data><Data>0</Data><Data>c0000017</Data></EventData></Event>
<Event><System><Provider Name="Something Else"/><EventID>1000</EventID></System></Event>"""


def test_event_parsing_named_and_positional():
    e = d.parse_app_error_events(NAMED)[0]
    assert e["module"] == "nvwgf2um.dll" and e["exception"] == "EXCEPTION_ACCESS_VIOLATION"
    events = d.parse_app_error_events(POSITIONAL)
    assert len(events) == 1 and events[0]["app"] == "age2_x1.exe" and events[0]["exception_code"] == "0xC0000017"


def obs(code, runtime, **kw):
    return d.Observation(d.classify_exit(code), runtime, **kw)


def test_session_outcomes():
    assert d.session_outcome(obs(0, 3600))[0] == d.LAUNCH_OK
    assert d.session_outcome(obs(0, 3600, user_confirmed_gameplay=True))[0] == d.GAMEPLAY_PASSED
    assert d.session_outcome(obs(0xC0000005, 9000))[0] == d.CRASH
    assert d.session_outcome(obs(0xC0000135, 1))[0] == d.LAUNCH_FAILED
    assert d.session_outcome(obs(1, 2))[0] == d.LAUNCH_FAILED
    assert d.session_outcome(obs(1, 3600))[0] == d.LAUNCH_OK  # nonzero after a long run: not a crash
    assert d.session_outcome(obs(0, 3, handed_off=True))[0] == d.INCONCLUSIVE
    assert d.session_outcome(obs(0, 3600, events=[{"module": "x.dll"}]))[0] == d.CRASH


def S(outcome, hours, fp="a", scen=None):
    return {"outcome": outcome, "runtime_s": hours * 3600, "config_fingerprint": fp, "scenario": scen}


def test_compare_is_conservative():
    assert d.compare([S(d.CRASH, 1)], [S(d.LAUNCH_OK, 1)])[0] == d.INCONCLUSIVE
    base = [S(d.CRASH, 2), S(d.CRASH, 2), S(d.LAUNCH_OK, 2)]
    good = [S(d.LAUNCH_OK, 3), S(d.GAMEPLAY_PASSED, 3)]
    assert d.compare(base, good)[0] == d.IMPROVEMENT
    assert d.compare(good + [S(d.LAUNCH_OK, 3)], base)[0] == d.REGRESSION


def test_verify_stable_requires_defined_scenario():
    sc = {"id": "late-game", "duration_minutes": 120}
    ok = [S(d.GAMEPLAY_PASSED, 2.5, scen="late-game") for _ in range(3)]
    assert d.verify_stable(ok, sc)[0] == d.VERIFIED_STABLE
    assert d.verify_stable(ok[:2], sc)[0] == d.INCONCLUSIVE
    assert d.verify_stable(ok + [S(d.CRASH, 1, scen="late-game")], sc)[0] == d.CRASH
    assert d.verify_stable([S(d.GAMEPLAY_PASSED, 1, scen="late-game")] * 3, sc)[0] == d.INCONCLUSIVE
    assert d.verify_stable(ok[:2] + [S(d.GAMEPLAY_PASSED, 3, fp="b", scen="late-game")], sc)[0] == d.INCONCLUSIVE
    assert d.verify_stable(ok, {"id": "other"})[0] == d.NOT_TESTED


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("LEGACYFORGE_HOME", str(tmp_path / "lfhome"))


def test_profile_validation():
    with pytest.raises(ValueError):
        monitor.LaunchProfile(priority="realtime").validate()
    with pytest.raises(ValueError):
        monitor.LaunchProfile(affinity=[999]).validate()
    with pytest.raises(ValueError):
        services.profile_path("../x")


@pytest.mark.skipif(sys.platform == "win32", reason="uses a python script as the 'game'")
def test_monitor_runs_and_records(tmp_path):
    prof = monitor.LaunchProfile(args=["-c", "import time; x = bytearray(30_000_000); time.sleep(1.2); raise SystemExit(3)"],
                                 affinity=[0])
    res = monitor.run(sys.executable, prof, interval=0.3)
    assert res.exit_code == 3 and not res.killed
    assert res.peak["working_set_mb"] and res.peak["working_set_mb"] > 20


def test_sessions_store_purge_and_sanitize(tmp_path):
    s = sessions.Session(game="civ5", exe=str(tmp_path / "Users" / "player" / "game.exe"), exe_sha256="0" * 64,
                         started="2026-11-22T20:00:00", ended="2026-11-22T23:00:00", runtime_s=10800,
                         exit={"kind": "exception", "code_hex": "0xC0000005", "name": "X"}, outcome=d.CRASH,
                         reasons=["r"], config={"fixes": [{"recipe": "civ5"}]}, config_fingerprint="f",
                         memory={"peak": {"private_mb": 3900}},
                         events=[{"module": "nvwgf2um.dll", "pid": "1234"}],
                         system={"windows_build": 26100, "gpu": "RTX"})
    sessions.save(s)
    assert len(sessions.load_all("civ5")) == 1
    rec = sessions.community_record(sessions.load_all("civ5")[0])
    assert rec["faulting_modules"] == ["nvwgf2um.dll"] and "exe" not in rec
    from pathlib import Path
    assert str(Path.home()) not in json.dumps(sessions.sanitize({"p": str(Path.home() / "x")}))
    assert sessions.purge("civ5") == 1 and sessions.load_all("civ5") == []


def test_settings_validation():
    with pytest.raises(KeyError):
        sessions.save_settings({"upload_everything": "1"})
    assert sessions.save_settings({"retention_days": "30"})["retention_days"] == 30


def test_registry_sign_verify_install(tmp_path):
    pytest.importorskip("cryptography")
    bundle = tmp_path / "bundle"
    (bundle / "recipes").mkdir(parents=True)
    (bundle / "recipes" / "x.yaml").write_text("game: x\nname: X\nfixes: []\n")
    key, kid = registry.generate_key(tmp_path / "keys")
    registry.build_and_sign(bundle, key, name="test", version="1", author="me")
    with pytest.raises(registry.RegistryError, match="trust store"):
        registry.verify(bundle)
    registry.trust_key(tmp_path / "keys" / f"{kid}.pub")
    assert registry.install(bundle) == ["x"]
    (bundle / "recipes" / "x.yaml").write_text("game: x\nname: X (tampered)\nfixes: []\n")
    with pytest.raises(registry.RegistryError, match="hash"):
        registry.verify(bundle)
    m = json.loads((bundle / "manifest.json").read_text())
    m["recipes"][0]["file"] = "../../etc/passwd"
    (bundle / "manifest.json").write_text(json.dumps(m))
    with pytest.raises(registry.RegistryError, match="signature"):
        registry.verify(bundle)


def test_services_analyze_end_to_end(tmp_path):
    d = tmp_path / "Game"
    d.mkdir()
    (d / "game.exe").write_bytes(build_pe(imports={"ddraw.dll": ["DirectDrawCreate"], "d3dx9_43.dll": ["D3DXCreateSprite"]}))
    rep = services.analyze(d / "game.exe", with_system=False, check_signature=False)
    ids = [r["id"] for r in rep["recommendations"]]
    assert "graphics.cnc-ddraw" in ids and "memory.laa" in ids
    assert rep["dependencies"][0]["runtime"].startswith("DirectX")
    from legacyforge import cli, report
    assert "Recommendations" in report.to_text(rep)
    assert cli.main(["analyze", str(d / "game.exe"), "--no-system", "--json", str(tmp_path / "r.json")]) == 0
    assert json.loads((tmp_path / "r.json").read_text())["format"] == "legacyforge-report/1"
