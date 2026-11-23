"""MCP server tests: guardrails at the function level, plus a real stdio
protocol round-trip (an MCP client talking to the server process)."""

import json
import os
import sys

import pytest

mcp = pytest.importorskip("mcp")

from legacyforge import mcp_tools as t  # noqa: E402
from legacyforge.recipe import data_home  # noqa: E402
from pebuilder import build_pe  # noqa: E402

RECIPE = """game: testgame
name: Test Game
detect: {exe: game.exe}
fixes:
  - ini: {file: s.ini, set: {A: {x: 2}}}
  - laa: {}
    optional: true
"""


@pytest.fixture
def env(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / "recipes").mkdir(parents=True)
    (home / "recipes" / "testgame.yaml").write_text(RECIPE)
    monkeypatch.setenv("LEGACYFORGE_HOME", str(home))
    g = tmp_path / "Game"
    g.mkdir()
    (g / "game.exe").write_bytes(build_pe(imports={"d3d9.dll": ["Direct3DCreate9"]}))
    (g / "s.ini").write_text("[A]\nx = 1\n")
    return g


def test_read_only_server_refuses_writes(env):
    pol = t.Policy()
    plan = t.plan_recipe(pol, "testgame", str(env))
    assert plan["plan_token"] and plan["steps"]
    with pytest.raises(t.ToolRefused, match="read-only"):
        t.apply_recipe(pol, "testgame", plan["plan_token"], str(env))
    assert (env / "s.ini").read_text() == "[A]\nx = 1\n"


def test_plan_token_binds_the_shown_plan(env):
    pol = t.Policy(allow_writes=True)
    plan = t.plan_recipe(pol, "testgame", str(env))
    with pytest.raises(t.ToolRefused, match="doesn't match"):  # changing a parameter after the preview
        t.apply_recipe(pol, "testgame", plan["plan_token"], str(env), params={"ini": {"set": {"A": {"x": 9}}}})
    with pytest.raises(t.ToolRefused, match="doesn't match"):
        t.apply_recipe(pol, "testgame", "0" * 24, str(env))
    other = t.Policy(allow_writes=True)  # tokens don't survive a server restart
    with pytest.raises(t.ToolRefused):
        t.apply_recipe(other, "testgame", plan["plan_token"], str(env))
    out = t.apply_recipe(pol, "testgame", plan["plan_token"], str(env))
    assert "x = 2" in (env / "s.ini").read_text() and out["applied"]
    t.revert_recipe(pol, "testgame", str(env))
    assert (env / "s.ini").read_text() == "[A]\nx = 1\n"


def test_exe_patching_needs_its_own_flag(env):
    pol = t.Policy(allow_writes=True)
    plan = t.plan_recipe(pol, "testgame", str(env), enable_optional=["laa"])
    assert plan["plan_token"] is None and plan["approvals_still_needed"][0]["token"] == "laa"
    plan = t.plan_recipe(pol, "testgame", str(env), enable_optional=["laa"], approvals=["laa"])
    with pytest.raises(t.ToolRefused, match="exe-patching"):
        t.apply_recipe(pol, "testgame", plan["plan_token"], str(env), enable_optional=["laa"], approvals=["laa"])


def test_launch_disabled_by_default(env):
    with pytest.raises(t.ToolRefused, match="allow-launch"):
        t.launch_game(t.Policy(allow_writes=True), "testgame")


def test_audit_log(env):
    t.wrap_write(t.Policy(), t.apply_recipe)  # wrapping itself doesn't log
    t.analyze_executable(exe_path=str(env / "game.exe"), include_system=False)
    with pytest.raises(t.ToolRefused):
        t.wrap_write(t.Policy(), t.apply_recipe)(recipe_id="testgame", plan_token="x", game_dir=str(env))
    lines = [json.loads(x) for x in (data_home() / "mcp-audit.log").read_text().splitlines()]
    assert [(x["tool"], x["outcome"]) for x in lines] == [("analyze_executable", "ok"), ("apply_recipe", "refused")]


def test_record_gameplay_requires_user_words(env):
    from legacyforge import sessions

    s = sessions.Session(game="testgame", exe="g", exe_sha256="0" * 64, started="2026-11-23T00:00:00",
                         ended="2026-11-23T02:00:00", runtime_s=7200, exit={"kind": "normal", "code": 0,
                         "code_hex": "0x00000000", "name": None, "meaning": None}, outcome="launch-successful",
                         reasons=[], config={}, config_fingerprint="f", memory={})
    sessions.save(s)
    pol = t.Policy(allow_writes=True)
    with pytest.raises(t.ToolRefused):
        t.record_gameplay_result(pol, "testgame", s.id, True, "")
    out = t.record_gameplay_result(pol, "testgame", s.id, True, "yep, two hours no crash")
    assert out["outcome"] == "gameplay-test-passed"


@pytest.mark.skipif(sys.platform == "win32", reason="stdio subprocess test tuned for POSIX CI")
def test_stdio_protocol_roundtrip(env):
    import anyio
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    params = StdioServerParameters(command=sys.executable, args=["-m", "legacyforge.mcp_server", "--allow-writes"],
                                   env={**os.environ, "PYTHONPATH": os.pathsep.join(sys.path)})

    async def go():
        async with stdio_client(params) as (r, w):
            async with ClientSession(r, w) as cs:
                await cs.initialize()
                names = {x.name for x in (await cs.list_tools()).tools}
                assert {"analyze_executable", "plan_recipe", "apply_recipe"} <= names and "launch_game" not in names
                res = await cs.call_tool("analyze_executable", {"exe_path": str(env / "game.exe"), "include_system": False})
                report = json.loads(res.content[0].text)
                assert report["executable"]["arch"] == "x32"
                res = await cs.call_tool("plan_recipe", {"recipe_id": "testgame", "game_dir": str(env)})
                plan = json.loads(res.content[0].text)
                res = await cs.call_tool("apply_recipe", {"recipe_id": "testgame", "game_dir": str(env),
                                                          "plan_token": plan["plan_token"]})
                assert not res.is_error, res.content
                return True

    assert anyio.run(go)
    assert "x = 2" in (env / "s.ini").read_text()
