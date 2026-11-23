"""LegacyForge MCP server for Claude Desktop / Claude Code (stdio).

    legacyforge-mcp                       # read-only: analyze, plan, history, sessions
    legacyforge-mcp --allow-writes        # + apply/revert recipes (non-exe fixes), record results
    legacyforge-mcp --allow-writes --allow-exe-patching --allow-launch

See docs/CLAUDE.md for setup.
"""

from __future__ import annotations

import argparse
import sys

from . import __version__
from . import mcp_tools as t

try:  # MCP Python SDK 2.x
    from mcp.server.mcpserver import MCPServer as _Server
except ImportError:  # 1.x
    try:
        from mcp.server.fastmcp import FastMCP as _Server  # type: ignore[no-redef]
    except ImportError:  # pragma: no cover
        _Server = None
from mcp.types import ToolAnnotations  # noqa: E402

READ = ToolAnnotations(read_only_hint=True, destructive_hint=False, open_world_hint=False)
WRITE = ToolAnnotations(read_only_hint=False, destructive_hint=True, idempotent_hint=False, open_world_hint=False)

INSTRUCTIONS = """LegacyForge helps make legacy 32-bit Windows games run on modern Windows.

Rules you must follow:
1. Start with read-only tools (analyze_executable, list_recipes, recipe_status, list_sessions).
   Explain findings in plain words, including how strong the evidence is. A 32-bit game is not
   automatically unstable.
2. Never change anything without showing the user the plan from plan_recipe and getting their
   explicit agreement for that specific plan.
3. Approval tokens (laa, laa-signed, replace-foreign, dgvoodoo2-unpinned) represent the USER's consent.
   Only include one after the user has explicitly agreed to it in their own words, after you explained
   its risk. Never add approvals on your own initiative.
4. Patching the executable (laa) is the riskiest step: recommend it only with evidence (recipe hash match,
   a recorded memory crash, or the user's report) and say it can break some games.
5. Do not claim a fix worked from a launch alone. Use sessions: compare_sessions and verify_stability.
6. If revert reports files changed since the patch, explain the options; use mode=force only if the user asks.
"""


def build_server(policy: t.Policy):
    if _Server is None:
        raise SystemExit("The MCP SDK is not installed: pip install legacyforge[mcp]")
    s = _Server("legacyforge", instructions=INSTRUCTIONS + f"\nServer policy: {policy.describe()}")

    s.tool(annotations=READ, description="Find installed games (Steam, GOG, given folders) and which have LegacyForge recipes.")(t.discover_games)
    s.tool(annotations=READ, description="Read-only compatibility report for a game executable (or list executables in a folder): architecture, 4 GiB flag, graphics API evidence, protection, dependencies, system, recommendations.")(t.analyze_executable)
    s.tool(annotations=READ, description="List available game recipes with their fixes, known issues and test plans.")(t.list_recipes)
    s.tool(annotations=READ, description="Is a recipe applied to a game folder, and has anything changed since?")(t.recipe_status)
    s.tool(annotations=READ, description="Modification history (all LegacyForge changes) for a game folder.")(t.modification_history)
    s.tool(annotations=READ, description="Recorded play sessions: outcome, crash evidence, memory peaks, configuration.")(t.list_sessions)
    s.tool(annotations=READ, description="Compare sessions across configurations (baseline vs with fixes).")(t.compare_sessions)
    s.tool(annotations=READ, description="Check whether a game is verified stable under a recipe test scenario.")(t.verify_stability)

    @s.tool(annotations=READ, description="Preview what applying a recipe would change. Returns steps, approvals still needed, and a plan_token for apply_recipe. Changes nothing.")
    def plan_recipe(recipe_id: str, game_dir: str | None = None, enable_optional: list[str] | None = None,
                    approvals: list[str] | None = None, params: dict | None = None) -> dict:
        return t.wrap_write(policy, t.plan_recipe)(recipe_id=recipe_id, game_dir=game_dir,
                                                   enable_optional=enable_optional, approvals=approvals,
                                                   params=params)

    if policy.allow_writes:
        @s.tool(annotations=WRITE, description="Apply a recipe exactly as previewed by plan_recipe (same arguments plus its plan_token). Transactional and reversible. Only call after the user explicitly agreed to the shown plan.")
        def apply_recipe(recipe_id: str, plan_token: str, game_dir: str | None = None,
                         enable_optional: list[str] | None = None, approvals: list[str] | None = None,
                         params: dict | None = None) -> dict:
            return t.wrap_write(policy, t.apply_recipe)(recipe_id=recipe_id, plan_token=plan_token,
                                                        game_dir=game_dir, enable_optional=enable_optional,
                                                        approvals=approvals, params=params)

        @s.tool(annotations=WRITE, description="Undo a recipe. mode: safe (stop if files changed since the patch), keep_current (restore everything else), force (overwrite changed files; only if the user asks).")
        def revert_recipe(recipe_id: str, game_dir: str | None = None, mode: str = "safe") -> dict:
            return t.wrap_write(policy, t.revert_recipe)(recipe_id=recipe_id, game_dir=game_dir, mode=mode)

        @s.tool(annotations=WRITE, description="Roll back an apply that was interrupted (crash or power loss).")
        def recover_recipe(recipe_id: str, game_dir: str | None = None) -> dict:
            return t.wrap_write(policy, t.recover_recipe)(recipe_id=recipe_id, game_dir=game_dir)

        @s.tool(annotations=WRITE, description="Record the user's own verdict on a play session (did the gameplay test pass?). Quote the user's words in user_words.")
        def record_gameplay_result(game: str, session_id: str, passed: bool, user_words: str) -> dict:
            return t.wrap_write(policy, t.record_gameplay_result)(game=game, session_id=session_id,
                                                                  passed=passed, user_words=user_words)

    if policy.allow_launch:
        @s.tool(annotations=WRITE, description="Launch a game (recipe id or exe path) with monitoring in the background; a session is saved when it exits.")
        def launch_game(target: str, game_dir: str | None = None, scenario: str | None = None,
                        max_minutes: float | None = None, notes: str | None = None) -> dict:
            return t.wrap_write(policy, t.launch_game)(target=target, game_dir=game_dir, scenario=scenario,
                                                       max_minutes=max_minutes, notes=notes)

    @s.prompt(description="Troubleshoot a legacy game: analyze, check history and sessions, then propose a plan.")
    def troubleshoot_game(game: str, symptom: str = "") -> str:
        return (f"Help me troubleshoot {game}. Symptom: {symptom or 'not specified'}.\n"
                "1. Find it (discover_games / list_recipes) and run analyze_executable on its main exe.\n"
                "2. Check recipe_status and list_sessions for evidence.\n"
                "3. Explain what you found and how confident you are.\n"
                "4. Propose the smallest reversible next step with plan_recipe, and wait for my go-ahead.")

    return s


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="legacyforge-mcp", description="LegacyForge MCP server (stdio)")
    ap.add_argument("--allow-writes", action="store_true", help="enable apply/revert/recover and result recording")
    ap.add_argument("--allow-exe-patching", action="store_true", help="allow approvals that modify game executables (laa)")
    ap.add_argument("--allow-launch", action="store_true", help="enable launching games with monitoring")
    ap.add_argument("--version", action="version", version=f"legacyforge-mcp {__version__}")
    a = ap.parse_args(argv)
    if a.allow_exe_patching and not a.allow_writes:
        ap.error("--allow-exe-patching requires --allow-writes")
    policy = t.Policy(a.allow_writes, a.allow_exe_patching, a.allow_launch)
    print(f"legacyforge-mcp {__version__} policy={policy.describe()}", file=sys.stderr)
    build_server(policy).run("stdio")
    return 0


if __name__ == "__main__":
    sys.exit(main())
