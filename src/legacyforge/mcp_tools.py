"""Tool implementations behind the LegacyForge MCP server.

Plain functions over `services`, kept separate from the MCP wiring so they
can be tested without an MCP client. Guardrails live here, not in prompts:

- Read-only tools are always available.
- Write tools exist only when the server was started with --allow-writes
  (and exe patching / launching need their own flags).
- `apply_recipe` only accepts a plan_token from `plan_recipe`, and the token
  binds the exact recipe, folder, fixes, parameters, approvals and exe hash.
  If anything differs from what the user was shown, apply is refused.
- Every call is appended to a local audit log (sanitized).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import diagnostics, engine, recipe, services, sessions
from .recipe import data_home

EXE_APPROVALS = {"laa", "laa-signed"}


class ToolRefused(Exception):
    """A guardrail refused the call. The message is shown to the assistant."""


@dataclass
class Policy:
    allow_writes: bool = False
    allow_exe_patching: bool = False
    allow_launch: bool = False
    secret: bytes = field(default_factory=lambda: secrets.token_bytes(32))

    def describe(self) -> dict:
        return {"writes": self.allow_writes, "exe_patching": self.allow_exe_patching,
                "launch": self.allow_launch}


# audit ---------------------------------------------------------------------

def audit(tool: str, args: dict, outcome: str, detail: str = "") -> None:
    p = data_home() / "mcp-audit.log"
    p.parent.mkdir(parents=True, exist_ok=True)
    entry = sessions.sanitize({"time": time.strftime("%Y-%m-%dT%H:%M:%S"), "tool": tool, "args": args,
                               "outcome": outcome, "detail": detail[:500]})
    with open(p, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, default=str) + "\n")


def audited(fn):
    def wrapper(*args, **kwargs):
        name = fn.__name__
        try:
            result = fn(*args, **kwargs)
        except ToolRefused as e:
            audit(name, kwargs, "refused", str(e))
            raise
        except Exception as e:
            audit(name, kwargs, "error", f"{type(e).__name__}: {e}")
            raise
        audit(name, kwargs, "ok")
        return result

    wrapper.__name__ = fn.__name__
    wrapper.__doc__ = fn.__doc__
    wrapper.__wrapped__ = fn
    return wrapper


# read-only -------------------------------------------------------------------

@audited
def discover_games(extra_dirs: list[str] | None = None) -> dict:
    return services.discover([Path(d) for d in extra_dirs or []])


@audited
def analyze_executable(exe_path: str, include_system: bool = True) -> dict:
    p = Path(exe_path)
    if p.is_dir():
        from .analysis import candidate_exes

        return {"folder": str(p), "candidate_executables": [str(x) for x in candidate_exes(p)],
                "hint": "call analyze_executable on one of these"}
    return services.analyze(p, with_system=include_system)


@audited
def list_recipes() -> list[dict]:
    out = []
    for r in recipe.all_recipes().values():
        out.append({"id": r.id, "name": r.name, "exe": r.exe, "steam_appid": r.steam_appid,
                    "fixes": [{"type": e.fix.type, "optional": e.optional, "status": e.status,
                               "note": e.note} for e in r.fixes],
                    "known_issues": r.known_issues, "test_plan": [t["id"] for t in r.test_plan],
                    "notes": r.notes})
    return out


def _token(policy: Policy, p: engine.Plan) -> str:
    material = json.dumps({
        "recipe": p.recipe.id, "dir": str(p.ctx.game_dir.resolve()), "exe": p.exe_sha256,
        "fixes": [[e.fix.type, e.fix.params] for e in p.entries],
        "approvals": sorted(p.ctx.approvals),
    }, sort_keys=True, default=str)
    return hmac.new(policy.secret, material.encode(), hashlib.sha256).hexdigest()[:24]


def _build_plan(recipe_id, game_dir, enable_optional, approvals, params) -> engine.Plan:
    return services.plan(recipe_id, Path(game_dir) if game_dir else None, enable=set(enable_optional or []),
                         approvals=set(approvals or []), params=params or {})


def plan_recipe(policy: Policy, recipe_id: str, game_dir: str | None = None,
                enable_optional: list[str] | None = None, approvals: list[str] | None = None,
                params: dict | None = None) -> dict:
    p = _build_plan(recipe_id, game_dir, enable_optional, approvals, params)
    missing = p.missing_approvals
    return {
        "recipe": p.recipe.id, "game_dir": str(p.ctx.game_dir),
        "edition": p.edition.name if p.edition else None, "edition_confirmed_by_hash": p.edition is not None,
        "steps": p.lines(),
        "approvals_given": sorted(p.ctx.approvals),
        "approvals_still_needed": [{"token": t, "reason": why} for t, why in missing],
        "modifies_executable": any(e.fix.modifies_executable for e in p.entries),
        "plan_token": None if missing else _token(policy, p),
        "notes": p.recipe.notes,
        "how_to_apply": ("Show these steps to the user. Only if they explicitly agree, call apply_recipe with "
                         "the same arguments and this plan_token." if not missing else
                         "Explain each needed approval to the user. Re-plan with an approval only if the user "
                         "explicitly grants it in their own words."),
        "server_policy": policy.describe(),
    }


def apply_recipe(policy: Policy, recipe_id: str, plan_token: str, game_dir: str | None = None,
                 enable_optional: list[str] | None = None, approvals: list[str] | None = None,
                 params: dict | None = None) -> dict:
    if not policy.allow_writes:
        raise ToolRefused("this LegacyForge server is read-only (start it with --allow-writes)")
    if set(approvals or []) & EXE_APPROVALS and not policy.allow_exe_patching:
        raise ToolRefused("executable patching is disabled on this server (start it with --allow-exe-patching)")
    p = _build_plan(recipe_id, game_dir, enable_optional, approvals, params)
    if p.missing_approvals:
        raise ToolRefused(f"plan still needs approvals: {[t for t, _ in p.missing_approvals]}")
    if not hmac.compare_digest(plan_token or "", _token(policy, p)):
        raise ToolRefused("plan_token doesn't match: the plan changed since it was shown "
                          "(different fixes, approvals, folder or exe). Call plan_recipe again and show "
                          "the user the new plan.")
    results = engine.apply(p)
    return {"applied": results, "undo": f"revert_recipe('{p.recipe.id}')"}


def revert_recipe(policy: Policy, recipe_id: str, game_dir: str | None = None, mode: str = "safe") -> dict:
    if not policy.allow_writes:
        raise ToolRefused("this LegacyForge server is read-only (start it with --allow-writes)")
    if mode not in ("safe", "keep_current", "force"):
        raise ToolRefused("mode must be safe, keep_current or force")
    log = services.revert(recipe_id, Path(game_dir) if game_dir else None,
                          force=mode == "force", keep_current=mode == "keep_current")
    return {"reverted": log}


def recover_recipe(policy: Policy, recipe_id: str, game_dir: str | None = None) -> dict:
    if not policy.allow_writes:
        raise ToolRefused("this LegacyForge server is read-only (start it with --allow-writes)")
    r = recipe.find(recipe_id)
    d = Path(game_dir) if game_dir else services.detect.locate(r)
    return {"recovered": engine.recover(r, d)}


@audited
def recipe_status(recipe_id: str, game_dir: str | None = None) -> dict:
    r = recipe.find(recipe_id)
    d = Path(game_dir) if game_dir else services.detect.locate(r)
    if d is None:
        return {"recipe": recipe_id, "found": False}
    st = engine.status(r, d)
    if not st:
        return {"recipe": recipe_id, "game_dir": str(d), "applied": False}
    return {"recipe": recipe_id, "game_dir": str(d), "applied": True, "state": st["state"],
            "created": st["created"], "fixes": st["fixes"], "tracked_changes": len(st["entries"]),
            "changed_since_patch": st["conflicts"]}


@audited
def modification_history(game_dir: str) -> list[dict]:
    return services.history(Path(game_dir))


@audited
def list_sessions(game: str | None = None, limit: int = 20) -> list[dict]:
    ss = sorted(sessions.load_all(game), key=lambda s: s["started"], reverse=True)[:max(1, min(limit, 200))]
    return [{"id": s["id"], "game": s["game"], "started": s["started"], "minutes": round(s["runtime_s"] / 60, 1),
             "outcome": s["outcome"], "reasons": s["reasons"], "exit": s["exit"].get("code_hex"),
             "faulting_modules": sorted({e.get("module") for e in s.get("events", []) if e.get("module")}),
             "peak_memory_mb": s.get("memory", {}).get("peak"), "config": s["config_fingerprint"],
             "fixes": s["config"].get("fixes"), "scenario": s.get("scenario"), "notes": s.get("notes"),
             "graphics_modules": sessions.graphics_modules(s.get("modules", []))}
            for s in ss]


@audited
def compare_sessions(game: str) -> list[dict]:
    return services.compare(game)


@audited
def verify_stability(game: str, scenario: str) -> dict:
    verdict, reasons = services.verify(game, scenario)
    return {"verdict": verdict, "reasons": reasons}


# launch / confirmation ------------------------------------------------------------

def launch_game(policy: Policy, target: str, game_dir: str | None = None, scenario: str | None = None,
                max_minutes: float | None = None, notes: str | None = None) -> dict:
    """Starts monitoring in a separate process so long play sessions don't block the chat."""
    if not policy.allow_launch:
        raise ToolRefused("launching is disabled on this server (start it with --allow-launch)")
    args = [sys.executable, "-m", "legacyforge", "launch", target, "--no-confirm"]
    if game_dir:
        args += ["--game-dir", game_dir]
    if scenario:
        args += ["--scenario", scenario]
    if max_minutes:
        args += ["--minutes", str(float(max_minutes))]
    if notes:
        args += ["--notes", notes[:500]]
    logs = data_home() / "launches"
    logs.mkdir(parents=True, exist_ok=True)
    log = logs / f"{time.strftime('%Y%m%d-%H%M%S')}.log"
    flags = 0
    if sys.platform == "win32":
        flags = 0x00000008 | 0x00000200  # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
    with open(log, "wb") as out:
        proc = subprocess.Popen(args, stdout=out, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                shell=False, creationflags=flags, start_new_session=sys.platform != "win32",
                                env=os.environ.copy())
    return {"started": True, "monitor_pid": proc.pid, "log": str(log),
            "next": "When the user says they've finished playing, call list_sessions for the result, then ask "
                    "whether the gameplay test passed and record it with record_gameplay_result."}


def record_gameplay_result(policy: Policy, game: str, session_id: str, passed: bool,
                           user_words: str) -> dict:
    """Record the user's own verdict on a session. `user_words` must quote what the user said."""
    if not policy.allow_writes:
        raise ToolRefused("this LegacyForge server is read-only (start it with --allow-writes)")
    if not user_words or len(user_words.strip()) < 2:
        raise ToolRefused("quote the user's own words confirming the result")
    return sessions.record_confirmation(game, session_id, passed, f"user (via assistant): {user_words[:200]}")


def wrap_write(policy: Policy, fn):
    """Bind the policy and audit a write tool."""
    def bound(**kwargs):
        try:
            result = fn(policy, **kwargs)
        except ToolRefused as e:
            audit(fn.__name__, kwargs, "refused", str(e))
            raise
        except Exception as e:
            audit(fn.__name__, kwargs, "error", f"{type(e).__name__}: {e}")
            raise
        audit(fn.__name__, kwargs, "ok")
        return result

    return bound


__all__ = ["Policy", "ToolRefused", "diagnostics"]
