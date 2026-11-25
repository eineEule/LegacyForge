"""Application services: the stable API the CLI (and a future GUI) call.

Workflow: discover -> analyze -> recommend -> plan/back up/apply -> launch ->
monitor -> verify -> restore. Every function returns plain data (dicts or
dataclasses); none of them print or prompt, so a GUI can reuse them as-is.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import asdict
from pathlib import Path

from . import analysis, deps, detect, diagnostics, engine, monitor, recipe, sessions, system, transaction
from .recommend import Context as RecContext
from .recommend import recommend as _recommend


# discover / analyze / recommend ---------------------------------------------

def discover(extra_dirs: list[Path] | None = None) -> dict:
    games = detect.discover(extra_dirs)
    known = []
    for r in recipe.all_recipes().values():
        d = detect.locate(r)
        if d:
            known.append({"recipe": r.id, "name": r.name, "dir": str(d),
                          "applied": engine.status(r, d) is not None})
    return {"recipes_found": known, "installed": games}


def analyze(exe: Path, *, with_system: bool = True, check_signature: bool = True) -> dict:
    """Full read-only compatibility report for one executable."""
    exe = Path(exe)
    sysinfo = system.inspect() if with_system else None
    a = analysis.analyze(exe, check_signature=check_signature,
                         os_64bit=sysinfo.os_64bit if sysinfo else True)
    # annotate proxies LegacyForge installed
    for p in a.folder["proxy_dlls"]:
        p["owner"] = transaction.owner_of(exe.parent / p["name"], exe.parent)
    reqs = deps.as_dicts(deps.check([i["dll"] for i in a.imports], exe.parent, a.arch == "x32"))
    match = recipe.match_exe(a.sha256, exe.name)
    rec, edition = match if match else (None, None)
    layers = system.compat_layers(str(exe.resolve()))
    observed = observed_problems(rec.id if rec else _game_id(exe))
    ctx = RecContext(exe=a, system=sysinfo.to_dict() if sysinfo else None, deps=reqs, recipe=rec,
                     recipe_hash_match=edition is not None, compat_layers=layers, observed=observed)
    recs = _recommend(ctx)
    return {
        "format": "legacyforge-report/1",
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "executable": a.to_dict(),
        "system": sysinfo.to_dict() if sysinfo else None,
        "dependencies": reqs,
        "compat_layers": layers,
        "recipe": {"id": rec.id, "name": rec.name,
                   "edition": edition.id if edition else None,
                   "edition_confirmed": edition is not None} if rec else None,
        "observed": observed,
        "recommendations": [r.to_dict() for r in recs],
    }


def _game_id(exe: Path) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "-", Path(exe).stem.lower())[:80] or "game"


def observed_problems(game: str) -> dict:
    out = {}
    for s in sessions.load_all(game) if re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", game) else []:
        for e in s.get("events", []):
            if e.get("exception_code") == "0xC0000017":
                out["memory_crash"] = True
        if s.get("exit", {}).get("code_hex") == "0xC0000017":
            out["memory_crash"] = True
    return out


# plan / apply / revert ------------------------------------------------------

def plan(recipe_id: str, game_dir: Path | None = None, **kw) -> engine.Plan:
    r = recipe.find(recipe_id)
    d = Path(game_dir) if game_dir else detect.locate(r)
    if d is None:
        raise recipe.RecipeError(f"couldn't find {r.name}; pass the game folder explicitly")
    return engine.make_plan(r, d, **kw)


def apply(p: engine.Plan) -> list[str]:
    return engine.apply(p)


def revert(recipe_id: str, game_dir: Path | None = None, **kw) -> list[str]:
    r = recipe.find(recipe_id)
    d = Path(game_dir) if game_dir else detect.locate(r)
    if d is None:
        raise recipe.RecipeError(f"couldn't find {r.name}; pass the game folder explicitly")
    return engine.revert(r, d, **kw)


def history(game_dir: Path) -> list[dict]:
    """Modification history for a game folder (all recipes, including v0.1 snapshots)."""
    out = []
    for t in transaction.all_in(Path(game_dir)):
        m = t.manifest
        out.append({"recipe": m.get("recipe"), "created": m.get("created"), "state": m.get("state"),
                    "fixes": m.get("fixes"), "files": len(m.get("entries", [])), "log": m.get("log", []),
                    "conflicts": [c.__dict__ for c in t.conflicts()]})
    return out


# profiles -------------------------------------------------------------------

def profile_path(game: str) -> Path:
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", game):
        raise ValueError(f"invalid game id {game!r}")
    return recipe.data_home() / "profiles" / f"{game}.json"


def load_profile(game: str) -> monitor.LaunchProfile:
    p = profile_path(game)
    if not p.exists():
        return monitor.LaunchProfile()
    data = json.loads(p.read_text())
    prof = monitor.LaunchProfile(**{k: v for k, v in data.items() if k in monitor.LaunchProfile.__annotations__})
    prof.validate()
    return prof


def save_profile(game: str, prof: monitor.LaunchProfile) -> Path:
    prof.validate()
    p = profile_path(game)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(asdict(prof), indent=2))
    return p


# launch / monitor / verify ---------------------------------------------------

def current_config(exe: Path, prof: monitor.LaunchProfile) -> dict:
    fixes = []
    for t in transaction.all_in(Path(exe).parent):
        if t.state == "committed":
            fixes.append({"recipe": t.manifest.get("recipe"), "fixes": t.manifest.get("fixes"),
                          "edition": t.manifest.get("meta", {}).get("edition")})
    return {"fixes": fixes, "profile": asdict(prof),
            "compat_layers": system.compat_layers(str(Path(exe).resolve()))}


def launch(exe: Path, *, game: str | None = None, scenario: str | None = None, max_minutes: float | None = None,
           interval: float = 5.0, confirm=None, notes: str | None = None, min_runtime_s: float = 60.0,
           on_sample=None) -> sessions.Session:
    """Run the game, observe it, classify the outcome and save a session.
    `confirm` is an optional callback returning True/False/None for "did the
    gameplay test pass?" (the CLI asks the user; automated runs pass None)."""
    exe = Path(exe)
    game = game or (recipe.match_exe(_sha(exe), exe.name) or (None,))[0]
    game_id = game.id if hasattr(game, "id") else (game or _game_id(exe))
    prof = load_profile(game_id)
    cfg = current_config(exe, prof)
    sysinfo = system.inspect()
    t_start = time.time()
    res = monitor.run(exe, prof, interval=interval, max_minutes=max_minutes, on_sample=on_sample)
    runtime = (res.ended - res.started).total_seconds()
    st = sessions.settings()
    events = monitor.crash_events(res.started, exe.name) if st["collect_event_log"] else []
    logs = monitor.wrapper_logs(exe.parent, t_start) if st["collect_wrapper_logs"] else []
    ex = diagnostics.classify_exit(res.exit_code, killed_by_user=res.killed)
    answer = None
    if confirm and ex.kind in ("normal", "error-code", "terminated") and not events and runtime >= min_runtime_s:
        answer = confirm(runtime)
    outcome, reasons = diagnostics.session_outcome(diagnostics.Observation(
        ex, runtime, events, res.handed_off, answer, min_runtime_s))
    gpus = sysinfo.gpus if isinstance(sysinfo.gpus, list) else []
    s = sessions.Session(
        game=game_id, exe=str(exe), exe_sha256=_sha(exe), started=res.started.isoformat(),
        ended=res.ended.isoformat(), runtime_s=round(runtime, 1), exit=asdict(ex), outcome=outcome,
        reasons=reasons, config=cfg, config_fingerprint=sessions.fingerprint(cfg),
        memory={"peak": res.peak, "samples": [asdict(x) for x in res.samples]}, events=events,
        wrapper_logs=logs, modules=res.modules, scenario=scenario, notes=notes,
        system={"windows_build": sysinfo.os.get("windows_build"), "platform": sysinfo.os.get("platform"),
                "gpu": gpus[0].get("Name") if gpus else None,
                "gpu_driver": gpus[0].get("DriverVersion") if gpus else None})
    sessions.save(s)
    sessions.apply_retention()
    return s


def _sha(exe: Path) -> str:
    from .fsutil import sha256_file

    return sha256_file(exe)


def compare(game: str) -> list[dict]:
    """Compare each configuration's sessions with the earliest configuration (the baseline)."""
    ss = sorted(sessions.load_all(game), key=lambda s: s["started"])
    groups: dict[str, list[dict]] = {}
    for s in ss:
        groups.setdefault(s["config_fingerprint"], []).append(s)
    if not groups:
        return []
    keys = list(groups)
    base = groups[keys[0]]
    out = [{"config": keys[0], "role": "baseline", "sessions": len(base),
            "fixes": base[0]["config"].get("fixes")}]
    for k in keys[1:]:
        verdict, reasons = diagnostics.compare(base, groups[k])
        out.append({"config": k, "role": "candidate", "sessions": len(groups[k]),
                    "fixes": groups[k][0]["config"].get("fixes"), "verdict": verdict, "reasons": reasons})
    return out


def verify(game: str, scenario_id: str, min_sessions: int = 3) -> tuple[str, list[str]]:
    r = recipe.all_recipes().get(game)
    scenario = next((t for t in (r.test_plan if r else []) if t["id"] == scenario_id), None) or \
        {"id": scenario_id, "duration_minutes": 60}
    return diagnostics.verify_stable(sessions.load_all(game), scenario, min_sessions)
