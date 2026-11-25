"""legacyforge command line (also installed as `oldgames` for v0.1 users)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__, detect, engine, monitor, pe, registry, report, services, sessions
from .archive import ArchiveError
from .fixes import FixError
from .fsutil import UnsafePathError
from .recipe import RecipeError, all_recipes, find
from .tools import ToolError
from .transaction import TransactionError


def _game_dir(r, override):
    if override:
        return Path(override)
    d = detect.locate(r)
    if d is None:
        raise RecipeError(f"couldn't find {r.name}. Pass --game-dir \"C:\\path\\to\\game\".")
    return d


def _params(items: list[str] | None) -> dict:
    out: dict[str, dict] = {}
    for it in items or []:
        key, sep, val = it.partition("=")
        ftype, dot, name = key.partition(".")
        if not sep or not dot:
            raise RecipeError(f"--param expects fix.key=value, got {it!r}")
        v: object = val
        if val.lower() in ("true", "false"):
            v = val.lower() == "true"
        elif val.lstrip("-").isdigit():
            v = int(val)
        out.setdefault(ftype, {})[name] = v
    return out


# --- commands -------------------------------------------------------------------

def cmd_list(a):
    for r in all_recipes().values():
        opt = [e.fix.type for e in r.fixes if e.optional]
        base = [e.fix.type for e in r.fixes if not e.optional]
        print(f"{r.id:24} {r.name}")
        print(f"{'':24} fixes: {', '.join(base) or '-'}" + (f"  optional: {', '.join(opt)}" if opt else ""))
    return 0


def cmd_discover(a):
    res = services.discover([Path(d) for d in a.dir or []])
    if a.json:
        print(json.dumps(res, indent=2))
        return 0
    print("Games with recipes:")
    for g in res["recipes_found"] or [{"name": "(none found)", "dir": "", "applied": False}]:
        print(f"  {g['name']:40} {g['dir']}" + ("  [patched]" if g.get("applied") else ""))
    print("\nInstalled games:")
    for g in res["installed"]:
        print(f"  [{g['source']}] {g.get('name') or '?':38} {g['dir']}")
    if not res["installed"]:
        print("  none found (Steam/GOG not detected). Use --dir, or analyze an exe directly.")
    return 0


def cmd_analyze(a):
    target = Path(a.target)
    if target.is_dir():
        cands = __import__("legacyforge.analysis", fromlist=["candidate_exes"]).candidate_exes(target)
        if not cands:
            raise RecipeError(f"no executables found in {target}")
        print("Executables found (largest first):")
        for p in cands:
            print(f"  {p}")
        print("\nRun: legacyforge analyze \"<one of the above>\"")
        return 0
    rep = services.analyze(target, with_system=not a.no_system, check_signature=not a.no_signature)
    if a.json:
        Path(a.json).write_text(report.to_json(rep), encoding="utf-8")
        print(f"report written to {a.json}")
    print(report.to_text(rep, verbose=a.verbose))
    return 0


def cmd_inspect(a):  # v0.1 compatibility: quick header facts
    info = pe.read_info(Path(a.exe))
    print(f"{Path(a.exe).name}\n  architecture : {info.arch}")
    if info.is_32bit:
        print(f"  4 GB aware   : {'yes' if info.large_address_aware else 'NO'}")
    print("  (run `legacyforge analyze` for the full report)")
    return 0


def _plan(a):
    r = find(a.recipe)
    return engine.make_plan(r, _game_dir(r, a.game_dir), set(a.with_ or []), a.allow_unpinned,
                            set(a.approve or []), params=_params(a.param))


def _print_plan(p):
    ed = p.edition.name if p.edition else "not confirmed by hash"
    print(f"{p.recipe.name} at {p.ctx.game_dir}\n  edition: {ed}")
    for line in p.lines():
        print(f"  {line}")
    for tok, why in p.missing_approvals:
        print(f"  NEEDS APPROVAL --approve {tok}: {why}")


def cmd_plan(a):
    p = _plan(a)
    _print_plan(p)
    for n in p.recipe.notes:
        print(f"  note: {n}")
    return 0


def cmd_apply(a):
    p = _plan(a)
    _print_plan(p)
    if p.missing_approvals:
        raise engine.ApprovalError(p.missing_approvals)
    if not a.yes and input("Apply these changes? Close the game first. [y/N] ").strip().lower() != "y":
        print("Cancelled.")
        return 1
    for line in engine.apply(p):
        print(f"  {line}")
    for n in p.recipe.notes:
        print(f"  note: {n}")
    print(f"Done. Undo anytime with: legacyforge revert {p.recipe.id}")
    return 0


def cmd_revert(a):
    r = find(a.recipe)
    for line in engine.revert(r, _game_dir(r, a.game_dir), force=a.force, keep_current=a.keep_current):
        print(f"  {line}")
    print("Reverted.")
    return 0


def cmd_recover(a):
    r = find(a.recipe)
    for line in engine.recover(r, _game_dir(r, a.game_dir)):
        print(f"  {line}")
    print("Recovered: the interrupted apply was rolled back.")
    return 0


def cmd_status(a):
    r = find(a.recipe)
    d = _game_dir(r, a.game_dir)
    s = engine.status(r, d)
    if not s:
        print(f"{r.name}: not applied ({d})")
        return 0
    print(f"{r.name}: {s['state']} {s['created']} ({', '.join(s['fixes'])})")
    print(f"  {len(s['entries'])} tracked change(s)")
    for c in s["conflicts"]:
        print(f"  CHANGED SINCE PATCH: {c['path']} - {c['reason']}")
    return 0


def cmd_history(a):
    for h in services.history(Path(a.game_dir)):
        print(f"{h['recipe']}: {h['state']} {h['created']} fixes={h['fixes']} files={h['files']}")
        for c in h["conflicts"]:
            print(f"  CHANGED SINCE PATCH: {c['path']}")
        if a.log:
            for line in h["log"]:
                print(f"    {line}")
    return 0


def cmd_profile(a):
    prof = services.load_profile(a.game)
    changed = False
    if a.affinity is not None:
        prof.affinity = None if a.affinity == "all" else [int(x) for x in a.affinity.split(",")]
        changed = True
    if a.priority:
        prof.priority, changed = a.priority, True
    if a.arg is not None:
        prof.args, changed = a.arg, True
    if a.env:
        prof.env.update(dict(e.split("=", 1) for e in a.env))
        changed = True
    if changed:
        services.save_profile(a.game, prof)
    print(json.dumps(prof.__dict__, indent=2))
    return 0


def cmd_launch(a):
    target = a.target
    exe = Path(target)
    game = a.game
    if not exe.suffix.lower() == ".exe":
        r = find(target)
        d = _game_dir(r, a.game_dir)
        exe, game = d / r.exe, r.id

    def confirm(runtime_s):
        if a.no_confirm:
            return None
        ans = input(f"Played {runtime_s / 60:.0f} min. Did the gameplay test pass? [y/n/skip] ").strip().lower()
        return True if ans == "y" else False if ans == "n" else None

    def on_sample(s):
        if a.verbose:
            print(f"  t={s.t:>6}s private={s.private_mb} MiB  working set={s.working_set_mb} MiB  "
                  f"virtual={s.virtual_mb} MiB")

    print(f"Launching {exe} (Ctrl+C stops monitoring and the game)")
    s = services.launch(exe, game=game, scenario=a.scenario, max_minutes=a.minutes, confirm=confirm,
                        notes=a.notes, interval=a.interval, on_sample=on_sample)
    print(f"Outcome: {s.outcome}")
    for line in s.reasons:
        print(f"  {line}")
    pk = s.memory["peak"]
    print(f"  peak private {pk['private_mb']} MiB, peak virtual {pk['virtual_mb']} MiB, runtime {s.runtime_s / 60:.1f} min")
    gm = sessions.graphics_modules(s.modules)
    if gm:
        print(f"  graphics modules loaded: {', '.join(gm)}")
    print(f"  session {s.id} saved")
    return 0


def cmd_sessions(a):
    if a.action == "list":
        for s in sessions.load_all(a.game):
            print(f"{s['id']}  {s['game']:20} {s['outcome']:22} {s['runtime_s'] / 60:6.1f} min  cfg {s['config_fingerprint']}")
    elif a.action == "compare":
        for g in services.compare(a.game):
            print(f"[{g['role']}] config {g['config']} ({g['sessions']} sessions) fixes={g['fixes']}")
            if g["role"] != "baseline":
                print(f"  verdict: {g['verdict']}")
                for x in g["reasons"]:
                    print(f"    {x}")
    elif a.action == "verify":
        verdict, reasons = services.verify(a.game, a.scenario)
        print(verdict)
        for x in reasons:
            print(f"  {x}")
    elif a.action == "purge":
        n = sessions.purge(a.game, a.older_than)
        print(f"deleted {n} session(s)")
    elif a.action == "export":
        recs = [sessions.community_record(s) for s in sessions.load_all(a.game)]
        Path(a.out).write_text(json.dumps(recs, indent=2))
        print(f"wrote {len(recs)} sanitized record(s) to {a.out}")
    return 0


def cmd_settings(a):
    s = sessions.save_settings(dict(kv.split("=", 1) for kv in a.set)) if a.set else sessions.settings()
    print(json.dumps(s, indent=2))
    return 0


def cmd_registry(a):
    if a.action == "keygen":
        key, kid = registry.generate_key(Path(a.path))
        print(f"private key {key} (keep secret), key id {kid}")
    elif a.action == "trust":
        print(f"trusted key {registry.trust_key(Path(a.path))}")
    elif a.action == "sign":
        m = registry.build_and_sign(Path(a.path), Path(a.key), name=a.name, version=a.version, author=a.author)
        print(f"signed {len(m['recipes'])} recipe(s) with key {m['key_id']}")
    elif a.action == "verify":
        m = registry.verify(Path(a.path))
        print(f"OK: {m['name']} {m['version']} by {m['author']}, {len(m['recipes'])} recipe(s)")
    elif a.action == "install":
        print("installed: " + ", ".join(registry.install(Path(a.path))))
    return 0


# --- parser --------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="legacyforge", description="Evidence-driven compatibility for legacy Windows games.")
    p.add_argument("--version", action="version", version=f"legacyforge {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="list recipes").set_defaults(func=cmd_list)
    s = sub.add_parser("discover", help="find installed games (Steam, GOG, folders)")
    s.add_argument("--dir", action="append", help="also include this folder")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_discover)
    sub.add_parser("scan", help="(v0.1) alias of discover").set_defaults(func=cmd_discover, dir=None, json=False)

    s = sub.add_parser("analyze", help="read-only compatibility report for an exe (or list exes in a folder)")
    s.add_argument("target")
    s.add_argument("--json", metavar="FILE", help="also write the full report as JSON")
    s.add_argument("--no-system", action="store_true", help="skip system inspection")
    s.add_argument("--no-signature", action="store_true", help="skip the Windows signature check")
    s.add_argument("-v", "--verbose", action="store_true")
    s.set_defaults(func=cmd_analyze)
    s = sub.add_parser("inspect", help="(v0.1) quick header facts")
    s.add_argument("exe")
    s.set_defaults(func=cmd_inspect)

    def game_args(sp, plan_opts=False):
        sp.add_argument("recipe", help="recipe id or path to a .yaml recipe")
        sp.add_argument("--game-dir", help="game install folder (skips auto-detect)")
        if plan_opts:
            sp.add_argument("--with", dest="with_", action="append", metavar="FIX", help="enable an optional fix")
            sp.add_argument("--approve", action="append", metavar="TOKEN", help="grant an approval the plan asks for")
            sp.add_argument("--param", action="append", metavar="FIX.KEY=VALUE", help="override a fix parameter")
            sp.add_argument("--allow-unpinned", action="store_true", help="allow tools without a pinned sha256")

    s = sub.add_parser("plan", help="show what apply would do")
    game_args(s, True)
    s.set_defaults(func=cmd_plan)
    s = sub.add_parser("apply", help="apply a recipe (transactional, reversible)")
    game_args(s, True)
    s.add_argument("-y", "--yes", action="store_true")
    s.set_defaults(func=cmd_apply)
    s = sub.add_parser("revert", help="undo a recipe, checking nothing changed since")
    game_args(s)
    s.add_argument("--force", action="store_true", help="overwrite files changed since the patch")
    s.add_argument("--keep-current", action="store_true", help="restore everything except files changed since")
    s.set_defaults(func=cmd_revert)
    s = sub.add_parser("recover", help="roll back an interrupted apply")
    game_args(s)
    s.set_defaults(func=cmd_recover)
    s = sub.add_parser("status", help="is a recipe applied? anything changed since?")
    game_args(s)
    s.set_defaults(func=cmd_status)
    s = sub.add_parser("history", help="modification history of a game folder")
    s.add_argument("game_dir")
    s.add_argument("--log", action="store_true")
    s.set_defaults(func=cmd_history)

    s = sub.add_parser("profile", help="per-game launch profile (affinity, priority, args, env)")
    s.add_argument("game")
    s.add_argument("--affinity", help="CPU list like 0 or 0,1; 'all' to clear")
    s.add_argument("--priority", choices=sorted(monitor.PRIORITIES))
    s.add_argument("--arg", action="append", help="launch argument (repeatable)")
    s.add_argument("--env", action="append", metavar="KEY=VALUE")
    s.set_defaults(func=cmd_profile)

    s = sub.add_parser("launch", help="launch and monitor a game, then record a session")
    s.add_argument("target", help="recipe id or path to the exe")
    s.add_argument("--game-dir")
    s.add_argument("--game", help="game id for sessions (default: recipe id or exe name)")
    s.add_argument("--scenario", help="test plan id this session belongs to")
    s.add_argument("--minutes", type=float, help="stop after this many minutes")
    s.add_argument("--interval", type=float, default=5.0, help="memory sample interval (s)")
    s.add_argument("--notes")
    s.add_argument("--no-confirm", action="store_true", help="don't ask whether gameplay passed")
    s.add_argument("-v", "--verbose", action="store_true")
    s.set_defaults(func=cmd_launch)

    s = sub.add_parser("sessions", help="list, compare, verify, purge or export test sessions")
    s.add_argument("action", choices=["list", "compare", "verify", "purge", "export"])
    s.add_argument("game", nargs="?")
    s.add_argument("--scenario", help="for verify")
    s.add_argument("--older-than", type=float, metavar="DAYS", help="for purge")
    s.add_argument("--out", default="legacyforge-results.json", help="for export")
    s.set_defaults(func=cmd_sessions)

    s = sub.add_parser("settings", help="diagnostic collection and retention settings")
    s.add_argument("--set", action="append", metavar="KEY=VALUE")
    s.set_defaults(func=cmd_settings)

    s = sub.add_parser("registry", help="signed recipe bundles")
    s.add_argument("action", choices=["keygen", "trust", "sign", "verify", "install"])
    s.add_argument("path")
    s.add_argument("--key")
    s.add_argument("--name", default="recipes")
    s.add_argument("--version", default="1")
    s.add_argument("--author", default="unknown")
    s.set_defaults(func=cmd_registry)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.cmd == "sessions" and args.action in ("compare", "verify") and not args.game:
        print("error: give a game id", file=sys.stderr)
        return 2
    if args.cmd == "sessions" and args.action == "verify" and not args.scenario:
        print("error: --scenario is required for verify", file=sys.stderr)
        return 2
    try:
        return args.func(args)
    except engine.ApprovalError as e:
        print(f"error: {e}", file=sys.stderr)
        return 3
    except (RecipeError, FixError, TransactionError, ToolError, pe.PEError, FileNotFoundError, ArchiveError,
            UnsafePathError, registry.RegistryError, ValueError, KeyError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
