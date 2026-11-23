"""oldgames command line."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__, detect, engine, pe
from .fixes import FixError
from .recipe import RecipeError, bundled, find
from .snapshot import SnapshotError
from .tools import ToolError


def _game_dir(recipe, override: str | None) -> Path:
    if override:
        return Path(override)
    d = detect.locate(recipe)
    if d is None:
        raise RecipeError(
            f"couldn't find {recipe.name}. Pass --game-dir \"C:\\path\\to\\game\"."
        )
    return d


def cmd_list(args) -> int:
    for r in bundled().values():
        opt = [e.fix.type for e in r.fixes if e.optional]
        base = [e.fix.type for e in r.fixes if not e.optional]
        extra = f"  optional: {', '.join(opt)}" if opt else ""
        print(f"{r.id:24} {r.name}\n{'':24} fixes: {', '.join(base)}{extra}")
    return 0


def cmd_scan(args) -> int:
    found = 0
    for r in bundled().values():
        d = detect.locate(r)
        if d:
            found += 1
            state = "applied" if engine.status(r, d) else "not applied"
            print(f"{r.id:24} {d}  [{state}]")
    if not found:
        print("No supported games found. Use --game-dir with apply if yours is installed elsewhere.")
    return 0


def cmd_inspect(args) -> int:
    exe = Path(args.exe)
    info = pe.read_info(exe)
    print(f"{exe.name}")
    print(f"  architecture : {info.arch}")
    if info.is_32bit:
        print(f"  4 GB aware   : {'yes' if info.large_address_aware else 'NO  (laa fix would help)'}")
    try:
        dlls = pe.imported_dlls(exe)
        gfx = [f"{d} ({pe.GRAPHICS_DLLS[d]})" for d in dlls if d in pe.GRAPHICS_DLLS]
        print(f"  graphics/av  : {', '.join(gfx) or 'none imported directly (may load at runtime)'}")
    except Exception as e:  # pefile missing or odd binary
        print(f"  imports      : unavailable ({e})")
    return 0


def _plan(args):
    recipe = find(args.recipe)
    game_dir = _game_dir(recipe, args.game_dir)
    return engine.make_plan(recipe, game_dir, set(args.with_ or []), args.allow_unpinned)


def cmd_plan(args) -> int:
    plan = _plan(args)
    print(f"{plan.recipe.name} at {plan.ctx.game_dir}")
    for line in plan.lines():
        print(f"  {line}")
    for n in plan.recipe.notes:
        print(f"  note: {n}")
    return 0


def cmd_apply(args) -> int:
    plan = _plan(args)
    print(f"{plan.recipe.name} at {plan.ctx.game_dir}")
    for line in plan.lines():
        print(f"  {line}")
    if not args.yes:
        if input("Apply these changes? Close the game first. [y/N] ").strip().lower() != "y":
            print("Cancelled.")
            return 1
    for line in engine.apply(plan):
        print(f"  {line}")
    for n in plan.recipe.notes:
        print(f"  note: {n}")
    print(f"Done. Undo anytime with: oldgames revert {plan.recipe.id}")
    return 0


def cmd_revert(args) -> int:
    recipe = find(args.recipe)
    for line in engine.revert(recipe, _game_dir(recipe, args.game_dir)):
        print(f"  {line}")
    print("Reverted.")
    return 0


def cmd_status(args) -> int:
    recipe = find(args.recipe)
    d = _game_dir(recipe, args.game_dir)
    s = engine.status(recipe, d)
    if not s:
        print(f"{recipe.name}: not applied ({d})")
    else:
        print(f"{recipe.name}: applied {s['created']} ({', '.join(s['fixes'])})")
        print(f"  {len(s['backed_up'])} file(s) backed up, {len(s['added'])} added")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="oldgames", description="Patch and wrap old PC games.")
    p.add_argument("--version", action="version", version=f"oldgames {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="list bundled recipes").set_defaults(func=cmd_list)
    sub.add_parser("scan", help="find installed games that have recipes").set_defaults(func=cmd_scan)

    s = sub.add_parser("inspect", help="show an exe's architecture, 4 GB flag and graphics API")
    s.add_argument("exe")
    s.set_defaults(func=cmd_inspect)

    def game_args(sp, with_opts=False):
        sp.add_argument("recipe", help="recipe id or path to a .yaml recipe")
        sp.add_argument("--game-dir", help="game install folder (skips auto-detect)")
        if with_opts:
            sp.add_argument("--with", dest="with_", action="append", metavar="FIX",
                            help="also run an optional fix (repeatable)")
            sp.add_argument("--allow-unpinned", action="store_true",
                            help="allow tools without a pinned sha256")

    s = sub.add_parser("plan", help="show what apply would do")
    game_args(s, True)
    s.set_defaults(func=cmd_plan)
    s = sub.add_parser("apply", help="apply a recipe")
    game_args(s, True)
    s.add_argument("-y", "--yes", action="store_true", help="don't ask for confirmation")
    s.set_defaults(func=cmd_apply)
    s = sub.add_parser("revert", help="undo everything a recipe changed")
    game_args(s)
    s.set_defaults(func=cmd_revert)
    s = sub.add_parser("status", help="is a recipe applied?")
    game_args(s)
    s.set_defaults(func=cmd_status)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (RecipeError, FixError, SnapshotError, ToolError, pe.PEError, FileNotFoundError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
