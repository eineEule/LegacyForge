"""Plan, apply, revert and status for a recipe against a game folder."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from .context import Context
from .fixes import FixError
from .recipe import FixEntry, Recipe, RecipeError
from .snapshot import Snapshot


@dataclass
class Plan:
    recipe: Recipe
    ctx: Context
    entries: list[FixEntry]

    def lines(self) -> list[str]:
        out = []
        for e in self.entries:
            line = f"[{e.fix.type}] {e.fix.describe(self.ctx)}"
            if e.note:
                line += f"  ({e.note})"
            out.append(line)
        return out


def snapshot_for(recipe: Recipe, game_dir: Path) -> Snapshot:
    return Snapshot(Path(game_dir) / ".oldgames" / recipe.id)


def make_plan(recipe: Recipe, game_dir: Path, enable: set[str] | None = None,
              allow_unpinned: bool = False) -> Plan:
    game_dir = Path(game_dir)
    if recipe.exe and not (game_dir / recipe.exe).exists():
        raise RecipeError(f"{recipe.exe} not found in {game_dir}; is this the right folder?")
    ctx = Context(game_dir=game_dir, allow_unpinned=allow_unpinned)
    entries = recipe.active(enable or set())
    unknown = (enable or set()) - {e.fix.type for e in recipe.fixes if e.optional}
    if unknown:
        raise RecipeError(f"--with {sorted(unknown)}: not optional fixes in this recipe")

    owners: dict[Path, list[str]] = defaultdict(list)
    for e in entries:
        for p in e.fix.writes(ctx):
            owners[p.resolve()].append(e.fix.type)
    clashes = {str(p): t for p, t in owners.items() if len(t) > 1 and len(set(t)) > 1}
    if clashes:
        detail = "; ".join(f"{Path(p).name} <- {', '.join(t)}" for p, t in clashes.items())
        raise RecipeError(f"fixes conflict over the same file: {detail}")
    return Plan(recipe, ctx, entries)


def apply(plan: Plan) -> list[str]:
    snap = snapshot_for(plan.recipe, plan.ctx.game_dir)
    snap.begin(plan.recipe.id, [e.fix.type for e in plan.entries])
    plan.ctx.snapshot = snap
    results = []
    try:
        for e in plan.entries:
            results.append(f"[{e.fix.type}] {e.fix.apply(plan.ctx)}")
    except Exception as exc:
        log = snap.revert()
        raise FixError(f"{exc}\nRolled back {len(log)} change(s); game left as it was.") from exc
    if not snap.manifest["backed_up"] and not snap.manifest["added"]:
        snap.revert()  # nothing changed; don't leave an empty snapshot behind
        results.append("nothing needed changing")
    return results


def revert(recipe: Recipe, game_dir: Path) -> list[str]:
    return snapshot_for(recipe, game_dir).revert()


def status(recipe: Recipe, game_dir: Path) -> dict | None:
    snap = snapshot_for(recipe, game_dir)
    return snap.manifest if snap.exists() else None
