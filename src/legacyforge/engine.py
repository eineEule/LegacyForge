"""Plan, apply, revert, recover and status for a recipe against a game folder."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from . import transaction, winapi
from .context import Context
from .fixes import FixError
from .fsutil import sha256_file
from .recipe import Edition, FixEntry, Recipe, RecipeError


class ApprovalError(Exception):
    def __init__(self, missing: list[tuple[str, str]]):
        self.missing = missing
        lines = "\n".join(f"  --approve {tok}   ({why})" for tok, why in missing)
        super().__init__(f"this plan needs your explicit approval:\n{lines}")


@dataclass
class Plan:
    recipe: Recipe
    ctx: Context
    entries: list[FixEntry]
    edition: Edition | None = None
    exe_sha256: str | None = None
    approvals_needed: list[tuple[str, str]] = field(default_factory=list)

    @property
    def missing_approvals(self) -> list[tuple[str, str]]:
        seen, out = set(), []
        for tok, why in self.approvals_needed:
            if tok not in self.ctx.approvals and tok not in seen:
                seen.add(tok)
                out.append((tok, why))
        return out

    def lines(self) -> list[str]:
        out = []
        for e in self.entries:
            line = f"[{e.fix.type}] {e.fix.describe(self.ctx)}"
            tags = [e.status]
            if e.fix.modifies_executable:
                tags.append("modifies exe")
            line += f"  ({', '.join(tags)})"
            if e.note:
                line += f"  - {e.note}"
            out.append(line)
        return out


def snapshot_for(recipe: Recipe, game_dir: Path, registry=None) -> transaction.Transaction:
    return transaction.for_recipe(recipe.id, Path(game_dir), registry)


def make_plan(recipe: Recipe, game_dir: Path, enable: set[str] | None = None, allow_unpinned: bool = False,
              approvals: set[str] | None = None, registry: winapi.Registry | None = None,
              params: dict[str, dict] | None = None) -> Plan:
    game_dir = Path(game_dir)
    if recipe.exe and not (game_dir / recipe.exe).exists():
        raise RecipeError(f"{recipe.exe} not found in {game_dir}; is this the right folder?")
    exe_sha = sha256_file(game_dir / recipe.exe) if recipe.exe else None
    edition = recipe.match_edition(exe_sha)
    ctx = Context(game_dir=game_dir, allow_unpinned=allow_unpinned, approvals=set(approvals or ()),
                  exe_hash_match=edition is not None, registry=registry,
                  known_hashes={h for ed in recipe.editions for h in ed.sha256})
    enable = set(enable or ())
    unknown = enable - {e.fix.type for e in recipe.fixes if e.optional}
    if unknown:
        raise RecipeError(f"--with {sorted(unknown)}: not optional fixes in this recipe")
    entries = recipe.active(enable, edition.id if edition else None)

    for ftype, overrides in (params or {}).items():
        targets = [e for e in entries if e.fix.type == ftype]
        if not targets:
            raise RecipeError(f"--param {ftype}.*: that fix isn't part of this plan")
        for e in targets:
            new = dict(e.fix.params) if isinstance(e.fix.params, dict) else {}
            new.update(overrides)
            try:
                e.fix = type(e.fix)(new, recipe_exe=recipe.exe)
            except FixError as err:
                raise RecipeError(str(err)) from err

    types = {e.fix.type for e in entries}
    for inc in recipe.incompatible:
        pair = set(inc["fixes"]) if isinstance(inc["fixes"], list) else {inc["fixes"]}
        if pair <= types:
            raise RecipeError(f"incompatible fixes {sorted(pair)}: {inc['reason']}")

    owners: dict[Path, list[str]] = defaultdict(list)
    for e in entries:
        for p in e.fix.writes(ctx):
            owners[p.resolve()].append(e.fix.type)
    clashes = {str(p): t for p, t in owners.items() if len(set(t)) > 1}
    if clashes:
        detail = "; ".join(f"{Path(p).name} <- {', '.join(t)}" for p, t in clashes.items())
        raise RecipeError(f"fixes conflict over the same file: {detail}")

    needed = [a for e in entries for a in e.fix.approvals_needed(ctx)]
    return Plan(recipe, ctx, entries, edition, exe_sha, needed)


def apply(plan: Plan) -> list[str]:
    if plan.missing_approvals:
        raise ApprovalError(plan.missing_approvals)
    tx = snapshot_for(plan.recipe, plan.ctx.game_dir, plan.ctx.registry)
    tx.begin(plan.recipe.id, [e.fix.type for e in plan.entries],
             {"edition": plan.edition.id if plan.edition else None, "exe_sha256": plan.exe_sha256,
              "approvals": sorted(plan.ctx.approvals)})
    plan.ctx.snapshot = tx
    results = []
    try:
        for e in plan.entries:
            tx.log(f"apply {e.fix.type}")
            results.append(f"[{e.fix.type}] {e.fix.apply(plan.ctx)}")
    except BaseException as exc:
        log = tx.revert(force=True)
        msg = f"{exc}\nRolled back {len(log)} change(s); game left as it was."
        if isinstance(exc, KeyboardInterrupt):
            raise
        raise FixError(msg) from exc
    tx.commit()
    if not tx.changed_anything():
        tx.discard()
        results.append("nothing needed changing")
    return results


def revert(recipe: Recipe, game_dir: Path, *, force: bool = False, keep_current: bool = False,
           registry: winapi.Registry | None = None) -> list[str]:
    tx = snapshot_for(recipe, game_dir, registry)
    if tx.exists() and tx.state == "in_progress":
        raise transaction.TransactionError(
            f"the last apply was interrupted; run `legacyforge recover {recipe.id}`")
    return tx.revert(force=force, keep_current=keep_current)


def recover(recipe: Recipe, game_dir: Path, registry: winapi.Registry | None = None) -> list[str]:
    tx = snapshot_for(recipe, game_dir, registry)
    if not tx.exists():
        raise transaction.TransactionError("nothing to recover")
    if tx.state != "in_progress":
        raise transaction.TransactionError("the last apply completed; use revert instead")
    return tx.revert(force=True)


def status(recipe: Recipe, game_dir: Path) -> dict | None:
    tx = snapshot_for(recipe, game_dir)
    if not tx.exists():
        return None
    m = dict(tx.manifest)
    m["conflicts"] = [c.__dict__ for c in tx.conflicts()]
    return m
