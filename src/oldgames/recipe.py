"""Recipe loading and validation."""

from __future__ import annotations

from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

import yaml

from .fixes import REGISTRY, Fix, FixError

META_KEYS = {"optional", "note"}


class RecipeError(Exception):
    pass


@dataclass
class FixEntry:
    fix: Fix
    optional: bool = False
    note: str | None = None


@dataclass
class Recipe:
    id: str
    name: str
    exe: str | None
    steam_appid: int | None
    paths: list[str]
    fixes: list[FixEntry]
    notes: list[str] = field(default_factory=list)
    source: Path | None = None

    def active(self, enabled_optional: set[str]) -> list[FixEntry]:
        return [e for e in self.fixes if not e.optional or e.fix.type in enabled_optional]


def parse(data: dict, source: Path | None = None) -> Recipe:
    if not isinstance(data, dict):
        raise RecipeError("recipe must be a mapping")
    for key in ("game", "name", "fixes"):
        if key not in data:
            raise RecipeError(f"missing '{key}'")
    detect = data.get("detect") or {}
    exe = detect.get("exe")
    entries: list[FixEntry] = []
    for i, raw in enumerate(data["fixes"]):
        if not isinstance(raw, dict):
            raise RecipeError(f"fixes[{i}]: expected a mapping like '- laa: game.exe'")
        types = [k for k in raw if k not in META_KEYS]
        if len(types) != 1:
            raise RecipeError(f"fixes[{i}]: expected exactly one fix type, got {types}")
        t = types[0]
        if t not in REGISTRY:
            raise RecipeError(f"fixes[{i}]: unknown fix type '{t}' (known: {sorted(REGISTRY)})")
        try:
            fix = REGISTRY[t](raw[t], recipe_exe=exe)
        except FixError as e:
            raise RecipeError(f"fixes[{i}]: {e}") from e
        entries.append(FixEntry(fix, bool(raw.get("optional", False)), raw.get("note")))
    notes = data.get("notes") or []
    if isinstance(notes, str):
        notes = [notes]
    return Recipe(
        id=str(data["game"]),
        name=str(data["name"]),
        exe=exe,
        steam_appid=detect.get("steam_appid"),
        paths=list(detect.get("paths") or []),
        fixes=entries,
        notes=notes,
        source=source,
    )


def load_file(path: Path) -> Recipe:
    try:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        raise RecipeError(f"{path}: invalid YAML: {e}") from e
    try:
        return parse(data, Path(path))
    except RecipeError as e:
        raise RecipeError(f"{Path(path).name}: {e}") from e


def bundled() -> dict[str, Recipe]:
    out = {}
    folder = resources.files("oldgames").joinpath("recipes")
    for item in sorted(folder.iterdir(), key=lambda p: p.name):
        if item.name.endswith((".yaml", ".yml")):
            with resources.as_file(item) as p:
                r = load_file(p)
            out[r.id] = r
    return out


def find(name_or_path: str) -> Recipe:
    p = Path(name_or_path)
    if p.suffix in (".yaml", ".yml") and p.exists():
        return load_file(p)
    recipes = bundled()
    if name_or_path not in recipes:
        raise RecipeError(f"no recipe '{name_or_path}'. Try `oldgames list`.")
    return recipes[name_or_path]
