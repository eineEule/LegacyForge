"""Recipe loading and strict schema validation.

Recipes are data, not code: YAML is parsed with safe_load, every key is
checked against the schema, and fixes can only name registered fix types
with validated parameters. Unknown keys are errors, so a typo can't silently
disable a safety setting.

schema_version 1: v0.1 recipes (game, name, detect, fixes, notes).
schema_version 2: adds editions with exe hashes, known issues with evidence,
fix status/ordering/incompatibilities, dependencies, test plans, evidence.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

import yaml

from .fixes import REGISTRY, Fix, FixError

MAX_RECIPE_BYTES = 256 * 1024
FIX_META = {"optional", "note", "status", "editions", "order", "verify"}
FIX_STATUS = {"verified", "known", "suggested", "experimental"}
TOP_KEYS = {"schema_version", "game", "name", "editions", "detect", "supported_windows", "known_issues",
            "fixes", "incompatible_fixes", "dependencies", "test_plan", "evidence", "notes", "author",
            "recipe_version"}


class RecipeError(Exception):
    pass


@dataclass
class FixEntry:
    fix: Fix
    optional: bool = False
    note: str | None = None
    status: str = "known"
    editions: list[str] = field(default_factory=list)
    order: int = 0
    verify: str | None = None


@dataclass
class Edition:
    id: str
    name: str
    exe: str | None = None
    sha256: list[str] = field(default_factory=list)
    version: str | None = None
    steam_appid: int | None = None
    notes: str | None = None


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
    schema_version: int = 1
    editions: list[Edition] = field(default_factory=list)
    known_issues: list[dict] = field(default_factory=list)
    incompatible: list[dict] = field(default_factory=list)
    dependencies: list[dict] = field(default_factory=list)
    test_plan: list[dict] = field(default_factory=list)
    evidence: list[dict] = field(default_factory=list)
    supported_windows: list[str] = field(default_factory=list)

    def active(self, enabled_optional: set[str], edition: str | None = None) -> list[FixEntry]:
        out = [e for e in self.fixes
               if (not e.optional or e.fix.type in enabled_optional)
               and (not e.editions or edition in e.editions)]
        return sorted(out, key=lambda e: e.order)

    def match_edition(self, sha256: str | None) -> Edition | None:
        if not sha256:
            return None
        return next((e for e in self.editions if sha256.lower() in e.sha256), None)


def _expect(cond: bool, msg: str) -> None:
    if not cond:
        raise RecipeError(msg)


def _str_list(v, where: str) -> list[str]:
    if v is None:
        return []
    if isinstance(v, str):
        return [v]
    _expect(isinstance(v, list) and all(isinstance(x, str) for x in v), f"{where}: expected a list of strings")
    return v


def _dict_list(v, where: str, required: set[str], allowed: set[str]) -> list[dict]:
    if v is None:
        return []
    _expect(isinstance(v, list), f"{where}: expected a list")
    for i, item in enumerate(v):
        _expect(isinstance(item, dict), f"{where}[{i}]: expected a mapping")
        missing = required - set(item)
        _expect(not missing, f"{where}[{i}]: missing {sorted(missing)}")
        extra = set(item) - allowed
        _expect(not extra, f"{where}[{i}]: unknown key(s) {sorted(extra)}")
    return v


def parse(data: dict, source: Path | None = None) -> Recipe:
    _expect(isinstance(data, dict), "recipe must be a mapping")
    _expect(all(isinstance(k, str) for k in data), "recipe keys must be strings")
    extra = set(data) - TOP_KEYS
    _expect(not extra, f"unknown top-level key(s) {sorted(extra)}")
    for key in ("game", "name", "fixes"):
        _expect(key in data, f"missing '{key}'")
    version = data.get("schema_version", 1)
    _expect(version in (1, 2), f"unsupported schema_version {version!r}")
    _expect(isinstance(data["game"], str) and data["game"].replace("-", "").replace("_", "").isalnum(),
            "game: use letters, digits, '-' and '_' only")

    detect = data.get("detect") or {}
    _expect(isinstance(detect, dict) and set(detect) <= {"steam_appid", "exe", "paths"},
            "detect: allowed keys are steam_appid, exe, paths")
    exe = detect.get("exe")

    editions = []
    for i, e in enumerate(_dict_list(data.get("editions"), "editions", {"id", "name"},
                                     {"id", "name", "exe", "sha256", "version", "steam_appid", "notes"})):
        hashes = [h.lower() for h in _str_list(e.get("sha256"), f"editions[{i}].sha256")]
        _expect(all(len(h) == 64 and all(c in "0123456789abcdef" for c in h) for h in hashes),
                f"editions[{i}].sha256: expected 64-character hex SHA-256 values")
        editions.append(Edition(str(e["id"]), str(e["name"]), e.get("exe"), hashes, e.get("version"),
                                e.get("steam_appid"), e.get("notes")))
    edition_ids = {e.id for e in editions}

    entries: list[FixEntry] = []
    _expect(isinstance(data["fixes"], list), "fixes: expected a list")
    for i, raw in enumerate(data["fixes"]):
        _expect(isinstance(raw, dict), f"fixes[{i}]: expected a mapping like '- laa: game.exe'")
        types = [k for k in raw if k not in FIX_META]
        _expect(len(types) == 1, f"fixes[{i}]: expected exactly one fix type, got {types}")
        t = types[0]
        _expect(t in REGISTRY, f"fixes[{i}]: unknown fix type '{t}' (known: {sorted(REGISTRY)})")
        status = raw.get("status", "known")
        _expect(status in FIX_STATUS, f"fixes[{i}].status must be one of {sorted(FIX_STATUS)}")
        eds = _str_list(raw.get("editions"), f"fixes[{i}].editions")
        _expect(set(eds) <= edition_ids, f"fixes[{i}].editions: unknown edition(s) {sorted(set(eds) - edition_ids)}")
        order = raw.get("order", 0)
        _expect(isinstance(order, int), f"fixes[{i}].order must be an integer")
        try:
            fix = REGISTRY[t](raw[t], recipe_exe=exe)
        except FixError as e:
            raise RecipeError(f"fixes[{i}]: {e}") from e
        entries.append(FixEntry(fix, bool(raw.get("optional", False)), raw.get("note"), status, eds, order,
                                raw.get("verify")))

    known_types = {e.fix.type for e in entries}
    incompatible = _dict_list(data.get("incompatible_fixes"), "incompatible_fixes", {"fixes", "reason"},
                              {"fixes", "reason"})
    for i, inc in enumerate(incompatible):
        _expect(set(_str_list(inc["fixes"], f"incompatible_fixes[{i}].fixes")) <= set(REGISTRY),
                f"incompatible_fixes[{i}]: unknown fix type")

    known_issues = _dict_list(data.get("known_issues"), "known_issues", {"id", "summary", "evidence"},
                              {"id", "summary", "evidence", "source", "editions", "status"})
    dependencies = _dict_list(data.get("dependencies"), "dependencies", {"runtime"},
                              {"runtime", "dlls", "required", "note"})
    test_plan = _dict_list(data.get("test_plan"), "test_plan", {"id", "steps", "pass_criteria"},
                           {"id", "edition", "steps", "pass_criteria", "duration_minutes", "fixes"})
    evidence = _dict_list(data.get("evidence"), "evidence", {"date", "outcome"},
                          {"date", "tester", "edition", "windows", "fixes", "outcome", "notes", "session"})
    del known_types
    notes = data.get("notes") or []
    return Recipe(
        id=str(data["game"]), name=str(data["name"]), exe=exe, steam_appid=detect.get("steam_appid"),
        paths=_str_list(detect.get("paths"), "detect.paths"), fixes=entries,
        notes=[notes] if isinstance(notes, str) else _str_list(notes, "notes"), source=source,
        schema_version=version, editions=editions, known_issues=known_issues, incompatible=incompatible,
        dependencies=dependencies, test_plan=test_plan, evidence=evidence,
        supported_windows=_str_list(data.get("supported_windows"), "supported_windows"),
    )


def load_file(path: Path) -> Recipe:
    path = Path(path)
    if path.stat().st_size > MAX_RECIPE_BYTES:
        raise RecipeError(f"{path.name}: recipe file too large")
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        raise RecipeError(f"{path}: invalid YAML: {e}") from e
    try:
        return parse(data, path)
    except RecipeError as e:
        raise RecipeError(f"{path.name}: {e}") from e


def data_home() -> Path:
    if os.environ.get("LEGACYFORGE_HOME"):
        return Path(os.environ["LEGACYFORGE_HOME"])
    if sys.platform == "win32":
        return Path(os.environ.get("LOCALAPPDATA", Path.home())) / "LegacyForge"
    return Path.home() / ".local" / "share" / "legacyforge"


def user_recipe_dir() -> Path:
    return data_home() / "recipes"


def bundled() -> dict[str, Recipe]:
    out = {}
    folder = resources.files("legacyforge").joinpath("recipes")
    for item in sorted(folder.iterdir(), key=lambda p: p.name):
        if item.name.endswith((".yaml", ".yml")):
            with resources.as_file(item) as p:
                r = load_file(p)
            out[r.id] = r
    return out


def all_recipes() -> dict[str, Recipe]:
    """Bundled recipes plus verified user-installed ones (user wins on id clash)."""
    out = bundled()
    d = user_recipe_dir()
    if d.is_dir():
        for p in sorted(d.glob("*.y*ml")):
            r = load_file(p)
            out[r.id] = r
    return out


def find(name_or_path: str) -> Recipe:
    p = Path(name_or_path)
    if p.suffix in (".yaml", ".yml") and p.exists():
        return load_file(p)
    recipes = all_recipes()
    if name_or_path not in recipes:
        raise RecipeError(f"no recipe '{name_or_path}'. Try `legacyforge list`.")
    return recipes[name_or_path]


def match_exe(sha256: str, exe_name: str | None = None) -> tuple[Recipe, Edition | None] | None:
    """Find the recipe for an executable: exact hash first, then exe name."""
    recipes = all_recipes().values()
    for r in recipes:
        ed = r.match_edition(sha256)
        if ed:
            return r, ed
    if exe_name:
        for r in recipes:
            names = {(r.exe or "").lower()} | {(e.exe or "").lower() for e in r.editions}
            if exe_name.lower() in {Path(n).name for n in names if n}:
                return r, None
    return None
