"""Transactional patching: back up, hash, log, and restore only when safe.

Layout: <game_dir>/.legacyforge/<recipe_id>/manifest.json + files/<n>
(v0.1 used <game_dir>/.oldgames/; those snapshots are still read and reverted.)

Every entry records the file's SHA-256 before and after LegacyForge touched
it. `revert` refuses to overwrite a file whose current hash is neither of
those (Steam updated it, the user edited it, another mod replaced it) unless
the caller picks a resolution. A manifest left in state "in_progress" means
an apply was interrupted; `recover` rolls it back.
"""

from __future__ import annotations

import json
import os
import shutil
import time
from dataclasses import dataclass
from pathlib import Path

from . import winapi
from .fsutil import atomic_copy, is_link, sha256_file

MANIFEST_VERSION = 2
DIR_NAME = ".legacyforge"
LEGACY_DIR_NAME = ".oldgames"


class TransactionError(Exception):
    pass


@dataclass
class Conflict:
    path: str
    expected: str | None
    actual: str | None
    reason: str


class ConflictError(TransactionError):
    def __init__(self, conflicts: list[Conflict]):
        self.conflicts = conflicts
        lines = [f"  {c.path}: {c.reason}" for c in conflicts]
        super().__init__(
            "files changed since LegacyForge patched them:\n" + "\n".join(lines) +
            "\nNothing was restored. Options: --keep-current (restore everything else, leave these as "
            "they are) or --force (overwrite them with the originals).")


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")


def _hash_or_none(p: Path) -> str | None:
    return sha256_file(p) if p.exists() and p.is_file() else None


class Transaction:
    def __init__(self, root: Path, registry: winapi.Registry | None = None):
        self.root = Path(root)
        self.manifest_path = self.root / "manifest.json"
        self.manifest: dict = {}
        self._registry = registry
        if self.manifest_path.exists():
            self.manifest = self._upgrade(json.loads(self.manifest_path.read_text(encoding="utf-8")))

    @property
    def registry(self) -> winapi.Registry:
        return self._registry or winapi.registry()

    # lifecycle ----------------------------------------------------------
    def exists(self) -> bool:
        return self.manifest_path.exists()

    @property
    def state(self) -> str | None:
        return self.manifest.get("state") if self.manifest else None

    def begin(self, recipe_id: str, fixes: list[str], meta: dict | None = None) -> None:
        if self.exists():
            if self.state == "in_progress":
                raise TransactionError(f"an earlier apply of '{recipe_id}' was interrupted. "
                                       f"Run `legacyforge recover {recipe_id}` first.")
            raise TransactionError(f"'{recipe_id}' is already applied here. "
                                   f"Run `legacyforge revert {recipe_id}` first.")
        if is_link(self.root.parent) or is_link(self.root):
            raise TransactionError(f"{self.root} is a link; refusing to store backups through it")
        (self.root / "files").mkdir(parents=True, exist_ok=True)
        self.manifest = {"version": MANIFEST_VERSION, "recipe": recipe_id, "created": _now(),
                         "state": "in_progress", "fixes": fixes, "meta": meta or {},
                         "entries": [], "log": []}
        self._save()

    def log(self, msg: str) -> None:
        self.manifest.setdefault("log", []).append(f"{_now()} {msg}")
        self._save()

    def _entry(self, path: str) -> dict | None:
        return next((e for e in self.manifest["entries"] if e.get("path") == path), None)

    def track(self, path: Path) -> None:
        """Call before creating or modifying a file."""
        path = Path(path)
        if is_link(path):
            raise TransactionError(f"{path} is a link; refusing to modify it")
        key = str(path.resolve())
        if self._entry(key):
            return
        if path.exists():
            if not path.is_file():
                raise TransactionError(f"{path} is not a regular file")
            stored = f"files/{len(self.manifest['entries'])}"
            shutil.copy2(path, self.root / stored)
            pre = sha256_file(path)
            if sha256_file(self.root / stored) != pre:
                raise TransactionError(f"backup of {path} failed verification")
            entry = {"kind": "modified", "path": key, "stored": stored, "pre_sha256": pre,
                     "post_sha256": None}
        else:
            missing = []
            parent = path.parent
            while not parent.exists():
                missing.append(parent)
                parent = parent.parent
            for d in reversed(missing):
                self.manifest["entries"].append({"kind": "dir", "path": str(d.resolve())})
            entry = {"kind": "added", "path": key, "pre_sha256": None, "post_sha256": None}
        self.manifest["entries"].append(entry)
        self.log(f"track {entry['kind']} {key}")

    def track_registry(self, hive: str, key: str, name: str) -> None:
        ident = f"registry:{hive}\\{key}\\{name}"
        if self._entry(ident):
            return
        prev = self.registry.get(hive, key, name)
        self.manifest["entries"].append({"kind": "registry", "path": ident, "hive": hive, "key": key,
                                         "name": name, "previous": prev, "written": None})
        self.log(f"track registry {ident} (previous={prev!r})")

    def commit(self) -> None:
        """Record post-change hashes; the transaction is now complete."""
        for e in self.manifest["entries"]:
            if e["kind"] == "registry":
                e["written"] = self.registry.get(e["hive"], e["key"], e["name"])
            elif e["kind"] == "dir":
                continue
            else:
                e["post_sha256"] = _hash_or_none(Path(e["path"]))
        self.manifest["state"] = "committed"
        self.log("commit")

    def changed_anything(self) -> bool:
        for e in self.manifest["entries"]:
            if e["kind"] == "dir":
                continue
            if e["kind"] == "registry":
                if e.get("written") != e.get("previous"):
                    return True
            elif e.get("post_sha256") != e.get("pre_sha256"):
                return True
        return False

    def discard(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)
        self._cleanup_parent()

    # validation ---------------------------------------------------------
    def conflicts(self) -> list[Conflict]:
        out = []
        interrupted = self.state != "committed"
        for e in self.manifest["entries"]:
            if e["kind"] == "dir":
                continue
            if e["kind"] == "registry":
                cur = self.registry.get(e["hive"], e["key"], e["name"])
                ok = {e.get("written"), e.get("previous")} if not interrupted else None
                if ok is not None and cur not in ok:
                    out.append(Conflict(e["path"], e.get("written"), cur, "registry value changed by someone else"))
                continue
            p = Path(e["path"])
            cur = _hash_or_none(p)
            expected = {e.get("post_sha256"), e.get("pre_sha256")}
            if interrupted and e.get("post_sha256") is None:
                continue  # mid-write state is ours by definition
            if e.get("legacy"):
                continue  # v0.1 manifests have no post hashes; caller warned separately
            if cur not in expected:
                reason = "file is missing" if cur is None else \
                    "contents changed (game update, manual edit, or another tool)"
                out.append(Conflict(e["path"], e.get("post_sha256"), cur, reason))
        return out

    # restore -------------------------------------------------------------
    def revert(self, *, force: bool = False, keep_current: bool = False) -> list[str]:
        if not self.exists():
            raise TransactionError("nothing to revert")
        conflicts = self.conflicts()
        skip = set()
        if conflicts and not force:
            if not keep_current:
                raise ConflictError(conflicts)
            skip = {c.path for c in conflicts}
        log: list[str] = []
        for e in self.manifest["entries"]:
            if e["kind"] == "modified":
                src = self.root / e["stored"]
                if not src.exists() or sha256_file(src) != e["pre_sha256"]:
                    raise TransactionError(f"backup for {e['path']} is missing or corrupt; "
                                           f"backups kept in {self.root}")
        for e in reversed(self.manifest["entries"]):
            path = e["path"]
            if path in skip:
                log.append(f"kept     {path} (changed since patch)")
                continue
            if e["kind"] == "dir":
                p = Path(path)
                if p.is_dir() and not is_link(p) and not any(p.iterdir()):
                    p.rmdir()
                    log.append(f"removed  {path}{os.sep}")
            elif e["kind"] == "added":
                p = Path(path)
                if p.exists() and not is_link(p):
                    p.unlink()
                    log.append(f"removed  {path}")
            elif e["kind"] == "modified":
                p = Path(path)
                if _hash_or_none(p) != e["pre_sha256"]:
                    atomic_copy(self.root / e["stored"], p)
                if sha256_file(p) != e["pre_sha256"]:
                    raise TransactionError(f"restore of {path} did not verify")
                log.append(f"restored {path}")
            elif e["kind"] == "registry":
                if e.get("previous") is None:
                    self.registry.delete(e["hive"], e["key"], e["name"])
                else:
                    self.registry.set(e["hive"], e["key"], e["name"], e["previous"])
                log.append(f"restored {path}")
        shutil.rmtree(self.root)
        self._cleanup_parent()
        return log

    def _cleanup_parent(self) -> None:
        parent = self.root.parent
        if parent.name in (DIR_NAME, LEGACY_DIR_NAME) and parent.exists() and not any(parent.iterdir()):
            parent.rmdir()

    # persistence ---------------------------------------------------------
    def _save(self) -> None:
        tmp = self.manifest_path.with_suffix(".tmp")
        data = json.dumps(self.manifest, indent=2).encode("utf-8")
        with open(tmp, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.manifest_path)

    @staticmethod
    def _upgrade(m: dict) -> dict:
        if m.get("version", 1) >= 2:
            return m
        entries = [{"kind": "modified", "path": b["path"], "stored": b["stored"],
                    "pre_sha256": b.get("sha256"), "post_sha256": None, "legacy": True}
                   for b in m.get("backed_up", [])]
        entries += [{"kind": "added", "path": p, "pre_sha256": None, "post_sha256": None, "legacy": True}
                    for p in m.get("added", [])]
        return {"version": 1, "recipe": m.get("recipe"), "created": m.get("created"), "state": "committed",
                "fixes": m.get("fixes", []), "meta": {"legacy_v01": True}, "entries": entries, "log": []}

    @property
    def is_legacy(self) -> bool:
        return bool(self.manifest.get("meta", {}).get("legacy_v01"))


def for_recipe(recipe_id: str, game_dir: Path, registry: winapi.Registry | None = None) -> Transaction:
    """The transaction for a recipe in a game folder, preferring an existing
    v0.1 (.oldgames) snapshot so old installs can still be reverted."""
    legacy = Path(game_dir) / LEGACY_DIR_NAME / recipe_id
    if (legacy / "manifest.json").exists():
        return Transaction(legacy, registry)
    return Transaction(Path(game_dir) / DIR_NAME / recipe_id, registry)


def all_in(game_dir: Path) -> list[Transaction]:
    out = []
    for name in (DIR_NAME, LEGACY_DIR_NAME):
        d = Path(game_dir) / name
        if d.is_dir():
            out += [Transaction(p) for p in sorted(d.iterdir()) if (p / "manifest.json").exists()]
    return out


def owner_of(path: Path, game_dir: Path) -> str | None:
    """Which recipe (if any) put this file here."""
    key = str(Path(path).resolve())
    folder = Path(game_dir).resolve()
    for d in [folder, *list(folder.parents)[:3]]:
        for t in all_in(d):
            for e in t.manifest.get("entries", []):
                if e.get("path") == key:
                    return t.manifest.get("recipe")
    return None


# back-compat name used by v0.1 code and tests
Snapshot = Transaction
