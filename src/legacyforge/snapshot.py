"""Back up every file before it is touched, so `revert` can undo everything.

Layout:  <game_dir>/.oldgames/<recipe_id>/manifest.json + files/<n>
The manifest is saved after every tracked file, so a crash mid-apply can
still be reverted.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import time
from pathlib import Path


class SnapshotError(Exception):
    pass


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class Snapshot:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.manifest_path = self.root / "manifest.json"
        self.manifest: dict = {}
        if self.manifest_path.exists():
            self.manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))

    def exists(self) -> bool:
        return self.manifest_path.exists()

    def begin(self, recipe_id: str, fixes: list[str]) -> None:
        if self.exists():
            raise SnapshotError(
                f"'{recipe_id}' is already applied here. Run `oldgames revert {recipe_id}` first."
            )
        (self.root / "files").mkdir(parents=True, exist_ok=True)
        self.manifest = {
            "recipe": recipe_id,
            "created": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "fixes": fixes,
            "backed_up": [],
            "added": [],
        }
        self._save()

    def _tracked(self, path: Path) -> bool:
        p = str(path.resolve())
        return p in self.manifest["added"] or any(b["path"] == p for b in self.manifest["backed_up"])

    def track(self, path: Path) -> None:
        """Call before creating or modifying `path`."""
        path = Path(path)
        if self._tracked(path):
            return
        resolved = str(path.resolve())
        if path.exists():
            stored = f"files/{len(self.manifest['backed_up'])}"
            shutil.copy2(path, self.root / stored)
            self.manifest["backed_up"].append(
                {"path": resolved, "stored": stored, "sha256": _sha256(path)}
            )
        else:
            self.manifest["added"].append(resolved)
        self._save()

    def _save(self) -> None:
        tmp = self.manifest_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.manifest, indent=2), encoding="utf-8")
        tmp.replace(self.manifest_path)

    def revert(self) -> list[str]:
        if not self.exists():
            raise SnapshotError("nothing to revert")
        log = []
        for p in reversed(self.manifest["added"]):
            if Path(p).exists():
                Path(p).unlink()
                log.append(f"removed  {p}")
        for b in self.manifest["backed_up"]:
            shutil.copy2(self.root / b["stored"], b["path"])
            log.append(f"restored {b['path']}")
        shutil.rmtree(self.root)
        parent = self.root.parent
        if parent.name == ".oldgames" and not any(parent.iterdir()):
            parent.rmdir()
        return log
