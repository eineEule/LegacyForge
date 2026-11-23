"""Per-apply context: where the game is, path variables, the active transaction,
the user's approvals, and the safe write helpers every fix must use."""

from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

from . import winapi
from .fsutil import UnsafePathError, atomic_write, ensure_within, is_link


def documents_dir() -> Path:
    """The real Documents folder (respects OneDrive redirection on Windows)."""
    if sys.platform == "win32":
        try:
            import ctypes
            from ctypes import wintypes

            buf = ctypes.create_unicode_buffer(wintypes.MAX_PATH)
            if ctypes.windll.shell32.SHGetFolderPathW(None, 5, None, 0, buf) == 0:  # CSIDL_PERSONAL
                return Path(buf.value)
        except Exception:
            pass
    return Path.home() / "Documents"


@dataclass
class Context:
    game_dir: Path
    snapshot: object | None = None          # transaction.Transaction while applying
    allow_unpinned: bool = False
    approvals: set[str] = field(default_factory=set)
    exe_hash_match: bool = False            # detected exe matches a recipe edition hash
    known_hashes: set[str] = field(default_factory=set)  # every edition hash the recipe lists
    registry: winapi.Registry | None = None
    variables: dict[str, str] = field(default_factory=dict)

    def __post_init__(self):
        self.game_dir = Path(self.game_dir)
        defaults = {
            "GAME_DIR": str(self.game_dir),
            "DOCUMENTS": str(documents_dir()),
            "HOME": str(Path.home()),
            "APPDATA": os.environ.get("APPDATA", str(Path.home() / "AppData" / "Roaming")),
            "LOCALAPPDATA": os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local")),
        }
        self.variables = {**defaults, **self.variables}

    @property
    def reg(self) -> winapi.Registry:
        return self.registry or winapi.registry()

    def resolve(self, value: str) -> Path:
        """Expand ${VARS}; relative paths are relative to the game folder and
        may not escape it."""

        def sub(m: re.Match) -> str:
            key = m.group(1)
            if key not in self.variables:
                raise KeyError(f"unknown path variable ${{{key}}}")
            return self.variables[key]

        expanded = re.sub(r"\$\{([A-Z_]+)\}", sub, value)
        p = Path(expanded)
        if p.is_absolute():
            return p
        if ".." in Path(value).parts:
            raise UnsafePathError(f"{value}: '..' is not allowed in recipe paths")
        return self.game_dir / p

    def track(self, path: Path) -> None:
        if self.snapshot is not None:
            self.snapshot.track(path)

    def write(self, path: Path, data: bytes) -> None:
        """Back up (if tracked), then atomically write. Paths inside the game
        folder are checked for links and escapes."""
        path = Path(path)
        try:
            path.resolve().relative_to(self.game_dir.resolve())
            inside = True
        except ValueError:
            inside = False
        if inside:
            ensure_within(self.game_dir, path)
        elif is_link(path):
            raise UnsafePathError(f"{path} is a link; refusing to write through it")
        self.track(path)
        atomic_write(path, data)
