"""Per-apply context: where the game is, path variables, the active snapshot."""

from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

from .snapshot import Snapshot


def documents_dir() -> Path:
    """The real Documents folder (respects OneDrive redirection on Windows)."""
    if sys.platform == "win32":
        try:
            import ctypes
            from ctypes import wintypes

            buf = ctypes.create_unicode_buffer(wintypes.MAX_PATH)
            # CSIDL_PERSONAL = 5
            if ctypes.windll.shell32.SHGetFolderPathW(None, 5, None, 0, buf) == 0:
                return Path(buf.value)
        except Exception:
            pass
    return Path.home() / "Documents"


@dataclass
class Context:
    game_dir: Path
    snapshot: Snapshot | None = None
    allow_unpinned: bool = False
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

    def resolve(self, value: str) -> Path:
        """Expand ${VARS}; relative paths are relative to the game folder."""

        def sub(m: re.Match) -> str:
            key = m.group(1)
            if key not in self.variables:
                raise KeyError(f"unknown path variable ${{{key}}}")
            return self.variables[key]

        expanded = re.sub(r"\$\{([A-Z_]+)\}", sub, value)
        p = Path(expanded)
        return p if p.is_absolute() else self.game_dir / p

    def track(self, path: Path) -> None:
        if self.snapshot is not None:
            self.snapshot.track(path)
