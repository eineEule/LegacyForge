"""Find installed games. Steam first; recipe `detect.paths` as a fallback.

TODO: GOG Galaxy (registry HKLM\\SOFTWARE\\WOW6432Node\\GOG.com\\Games), Epic, disc installs.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

from .context import Context
from .recipe import Recipe


def parse_vdf(text: str) -> dict:
    """Tiny parser for Valve's KeyValues text format (enough for library files)."""
    tokens = re.findall(r'"((?:[^"\\]|\\.)*)"|([{}])', text)
    stack: list[dict] = [{}]
    pending: str | None = None
    for quoted, brace in tokens:
        if brace == "{":
            new: dict = {}
            stack[-1][pending or ""] = new
            stack.append(new)
            pending = None
        elif brace == "}":
            if len(stack) > 1:
                stack.pop()
        elif pending is None:
            pending = quoted
        else:
            stack[-1][pending] = quoted.replace("\\\\", "\\")
            pending = None
    return stack[0]


def steam_root() -> Path | None:
    candidates: list[Path] = []
    if sys.platform == "win32":
        try:
            import winreg

            for hive, key in (
                (winreg.HKEY_CURRENT_USER, r"Software\Valve\Steam"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Valve\Steam"),
            ):
                try:
                    with winreg.OpenKey(hive, key) as k:
                        for name in ("SteamPath", "InstallPath"):
                            try:
                                candidates.append(Path(winreg.QueryValueEx(k, name)[0]))
                            except OSError:
                                pass
                except OSError:
                    pass
        except ImportError:
            pass
        candidates.append(Path(r"C:\Program Files (x86)\Steam"))
    else:
        candidates += [Path.home() / ".steam/steam", Path.home() / ".local/share/Steam"]
    for c in candidates:
        if (c / "steamapps").is_dir():
            return c
    return None


def steam_libraries(root: Path | None = None) -> list[Path]:
    root = root or steam_root()
    if root is None:
        return []
    libs = [root]
    vdf = root / "steamapps" / "libraryfolders.vdf"
    if vdf.exists():
        data = parse_vdf(vdf.read_text(encoding="utf-8", errors="replace"))
        folders = data.get("libraryfolders") or data.get("LibraryFolders") or {}
        for v in folders.values():
            path = v.get("path") if isinstance(v, dict) else v
            if path and Path(path) not in libs:
                libs.append(Path(path))
    return [lib for lib in libs if (lib / "steamapps").is_dir()]


def find_steam_app(appid: int, libraries: list[Path] | None = None) -> Path | None:
    for lib in libraries if libraries is not None else steam_libraries():
        manifest = lib / "steamapps" / f"appmanifest_{appid}.acf"
        if manifest.exists():
            data = parse_vdf(manifest.read_text(encoding="utf-8", errors="replace"))
            installdir = (data.get("AppState") or {}).get("installdir")
            if installdir:
                d = lib / "steamapps" / "common" / installdir
                if d.is_dir():
                    return d
    return None


def locate(recipe: Recipe, libraries: list[Path] | None = None) -> Path | None:
    """Return the game folder (the folder the recipe's paths are relative to)."""
    if recipe.steam_appid:
        d = find_steam_app(int(recipe.steam_appid), libraries)
        if d and (not recipe.exe or (d / recipe.exe).exists()):
            return d
    for raw in recipe.paths:
        try:
            d = Context(game_dir=Path(".")).resolve(raw)
        except KeyError:
            continue
        if d.is_dir() and (not recipe.exe or (d / recipe.exe).exists()):
            return d
    return None
