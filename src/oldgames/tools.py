"""Download third-party tools from their official sources, pinned by SHA-256.

The project never bundles tools like DXVK or ReShade. Each is fetched at
apply time from the URL in data/tools.yaml and verified against its pin.
"""

from __future__ import annotations

import hashlib
import os
import sys
import urllib.request
from importlib import resources
from pathlib import Path

import yaml


class ToolError(Exception):
    pass


def cache_dir() -> Path:
    base = os.environ.get("OLDGAMES_CACHE")
    if base:
        return Path(base)
    if sys.platform == "win32":
        return Path(os.environ.get("LOCALAPPDATA", Path.home())) / "oldgames" / "cache"
    return Path.home() / ".cache" / "oldgames"


def load_pins() -> dict:
    text = resources.files("oldgames").joinpath("data/tools.yaml").read_text(encoding="utf-8")
    return yaml.safe_load(text)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch(name: str, allow_unpinned: bool = False) -> Path:
    pins = load_pins()
    if name not in pins:
        raise ToolError(f"unknown tool '{name}'")
    spec = pins[name]
    url, pin = spec["url"], spec.get("sha256")
    dest = cache_dir() / f"{name}-{spec['version']}-{Path(url).name}"
    dest.parent.mkdir(parents=True, exist_ok=True)

    if not dest.exists():
        print(f"  downloading {name} {spec['version']} from {url}")
        tmp = dest.with_suffix(dest.suffix + ".part")
        req = urllib.request.Request(url, headers={"User-Agent": "oldgames"})
        with urllib.request.urlopen(req, timeout=120) as r, open(tmp, "wb") as f:
            while chunk := r.read(1 << 20):
                f.write(chunk)
        tmp.replace(dest)

    actual = _sha256(dest)
    if pin:
        if actual != pin.lower():
            dest.unlink()
            raise ToolError(
                f"{name}: hash mismatch (expected {pin}, got {actual}). Download deleted."
            )
    elif not allow_unpinned:
        raise ToolError(
            f"{name} {spec['version']} has no pinned sha256 in tools.yaml.\n"
            f"  Downloaded file hashes to {actual}.\n"
            f"  Verify it against the official release, add it to tools.yaml, "
            f"or rerun with --allow-unpinned."
        )
    else:
        print(f"  WARNING: {name} is unpinned; sha256={actual}")
    return dest
