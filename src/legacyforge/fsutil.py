"""Filesystem safety helpers: hashing, atomic writes, path containment, link checks.

Game folders, downloaded archives and recipes are untrusted input. Everything
that writes into a game folder goes through these helpers.
"""

from __future__ import annotations

import hashlib
import os
import stat
import tempfile
from pathlib import Path

FILE_ATTRIBUTE_REPARSE_POINT = 0x400


class UnsafePathError(Exception):
    pass


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def is_link(path: Path) -> bool:
    """True for symlinks and Windows reparse points (junctions included)."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return False
    if stat.S_ISLNK(st.st_mode):
        return True
    return bool(getattr(st, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT)


def ensure_within(base: Path, target: Path) -> Path:
    """Return target resolved, refusing anything that escapes base or passes
    through a link on the way."""
    base_r = Path(base).resolve()
    target = Path(target)
    full = target if target.is_absolute() else base_r / target
    # walk each existing component below base looking for links
    try:
        rel = Path(os.path.abspath(full)).relative_to(Path(os.path.abspath(base_r)))
    except ValueError:
        raise UnsafePathError(f"{target} is outside {base}")
    cur = base_r
    for part in rel.parts:
        if part in ("..", ""):
            raise UnsafePathError(f"{target}: parent references are not allowed")
        cur = cur / part
        if is_link(cur):
            raise UnsafePathError(f"{cur} is a link; refusing to write through it")
    resolved = full.resolve()
    if resolved != base_r and base_r not in resolved.parents:
        raise UnsafePathError(f"{target} resolves outside {base}")
    return resolved


def atomic_write(path: Path, data: bytes) -> None:
    """Write via a temp file in the same folder, then replace. A crash leaves
    either the old file or the new one, never half of each."""
    path = Path(path)
    if is_link(path):
        raise UnsafePathError(f"{path} is a link; refusing to overwrite it")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".lftmp", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        if path.exists():
            try:
                shutil_copymode(path, tmp)
            except OSError:
                pass
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def shutil_copymode(src: Path, dst: str) -> None:
    import shutil

    shutil.copymode(src, dst)


def atomic_copy(src: Path, dst: Path) -> None:
    atomic_write(dst, Path(src).read_bytes())
