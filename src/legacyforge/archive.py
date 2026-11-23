"""Safe reading of third-party archives (DXVK tarballs, cnc-ddraw and dgVoodoo2 zips).

Members are only ever read into memory and written by LegacyForge to a path it
chose; archive paths are never used as destinations. Still, every member is
validated: no absolute paths, no '..', no links/devices, and size limits
against decompression bombs.
"""

from __future__ import annotations

import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

MAX_MEMBER_BYTES = 256 << 20
MAX_TOTAL_BYTES = 1 << 30
MAX_MEMBERS = 20000
MAX_RATIO = 200  # uncompressed / compressed, zip only


class ArchiveError(Exception):
    pass


@dataclass
class Member:
    name: str          # normalised, forward slashes
    size: int


def _normalise(name: str) -> str:
    n = name.replace("\\", "/")
    p = PurePosixPath(n)
    if n.startswith("/") or (len(n) > 1 and n[1] == ":") or p.is_absolute():
        raise ArchiveError(f"absolute path in archive: {name!r}")
    if any(part == ".." for part in p.parts):
        raise ArchiveError(f"path traversal in archive: {name!r}")
    if any(ch in n for ch in "\0"):
        raise ArchiveError(f"invalid character in archive path: {name!r}")
    return str(p)


class SafeArchive:
    def __init__(self, path: Path):
        self.path = Path(path)
        self._zip: zipfile.ZipFile | None = None
        self._tar: tarfile.TarFile | None = None
        self.members: dict[str, Member] = {}
        if zipfile.is_zipfile(self.path):
            self._zip = zipfile.ZipFile(self.path)
            infos = self._zip.infolist()
            if len(infos) > MAX_MEMBERS:
                raise ArchiveError("too many members")
            total = 0
            for i in infos:
                if i.is_dir():
                    continue
                mode = (i.external_attr >> 16) & 0o170000
                if mode == 0o120000:
                    raise ArchiveError(f"symlink in archive: {i.filename!r}")
                name = _normalise(i.filename)
                if i.file_size > MAX_MEMBER_BYTES:
                    raise ArchiveError(f"{name} is too large")
                if i.compress_size and i.file_size / max(i.compress_size, 1) > MAX_RATIO and i.file_size > (1 << 20):
                    raise ArchiveError(f"{name} has a suspicious compression ratio")
                total += i.file_size
                self.members[name.lower()] = Member(name, i.file_size)
            if total > MAX_TOTAL_BYTES:
                raise ArchiveError("archive expands beyond the size limit")
        elif tarfile.is_tarfile(self.path):
            self._tar = tarfile.open(self.path, "r:*")
            total = 0
            for count, m in enumerate(self._tar):
                if count > MAX_MEMBERS:
                    raise ArchiveError("too many members")
                if m.isdir():
                    continue
                if not m.isfile():
                    raise ArchiveError(f"link or special file in archive: {m.name!r}")
                name = _normalise(m.name)
                if m.size > MAX_MEMBER_BYTES:
                    raise ArchiveError(f"{name} is too large")
                total += m.size
                self.members[name.lower()] = Member(name, m.size)
            if total > MAX_TOTAL_BYTES:
                raise ArchiveError("archive expands beyond the size limit")
        else:
            raise ArchiveError(f"{self.path.name} is not a zip or tar archive")

    def find(self, *, filename: str, under: str | None = None) -> Member | None:
        """Member whose basename matches (case-insensitive), optionally within a
        folder whose path contains `under` (e.g. 'x32' or 'ms/x86')."""
        filename = filename.lower()
        for key, m in sorted(self.members.items()):
            if PurePosixPath(key).name != filename:
                continue
            if under and f"/{under.lower().strip('/')}/" not in f"/{key}":
                continue
            return m
        return None

    def read(self, member: Member) -> bytes:
        if self._zip is not None:
            with self._zip.open(member.name if member.name in self._zip.namelist() else
                                next(n for n in self._zip.namelist() if _normalise(n) == member.name)) as f:
                data = f.read(MAX_MEMBER_BYTES + 1)
        else:
            assert self._tar is not None
            ti = next(t for t in self._tar.getmembers() if t.isfile() and _normalise(t.name) == member.name)
            f = self._tar.extractfile(ti)
            if f is None:
                raise ArchiveError(f"cannot read {member.name}")
            data = f.read(MAX_MEMBER_BYTES + 1)
        if len(data) > MAX_MEMBER_BYTES or len(data) != member.size:
            raise ArchiveError(f"{member.name}: size mismatch while reading")
        return data

    def close(self) -> None:
        if self._zip:
            self._zip.close()
        if self._tar:
            self._tar.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
