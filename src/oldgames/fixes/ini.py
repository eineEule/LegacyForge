"""Edit INI-style config files while preserving comments and layout."""

from __future__ import annotations

import re
from pathlib import Path

from ..context import Context
from .base import Fix, FixError, register

SECTION_RE = re.compile(r"^\s*\[(.+?)\]\s*$")


def _key_re(key: str) -> re.Pattern:
    return re.compile(r"^(\s*)(" + re.escape(key) + r")(\s*=\s*)(.*?)(\r?\n?)$", re.IGNORECASE)


def edit_ini(text: str, settings: dict) -> tuple[str, list[str]]:
    """settings: {section_or_None: {key: value}}. Section None means: change
    the key wherever it appears. Missing keys are appended to their section
    (created if needed). Returns (new_text, change_log)."""
    lines = text.splitlines(keepends=True)
    if lines and not lines[-1].endswith("\n"):
        lines[-1] += "\n"
    log: list[str] = []

    for section, pairs in settings.items():
        for key, value in pairs.items():
            value = str(value)
            pattern = _key_re(key)
            current = None
            found = False
            section_end = None
            for i, line in enumerate(lines):
                m = SECTION_RE.match(line)
                if m:
                    if section is not None and current is not None and current.lower() == section.lower():
                        section_end = i
                    current = m.group(1)
                    continue
                if section is not None and (current or "").lower() != section.lower():
                    continue
                km = pattern.match(line)
                if km:
                    found = True
                    if km.group(4) != value:
                        lines[i] = f"{km.group(1)}{km.group(2)}{km.group(3)}{value}{km.group(5) or chr(10)}"
                        log.append(f"{key}: {km.group(4)} -> {value}")
                    else:
                        log.append(f"{key}: already {value}")
            if found:
                continue
            if section is None:
                raise FixError(f"ini: key '{key}' not found and no section given")
            if section_end is None and current is not None and current.lower() == section.lower():
                section_end = len(lines)
            if section_end is None:
                lines.append(f"[{section}]\n")
                section_end = len(lines)
            lines.insert(section_end, f"{key} = {value}\n")
            log.append(f"{key}: added = {value}")
    return "".join(lines), log


@register
class Ini(Fix):
    """Recipe form:
    - ini:
        file: "${DOCUMENTS}/My Games/Game/settings.ini"
        set:
          UserSettings: {MSAASamples: 2}   # section -> {key: value}
          "*": {LoggingEnabled: 1}         # any section
    """

    type = "ini"

    def validate(self) -> None:
        p = self.params
        if not isinstance(p, dict) or not isinstance(p.get("file"), str) or not isinstance(p.get("set"), dict):
            raise FixError("ini: needs 'file' and 'set'")
        for sec, pairs in p["set"].items():
            if not isinstance(pairs, dict):
                raise FixError(f"ini: section '{sec}' must map keys to values")

    def _settings(self) -> dict:
        return {(None if s == "*" else s): v for s, v in self.params["set"].items()}

    def writes(self, ctx: Context) -> list[Path]:
        return [ctx.resolve(self.params["file"])]

    def describe(self, ctx: Context) -> str:
        keys = [k for pairs in self.params["set"].values() for k in pairs]
        return f"edit {Path(self.params['file']).name}: {', '.join(keys)}"

    def apply(self, ctx: Context) -> str:
        path = ctx.resolve(self.params["file"])
        if not path.exists():
            raise FixError(f"ini: {path} not found (run the game once to create it)")
        raw = path.read_bytes()
        if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
            encoding = "utf-16"
        elif raw[:3] == b"\xef\xbb\xbf":
            encoding = "utf-8-sig"
        else:
            encoding = "utf-8"  # old games often write ANSI; surrogateescape keeps those bytes
        text = raw.decode(encoding, errors="surrogateescape")
        new, log = edit_ini(text, self._settings())
        if new != text:
            ctx.track(path)
            path.write_bytes(new.encode(encoding, errors="surrogateescape"))
        return f"{path.name}: " + "; ".join(log)
