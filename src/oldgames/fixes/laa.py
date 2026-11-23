"""Large Address Aware flag: lets a 32-bit game use 4 GB instead of 2 GB."""

from __future__ import annotations

from pathlib import Path

from .. import pe
from ..context import Context
from .base import Fix, FixError, register


@register
class LAA(Fix):
    """Recipe forms:
    - laa: game.exe
    - laa: [game.exe, launcher.exe]
    - laa: {}            # uses detect.exe
    """

    type = "laa"

    def _targets(self, ctx: Context) -> list[Path]:
        p = self.params
        if isinstance(p, str):
            return [ctx.resolve(p)]
        if isinstance(p, list):
            return [ctx.resolve(x) for x in p]
        return [self._exe(ctx)]

    def validate(self) -> None:
        p = self.params
        ok = isinstance(p, (str, dict)) or (isinstance(p, list) and all(isinstance(x, str) for x in p))
        if not ok:
            raise FixError("laa: expected an exe name, a list of them, or {}")

    def writes(self, ctx: Context) -> list[Path]:
        return self._targets(ctx)

    def describe(self, ctx: Context) -> str:
        return "set Large Address Aware (4 GB) flag on " + ", ".join(t.name for t in self._targets(ctx))

    def apply(self, ctx: Context) -> str:
        out = []
        for exe in self._targets(ctx):
            if not exe.exists():
                raise FixError(f"laa: {exe} not found")
            info = pe.read_info(exe)
            if not info.is_32bit:
                out.append(f"{exe.name}: 64-bit, not needed")
            elif info.large_address_aware:
                out.append(f"{exe.name}: already 4 GB aware")
            else:
                ctx.track(exe)
                pe.set_laa(exe)
                out.append(f"{exe.name}: LAA flag set")
        return "; ".join(out)
