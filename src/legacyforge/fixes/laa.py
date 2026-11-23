"""Large Address Aware flag: lets a 32-bit game use 4 GiB instead of 2 GiB on
64-bit Windows. Never applied blindly: it needs a recipe whose edition hash
matches the executable, or the user's explicit approval (`--approve laa`)."""

from __future__ import annotations

from pathlib import Path

from .. import pe
from ..analysis import PROTECTION_SECTIONS
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
    modifies_executable = True
    summary = "set the Large Address Aware (4 GiB) flag"

    def _targets(self, ctx: Context) -> list[Path]:
        p = self.params
        if isinstance(p, str):
            return [ctx.resolve(p)]
        if isinstance(p, list):
            return [ctx.resolve(x) for x in p]
        return [self._exe(ctx)]

    def validate(self) -> None:
        p = self.params
        ok = isinstance(p, str) or (isinstance(p, dict) and set(p) <= {"exe"}) or \
            (isinstance(p, list) and all(isinstance(x, str) for x in p))
        if not ok:
            raise FixError("laa: expected an exe name, a list of them, or {}")

    def writes(self, ctx: Context) -> list[Path]:
        return self._targets(ctx)

    def approvals_needed(self, ctx: Context) -> list[tuple[str, str]]:
        from ..fsutil import sha256_file

        out = []
        unconfirmed = [exe.name for exe in self._targets(ctx)
                       if not (exe.exists() and sha256_file(exe) in ctx.known_hashes)]
        if unconfirmed:
            out.append(("laa", f"modifies {', '.join(unconfirmed)}; that exact version isn't confirmed by the "
                               "recipe's hashes, and some games break with LAA"))
        for exe in self._targets(ctx):
            if exe.exists():
                try:
                    if pe.load(exe).has_signature:
                        out.append(("laa-signed", f"{exe.name} is digitally signed; patching invalidates "
                                                  f"the signature"))
                except pe.PEError:
                    pass
        return out

    def describe(self, ctx: Context) -> str:
        return "set Large Address Aware (4 GiB) flag on " + ", ".join(t.name for t in self._targets(ctx))

    def apply(self, ctx: Context) -> str:
        out = []
        for exe in self._targets(ctx):
            if not exe.exists():
                raise FixError(f"laa: {exe} not found")
            p = pe.load(exe)
            prot = [s.name for s in p.sections if s.name.lower() in PROTECTION_SECTIONS]
            if prot:
                raise FixError(f"laa: {exe.name} has protection/packer sections {prot}; "
                               f"LegacyForge does not modify protected executables")
            if not p.is_32bit:
                out.append(f"{exe.name}: 64-bit, not needed")
            elif p.info.large_address_aware:
                out.append(f"{exe.name}: already 4 GiB aware")
            else:
                data = bytearray(p.data)
                pe.set_laa_bytes(data)
                pe.verify_laa_patch(p.data, bytes(data))
                ctx.write(exe, bytes(data))
                if not pe.read_info(exe).large_address_aware:
                    raise FixError(f"laa: {exe.name} did not verify after writing")
                out.append(f"{exe.name}: LAA flag set and verified")
        return "; ".join(out)
