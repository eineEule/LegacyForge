"""Windows compatibility settings for one executable, via Microsoft's own
per-user AppCompatFlags layers (what the exe's Properties > Compatibility tab
writes). Per-user (HKCU) only, scoped to the exact exe path, fully reversible.
No custom API hooking, no system-wide shims, never 'Run as administrator'."""

from __future__ import annotations

from pathlib import Path

from .. import winapi
from ..context import Context
from ..system import LAYERS_KEY
from .base import Fix, FixError, register

MODES = {"win95": "WIN95", "win98": "WIN98", "winxpsp2": "WINXPSP2", "winxpsp3": "WINXPSP3",
         "vista": "VISTARTM", "vistasp2": "VISTASP2", "win7": "WIN7RTM", "win8": "WIN8RTM"}
DPI = {"application": "HIGHDPIAWARE", "system": "DPIUNAWARE", "system-enhanced": "GDIDPISCALING DPIUNAWARE"}
COLOR = {"256": "256COLOR", "16bit": "16BITCOLOR"}
ALL_FLAGS = set(MODES.values()) | {"HIGHDPIAWARE", "DPIUNAWARE", "GDIDPISCALING", "256COLOR", "16BITCOLOR",
                                   "640X480", "DISABLEDXMAXIMIZEDWINDOWEDMODE"}


@register
class Compat(Fix):
    """- compat: {mode: winxpsp3, dpi: application, disable_fullscreen_optimizations: true,
                  color: 16bit, resolution_640x480: false, exe: game.exe}"""

    type = "compat"
    summary = "Windows compatibility settings for the executable (per user)"

    def validate(self) -> None:
        self._check_keys({"exe", "mode", "dpi", "disable_fullscreen_optimizations", "color",
                          "resolution_640x480"})
        p = self.params
        if not isinstance(p, dict):
            raise FixError("compat: expected a mapping")
        if "mode" in p and p["mode"] not in MODES:
            raise FixError(f"compat: mode must be one of {sorted(MODES)}")
        if "dpi" in p and p["dpi"] not in DPI:
            raise FixError(f"compat: dpi must be one of {sorted(DPI)}")
        if "color" in p and p["color"] not in COLOR:
            raise FixError(f"compat: color must be one of {sorted(COLOR)}")
        if not self.flags():
            raise FixError("compat: no settings given")

    def flags(self) -> list[str]:
        p, out = self.params, []
        if p.get("mode"):
            out.append(MODES[p["mode"]])
        if p.get("dpi"):
            out += DPI[p["dpi"]].split()
        if p.get("color"):
            out.append(COLOR[p["color"]])
        if p.get("resolution_640x480"):
            out.append("640X480")
        if p.get("disable_fullscreen_optimizations"):
            out.append("DISABLEDXMAXIMIZEDWINDOWEDMODE")
        return out

    def describe(self, ctx: Context) -> str:
        return f"Windows compatibility for {self._exe(ctx).name}: {' '.join(self.flags())} (current user)"

    @staticmethod
    def merge(existing: str | None, ours: list[str]) -> str:
        tokens = (existing or "").split()
        prefix = [t for t in tokens if t in ("~", "$")] or ["~"]
        keep = [t for t in tokens if t not in ("~", "$")]
        if any(t in MODES.values() for t in ours):
            keep = [t for t in keep if t not in MODES.values()]
        if any(t in ("HIGHDPIAWARE", "DPIUNAWARE", "GDIDPISCALING") for t in ours):
            keep = [t for t in keep if t not in ("HIGHDPIAWARE", "DPIUNAWARE", "GDIDPISCALING")]
        merged = keep + [t for t in ours if t not in keep]
        return " ".join(prefix[:1] + merged)

    def apply(self, ctx: Context) -> str:
        if not winapi.IS_WINDOWS and ctx.registry is None:
            raise FixError("compat: Windows compatibility settings can only be applied on Windows")
        exe = self._exe(ctx)
        if not exe.exists():
            raise FixError(f"compat: {exe} not found")
        name = str(Path(exe).resolve())
        reg = ctx.reg
        if ctx.snapshot is not None:
            ctx.snapshot.track_registry(winapi.HKCU, LAYERS_KEY, name)
        new = self.merge(reg.get(winapi.HKCU, LAYERS_KEY, name), self.flags())
        reg.set(winapi.HKCU, LAYERS_KEY, name, new)
        if reg.get(winapi.HKCU, LAYERS_KEY, name) != new:
            raise FixError("compat: setting did not verify")
        return f"{exe.name}: {new}"
