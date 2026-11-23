"""ReShade post-processing (experimental).

Installs the ReShade DLL under the graphics API's name next to the exe.
Shader packs are not installed yet; use the in-game overlay (Home key) to
add effects. Cannot be combined with DXVK on the same DLL name, which the
engine detects as a conflict.
"""

from __future__ import annotations

import zipfile
from pathlib import Path

from .. import pe, tools
from ..context import Context
from .base import Fix, FixError, register

API_DLL = {
    "d3d9": "d3d9.dll",
    "dxgi": "dxgi.dll",
    "d3d11": "dxgi.dll",
    "opengl": "opengl32.dll",
}

INI_TEMPLATE = """[GENERAL]
EffectSearchPaths=.\\reshade-shaders\\Shaders\\**
TextureSearchPaths=.\\reshade-shaders\\Textures\\**
"""


@register
class ReShade(Fix):
    """Recipe form:
    - reshade: {api: d3d9}         # or dxgi / d3d11 / opengl
    """

    type = "reshade"

    def validate(self) -> None:
        if not isinstance(self.params, dict) or self.params.get("api") not in API_DLL:
            raise FixError(f"reshade: 'api' must be one of {sorted(API_DLL)}")

    def _dll(self) -> str:
        return API_DLL[self.params["api"]]

    def writes(self, ctx: Context) -> list[Path]:
        d = self._exe(ctx).parent
        return [d / self._dll(), d / "ReShade.ini"]

    def describe(self, ctx: Context) -> str:
        return f"install ReShade as {self._dll()} (experimental)"

    def apply(self, ctx: Context) -> str:
        exe = self._exe(ctx)
        if not exe.exists():
            raise FixError(f"reshade: {exe} not found")
        member = "ReShade32.dll" if pe.read_info(exe).is_32bit else "ReShade64.dll"
        setup = tools.fetch("reshade", ctx.allow_unpinned)
        try:
            with zipfile.ZipFile(setup) as z:
                data = z.read(member)
        except (zipfile.BadZipFile, KeyError) as e:
            raise FixError(f"reshade: could not extract {member} from installer: {e}")
        dest = exe.parent / self._dll()
        ctx.track(dest)
        dest.write_bytes(data)
        ini = exe.parent / "ReShade.ini"
        if not ini.exists():
            ctx.track(ini)
            ini.write_text(INI_TEMPLATE, encoding="utf-8")
        return f"ReShade installed as {dest.name}"
