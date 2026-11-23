"""DXVK: translate Direct3D 8/9/10/11 to Vulkan by dropping DLLs next to the exe."""

from __future__ import annotations

import tarfile
from pathlib import Path

from .. import pe, tools
from ..context import Context
from .base import Fix, FixError, register

API_DLLS = {
    "d3d8": ["d3d8.dll", "d3d9.dll"],
    "d3d9": ["d3d9.dll"],
    "d3d10": ["d3d10core.dll", "d3d11.dll", "dxgi.dll"],
    "d3d11": ["d3d11.dll", "dxgi.dll"],
}


@register
class DXVK(Fix):
    """Recipe form:
    - dxvk: {api: d3d9}            # or d3d8 / d3d10 / d3d11
      (optional) exe: path to the exe; DLLs go next to it, arch is read from it
    """

    type = "dxvk"

    def validate(self) -> None:
        if not isinstance(self.params, dict) or self.params.get("api") not in API_DLLS:
            raise FixError(f"dxvk: 'api' must be one of {sorted(API_DLLS)}")

    def _dlls(self) -> list[str]:
        return API_DLLS[self.params["api"]]

    def writes(self, ctx: Context) -> list[Path]:
        target = self._exe(ctx).parent
        return [target / d for d in self._dlls()]

    def describe(self, ctx: Context) -> str:
        return f"install DXVK for {self.params['api']} ({', '.join(self._dlls())})"

    def apply(self, ctx: Context) -> str:
        exe = self._exe(ctx)
        if not exe.exists():
            raise FixError(f"dxvk: {exe} not found")
        arch = pe.read_info(exe).arch
        archive = tools.fetch("dxvk", ctx.allow_unpinned)
        wanted = set(self._dlls())
        written = []
        with tarfile.open(archive, "r:gz") as tar:
            for m in tar.getmembers():
                parts = Path(m.name).parts
                if len(parts) == 3 and parts[1] == arch and parts[2] in wanted and m.isfile():
                    dest = exe.parent / parts[2]
                    ctx.track(dest)
                    src = tar.extractfile(m)
                    assert src is not None
                    dest.write_bytes(src.read())
                    written.append(parts[2])
        missing = wanted - set(written)
        if missing:
            raise FixError(f"dxvk: archive missing {sorted(missing)} for {arch}")
        return f"DXVK {arch} installed: {', '.join(sorted(written))}"
