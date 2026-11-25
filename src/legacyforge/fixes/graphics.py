"""Graphics backends: DXVK, cnc-ddraw, dgVoodoo2, ReShade.

All of them work by placing proxy DLLs next to the game executable, so they
share the same rules:
- a DLL already in the folder that LegacyForge did not install is foreign:
  replacing it needs explicit approval (`--approve replace-foreign`);
- every DLL installed must match the executable's architecture;
- two backends in one recipe can't claim the same DLL (engine-level check);
- everything goes through the transaction, so removal restores the folder.
"""

from __future__ import annotations

import re
from pathlib import Path

from .. import pe, tools, transaction
from ..archive import SafeArchive
from ..context import Context
from .base import Fix, FixError, register
from .ini import edit_ini


class GraphicsBackend(Fix):
    def proxy_targets(self, ctx: Context) -> list[Path]:
        raise NotImplementedError

    def writes(self, ctx: Context) -> list[Path]:
        return self.proxy_targets(ctx)

    def approvals_needed(self, ctx: Context) -> list[tuple[str, str]]:
        out = []
        for p in self.proxy_targets(ctx):
            if p.suffix.lower() == ".dll" and p.exists() and transaction.owner_of(p, ctx.game_dir) is None:
                out.append(("replace-foreign", f"{p.name} already exists and wasn't installed by "
                                               f"LegacyForge (game file, mod or another tool)"))
        return out

    def _install_dll(self, ctx: Context, dest: Path, data: bytes, exe_arch: str) -> None:
        try:
            info = pe.read_info_bytes(data)
        except pe.PEError as e:
            raise FixError(f"{self.type}: {dest.name} from the archive is not a valid DLL: {e}")
        if info.arch != exe_arch:
            raise FixError(f"{self.type}: {dest.name} is {info.arch} but the game is {exe_arch}")
        ctx.write(dest, data)


# --- DXVK ------------------------------------------------------------------

DXVK_API_DLLS = {
    "d3d8": ["d3d8.dll", "d3d9.dll"],
    "d3d9": ["d3d9.dll"],
    "d3d10": ["d3d10core.dll", "d3d11.dll", "dxgi.dll"],
    "d3d11": ["d3d11.dll", "dxgi.dll"],
}
DXVK_CONF_KEY = re.compile(r"^(dxgi|d3d8|d3d9|d3d10|d3d11|dxvk)\.[A-Za-z0-9]+$")


@register
class DXVK(GraphicsBackend):
    """- dxvk: {api: d3d9, exe: game.exe, config: {d3d9.maxFrameRate: 60}}"""

    type = "dxvk"
    summary = "install DXVK (Direct3D 8-11 to Vulkan)"

    def validate(self) -> None:
        self._check_keys({"api", "exe", "config"})
        if not isinstance(self.params, dict) or self.params.get("api") not in DXVK_API_DLLS:
            raise FixError(f"dxvk: 'api' must be one of {sorted(DXVK_API_DLLS)}")
        for k, v in (self.params.get("config") or {}).items():
            if not DXVK_CONF_KEY.match(str(k)) or not isinstance(v, (str, int, float, bool)):
                raise FixError(f"dxvk: invalid config entry {k!r}")

    def _dlls(self) -> list[str]:
        return DXVK_API_DLLS[self.params["api"]]

    def describe_static(self) -> str:
        return f"install DXVK for {self.params['api']} ({', '.join(self._dlls())})"

    def proxy_targets(self, ctx: Context) -> list[Path]:
        d = self._exe(ctx).parent
        out = [d / x for x in self._dlls()]
        if self.params.get("config"):
            out.append(d / "dxvk.conf")
        return out

    def describe(self, ctx: Context) -> str:
        v = tools.load_pins()["dxvk"]["version"]
        return f"install DXVK {v} for {self.params['api']} ({', '.join(self._dlls())})"

    def apply(self, ctx: Context) -> str:
        exe = self._exe(ctx)
        if not exe.exists():
            raise FixError(f"dxvk: {exe} not found")
        arch = pe.read_info(exe).arch
        with SafeArchive(tools.fetch("dxvk", ctx.allow_unpinned)) as ar:
            for dll in self._dlls():
                m = ar.find(filename=dll, under=arch)
                if m is None:
                    raise FixError(f"dxvk: archive has no {arch}/{dll}")
                self._install_dll(ctx, exe.parent / dll, ar.read(m), arch)
        cfg = self.params.get("config")
        if cfg:
            def fmt(v):
                return str(v).lower() if isinstance(v, bool) else str(v)
            ctx.write(exe.parent / "dxvk.conf",
                      ("# written by LegacyForge\n" + "".join(f"{k} = {fmt(v)}\n" for k, v in cfg.items()))
                      .encode())
        return f"DXVK {tools.load_pins()['dxvk']['version']} ({arch}) installed: {', '.join(self._dlls())}"


# --- cnc-ddraw ---------------------------------------------------------------

CNC_KEYS = {"windowed", "fullscreen", "maintas", "boxing", "maxfps", "vsync", "renderer", "border",
            "adjmouse", "width", "height", "nonexclusive", "singlecpu", "maxgameticks", "resizable",
            "aspect_ratio", "devmode", "shader"}
CNC_RENDERERS = {"auto", "opengl", "gdi", "direct3d9", "direct3d9on12", "openglcore"}


@register
class CncDDraw(GraphicsBackend):
    """- cnc-ddraw: {exe: game.exe, settings: {windowed: true, maintas: true, renderer: auto}}"""

    type = "cnc-ddraw"
    summary = "install cnc-ddraw (DirectDraw replacement: windowed/borderless, scaling)"

    def validate(self) -> None:
        self._check_keys({"exe", "settings"})
        if not isinstance(self.params, dict):
            raise FixError("cnc-ddraw: expected a mapping")
        for k, v in (self.params.get("settings") or {}).items():
            if k not in CNC_KEYS:
                raise FixError(f"cnc-ddraw: setting {k!r} not allowed (allowed: {sorted(CNC_KEYS)})")
            if not isinstance(v, (str, int, bool)):
                raise FixError(f"cnc-ddraw: setting {k!r} must be a scalar")
            if k == "renderer" and v not in CNC_RENDERERS:
                raise FixError(f"cnc-ddraw: renderer must be one of {sorted(CNC_RENDERERS)}")

    def proxy_targets(self, ctx: Context) -> list[Path]:
        d = self._exe(ctx).parent
        return [d / "ddraw.dll", d / "ddraw.ini"]

    def describe(self, ctx: Context) -> str:
        s = self.params.get("settings") or {}
        extra = f" with {', '.join(f'{k}={v}' for k, v in s.items())}" if s else ""
        return f"install cnc-ddraw {tools.load_pins()['cnc-ddraw']['version']}{extra}"

    def apply(self, ctx: Context) -> str:
        exe = self._exe(ctx)
        if not exe.exists():
            raise FixError(f"cnc-ddraw: {exe} not found")
        arch = pe.read_info(exe).arch
        if arch != "x32":
            raise FixError("cnc-ddraw: only 32-bit games are supported")
        n = 0
        with SafeArchive(tools.fetch("cnc-ddraw", ctx.allow_unpinned)) as ar:
            dll = ar.find(filename="ddraw.dll")
            ini = ar.find(filename="ddraw.ini")
            if not dll or not ini:
                raise FixError("cnc-ddraw: archive is missing ddraw.dll or ddraw.ini")
            self._install_dll(ctx, exe.parent / "ddraw.dll", ar.read(dll), arch)
            text = ar.read(ini).decode("latin-1")
            settings = {k: (str(v).lower() if isinstance(v, bool) else str(v))
                        for k, v in (self.params.get("settings") or {}).items()}
            if settings:
                text, _ = edit_ini(text, {"ddraw": settings})
            ctx.write(exe.parent / "ddraw.ini", text.encode("latin-1"))
            for key, m in ar.members.items():
                if key.startswith("shaders/") and m.size and not key.endswith(".zip"):
                    dest = exe.parent.joinpath(*Path(m.name).parts)
                    ctx.write(dest, ar.read(m))
                    n += 1
        return f"cnc-ddraw installed (ddraw.dll, ddraw.ini, {n} shader files)"


# --- dgVoodoo2 -----------------------------------------------------------------

DGV_API = {
    "ddraw": ("ms", ["DDraw.dll", "D3DImm.dll"]),
    "d3d8": ("ms", ["D3D8.dll"]),
    "d3d9": ("ms", ["D3D9.dll"]),
    "glide": ("3dfx", ["Glide.dll", "Glide2x.dll", "Glide3x.dll"]),
}


@register
class DgVoodoo2(GraphicsBackend):
    """- dgvoodoo2: {api: glide, archive: "C:/Downloads/dgVoodoo2_86_5.zip", sha256: ...}

    dgVoodoo2 is freeware by Dege; LegacyForge never downloads or bundles it.
    The user supplies the archive they downloaded from the author's site."""

    type = "dgvoodoo2"
    summary = "install dgVoodoo2 (user-supplied) for DirectDraw / D3D 1-9 / Glide"

    def validate(self) -> None:
        self._check_keys({"api", "archive", "sha256", "exe"})
        if not isinstance(self.params, dict) or self.params.get("api") not in DGV_API:
            raise FixError(f"dgvoodoo2: 'api' must be one of {sorted(DGV_API)}")

    def _files(self) -> list[str]:
        return DGV_API[self.params["api"]][1]

    def proxy_targets(self, ctx: Context) -> list[Path]:
        d = self._exe(ctx).parent
        return [d / f for f in self._files()] + [d / "dgVoodoo.conf"]

    def approvals_needed(self, ctx: Context) -> list[tuple[str, str]]:
        out = super().approvals_needed(ctx)
        if not self.params.get("sha256"):
            out.append(("dgvoodoo2-unpinned", "no sha256 given for your dgVoodoo2 archive; "
                                              "LegacyForge can't confirm it is the genuine release"))
        return out

    def describe(self, ctx: Context) -> str:
        return f"install dgVoodoo2 ({self.params['api']}) from your archive"

    def apply(self, ctx: Context) -> str:
        from ..fsutil import sha256_file

        archive = self.params.get("archive")
        if not archive:
            raise FixError("dgvoodoo2: pass the path of the dgVoodoo2 zip you downloaded "
                           "(--param archive=...) or set 'archive' in the recipe")
        archive = Path(archive)
        if not archive.is_file():
            raise FixError(f"dgvoodoo2: {archive} not found")
        want = self.params.get("sha256")
        if want and sha256_file(archive) != want.lower():
            raise FixError("dgvoodoo2: archive hash does not match the recipe")
        exe = self._exe(ctx)
        arch = pe.read_info(exe).arch
        sub = "x86" if arch == "x32" else "x64"
        vendor = DGV_API[self.params["api"]][0]
        installed = []
        with SafeArchive(archive) as ar:
            for f in self._files():
                m = ar.find(filename=f, under=f"{vendor}/{sub}") or ar.find(filename=f, under=sub)
                if m is None:
                    if self.params["api"] == "glide":
                        continue  # not every release ships every Glide version
                    raise FixError(f"dgvoodoo2: {sub}/{f} not found in the archive")
                self._install_dll(ctx, exe.parent / f, ar.read(m), arch)
                installed.append(f)
            conf = ar.find(filename="dgVoodoo.conf")
            if conf and not (exe.parent / "dgVoodoo.conf").exists():
                ctx.write(exe.parent / "dgVoodoo.conf", ar.read(conf))
        if not installed:
            raise FixError("dgvoodoo2: no matching DLLs found in the archive")
        return f"dgVoodoo2 installed: {', '.join(installed)}"


# --- ReShade (experimental) ---------------------------------------------------------

RESHADE_DLL = {"d3d9": "d3d9.dll", "dxgi": "dxgi.dll", "d3d11": "dxgi.dll", "opengl": "opengl32.dll"}
RESHADE_INI = """[GENERAL]
EffectSearchPaths=.\\reshade-shaders\\Shaders\\**
TextureSearchPaths=.\\reshade-shaders\\Textures\\**
"""


@register
class ReShade(GraphicsBackend):
    """- reshade: {api: d3d9}   (experimental; no shader packs installed yet)"""

    type = "reshade"
    summary = "install ReShade post-processing (experimental)"

    def validate(self) -> None:
        self._check_keys({"api", "exe"})
        if not isinstance(self.params, dict) or self.params.get("api") not in RESHADE_DLL:
            raise FixError(f"reshade: 'api' must be one of {sorted(RESHADE_DLL)}")

    def proxy_targets(self, ctx: Context) -> list[Path]:
        d = self._exe(ctx).parent
        return [d / RESHADE_DLL[self.params["api"]], d / "ReShade.ini"]

    def describe(self, ctx: Context) -> str:
        return f"install ReShade as {RESHADE_DLL[self.params['api']]} (experimental)"

    def apply(self, ctx: Context) -> str:
        exe = self._exe(ctx)
        if not exe.exists():
            raise FixError(f"reshade: {exe} not found")
        arch = pe.read_info(exe).arch
        member = "ReShade32.dll" if arch == "x32" else "ReShade64.dll"
        with SafeArchive(tools.fetch("reshade", ctx.allow_unpinned)) as ar:
            m = ar.find(filename=member)
            if m is None:
                raise FixError(f"reshade: {member} not found in the installer")
            dest = exe.parent / RESHADE_DLL[self.params["api"]]
            self._install_dll(ctx, dest, ar.read(m), arch)
        ini = exe.parent / "ReShade.ini"
        if not ini.exists():
            ctx.write(ini, RESHADE_INI.encode())
        return f"ReShade installed as {dest.name}"
