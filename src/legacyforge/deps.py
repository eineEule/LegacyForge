"""Runtime dependency detection: which runtimes an executable needs, and
whether they can be found. Detection only; LegacyForge never installs
system-wide runtimes itself and never fetches DLLs from DLL-download sites."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from pathlib import Path

from . import winapi

VC_REDIST_2015_2022 = "https://aka.ms/vs/17/release/vc_redist.x86.exe"
MS_DOWNLOAD_CENTER = "Microsoft Download Center (search the exact package name)"

# (pattern, runtime name, official source, note)
RULES: list[tuple[str, str, str, str]] = [
    (r"msvc[rp]71\.dll", "Visual C++ .NET 2003 runtime", "ships with the game",
     "No official redistributable installer exists; the game normally ships these DLLs."),
    (r"msvc[rp]80\.dll", "Visual C++ 2005 SP1 Redistributable (x86)", MS_DOWNLOAD_CENTER, ""),
    (r"msvc[rp]90\.dll", "Visual C++ 2008 SP1 Redistributable (x86)", MS_DOWNLOAD_CENTER, ""),
    (r"msvc[rp]100\.dll", "Visual C++ 2010 SP1 Redistributable (x86)", MS_DOWNLOAD_CENTER, ""),
    (r"msvc[rp]110\.dll", "Visual C++ 2012 Update 4 Redistributable (x86)", MS_DOWNLOAD_CENTER, ""),
    (r"msvc[rp]120\.dll", "Visual C++ 2013 Redistributable (x86)", MS_DOWNLOAD_CENTER, ""),
    (r"(vcruntime140(_1)?|msvcp140)\.dll", "Visual C++ 2015-2022 Redistributable", VC_REDIST_2015_2022, ""),
    (r"api-ms-win-crt-.*\.dll", "Universal C Runtime", "built into Windows 10 and 11", ""),
    (r"d3dx(9|10|11)_\d+\.dll|d3dcompiler_\d+\.dll|xinput1_[123]\.dll|xaudio2_[0-7]\.dll|"
     r"x3daudio1_\d\.dll|xactengine\d_\d\.dll|xapofx1_\d\.dll",
     "DirectX End-User Runtimes (June 2010)", MS_DOWNLOAD_CENTER,
     "Optional legacy DirectX components. Modern Windows includes Direct3D itself, "
     "but not these helper libraries."),
    (r"xinput1_4\.dll|xinput9_1_0\.dll", "XInput (built into Windows 8+)", "built into Windows", ""),
    (r"mscoree\.dll", ".NET Framework", "Windows Features / Microsoft", ""),
    (r"openal32\.dll", "OpenAL", "openal.org (Creative OpenAL installer)", "Many games ship it locally."),
    (r"binkw32\.dll|mss32\.dll|smackw32\.dll|physxloader\.dll|fmod(ex)?\.dll",
     "Game-bundled middleware", "ships with the game", "Should be in the game folder; reinstall if missing."),
]

BUILT_IN = {"kernel32.dll", "user32.dll", "gdi32.dll", "advapi32.dll", "shell32.dll", "ole32.dll",
            "oleaut32.dll", "comctl32.dll", "comdlg32.dll", "winmm.dll", "ws2_32.dll", "wsock32.dll",
            "version.dll", "shlwapi.dll", "imm32.dll", "msvcrt.dll", "ntdll.dll", "rpcrt4.dll",
            "dsound.dll", "dinput.dll", "dinput8.dll", "ddraw.dll", "d3d8.dll", "d3d9.dll", "d3d11.dll",
            "dxgi.dll", "d3d10.dll", "d3d10_1.dll", "opengl32.dll", "glu32.dll", "winspool.drv",
            "setupapi.dll", "wininet.dll", "iphlpapi.dll", "dbghelp.dll", "psapi.dll", "msacm32.dll",
            "avifil32.dll", "msvfw32.dll", "dplayx.dll", "dpnet.dll", "crypt32.dll", "secur32.dll",
            "userenv.dll", "uxtheme.dll", "dwmapi.dll", "hid.dll", "xinput9_1_0.dll", "xinput1_4.dll",
            "mfplat.dll", "quartz.dll", "strmiids.dll", "d3dim.dll", "d3dim700.dll", "mpr.dll",
            "netapi32.dll", "wintrust.dll", "normaliz.dll", "bcrypt.dll", "dwrite.dll", "d2d1.dll"}


@dataclass
class Requirement:
    dll: str
    runtime: str
    status: str        # present-in-game-folder | present-on-system | missing | unknown | built-in
    source: str
    note: str = ""


def classify(dll: str) -> tuple[str, str, str] | None:
    for pat, name, src, note in RULES:
        if re.fullmatch(pat, dll, re.I):
            return name, src, note
    return None


SXS = re.compile(r"(msvc[rp]|mfc|atl)(80|90)\.dll", re.I)


def sxs_present(dll: str, is_32bit: bool, winsxs: Path | None = None) -> bool | None:
    """VC++ 2005/2008 runtimes live in WinSxS, not System32/SysWOW64.
    True/False when the store can be read, None when it can't."""
    m = SXS.fullmatch(dll)
    if not m:
        return None
    kind = {"msvcr": "crt", "msvcp": "crt", "mfc": "mfc", "atl": "atl"}[m.group(1).lower()]
    ver = m.group(2)
    if winsxs is None:
        import os

        if not winapi.IS_WINDOWS:
            return None
        winsxs = Path(os.environ.get("SystemRoot", r"C:\Windows"), "WinSxS")
    try:
        prefix = f"{'x86' if is_32bit else 'amd64'}_microsoft.vc{ver}.{kind}_"
        dirs = [d for d in winsxs.iterdir() if d.name.lower().startswith(prefix)]
    except OSError:
        return None
    return any((d / dll).exists() or (d / dll.lower()).exists() for d in dirs)


def check(imports: list[str], game_dir: Path, is_32bit: bool, winsxs: Path | None = None) -> list[Requirement]:
    game_files = {p.name.lower() for p in Path(game_dir).iterdir()} if Path(game_dir).is_dir() else set()
    sys_dirs = winapi.system_dll_dirs(is_32bit)
    out: list[Requirement] = []
    for dll in sorted(set(d.lower() for d in imports)):
        c = classify(dll)
        if c is None:
            if dll in BUILT_IN:
                continue
            name, src, note = "Unrecognised library", "unknown", "Not a known runtime; may ship with the game."
        else:
            name, src, note = c
        if dll in game_files:
            status = "present-in-game-folder"
        elif name.endswith("(built into Windows 8+)") or src.startswith("built into"):
            status = "built-in"
        elif SXS.fullmatch(dll) and (winsxs is not None or sys_dirs):
            found = sxs_present(dll, is_32bit, winsxs)
            status = {True: "present-on-system", False: "missing", None: "unknown"}[found]
            note = (note + " " if note else "") + "Side-by-side runtime (checked in WinSxS)."
        elif sys_dirs:
            status = "present-on-system" if any(Path(d, dll).exists() for d in sys_dirs) else "missing"
        else:
            status = "unknown"
        if c is None and status in ("present-on-system", "present-in-game-folder"):
            continue  # an unrecognised DLL that resolves fine is not worth reporting
        out.append(Requirement(dll, name, status, src, note))
    return out


def as_dicts(reqs: list[Requirement]) -> list[dict]:
    return [asdict(r) for r in reqs]
