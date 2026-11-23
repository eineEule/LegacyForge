"""System compatibility inspection. Read-only; every probe degrades to
'unavailable: <reason>' rather than guessing."""

from __future__ import annotations

import ctypes
import os
import platform
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

from . import winapi

LAYERS_KEY = r"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers"


@dataclass
class SystemInfo:
    os: dict
    memory: dict
    gpus: list | str
    vulkan: dict
    legacy_runtimes: dict
    security: dict
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def os_64bit(self) -> bool | None:
        return self.os.get("64bit")

    @property
    def vulkan_32bit(self) -> bool | None:
        return self.vulkan.get("loader_32bit")


def _probe(fn, *a):
    try:
        return fn(*a)
    except winapi.Unavailable as e:
        return f"unavailable: {e}"
    except Exception as e:  # a probe must never break analysis
        return f"unavailable: {type(e).__name__}: {e}"


def _os() -> dict:
    info = {"platform": sys.platform, "release": platform.release(), "version": platform.version(),
            "machine": platform.machine()}
    info["64bit"] = platform.machine().lower() in ("amd64", "x86_64", "arm64", "aarch64")
    if winapi.IS_WINDOWS:
        v = sys.getwindowsversion()
        info.update(windows_build=v.build, windows_major=v.major,
                    windows_name="Windows 11" if v.major == 10 and v.build >= 22000 else
                    f"Windows {platform.release()}")
        info["edition"] = platform.win32_edition() if hasattr(platform, "win32_edition") else None
    return info


def _memory() -> dict:
    if winapi.IS_WINDOWS:
        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                        ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                        ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                        ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                        ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]

        m = MEMORYSTATUSEX()
        m.dwLength = ctypes.sizeof(m)
        if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m)):
            raise winapi.Unavailable("GlobalMemoryStatusEx failed")
        return {"total_gib": round(m.ullTotalPhys / 2**30, 1), "available_gib": round(m.ullAvailPhys / 2**30, 1),
                "commit_limit_gib": round(m.ullTotalPageFile / 2**30, 1),
                "note": "a 32-bit game is limited by its own address space (2 or 4 GiB), "
                        "not by installed RAM"}
    if hasattr(os, "sysconf"):
        pages, size = os.sysconf("SC_PHYS_PAGES"), os.sysconf("SC_PAGE_SIZE")
        return {"total_gib": round(pages * size / 2**30, 1)}
    raise winapi.Unavailable("no memory probe for this platform")


def _gpus():
    data = winapi.powershell_json(
        "Get-CimInstance Win32_VideoController | Select-Object Name,DriverVersion,"
        "@{n='DriverDate';e={if ($_.DriverDate) { $_.DriverDate.ToString('yyyy-MM-dd') }}},"
        "AdapterCompatibility")
    if isinstance(data, dict):
        data = [data]
    return data or []


def _vulkan() -> dict:
    if not winapi.IS_WINDOWS:
        raise winapi.Unavailable("Vulkan loader check is Windows-specific")
    root = os.environ.get("SystemRoot", r"C:\Windows")
    return {
        "loader_64bit": Path(root, "System32", "vulkan-1.dll").exists(),
        "loader_32bit": Path(root, "SysWOW64", "vulkan-1.dll").exists(),
        "note": "32-bit games need the SysWOW64 loader; presence does not prove the driver "
                "supports every Vulkan feature DXVK needs",
    }


LEGACY_RUNTIME_FILES = {
    "DirectX 9 extensions (d3dx9_43)": "d3dx9_43.dll",
    "XInput 1.3 (DirectX June 2010)": "xinput1_3.dll",
    "XAudio 2.7 (DirectX June 2010)": "xaudio2_7.dll",
    "VC++ 2010 (x86)": "msvcr100.dll",
    "VC++ 2012 (x86)": "msvcr110.dll",
    "VC++ 2013 (x86)": "msvcr120.dll",
    "VC++ 2015-2022 (x86)": "vcruntime140.dll",
    "OpenAL": "OpenAL32.dll",
}


def _runtimes() -> dict:
    dirs = winapi.system_dll_dirs(is_32bit_target=True)
    if not dirs:
        raise winapi.Unavailable("runtime check is Windows-specific")
    out = {name: ("present" if Path(dirs[0], f).exists() else "missing")
           for name, f in LEGACY_RUNTIME_FILES.items()}
    out["VC++ 2005/2008"] = "unknown (side-by-side assemblies; check Installed apps)"
    net35 = winapi.registry().get(winapi.HKLM, r"SOFTWARE\Microsoft\NET Framework Setup\NDP\v3.5", "Install")
    out[".NET Framework 3.5"] = "present" if net35 == "1" else "missing or unknown"
    return out


def _security() -> dict:
    out: dict = {}
    try:
        cfa = winapi.powershell_json("Get-MpPreference | Select-Object EnableControlledFolderAccess")
        val = (cfa or {}).get("EnableControlledFolderAccess")
        out["controlled_folder_access"] = {0: "off", 1: "on", 2: "audit"}.get(val, str(val))
    except winapi.Unavailable as e:
        out["controlled_folder_access"] = f"unavailable: {e}"
    if winapi.IS_WINDOWS:
        try:
            out["running_as_admin"] = bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            pass
    return out


def compat_layers(exe_path: str, reg: winapi.Registry | None = None) -> dict:
    """Existing per-exe Windows compatibility layers (user and machine)."""
    reg = reg or winapi.registry()
    return {hive: reg.get(hive, LAYERS_KEY, exe_path) for hive in (winapi.HKCU, winapi.HKLM)}


def inspect() -> SystemInfo:
    notes = []
    if not winapi.IS_WINDOWS:
        notes.append("Not running on Windows: Windows-only probes are reported as unavailable.")
    return SystemInfo(
        os=_os(), memory=_probe(_memory), gpus=_probe(_gpus), vulkan=_probe(_vulkan) if winapi.IS_WINDOWS
        else {"status": "unavailable: Windows-specific"},
        legacy_runtimes=_probe(_runtimes) if winapi.IS_WINDOWS else {"status": "unavailable: Windows-specific"},
        security=_security(), notes=notes,
    )
