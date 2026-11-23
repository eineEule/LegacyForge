"""Narrow, read-only access to Windows facilities, with safe fallbacks elsewhere.

Rules: subprocesses get argument lists (never a shell); user-controlled values
(paths) reach PowerShell only through environment variables, never by being
pasted into script text; every probe returns None or raises Unavailable
instead of guessing.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from typing import Any, Protocol

IS_WINDOWS = sys.platform == "win32"


class Unavailable(Exception):
    """The fact can't be determined on this machine (not an error in the game)."""


def run(args: list[str], *, env_extra: dict[str, str] | None = None, timeout: int = 30) -> str:
    if not args or not shutil.which(args[0]):
        raise Unavailable(f"{args[0] if args else '?'} not available")
    env = os.environ.copy()
    env.update(env_extra or {})
    flags = 0x08000000 if IS_WINDOWS else 0  # CREATE_NO_WINDOW
    try:
        out = subprocess.run(args, capture_output=True, timeout=timeout, env=env, shell=False,
                             check=False, creationflags=flags)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise Unavailable(str(e)) from e
    if out.returncode != 0:
        raise Unavailable(out.stderr.decode(errors="replace").strip()[:300] or f"exit {out.returncode}")
    return out.stdout.decode("utf-8", errors="replace")


def powershell_json(script: str, env_extra: dict[str, str] | None = None) -> Any:
    """Run a fixed PowerShell script; pass any variable input via env_extra."""
    if not IS_WINDOWS:
        raise Unavailable("PowerShell probes only run on Windows")
    text = run(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                "-Command", script + " | ConvertTo-Json -Depth 4 -Compress"], env_extra=env_extra)
    text = text.strip()
    return json.loads(text) if text else None


def authenticode(path: str) -> dict:
    """Signature status from Windows itself (Get-AuthenticodeSignature)."""
    data = powershell_json(
        "Get-AuthenticodeSignature -LiteralPath $env:LF_TARGET | Select-Object "
        "@{n='Status';e={$_.Status.ToString()}},StatusMessage,"
        "@{n='Signer';e={$_.SignerCertificate.Subject}}",
        {"LF_TARGET": path},
    )
    return data or {}


# Registry ---------------------------------------------------------------

HKCU, HKLM = "HKCU", "HKLM"


class Registry(Protocol):
    def get(self, hive: str, key: str, name: str) -> str | None: ...
    def set(self, hive: str, key: str, name: str, value: str) -> None: ...
    def delete(self, hive: str, key: str, name: str) -> None: ...


class WindowsRegistry:
    """REG_SZ values only; HKLM is read-only here (no elevation, ever)."""

    def _hive(self, hive: str):
        import winreg

        return {HKCU: winreg.HKEY_CURRENT_USER, HKLM: winreg.HKEY_LOCAL_MACHINE}[hive]

    def get(self, hive: str, key: str, name: str) -> str | None:
        import winreg

        try:
            with winreg.OpenKey(self._hive(hive), key) as k:
                return str(winreg.QueryValueEx(k, name)[0])
        except OSError:
            return None

    def set(self, hive: str, key: str, name: str, value: str) -> None:
        import winreg

        if hive != HKCU:
            raise PermissionError("LegacyForge only writes per-user (HKCU) settings")
        with winreg.CreateKeyEx(self._hive(hive), key, 0, winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, name, 0, winreg.REG_SZ, value)

    def delete(self, hive: str, key: str, name: str) -> None:
        import winreg

        if hive != HKCU:
            raise PermissionError("LegacyForge only writes per-user (HKCU) settings")
        try:
            with winreg.OpenKey(self._hive(hive), key, 0, winreg.KEY_SET_VALUE) as k:
                winreg.DeleteValue(k, name)
        except FileNotFoundError:
            pass

    def subkeys(self, hive: str, key: str) -> list[str]:
        import winreg

        out = []
        try:
            with winreg.OpenKey(self._hive(hive), key) as k:
                i = 0
                while True:
                    try:
                        out.append(winreg.EnumKey(k, i))
                    except OSError:
                        break
                    i += 1
        except OSError:
            pass
        return out


class MemoryRegistry:
    """In-memory registry for tests and non-Windows dry runs."""

    def __init__(self):
        self.values: dict[tuple[str, str, str], str] = {}

    def get(self, hive, key, name):
        return self.values.get((hive, key.lower(), name.lower()))

    def set(self, hive, key, name, value):
        if hive != HKCU:
            raise PermissionError("LegacyForge only writes per-user (HKCU) settings")
        self.values[(hive, key.lower(), name.lower())] = value

    def delete(self, hive, key, name):
        self.values.pop((hive, key.lower(), name.lower()), None)

    def subkeys(self, hive, key):
        return []


_default_registry: Registry | None = None


def registry() -> Registry:
    global _default_registry
    if _default_registry is None:
        _default_registry = WindowsRegistry() if IS_WINDOWS else MemoryRegistry()
    return _default_registry


def set_registry(reg: Registry | None) -> None:
    """Swap the registry backend (tests)."""
    global _default_registry
    _default_registry = reg


def system_dll_dirs(is_32bit_target: bool) -> list[str]:
    """Where Windows looks for system DLLs for a process of that bitness."""
    if not IS_WINDOWS:
        return []
    root = os.environ.get("SystemRoot", r"C:\Windows")
    if is_32bit_target and os.path.isdir(os.path.join(root, "SysWOW64")):
        return [os.path.join(root, "SysWOW64")]
    return [os.path.join(root, "System32")]
