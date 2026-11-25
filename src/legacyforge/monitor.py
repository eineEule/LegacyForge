"""Launch a game and observe it: exit code, runtime, memory, crash events.

Monitoring is read-only: no injection, no debugger attach, no memory dumps.
Memory figures come from the OS (GetProcessMemoryInfo / VirtualQueryEx on
Windows, /proc elsewhere for tests).
"""

from __future__ import annotations

import ctypes
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import diagnostics, winapi

PRIORITIES = {"below-normal": 0x00004000, "normal": 0x00000020, "above-normal": 0x00008000, "high": 0x00000080}


@dataclass
class LaunchProfile:
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    affinity: list[int] | None = None      # CPU indices, e.g. [0] for single-core games
    priority: str = "normal"
    working_dir: str | None = None

    def validate(self) -> None:
        if self.priority not in PRIORITIES:
            raise ValueError(f"priority must be one of {sorted(PRIORITIES)} (realtime is not allowed)")
        if self.affinity is not None:
            n = os.cpu_count() or 1
            if not self.affinity or any(not isinstance(c, int) or c < 0 or c >= n for c in self.affinity):
                raise ValueError(f"affinity must list CPU indices between 0 and {n - 1}")
        for k in self.env:
            if not k.replace("_", "").isalnum():
                raise ValueError(f"invalid environment variable name {k!r}")
        if not all(isinstance(a, str) for a in self.args):
            raise ValueError("args must be strings")


@dataclass
class Sample:
    t: float
    private_mb: float | None = None
    working_set_mb: float | None = None
    virtual_mb: float | None = None


@dataclass
class RunResult:
    pid: int
    started: datetime
    ended: datetime
    exit_code: int | None
    killed: bool
    samples: list[Sample]
    peak: dict
    handed_off: bool = False
    modules: list[dict] = field(default_factory=list)   # DLLs seen loaded during the run


# memory probes -------------------------------------------------------------

if winapi.IS_WINDOWS:
    from ctypes import wintypes

    class PROCESS_MEMORY_COUNTERS_EX(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD),
                    ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t),
                    ("PrivateUsage", ctypes.c_size_t)]

    class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                    ("AllocationProtect", wintypes.DWORD), ("PartitionId", wintypes.WORD),
                    ("RegionSize", ctypes.c_size_t), ("State", wintypes.DWORD),
                    ("Protect", wintypes.DWORD), ("Type", wintypes.DWORD)]

    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _psapi = ctypes.WinDLL("psapi", use_last_error=True)
    PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, SYNCHRONIZE = 0x0400, 0x0010, 0x00100000
    MEM_FREE = 0x10000
    _k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _k32.OpenProcess.restype = wintypes.HANDLE
    _k32.VirtualQueryEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p,
                                    ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t]
    _k32.VirtualQueryEx.restype = ctypes.c_size_t
    _k32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    _k32.WaitForSingleObject.restype = wintypes.DWORD
    _k32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    _k32.CloseHandle.argtypes = [wintypes.HANDLE]
    _k32.SetProcessAffinityMask.argtypes = [wintypes.HANDLE, ctypes.c_size_t]
    _k32.SetPriorityClass.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    _psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD]
    _psapi.EnumProcessModulesEx.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.HMODULE), wintypes.DWORD,
                                            ctypes.POINTER(wintypes.DWORD), wintypes.DWORD]
    _psapi.GetModuleFileNameExW.argtypes = [wintypes.HANDLE, wintypes.HMODULE, wintypes.LPWSTR, wintypes.DWORD]
    LIST_MODULES_ALL = 0x03  # 32-bit modules of a WOW64 process too (plain EnumProcessModules hides them)


def _win_sample(handle) -> Sample:
    c = PROCESS_MEMORY_COUNTERS_EX()
    c.cb = ctypes.sizeof(c)
    _psapi.GetProcessMemoryInfo(handle, ctypes.byref(c), c.cb)
    used = 0
    addr = 0
    mbi = MEMORY_BASIC_INFORMATION()
    while addr < (1 << 32) and _k32.VirtualQueryEx(handle, ctypes.c_void_p(addr), ctypes.byref(mbi),
                                                    ctypes.sizeof(mbi)):
        if mbi.State != MEM_FREE:
            used += mbi.RegionSize
        nxt = (mbi.BaseAddress or 0) + mbi.RegionSize
        if nxt <= addr:
            break
        addr = nxt
    return Sample(0, round(c.PrivateUsage / 2**20, 1), round(c.WorkingSetSize / 2**20, 1),
                  round(used / 2**20, 1))


def _win_modules(handle) -> list[dict]:
    arr = (wintypes.HMODULE * 2048)()
    needed = wintypes.DWORD()
    if not _psapi.EnumProcessModulesEx(handle, arr, ctypes.sizeof(arr), ctypes.byref(needed), LIST_MODULES_ALL):
        return []
    out = []
    buf = ctypes.create_unicode_buffer(1024)
    for i in range(min(needed.value // ctypes.sizeof(wintypes.HMODULE), 2048)):
        if _psapi.GetModuleFileNameExW(handle, arr[i], buf, 1024):
            out.append({"name": Path(buf.value).name, "path": buf.value})
    return out


def _proc_modules(pid: int) -> list[dict]:
    seen: dict[str, str] = {}
    try:
        for line in Path(f"/proc/{pid}/maps").read_text().splitlines():
            parts = line.split(None, 5)
            if len(parts) == 6 and parts[5].startswith("/") and (".so" in parts[5] or parts[5].lower().endswith(".dll")):
                seen.setdefault(Path(parts[5]).name, parts[5])
    except OSError:
        return []
    return [{"name": n, "path": p} for n, p in seen.items()]


def _proc_sample(pid: int) -> Sample:
    vals = {}
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            k, _, v = line.partition(":")
            if k in ("VmRSS", "VmSize", "RssAnon"):
                vals[k] = int(v.split()[0]) / 1024
    except OSError:
        return Sample(0)
    return Sample(0, vals.get("RssAnon"), vals.get("VmRSS"), vals.get("VmSize"))


# launch ------------------------------------------------------------------

def _set_affinity(proc: subprocess.Popen, cpus: list[int]) -> None:
    mask = sum(1 << c for c in cpus)
    if winapi.IS_WINDOWS:
        if not _k32.SetProcessAffinityMask(int(proc._handle), mask):  # type: ignore[attr-defined]
            raise OSError(ctypes.get_last_error(), "SetProcessAffinityMask failed")
    elif hasattr(os, "sched_setaffinity"):
        os.sched_setaffinity(proc.pid, set(cpus))


def _set_priority(proc: subprocess.Popen, priority: str) -> None:
    if priority == "normal":
        return
    if winapi.IS_WINDOWS:
        _k32.SetPriorityClass(int(proc._handle), PRIORITIES[priority])  # type: ignore[attr-defined]
    elif priority == "below-normal":
        os.setpriority(os.PRIO_PROCESS, proc.pid, 5)


def find_pids(image_name: str) -> list[int]:
    """PIDs of running processes with this image name (Windows: tasklist)."""
    if not winapi.IS_WINDOWS:
        return []
    out = winapi.run(["tasklist", "/FO", "CSV", "/NH", "/FI", f"IMAGENAME eq {image_name}"])
    pids = []
    for line in out.splitlines():
        parts = [p.strip('"') for p in line.split('","')]
        if len(parts) >= 2 and parts[0].lower() == image_name.lower() and parts[1].strip('"').isdigit():
            pids.append(int(parts[1].strip('"')))
    return pids


def run(exe: Path, profile: LaunchProfile, *, interval: float = 5.0, max_minutes: float | None = None,
        handoff_seconds: float = 15.0, follow: bool = True, on_sample=None) -> RunResult:
    profile.validate()
    exe = Path(exe)
    env = os.environ.copy()
    env.update(profile.env)
    cwd = profile.working_dir or str(exe.parent)
    started = datetime.now(timezone.utc)
    t0 = time.monotonic()
    proc = subprocess.Popen([str(exe), *profile.args], cwd=cwd, env=env, shell=False)
    if profile.affinity:
        _set_affinity(proc, profile.affinity)
    _set_priority(proc, profile.priority)

    samples: list[Sample] = []
    killed = False
    handle = None
    pid = proc.pid
    if winapi.IS_WINDOWS:
        handle = _k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | SYNCHRONIZE, False, pid)

    modules: dict[str, dict] = {}
    next_module_scan = [0.0]

    def sample(h=None):
        h = h or handle
        s = _win_sample(h) if h else _proc_sample(pid)
        s.t = round(time.monotonic() - t0, 1)
        samples.append(s)
        if s.t >= next_module_scan[0]:  # module list: soon after start, then every 5 minutes
            try:
                for m in (_win_modules(h) if h else _proc_modules(pid)):
                    modules.setdefault(m["path"].lower(), m)
            except Exception:
                pass
            next_module_scan[0] = s.t + 300
        if on_sample:
            on_sample(s)

    exit_code = None
    handed_off = False
    try:
        while True:
            try:
                exit_code = proc.wait(timeout=interval)
                break
            except subprocess.TimeoutExpired:
                sample()
                if max_minutes and time.monotonic() - t0 > max_minutes * 60:
                    proc.terminate()
                    killed = True
        runtime = time.monotonic() - t0
        if follow and winapi.IS_WINDOWS and runtime < handoff_seconds and exit_code == 0:
            # e.g. a Steam game relaunching itself through Steam: follow the real process
            deadline = time.monotonic() + 60
            pids: list[int] = []
            while time.monotonic() < deadline and not pids:
                time.sleep(2)
                pids = [p for p in find_pids(exe.name) if p != pid]
            if pids:
                handed_off = True
                pid = pids[0]
                exit_code = _wait_pid(pid, interval, sample)
            else:
                handed_off = runtime < 5
    except KeyboardInterrupt:
        proc.terminate()
        killed = True
        exit_code = proc.wait()
    finally:
        if handle:
            _k32.CloseHandle(handle)
    ended = datetime.now(timezone.utc)
    peak = {
        "private_mb": max((s.private_mb or 0 for s in samples), default=None),
        "working_set_mb": max((s.working_set_mb or 0 for s in samples), default=None),
        "virtual_mb": max((s.virtual_mb or 0 for s in samples), default=None),
    }
    return RunResult(pid, started, ended, exit_code, killed, _downsample(samples), peak, handed_off,
                     sorted(modules.values(), key=lambda m: m["name"].lower()))


def _wait_pid(pid: int, interval: float, sample_cb) -> int | None:
    h = _k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | SYNCHRONIZE, False, pid)
    if not h:
        return None
    try:
        while _k32.WaitForSingleObject(h, int(interval * 1000)) == 0x102:  # WAIT_TIMEOUT
            sample_cb(h)
        code = wintypes.DWORD()
        _k32.GetExitCodeProcess(h, ctypes.byref(code))
        return code.value
    finally:
        _k32.CloseHandle(h)


def _downsample(samples: list[Sample], keep: int = 240) -> list[Sample]:
    if len(samples) <= keep:
        return samples
    step = len(samples) / keep
    return [samples[int(i * step)] for i in range(keep)] + [samples[-1]]


def crash_events(start: datetime, exe_name: str) -> list[dict]:
    """Application Error events for this exe since start (Windows only)."""
    if not winapi.IS_WINDOWS:
        return []
    try:
        xml = winapi.run(["wevtutil", "qe", "Application", f"/q:{diagnostics.event_query(start)}",
                          "/f:xml", "/c:50", "/rd:true"])
    except winapi.Unavailable:
        return []
    xml = "<Events>" + xml + "</Events>"
    return [e for e in diagnostics.parse_app_error_events(xml)
            if (e.get("app") or "").lower() == exe_name.lower()]


def wrapper_logs(game_dir: Path, since: float, max_lines: int = 40) -> list[dict]:
    """Tails of DXVK / wrapper logs written during the session."""
    out = []
    for p in Path(game_dir).glob("*.log"):
        name = p.name.lower()
        if not any(k in name for k in ("d3d", "dxgi", "dxvk", "ddraw", "dgvoodoo", "reshade")):
            continue
        try:
            if p.stat().st_mtime < since or p.is_symlink():
                continue
            lines = p.read_text(errors="replace").splitlines()[-max_lines:]
        except OSError:
            continue
        out.append({"file": p.name, "tail": lines})
    return out


if sys.platform != "win32":
    def _win_sample(handle):  # noqa: F811 - placeholder off Windows
        return Sample(0)

    def _win_modules(handle):  # noqa: F811
        return []
