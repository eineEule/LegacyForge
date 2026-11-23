"""Crash diagnostics: exit classification, Windows Event Log parsing, and
evidence-based stability outcomes. Pure functions, testable anywhere.

A nonzero exit code is not automatically a crash: many games exit with
arbitrary codes. Only Windows exception codes (NTSTATUS 0xC.......) or a
matching Application Error event count as crash evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

# Session outcomes
NOT_TESTED = "not-tested"
LAUNCH_OK = "launch-successful"
LAUNCH_FAILED = "launch-failed"
GAMEPLAY_PASSED = "gameplay-test-passed"
CRASH = "crash-observed"
IMPROVEMENT = "improvement-observed"
REGRESSION = "regression-observed"
INCONCLUSIVE = "inconclusive"
VERIFIED_STABLE = "verified-stable"
OUTCOMES = [NOT_TESTED, LAUNCH_OK, LAUNCH_FAILED, GAMEPLAY_PASSED, CRASH, IMPROVEMENT, REGRESSION,
            INCONCLUSIVE, VERIFIED_STABLE]

EXCEPTIONS = {
    0xC0000005: ("EXCEPTION_ACCESS_VIOLATION", "invalid memory access"),
    0xC0000017: ("STATUS_NO_MEMORY", "out of memory"),
    0xC00000FD: ("EXCEPTION_STACK_OVERFLOW", "stack overflow"),
    0xC0000094: ("EXCEPTION_INT_DIVIDE_BY_ZERO", "integer divide by zero"),
    0xC000001D: ("EXCEPTION_ILLEGAL_INSTRUCTION", "illegal CPU instruction"),
    0xC0000409: ("STATUS_STACK_BUFFER_OVERRUN", "fast-fail / stack buffer overrun"),
    0xC0000374: ("STATUS_HEAP_CORRUPTION", "heap corruption"),
    0xC0000135: ("STATUS_DLL_NOT_FOUND", "a required DLL was not found"),
    0xC0000142: ("STATUS_DLL_INIT_FAILED", "a DLL failed to initialise"),
    0xC000007B: ("STATUS_INVALID_IMAGE_FORMAT", "32/64-bit DLL mismatch or corrupt DLL"),
    0xE06D7363: ("MSVC_CPP_EXCEPTION", "unhandled C++ exception"),
    0x80000003: ("EXCEPTION_BREAKPOINT", "breakpoint / assertion"),
    0xC000013A: ("STATUS_CONTROL_C_EXIT", "terminated by Ctrl+C or console close"),
}
MEMORY_CODES = {0xC0000017}
LAUNCH_CODES = {0xC0000135, 0xC0000142, 0xC000007B}


@dataclass
class ExitInfo:
    kind: str              # normal | error-code | exception | terminated | unknown
    code: int | None
    code_hex: str | None
    name: str | None = None
    meaning: str | None = None


def classify_exit(code: int | None, *, killed_by_user: bool = False) -> ExitInfo:
    if code is None:
        return ExitInfo("unknown", None, None)
    u = code & 0xFFFFFFFF
    hx = f"0x{u:08X}"
    if killed_by_user:
        return ExitInfo("terminated", code, hx, meaning="stopped by LegacyForge at your request")
    if u == 0:
        return ExitInfo("normal", code, hx)
    if u in EXCEPTIONS:
        name, meaning = EXCEPTIONS[u]
        kind = "terminated" if u == 0xC000013A else "exception"
        return ExitInfo(kind, code, hx, name, meaning)
    if (u >> 28) == 0xC:
        return ExitInfo("exception", code, hx, "NTSTATUS error", "unhandled Windows exception")
    if u == 1 or u == 0xFFFFFFFF:
        return ExitInfo("error-code", code, hx, meaning="nonzero exit; could be a normal quit, "
                                                       "a handled error, or a forced termination")
    return ExitInfo("error-code", code, hx, meaning="nonzero exit code (not by itself evidence of a crash)")


# Event Log ----------------------------------------------------------------

APP_ERROR_FIELDS = ["AppName", "AppVersion", "AppTimeStamp", "ModuleName", "ModuleVersion", "ModuleTimeStamp",
                    "ExceptionCode", "FaultingOffset", "ProcessId", "ProcessCreationTime", "AppPath",
                    "ModulePath", "ReportId", "PackageFullName", "PackageRelativeAppId"]


def parse_app_error_events(xml: str) -> list[dict]:
    """Parse `wevtutil qe Application /f:xml` output for Application Error (1000)
    events. Regex-based; the XML is treated as untrusted text."""
    events = []
    for ev in re.findall(r"<Event[ >].*?</Event>", xml, re.S):
        eid = re.search(r"<EventID[^>]*>(\d+)</EventID>", ev)
        prov = re.search(r"<Provider[^>]*Name=['\"]([^'\"]+)", ev)
        when = re.search(r"<TimeCreated[^>]*SystemTime=['\"]([^'\"]+)", ev)
        if not eid or eid.group(1) != "1000" or not prov or prov.group(1) != "Application Error":
            continue
        data = re.findall(r"<Data(?:\s+Name=['\"]([^'\"]+)['\"])?\s*>(.*?)</Data>|<Data(?:\s+Name=['\"]([^'\"]+)['\"])?\s*/>",
                          ev, re.S)
        fields: dict[str, str] = {}
        for i, (n1, val, n2) in enumerate(data):
            name = n1 or n2 or (APP_ERROR_FIELDS[i] if i < len(APP_ERROR_FIELDS) else f"field{i}")
            fields[name] = val.strip()
        code = fields.get("ExceptionCode", "")
        try:
            code_int = int(code, 16) if code else None
        except ValueError:
            code_int = None
        events.append({
            "time": when.group(1) if when else None, "app": fields.get("AppName"),
            "app_version": fields.get("AppVersion"), "module": fields.get("ModuleName"),
            "module_version": fields.get("ModuleVersion"),
            "exception_code": f"0x{code_int:08X}" if code_int is not None else code or None,
            "exception": EXCEPTIONS.get(code_int, (None, None))[0] if code_int else None,
            "offset": fields.get("FaultingOffset"), "pid": fields.get("ProcessId"),
        })
    return events


def event_query(start: datetime) -> str:
    """XPath for Application Error events since `start` (generated, no user input)."""
    ts = start.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    return (f"*[System[Provider[@Name='Application Error'] and (EventID=1000) and "
            f"TimeCreated[@SystemTime>='{ts}']]]")


# Outcomes -----------------------------------------------------------------

@dataclass
class Observation:
    exit: ExitInfo
    runtime_s: float
    events: list[dict] = field(default_factory=list)
    handed_off: bool = False
    user_confirmed_gameplay: bool | None = None
    min_runtime_s: float = 60.0


def session_outcome(o: Observation) -> tuple[str, list[str]]:
    """Classify one session. Returns (outcome, reasons)."""
    reasons: list[str] = []
    if o.events:
        e = o.events[0]
        reasons.append(f"Application Error event: module {e.get('module')}, exception {e.get('exception_code')}")
        return CRASH, reasons
    if o.exit.kind == "exception":
        reasons.append(f"process ended with {o.exit.code_hex} ({o.exit.name}: {o.exit.meaning})")
        if o.exit.code is not None and (o.exit.code & 0xFFFFFFFF) in LAUNCH_CODES and o.runtime_s < o.min_runtime_s:
            return LAUNCH_FAILED, reasons
        return CRASH, reasons
    if o.handed_off:
        reasons.append("the launched process handed off to another process (e.g. Steam relaunch); "
                       "the game itself was not observed")
        return INCONCLUSIVE, reasons
    if o.exit.kind == "terminated":
        reasons.append(o.exit.meaning or "terminated")
        return INCONCLUSIVE, reasons
    if o.runtime_s < 10 and o.exit.kind != "normal":
        reasons.append(f"exited after {o.runtime_s:.0f}s with {o.exit.code_hex}")
        return LAUNCH_FAILED, reasons
    if o.user_confirmed_gameplay is True:
        reasons.append(f"you confirmed the gameplay test passed ({o.runtime_s / 60:.0f} min)")
        return GAMEPLAY_PASSED, reasons
    if o.user_confirmed_gameplay is False:
        reasons.append("you reported the gameplay test failed")
        return CRASH if o.exit.kind != "normal" else INCONCLUSIVE, reasons
    if o.runtime_s >= o.min_runtime_s:
        reasons.append(f"ran {o.runtime_s / 60:.1f} min and exited ({o.exit.code_hex}); "
                       "launch works, gameplay not confirmed")
        return LAUNCH_OK, reasons
    reasons.append(f"short run ({o.runtime_s:.0f}s) without crash evidence")
    return INCONCLUSIVE, reasons


def compare(baseline: list[dict], candidate: list[dict]) -> tuple[str, list[str]]:
    """Compare two groups of sessions (dicts with 'outcome' and 'runtime_s').
    Small samples are reported as inconclusive rather than over-claimed."""
    def stats(ss):
        crashes = sum(1 for s in ss if s["outcome"] == CRASH)
        hours = sum(s.get("runtime_s", 0) for s in ss) / 3600
        return crashes, hours, len(ss)

    bc, bh, bn = stats(baseline)
    cc, ch, cn = stats(candidate)
    reasons = [f"baseline: {bc} crash(es) in {bn} session(s), {bh:.1f} h",
               f"candidate: {cc} crash(es) in {cn} session(s), {ch:.1f} h"]
    if bn < 2 or cn < 2 or bh < 1 or ch < 1:
        reasons.append("not enough sessions or play time to compare (need 2+ sessions and 1+ hour each)")
        return INCONCLUSIVE, reasons
    brate, crate = bc / bh, cc / ch
    if crate < brate * 0.5:
        return IMPROVEMENT, reasons + [f"crash rate {brate:.2f}/h -> {crate:.2f}/h"]
    if crate > brate * 1.5 and cc >= 2:
        return REGRESSION, reasons + [f"crash rate {brate:.2f}/h -> {crate:.2f}/h"]
    return INCONCLUSIVE, reasons + [f"crash rate {brate:.2f}/h -> {crate:.2f}/h (no clear difference)"]


def verify_stable(sessions: list[dict], scenario: dict, min_sessions: int = 3) -> tuple[str, list[str]]:
    """'Verified stable' only under a defined scenario: N passing sessions, each
    at least the scenario's duration, same configuration, no crashes."""
    need = float(scenario.get("duration_minutes", 60)) * 60
    rel = [s for s in sessions if s.get("scenario") == scenario.get("id")]
    if not rel:
        return NOT_TESTED, [f"no sessions recorded for scenario {scenario.get('id')}"]
    fps = {s.get("config_fingerprint") for s in rel}
    if len(fps) > 1:
        return INCONCLUSIVE, ["sessions used different configurations; verify one configuration at a time"]
    crashes = [s for s in rel if s["outcome"] == CRASH]
    passed = [s for s in rel if s["outcome"] == GAMEPLAY_PASSED and s.get("runtime_s", 0) >= need]
    if crashes:
        return CRASH, [f"{len(crashes)} crash(es) in {len(rel)} session(s)"]
    if len(passed) >= min_sessions:
        return VERIFIED_STABLE, [f"{len(passed)} passing sessions of {need / 60:.0f}+ min under scenario "
                                 f"{scenario.get('id')}, no crashes"]
    return INCONCLUSIVE, [f"{len(passed)}/{min_sessions} qualifying passing sessions so far"]
