"""Test sessions: what was run, under which configuration, and what happened.

Everything stays on this machine under the LegacyForge data folder. No
memory dumps are ever collected. Retention is configurable and `purge`
deletes sessions; `export` writes a sanitized copy (no user names, paths
or machine names) for sharing.
"""

from __future__ import annotations

import getpass
import hashlib
import json
import os
import platform
import re
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .recipe import data_home

DEFAULT_SETTINGS = {"retention_days": 90, "collect_wrapper_logs": True, "collect_event_log": True}


def settings() -> dict:
    p = data_home() / "settings.json"
    s = dict(DEFAULT_SETTINGS)
    if p.exists():
        try:
            s.update({k: v for k, v in json.loads(p.read_text()).items() if k in DEFAULT_SETTINGS})
        except (OSError, ValueError):
            pass
    return s


def save_settings(new: dict) -> dict:
    s = settings()
    for k, v in new.items():
        if k not in DEFAULT_SETTINGS:
            raise KeyError(f"unknown setting {k!r} (known: {sorted(DEFAULT_SETTINGS)})")
        s[k] = type(DEFAULT_SETTINGS[k])(v)
    p = data_home() / "settings.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(s, indent=2))
    return s


@dataclass
class Session:
    game: str
    exe: str
    exe_sha256: str
    started: str
    ended: str
    runtime_s: float
    exit: dict
    outcome: str
    reasons: list[str]
    config: dict
    config_fingerprint: str
    memory: dict
    events: list[dict] = field(default_factory=list)
    wrapper_logs: list[dict] = field(default_factory=list)
    scenario: str | None = None
    notes: str | None = None
    system: dict = field(default_factory=dict)
    id: str = field(default_factory=lambda: time.strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6])
    schema: int = 1


def fingerprint(config: dict) -> str:
    return hashlib.sha256(json.dumps(config, sort_keys=True, default=str).encode()).hexdigest()[:16]


def _dir(game: str) -> Path:
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", game):
        raise ValueError(f"invalid game id {game!r}")
    return data_home() / "sessions" / game


def save(s: Session) -> Path:
    d = _dir(s.game)
    d.mkdir(parents=True, exist_ok=True)
    p = d / f"{s.id}.json"
    p.write_text(json.dumps(asdict(s), indent=2, default=str))
    return p


def load_all(game: str | None = None) -> list[dict]:
    root = data_home() / "sessions"
    dirs = [_dir(game)] if game else ([p for p in root.iterdir() if p.is_dir()] if root.is_dir() else [])
    out = []
    for d in dirs:
        for p in sorted(d.glob("*.json")) if d.is_dir() else []:
            try:
                out.append(json.loads(p.read_text()))
            except (OSError, ValueError):
                continue
    return out


def purge(game: str | None = None, older_than_days: float | None = None) -> int:
    root = data_home() / "sessions"
    if not root.is_dir():
        return 0
    cutoff = time.time() - older_than_days * 86400 if older_than_days is not None else None
    n = 0
    for d in ([_dir(game)] if game else [p for p in root.iterdir() if p.is_dir()]):
        for p in (d.glob("*.json") if d.is_dir() else []):
            if cutoff is None or p.stat().st_mtime < cutoff:
                p.unlink()
                n += 1
    return n


def apply_retention() -> int:
    return purge(older_than_days=settings()["retention_days"])


# sanitizing ---------------------------------------------------------------

def _scrubbers() -> list[tuple[re.Pattern, str]]:
    subs = []
    home = str(Path.home())
    for variant in {home, home.replace("\\", "/"), home.replace("/", "\\")}:
        subs.append((re.compile(re.escape(variant), re.I), "~"))
    for val, label in ((getpass.getuser(), "<user>"), (platform.node(), "<host>"),
                       (os.environ.get("COMPUTERNAME", ""), "<host>"), (os.environ.get("USERNAME", ""), "<user>")):
        if val and len(val) > 2:
            subs.append((re.compile(r"\b" + re.escape(val) + r"\b", re.I), label))
    subs.append((re.compile(r"[A-Za-z]:\\Users\\[^\\\"']+", re.I), r"~"))
    subs.append((re.compile(r"/(home|Users)/[^/\"']+"), "~"))
    return subs


def sanitize(obj):
    subs = _scrubbers()

    def clean(v):
        if isinstance(v, str):
            for pat, rep in subs:
                v = pat.sub(rep, v)
            return v
        if isinstance(v, list):
            return [clean(x) for x in v]
        if isinstance(v, dict):
            return {k: clean(x) for k, x in v.items() if k not in ("pid",)}
        return v

    return clean(obj)


def community_record(s: dict) -> dict:
    """Privacy-preserving result format for a future shared database:
    only what is needed to reproduce, nothing that identifies the player."""
    return sanitize({
        "format": "legacyforge-result/1",
        "game": s["game"], "exe_sha256": s["exe_sha256"], "outcome": s["outcome"],
        "runtime_minutes": round(s.get("runtime_s", 0) / 60, 1), "scenario": s.get("scenario"),
        "exit": {k: s["exit"].get(k) for k in ("kind", "code_hex", "name")},
        "faulting_modules": sorted({e.get("module") for e in s.get("events", []) if e.get("module")}),
        "fixes": s.get("config", {}).get("fixes", []),
        "compat_layers": s.get("config", {}).get("compat_layers"),
        "system": {k: s.get("system", {}).get(k) for k in ("windows_build", "gpu", "gpu_driver")},
        "peak_private_mb": s.get("memory", {}).get("peak", {}).get("private_mb"),
    })


def record_confirmation(game: str, session_id: str, passed: bool, by: str) -> dict:
    """Record a user's gameplay verdict on a saved session and re-derive its outcome.
    Crash evidence always wins over a 'passed' claim."""
    from . import diagnostics as d

    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", session_id):
        raise ValueError("invalid session id")
    p = _dir(game) / f"{session_id}.json"
    if not p.exists():
        raise FileNotFoundError(f"no session {session_id} for {game}")
    s = json.loads(p.read_text())
    ex = d.ExitInfo(**s["exit"])
    outcome, reasons = d.session_outcome(d.Observation(ex, s["runtime_s"], s.get("events", []), False, passed,
                                                       min_runtime_s=0))
    s["outcome"], s["reasons"] = outcome, reasons
    s["confirmation"] = {"passed": passed, "by": by, "at": time.strftime("%Y-%m-%dT%H:%M:%S")}
    p.write_text(json.dumps(s, indent=2, default=str))
    return {"id": session_id, "outcome": outcome, "reasons": reasons}
