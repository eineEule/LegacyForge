"""Conservative, rule-based compatibility recommendations.

Rules map observed evidence to fixes. They never apply anything. A 32-bit
executable is not, by itself, a stability problem: memory fixes are only
proposed with evidence (a recipe, a measured session, or the user's report).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Callable

from .analysis import STRONG, ExeAnalysis

VERIFIED = "verified"            # tested by LegacyForge under a recorded scenario
KNOWN_GAME = "known-game-fix"    # documented for this game by a recipe or the tool's own docs
SUGGESTED = "suggested"          # plausible from evidence, unverified for this game
EXPERIMENTAL = "experimental"    # may help, may break; test and be ready to revert
INFO = "information"             # no fix; something to know


@dataclass
class Recommendation:
    id: str
    category: str
    problem: str
    evidence: list[str]
    fix: str | None
    fix_type: str | None
    benefit: str
    prerequisites: list[str]
    side_effects: list[str]
    risk: str                    # low | medium | high
    needs_admin: bool
    modifies_executable: bool
    rollback: bool
    verification: str
    confidence: str              # low | medium | high
    blocked_by: list[str] = field(default_factory=list)
    merge_key: str | None = None  # same key = same fix for the same target; merged into one

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("merge_key", None)
        return d



@dataclass
class Context:
    exe: ExeAnalysis
    system: dict | None = None
    deps: list[dict] = field(default_factory=list)
    recipe: object | None = None            # recipe.Recipe when the game is known
    recipe_hash_match: bool = False
    compat_layers: dict = field(default_factory=dict)
    observed: dict = field(default_factory=dict)   # e.g. {"memory_crash": True} from sessions


Rule = Callable[[Context], list[Recommendation]]
RULES: list[Rule] = []


def rule(fn: Rule) -> Rule:
    RULES.append(fn)
    return fn


def _protected(c: Context) -> list[str]:
    return [e.detail for e in c.exe.protection if e.strength != "weak" or "packed" in e.detail]


@rule
def memory_laa(c: Context) -> list[Recommendation]:
    e = c.exe
    if e.arch != "x32" or e.large_address_aware:
        return []
    evidence = ["32-bit executable without the Large Address Aware flag (2 GiB limit)"]
    blocked = []
    if e.signature.get("present"):
        blocked.append("executable is Authenticode-signed; patching invalidates the signature")
    prot = _protected(c)
    if prot:
        blocked.append("protection or packing detected (" + "; ".join(prot) +
                       "); patching may break DRM/anti-cheat checks")
    if e.is_dotnet:
        blocked.append(".NET executable: memory behaviour is controlled by the runtime")
    recipe_says = c.recipe is not None and any(
        f.fix.type == "laa" for f in getattr(c.recipe, "fixes", []))
    if c.observed.get("memory_crash"):
        evidence.append("a recorded session ended in an out-of-memory style crash")
    if recipe_says:
        evidence.append(f"the {c.recipe.name} recipe lists this fix")
    category = KNOWN_GAME if recipe_says and c.recipe_hash_match else \
        SUGGESTED if (recipe_says or c.observed.get("memory_crash")) else EXPERIMENTAL
    return [Recommendation(
        id="memory.laa", category=category, merge_key="laa",
        problem="Game may run out of address space in long or large sessions",
        evidence=evidence, fix="Set the Large Address Aware flag (allows 4 GiB on 64-bit Windows)",
        fix_type="laa", benefit="Doubles usable address space IF the game is limited by it",
        prerequisites=["64-bit Windows", "unprotected, unsigned executable",
                       "exact executable version known (recipe hash) or your explicit approval"],
        side_effects=["Some games assume pointers below 2 GiB and crash with LAA",
                      "Launcher or Steam updates may restore the original exe"],
        risk="medium", needs_admin=False, modifies_executable=True, rollback=True,
        verification="Play a long session; compare peak private bytes and crash outcome with a "
                     "baseline session (legacyforge launch --compare)",
        confidence="medium" if category == KNOWN_GAME else "low", blocked_by=blocked)]


@rule
def graphics(c: Context) -> list[Recommendation]:
    e, out = c.exe, []
    apis = e.apis()
    proxies = {p["name"].lower() for p in e.folder.get("proxy_dlls", []) if not p.get("owner")}
    ours = {p["name"].lower(): p["owner"] for p in e.folder.get("proxy_dlls", []) if p.get("owner")}
    vulkan32 = (c.system or {}).get("vulkan", {}).get("loader_32bit") if isinstance(
        (c.system or {}).get("vulkan"), dict) else None

    if "directdraw" in apis and not apis & {"d3d8", "d3d9", "d3d10", "d3d11", "dxgi", "opengl"}:
        out.append(Recommendation(
            id="graphics.cnc-ddraw", category=SUGGESTED, merge_key="cnc-ddraw",
            problem="DirectDraw games often have black screens, broken Alt+Tab, slow rendering "
                    "or bad scaling on modern Windows",
            evidence=[x.detail for g in e.graphics if g.api == "directdraw" for x in g.evidence],
            fix="Install cnc-ddraw (DirectDraw re-implementation with windowed/borderless modes and scaling)",
            fix_type="cnc-ddraw", benefit="Stable fullscreen/windowed output, correct scaling, Alt+Tab",
            prerequisites=["game must have a DirectDraw (2D/software) renderer; cnc-ddraw does not "
                           "support Direct3D games"],
            side_effects=["Replaces ddraw.dll in the game folder"], risk="low", needs_admin=False,
            modifies_executable=False, rollback=True,
            verification="Launch; check display mode, Alt+Tab and in-game speed",
            confidence="medium", blocked_by=["ddraw.dll from another source is already present"]
            if "ddraw.dll" in proxies else []))
        if "ddraw.dll" in ours:
            out[-1].evidence.append(f"already installed by LegacyForge ({ours['ddraw.dll']}); "
                                    f"record a session to judge it")
    if "glide" in apis:
        out.append(Recommendation(
            id="graphics.dgvoodoo2", category=SUGGESTED, merge_key="dgvoodoo2",
            problem="3dfx Glide has no native support on modern GPUs",
            evidence=[x.detail for g in e.graphics if g.api == "glide" for x in g.evidence],
            fix="Install dgVoodoo2's Glide wrapper (you supply the dgVoodoo2 download)",
            fix_type="dgvoodoo2", benefit="Glide rendering on modern hardware",
            prerequisites=["dgVoodoo2 archive downloaded by you from the author's site "
                           "(LegacyForge does not redistribute it)"],
            side_effects=["Adds Glide DLLs and dgVoodoo.conf to the game folder"], risk="low",
            needs_admin=False, modifies_executable=False, rollback=True,
            verification="Launch and confirm the Glide renderer option works", confidence="medium"))
    strong = {x.api for x in e.graphics if x.strength == STRONG}
    for api, dlls in (("d3d9", ["d3d9.dll"]), ("d3d11", ["d3d11.dll", "dxgi.dll"]), ("d3d8", ["d3d8.dll"])):
        g = next((x for x in e.graphics if x.api == api and x.strength == STRONG), None)
        if not g:
            continue
        if api == "d3d9" and "d3d11" in strong:
            continue  # a D3D11 exe that also imports d3d9 usually uses it only for helpers
        blocked = [f"{d} from another source is already in the game folder" for d in dlls if d in proxies]
        if vulkan32 is False:
            blocked.append("no 32-bit Vulkan loader found (SysWOW64\\vulkan-1.dll)")
        out.append(Recommendation(
            id=f"graphics.dxvk-{api}", category=EXPERIMENTAL, merge_key=f"dxvk:{api}",
            problem="Legacy Direct3D drivers can stutter, leak memory or misrender on modern GPUs",
            evidence=[x.detail for x in g.evidence] + (
                ["also imports d3d9.dll (typically helper functions in a D3D11 renderer)"]
                if api == "d3d11" and "d3d9" in strong else []),
            fix=f"Try DXVK for {api.upper()} (Direct3D to Vulkan translation)", fix_type="dxvk",
            benefit="Can improve frame pacing and reduce driver-side memory use; results vary by game",
            prerequisites=["GPU and driver with Vulkan 1.3 support", "32-bit Vulkan loader for 32-bit games"],
            side_effects=["Shader compilation stutter on first run", "Overlays and ReShade may conflict",
                          "Some games render incorrectly"], risk="medium", needs_admin=False,
            modifies_executable=False, rollback=True,
            verification="A/B test sessions with and without DXVK; compare crashes and duration",
            confidence="low", blocked_by=blocked))
    unknown_proxies = [p for p in e.folder.get("proxy_dlls", []) if not p.get("owner")]
    if unknown_proxies:
        out.append(Recommendation(
            id="graphics.existing-wrappers", category=INFO,
            problem="Wrapper or proxy DLLs are already in the game folder",
            evidence=[f"{p['name']} ({p.get('description') or 'no version info'}, {p.get('arch')})"
                      for p in unknown_proxies],
            fix=None, fix_type=None, benefit="Avoid stacking wrappers that fight over the same DLL",
            prerequisites=[], side_effects=[], risk="low", needs_admin=False, modifies_executable=False,
            rollback=False, verification="Confirm whether these came from the game, a mod or another tool",
            confidence="high"))
    return out


@rule
def windows_settings(c: Context) -> list[Recommendation]:
    e, out = c.exe, []
    path = e.path.lower()
    if ("\\program files" in path or "/program files" in path) and "execution_level" not in e.manifest:
        out.append(Recommendation(
            id="windows.virtualstore", category=INFO,
            problem="Game writes into Program Files are silently redirected to VirtualStore",
            evidence=["installed under Program Files", "no requestedExecutionLevel in manifest"],
            fix=None, fix_type=None,
            benefit="Explains 'missing' saves or settings: look in %LOCALAPPDATA%\\VirtualStore",
            prerequisites=[], side_effects=[], risk="low", needs_admin=False, modifies_executable=False,
            rollback=False, verification="Check %LOCALAPPDATA%\\VirtualStore for the game's files",
            confidence="medium"))
    if not e.manifest.get("dpi_aware") and not e.manifest.get("dpi_awareness"):
        out.append(Recommendation(
            id="windows.dpi", category=SUGGESTED,
            problem="Not DPI-aware: on scaled displays Windows may blur or mis-size the game",
            evidence=["no dpiAware setting in the application manifest"],
            fix="Per-exe compatibility setting: high-DPI override (application)", fix_type="compat",
            benefit="Crisp rendering and correct window size on 125-200% scaling",
            prerequisites=["only if you see blur or wrong sizing"], side_effects=["Small UI on high-DPI screens"],
            risk="low", needs_admin=False, modifies_executable=False, rollback=True,
            verification="Launch on the scaled display; compare sharpness and window size",
            confidence="medium"))
    layers = {k: v for k, v in c.compat_layers.items() if v}
    if layers:
        out.append(Recommendation(
            id="windows.existing-layers", category=INFO,
            problem="Windows compatibility settings are already applied to this executable",
            evidence=[f"{h}: {v}" for h, v in layers.items()], fix=None, fix_type=None,
            benefit="Existing settings change behaviour and must be considered when testing fixes",
            prerequisites=[], side_effects=[], risk="low", needs_admin=False, modifies_executable=False,
            rollback=False, verification="Review in the exe's Properties > Compatibility tab",
            confidence="high"))
    return out


@rule
def runtimes(c: Context) -> list[Recommendation]:
    missing = [d for d in c.deps if d["status"] == "missing"]
    out = []
    for runtime in sorted({d["runtime"] for d in missing}):
        dlls = [d["dll"] for d in missing if d["runtime"] == runtime]
        src = next(d["source"] for d in missing if d["runtime"] == runtime)
        out.append(Recommendation(
            id=f"runtime.{runtime.lower().replace(' ', '-')}", category=SUGGESTED,
            problem=f"Required library not found: {', '.join(dlls)}",
            evidence=[f"imports {d}; not in game folder or system directory" for d in dlls],
            fix=f"Install {runtime} from the official source: {src}", fix_type=None,
            benefit="Game can load its required libraries", prerequisites=["your consent; installer runs as you"],
            side_effects=["System-wide install"], risk="low", needs_admin=True, modifies_executable=False,
            rollback=False, verification="Re-run legacyforge analyze; status should change to present",
            confidence="high"))
    return out


@rule
def protection_notice(c: Context) -> list[Recommendation]:
    prot = _protected(c)
    if not prot:
        return []
    return [Recommendation(
        id="info.protection", category=INFO,
        problem="Copy protection, packing or anti-cheat detected",
        evidence=prot, fix=None, fix_type=None,
        benefit="LegacyForge will not modify this executable or bypass protection",
        prerequisites=[], side_effects=[], risk="low", needs_admin=False, modifies_executable=False,
        rollback=False, verification="n/a", confidence="medium")]


@rule
def recipe_fixes(c: Context) -> list[Recommendation]:
    if c.recipe is None:
        return []
    out = []
    covered = {"laa"}
    for i, entry in enumerate(c.recipe.fixes):
        t = entry.fix.type
        if t in covered:
            continue
        params = entry.fix.params if isinstance(entry.fix.params, dict) else {}
        key = f"dxvk:{params.get('api')}" if t == "dxvk" else t if t in ("cnc-ddraw", "dgvoodoo2") else None
        status = getattr(entry, "status", None) or KNOWN_GAME
        out.append(Recommendation(
            id=f"recipe.{c.recipe.id}.{i + 1}.{t}", merge_key=key,
            category={"verified": VERIFIED, "known": KNOWN_GAME, "suggested": SUGGESTED,
                      "experimental": EXPERIMENTAL}.get(status, KNOWN_GAME),
            problem=f"{c.recipe.name}: listed compatibility fix" + (f" ({entry.note})" if entry.note else ""),
            evidence=[f"listed in the {c.recipe.name} recipe"] + (
                ["executable hash matches the recipe"] if c.recipe_hash_match else
                ["executable version not confirmed against the recipe"]),
            fix=entry.fix.describe_static(), fix_type=t, benefit=entry.note or "see recipe notes",
            prerequisites=[], side_effects=[], risk="medium" if t in ("laa", "dxvk", "reshade") else "low",
            needs_admin=False, modifies_executable=t == "laa", rollback=True,
            verification="legacyforge launch, then compare with a baseline session",
            confidence="medium" if c.recipe_hash_match else "low"))
    return out


ORDER = [VERIFIED, KNOWN_GAME, SUGGESTED, EXPERIMENTAL, INFO]


def recommend(ctx: Context) -> list[Recommendation]:
    recs: list[Recommendation] = []
    for r in RULES:
        recs.extend(r(ctx))
    # A recipe entry and a generic rule for the SAME fix on the SAME target
    # (e.g. DXVK for d3d11) merge, keeping the stronger category and both sets
    # of evidence. Everything else stays separate.
    merged: dict[str, Recommendation] = {}
    out: list[Recommendation] = []
    for r in recs:
        key = r.merge_key or r.id
        if key in merged:
            m = merged[key]
            keep, other = (m, r) if ORDER.index(m.category) <= ORDER.index(r.category) else (r, m)
            if keep is r:
                out[out.index(m)] = r
                merged[key] = r
            keep.evidence = keep.evidence + [e for e in other.evidence if e not in keep.evidence]
            keep.blocked_by = keep.blocked_by + [b for b in other.blocked_by if b not in keep.blocked_by]
            if ORDER.index(other.category) < ORDER.index(keep.category):
                keep.category = other.category
            continue
        merged[key] = r
        out.append(r)
    out.sort(key=lambda r: (ORDER.index(r.category), r.id))
    return out
