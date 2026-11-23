"""Executable and game-folder analysis. Read-only: never modifies anything.

Static findings are evidence with a strength, not conclusions: a game can
load a graphics API at runtime without importing it.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

from . import pe, winapi
from .fsutil import sha256_bytes

STRONG, MEDIUM, WEAK = "strong", "medium", "weak"

# import name -> (api id, label)
API_BY_DLL = {
    "ddraw.dll": ("directdraw", "DirectDraw (2D; may also drive Direct3D 5-7)"),
    "d3dim.dll": ("d3d5-7", "Direct3D 5-7 immediate mode"),
    "d3dim700.dll": ("d3d5-7", "Direct3D 7"),
    "d3d8.dll": ("d3d8", "Direct3D 8"),
    "d3d9.dll": ("d3d9", "Direct3D 9"),
    "d3d10.dll": ("d3d10", "Direct3D 10"),
    "d3d10_1.dll": ("d3d10", "Direct3D 10.1"),
    "d3d10core.dll": ("d3d10", "Direct3D 10"),
    "d3d11.dll": ("d3d11", "Direct3D 11"),
    "dxgi.dll": ("dxgi", "DXGI (Direct3D 10/11)"),
    "opengl32.dll": ("opengl", "OpenGL"),
    "glide.dll": ("glide", "3dfx Glide"),
    "glide2x.dll": ("glide", "3dfx Glide 2"),
    "glide3x.dll": ("glide", "3dfx Glide 3"),
}

# DLL names Windows lets a game folder override, i.e. how wrappers get loaded.
PROXY_DLLS = sorted(set(API_BY_DLL) | {"dinput.dll", "dinput8.dll", "dsound.dll", "winmm.dll",
                                        "version.dll", "xinput1_3.dll", "d3dimm.dll", "dxgi.dll"})

# Section names known to belong to packers / protection systems.
PROTECTION_SECTIONS = {
    "upx0": "UPX packer", "upx1": "UPX packer", ".aspack": "ASPack packer",
    ".themida": "Themida protection", ".vmp0": "VMProtect", ".vmp1": "VMProtect",
    ".enigma1": "Enigma Protector", ".securom": "SecuROM DRM", "stxt774": "SafeDisc DRM",
    "stxt371": "SafeDisc DRM", ".bind": "Steam DRM wrapper (SteamStub)", ".petite": "Petite packer",
    ".mpress1": "MPRESS packer",
}

ANTICHEAT_MARKERS = {
    "pb": "PunkBuster", "punkbuster": "PunkBuster", "easyanticheat": "Easy Anti-Cheat",
    "battleye": "BattlEye", "gameguard": "nProtect GameGuard", "xigncode": "XIGNCODE",
}

GAME_LOCAL_LIBS = {
    "binkw32.dll": "Bink video", "mss32.dll": "Miles Sound System", "physxloader.dll": "PhysX (legacy)",
    "fmod.dll": "FMOD audio", "fmodex.dll": "FMOD Ex audio", "openal32.dll": "OpenAL",
    "smackw32.dll": "Smacker video", "msvcr71.dll": "VC++ 2003 runtime", "msvcp71.dll": "VC++ 2003 runtime",
}


@dataclass
class Evidence:
    source: str      # import | delay-import | string | folder | header | windows
    detail: str
    strength: str


@dataclass
class GraphicsFinding:
    api: str
    label: str
    evidence: list[Evidence] = field(default_factory=list)

    @property
    def strength(self) -> str:
        order = [STRONG, MEDIUM, WEAK]
        return min((e.strength for e in self.evidence), key=order.index, default=WEAK)


@dataclass
class ProxyDll:
    name: str
    arch: str | None
    description: str | None
    sha256: str
    owner: str | None = None   # recipe/backend that installed it, if LegacyForge did


@dataclass
class ExeAnalysis:
    path: str
    sha256: str
    size: int
    arch: str
    subsystem: str
    subsystem_version: str
    large_address_aware: bool | None
    address_space: str
    dll_flags: list[str]
    is_dotnet: bool
    link_timestamp: int
    header_issues: list[str]
    imports: list[dict]
    graphics: list[GraphicsFinding]
    version_info: dict
    manifest: dict
    signature: dict
    protection: list[Evidence]
    overlay_bytes: int
    folder: dict

    def to_dict(self) -> dict:
        d = asdict(self)
        for g, obj in zip(d["graphics"], self.graphics):
            g["strength"] = obj.strength
        return d

    def apis(self, min_strength: str = MEDIUM) -> set[str]:
        order = [STRONG, MEDIUM, WEAK]
        return {g.api for g in self.graphics if order.index(g.strength) <= order.index(min_strength)}


def address_space(is_32bit: bool, laa: bool, os_64bit: bool | None = True) -> str:
    if not is_32bit:
        return "64-bit process: address space is not a practical limit"
    if not laa:
        return "2 GiB user address space (32-bit, not Large Address Aware)"
    if os_64bit is False:
        return "2 GiB by default on 32-bit Windows (3 GiB only with the IncreaseUserVa boot option)"
    return "4 GiB user address space on 64-bit Windows (Large Address Aware)"


def _string_hits(data: bytes, names: list[str]) -> set[str]:
    hits = set()
    low = data.lower()
    for n in names:
        b = n.encode()
        if b in low or n.encode("utf-16-le") in low:
            hits.add(n)
    return hits


def analyze_folder(exe: Path, exe_arch: str | None = None) -> dict:
    folder = exe.parent
    proxies, anticheat, local_libs = [], [], []
    try:
        entries = list(folder.iterdir())
    except OSError:
        entries = []
    lower = {p.name.lower(): p for p in entries}
    for name in PROXY_DLLS:
        p = lower.get(name)
        if p and p.is_file() and not p.is_symlink():
            data = p.read_bytes()[: 64 << 20]
            arch = desc = None
            try:
                pf = pe.PEFile(data)
                arch = pf.info.arch
                vi, _ = pf.resources()
                desc = " / ".join(v for v in (vi.get("CompanyName"), vi.get("FileDescription"),
                                              vi.get("ProductName")) if v) or None
            except pe.PEError:
                desc = "not a valid PE file"
            proxies.append(asdict(ProxyDll(p.name, arch, desc, sha256_bytes(data))))
    for name, label in ANTICHEAT_MARKERS.items():
        if name in lower:
            anticheat.append({"marker": lower[name].name, "system": label})
    for name, label in GAME_LOCAL_LIBS.items():
        if name in lower:
            local_libs.append({"dll": lower[name].name, "library": label})
    return {"dir": str(folder), "proxy_dlls": proxies, "anticheat": anticheat, "bundled_libraries": local_libs}


def analyze(exe: Path, *, check_signature: bool = True, os_64bit: bool | None = True) -> ExeAnalysis:
    exe = Path(exe)
    data = exe.read_bytes() if exe.stat().st_size <= pe.MAX_ANALYZE_BYTES else b""
    if not data:
        raise pe.PEError("file too large to analyze")
    p = pe.PEFile(data)
    issues = p.integrity_issues()

    try:
        imports = p.imports()
    except pe.PEError as e:
        imports = []
        issues.append(f"import table unreadable: {e}")
    try:
        version, manifest_text = p.resources()
    except pe.PEError as e:
        version, manifest_text = {}, None
        issues.append(f"resources unreadable: {e}")

    # graphics evidence
    found: dict[str, GraphicsFinding] = {}

    def note(dll: str, ev: Evidence):
        api, label = API_BY_DLL[dll]
        found.setdefault(api, GraphicsFinding(api, label)).evidence.append(ev)

    imported = {d.name for d in imports}
    for d in imports:
        if d.name in API_BY_DLL:
            note(d.name, Evidence("delay-import" if d.delay else "import", f"imports {d.name}", STRONG))
    for name in _string_hits(data, list(API_BY_DLL)) - imported:
        note(name, Evidence("string", f"'{name}' appears in the binary (possible runtime load)", WEAK))
    folder = analyze_folder(exe)
    for b in folder["bundled_libraries"] + [{"dll": x["name"]} for x in folder["proxy_dlls"]]:
        n = b["dll"].lower()
        if n.startswith("glide") and n in API_BY_DLL:
            note(n, Evidence("folder", f"{b['dll']} ships in the game folder", MEDIUM))
    graphics = sorted(found.values(), key=lambda g: [STRONG, MEDIUM, WEAK].index(g.strength))
    if not any(g.strength != WEAK for g in graphics) and "gdi32.dll" in imported:
        graphics.append(GraphicsFinding("software", "Software / GDI rendering (possible)",
                                        [Evidence("import", "imports gdi32.dll and no 3D API", WEAK)]))

    # protection / packing
    protection: list[Evidence] = []
    for s in p.sections:
        label = PROTECTION_SECTIONS.get(s.name.lower())
        if label:
            protection.append(Evidence("header", f"section '{s.name}' ({label})", MEDIUM))
        if s.executable and s.entropy >= 7.2 and s.raw_size > 4096:
            protection.append(Evidence("header", f"executable section '{s.name}' has entropy "
                                                 f"{s.entropy} (compressed or encrypted code)", WEAK))
    total_funcs = sum(len(d.functions) for d in imports)
    if imports and total_funcs <= 6 and {"loadlibrarya", "getprocaddress"} <= \
            {f.lower() for d in imports for f in d.functions}:
        protection.append(Evidence("import", "tiny import table resolving APIs at runtime "
                                             "(typical of packed executables)", WEAK))
    for a in folder["anticheat"]:
        protection.append(Evidence("folder", f"{a['system']} files present ({a['marker']})", MEDIUM))

    # signature
    sig: dict = {"present": p.has_signature, "status": "unsigned" if not p.has_signature else "unknown"}
    if p.has_signature and check_signature:
        try:
            res = winapi.authenticode(str(exe))
            sig.update(status=str(res.get("Status", "unknown")).lower(),
                       signer=res.get("Signer"), message=res.get("StatusMessage"))
        except winapi.Unavailable as e:
            sig["note"] = f"validity not checked: {e}"

    laa = p.info.large_address_aware if p.is_32bit else None
    return ExeAnalysis(
        path=str(exe), sha256=sha256_bytes(data), size=len(data), arch=p.info.arch,
        subsystem=p.subsystem_name, subsystem_version="%d.%d" % p.subsystem_version,
        large_address_aware=laa,
        address_space=address_space(p.is_32bit, bool(laa), os_64bit),
        dll_flags=p.dll_flags, is_dotnet=p.is_dotnet, link_timestamp=p.timestamp,
        header_issues=issues,
        imports=[{"dll": d.name, "delay": d.delay, "functions": len(d.functions)} for d in imports],
        graphics=graphics, version_info=version, manifest=pe.manifest_facts(manifest_text),
        signature=sig, protection=protection, overlay_bytes=p.overlay_size, folder=folder,
    )


_INSTALLER = re.compile(r"(unins|setup|install|crash|report|redist|vcredist|dxsetup|config|launcher)",
                        re.I)


def candidate_exes(folder: Path, limit: int = 20) -> list[Path]:
    """Likely game executables in a folder (largest first, installers skipped)."""
    out = []
    for p in Path(folder).rglob("*.exe"):
        if len(p.relative_to(folder).parts) > 3 or _INSTALLER.search(p.name) or p.is_symlink():
            continue
        out.append(p)
    out.sort(key=lambda p: p.stat().st_size, reverse=True)
    return out[:limit]
