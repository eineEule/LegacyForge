"""Human-readable rendering of analysis reports (the JSON form is the source of truth)."""

from __future__ import annotations

import json


def to_json(report: dict) -> str:
    return json.dumps(report, indent=2, default=str)


def to_text(r: dict, *, verbose: bool = False) -> str:
    e = r["executable"]
    L: list[str] = []
    vi = e.get("version_info") or {}
    title = vi.get("ProductName") or vi.get("FileDescription") or e["path"]
    L.append(f"== {title}")
    L.append(f"   {e['path']}")
    L.append(f"   sha256 {e['sha256']}")
    if vi:
        L.append("   version " + ", ".join(f"{k}={vi[k]}" for k in ("CompanyName", "FileVersion", "ProductVersion")
                                         if vi.get(k)))
    L.append("")
    L.append("Executable")
    L.append(f"  architecture   : {e['arch']} ({e['subsystem']}, subsystem {e['subsystem_version']})")
    if e["arch"] == "x32":
        L.append(f"  4 GiB aware    : {'yes' if e['large_address_aware'] else 'no'}")
    L.append(f"  address space  : {e['address_space']}")
    sig = e["signature"]
    L.append(f"  signature      : {sig['status']}" + (f" ({sig.get('signer')})" if sig.get("signer") else "")
             + (f" - {sig['note']}" if sig.get("note") else ""))
    if e["manifest"]:
        L.append("  manifest       : " + ", ".join(f"{k}={v}" for k, v in e["manifest"].items()))
    if e["is_dotnet"]:
        L.append("  runtime        : .NET")
    if e["header_issues"]:
        for i in e["header_issues"]:
            L.append(f"  header         : {i}")
    L.append("")
    L.append("Graphics (static evidence; runtime loading can't be ruled out)")
    if not e["graphics"]:
        L.append("  no graphics API found in imports or strings")
    for g in e["graphics"]:
        L.append(f"  {g['label']:<42} [{g['strength']}] " + "; ".join(x["detail"] for x in g["evidence"][:2]))
    if e["protection"]:
        L.append("")
        L.append("Protection / packing")
        for p in e["protection"]:
            L.append(f"  [{p['strength']}] {p['detail']}")
    f = e["folder"]
    if f["proxy_dlls"] or f["bundled_libraries"]:
        L.append("")
        L.append("Game folder")
        for p in f["proxy_dlls"]:
            owner = f"installed by LegacyForge ({p['owner']})" if p.get("owner") else "not installed by LegacyForge"
            L.append(f"  proxy {p['name']:<16} {p.get('arch') or '?':<4} {p.get('description') or ''}  [{owner}]")
        for b in f["bundled_libraries"]:
            L.append(f"  bundled {b['dll']:<14} {b['library']}")
    if r.get("dependencies"):
        L.append("")
        L.append("Runtime dependencies")
        for d in r["dependencies"]:
            L.append(f"  {d['dll']:<22} {d['status']:<24} {d['runtime']}")
    s = r.get("system")
    if s:
        L.append("")
        L.append("System")
        o = s["os"]
        L.append(f"  OS             : {o.get('windows_name') or o.get('platform')} "
                 f"build {o.get('windows_build', o.get('release'))}, {'64' if o.get('64bit') else '32'}-bit")
        g = s["gpus"]
        if isinstance(g, list):
            for x in g:
                L.append(f"  GPU            : {x.get('Name')} driver {x.get('DriverVersion')} ({x.get('DriverDate')})")
        else:
            L.append(f"  GPU            : {g}")
        v = s["vulkan"]
        L.append(f"  Vulkan         : " + (f"32-bit loader {'yes' if v.get('loader_32bit') else 'no'}, "
                                         f"64-bit loader {'yes' if v.get('loader_64bit') else 'no'}"
                                         if "loader_32bit" in v else str(v.get("status", v))))
        for n in s.get("notes", []):
            L.append(f"  note           : {n}")
    if r.get("recipe"):
        rc = r["recipe"]
        L.append("")
        L.append(f"Recipe: {rc['name']} ({rc['id']}) - edition "
                 f"{rc['edition'] + ' (hash confirmed)' if rc['edition_confirmed'] else 'NOT confirmed by hash'}")
    L.append("")
    L.append("Recommendations (nothing has been changed)")
    if not r["recommendations"]:
        L.append("  none: no evidence of a compatibility problem. Play it and record a session if issues appear.")
    for i, x in enumerate(r["recommendations"], 1):
        L.append(f"  {i}. [{x['category']}] {x['problem']}")
        if x["fix"]:
            L.append(f"     fix        : {x['fix']}")
        L.append(f"     evidence   : {'; '.join(x['evidence'])}")
        if x["fix"]:
            L.append(f"     risk {x['risk']}, confidence {x['confidence']}, "
                     f"{'modifies exe' if x['modifies_executable'] else 'does not modify exe'}, "
                     f"{'needs admin' if x['needs_admin'] else 'no admin'}, "
                     f"{'reversible' if x['rollback'] else 'not reversible by LegacyForge'}")
        if verbose or x["blocked_by"]:
            if x["side_effects"]:
                L.append(f"     side effects: {'; '.join(x['side_effects'])}")
            if x["prerequisites"]:
                L.append(f"     requires   : {'; '.join(x['prerequisites'])}")
            L.append(f"     verify     : {x['verification']}")
        for b in x["blocked_by"]:
            L.append(f"     BLOCKED    : {b}")
    return "\n".join(L)
