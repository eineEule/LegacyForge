# Architecture

```
            CLI (cli.py)                 future GUI
                 \                         /
                  services.py  (stable application API: plain data in/out, no printing)
     ┌──────────────┬───────────┬────────────┬─────────────┬──────────────┐
 discovery      analysis     recommend     engine        monitor / diagnostics / sessions
 detect.py      pe.py        recommend.py  engine.py     monitor.py  diagnostics.py  sessions.py
                analysis.py               transaction.py
                system.py                 context.py ── fixes/ (laa, ini, compat, graphics)
                deps.py                   archive.py, tools.py, fsutil.py
                                          recipe.py ── recipes/*.yaml   registry.py (signed bundles)
                         winapi.py (all Windows access: registry, PowerShell, paths)
```

Workflow: **Discover → Analyze → Recommend → Back up → Apply → Launch → Monitor → Verify → Restore**

| Logical component | Module | Notes |
|---|---|---|
| Core engine | `engine.py`, `context.py` | Plans with conflict, incompatibility and approval checks; applies inside a transaction |
| Executable analyzer | `pe.py`, `analysis.py` | Bounds-checked PE parser; imports, delay imports, version info, manifest, signature, packing heuristics |
| System analyzer | `system.py` | OS/build, memory, GPU and driver, Vulkan loaders (32/64-bit), legacy runtimes, Defender CFA, compat layers |
| Compatibility rules | `recommend.py` | Rule functions → `Recommendation` with category, evidence, risk, admin, exe-modification, rollback, verification, confidence |
| Graphics backends | `fixes/graphics.py` | DXVK, cnc-ddraw, dgVoodoo2 (user-supplied), ReShade; shared proxy-DLL ownership rules |
| Memory fixes | `fixes/laa.py`, `pe.py` | LAA with protection/signature checks, approval or hash gating, post-patch byte-level verification |
| Windows compatibility | `fixes/compat.py` | Per-user AppCompatFlags layers (Microsoft's own mechanism), exact-exe scope |
| Dependency manager | `deps.py` | Maps imports to runtimes; reports present/missing; never installs |
| Runtime monitoring | `monitor.py` | Launch profiles (affinity, priority, args, env), memory sampling, Steam hand-off following |
| Crash diagnostics | `diagnostics.py` | Exit-code classification, Event Log 1000 parsing, outcome rules, baseline comparison, stability verification |
| Transaction manager | `transaction.py` | Backups, pre/post SHA-256, conflict detection, recovery, registry entries, v0.1 compatibility |
| Recipe registry | `recipe.py`, `registry.py` | Strict schema v1/v2; Ed25519-signed bundles with a local trust store |
| Game discovery | `detect.py` | Steam (VDF), GOG (registry), arbitrary folders, manual exe |
| GUI API | `services.py` | Functions return dicts and dataclasses; callbacks for confirmation and progress |

## Key invariants

- **Analysis never writes.** `analyze` and `system.inspect` have no write paths.
- **Every write goes through `Context.write`**: track (backup + hash), link and escape checks, then
  an atomic replace.
- **Every apply is a transaction**: `in_progress` until all fixes succeed. Any exception rolls back.
  A crash leaves `in_progress` for `recover`.
- **Revert validates first**: current hash must equal the recorded post-patch (or original) hash,
  and the backup must match its recorded hash. Otherwise it stops with options.
- **Recipes are data**: allowlisted fix types and parameters only, with no shell, scripts or
  arbitrary paths.
- **Windows access is centralised** in `winapi.py`: argument lists only, user values passed through
  environment variables, HKCU-only writes.
