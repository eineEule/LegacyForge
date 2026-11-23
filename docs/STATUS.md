# Completed vs planned

Legend:
- ✅ implemented and covered by automated tests
- 🟡 implemented; needs real-Windows validation (the code paths can't run in CI here)
- ⏳ planned

## Phase 1: Universal analyzer
| Item | Status |
|---|---|
| PE32/PE32+, subsystem, LAA, header integrity, imports, delay imports, manifest, version info, SHA-256, overlay, .NET flag | ✅ |
| Graphics API evidence (DirectDraw, D3D5–7 via ddraw/d3dim, D3D8–11, OpenGL, Glide, software) with strength levels | ✅ |
| Packing/protection/anti-cheat heuristics | ✅ (heuristic by nature) |
| Signature presence | ✅ · validity via Windows 🟡 |
| System: OS/build, memory, GPU and driver, Vulkan 32/64-bit loaders, legacy runtimes, Defender CFA, existing compat layers | 🟡 (structure tested; probes are Windows-only) |
| Discovery: Steam, GOG registry, folders, manual exe | ✅ Steam/folders · 🟡 GOG |
| Structured JSON + text reports | ✅ |
| Conservative recommendation engine (4 categories + info, all required fields) | ✅ |

## Phase 2: Expanded fixes
| Item | Status |
|---|---|
| Transaction manager: pre/post hashes, conflicts, keep-current/force, recovery, verified backups, atomic writes, created-directory cleanup, v0.1 compatibility | ✅ |
| Safe archive extraction | ✅ |
| DXVK: pinned version, arch-validated DLLs, conflict detection, dxvk.conf | ✅ · on-hardware 🟡 |
| cnc-ddraw 7.1.0.0: pinned, settings allowlist, shaders | ✅ (real release installed in a mock folder) · on-hardware 🟡 |
| dgVoodoo2 from a user-supplied archive (no redistribution) | ✅ with synthetic archive · real archive layout 🟡 |
| Proxy DLL ownership, foreign-DLL approval | ✅ |
| Windows compat layers (mode, FSO, DPI, colour, 640×480), HKCU, reversible | ✅ with in-memory registry · 🟡 on Windows |
| Runtime dependency detection (VC++ 2003–2022, DirectX June 2010 components, XInput, .NET, OpenAL, game middleware) | ✅ mapping · 🟡 system lookup |
| CPU affinity and priority launch profiles (no system-wide changes) | ✅ Linux · 🟡 Windows |
| Recipe schema v2 (editions and hashes, known issues with evidence, ordering, incompatibilities, dependencies, test plans, evidence) | ✅ |
| FPS limiting | ✅ via backend settings (dxvk `maxFrameRate`, cnc-ddraw `maxfps`) |
| Engine-specific timing workarounds | ⏳ (needs per-game research) |

## Phase 3: Diagnostics
| Item | Status |
|---|---|
| Launch and monitor, memory samples (private, working set, virtual) | ✅ Linux · 🟡 Windows (GetProcessMemoryInfo / VirtualQueryEx) |
| Steam relaunch hand-off following | 🟡 |
| Exit classification (NTSTATUS), Event Log 1000 parsing | ✅ parsing · 🟡 live `wevtutil` |
| Wrapper log collection | ✅ |
| Sessions, outcome categories, baseline comparison, "verified stable" rules | ✅ |
| Privacy controls (local, retention, purge, sanitized export, no dumps) | ✅ |

## Phase 4: Community infrastructure
| Item | Status |
|---|---|
| Signed bundle format, keygen/sign/trust/verify/install | ✅ |
| Privacy-preserving result format (`legacyforge-result/1`) | ✅ |
| GUI-ready service API (`services.py`) | ✅ |
| Remote registry hosting / submission | ⏳ |
| Key revocation | ⏳ |
| GUI | ⏳ |
| MCP server for Claude: read-only by default, flag-gated writes, plan-token binding, audit log, stdio protocol test | ✅ · Claude Desktop on Windows 🟡 |
| One-click Claude Desktop extension packaging | ⏳ |

## Needs a Windows machine and the real games
- Run `pytest -m integration` with `LEGACYFORGE_GAME_EXE` set (see `tests/integration`).
- Record exe hashes for each edition, then baseline and fix sessions (see the compatibility matrix).
