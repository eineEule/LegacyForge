# LegacyForge

An evidence-driven compatibility engine for legacy 32-bit Windows PC games (roughly 1995–2012) on
Windows 10 and 11. Formerly `oldgames`.

It analyzes an executable it has never seen, explains what it found and how sure it is, and
recommends fixes conservatively. It applies only what you choose, inside a transaction it can undo,
then launches the game and records evidence of whether things got better.

```
Discover → Analyze → Recommend → Back up → Apply → Launch → Monitor → Verify → Restore
```

LegacyForge can't guarantee any game becomes stable. It tells you what it knows, what it's guessing
and what it changed.

## Why

Many classic PC games still run on Windows 10 and 11 but crash or misbehave. Common causes are the
32-bit memory ceiling, DirectDraw and old Direct3D drivers, high-DPI scaling, and missing runtimes.
The fixes are well known but scattered across forums and wikis, and applying them by hand
(hex-editing an exe, dropping DLLs into a game folder) is easy to get wrong and hard to undo.
LegacyForge turns that knowledge into a tool that explains itself and can always put things back.

## How it works

1. **Discover.** Finds games through Steam library files, the GOG registry, or any folder or exe
   you point at. Steam isn't required.
2. **Analyze (read-only).** Parses the executable with a bounds-checked PE parser and reports:
   - 32 or 64-bit, and whether it already has the 4 GB (Large Address Aware) flag
   - imported DLLs, including delay-loaded ones
   - version info, manifest (DPI awareness, privilege level), signature, signs of packing or DRM
   - which graphics API it likely uses (DirectDraw, Direct3D 5–11, OpenGL, Glide), each finding
     marked strong, medium or weak
   - your system: Windows build, GPU and driver, 32/64-bit Vulkan loaders, legacy runtimes, and
     any existing Windows compatibility settings

   Nothing is modified.
3. **Recommend.** Rules map that evidence to fixes. Each recommendation states the problem,
   evidence, risk, confidence, whether it touches the exe or needs admin, how to undo it and how
   to verify it. Unknown games get conservative advice: being 32-bit alone is not treated as a
   problem.
4. **Back up and apply.** A recipe (YAML) or your own choice of fixes runs as a transaction:
   - every file is backed up and SHA-256 hashed first, and written atomically
   - if any step fails, everything rolls back
   - risky steps (patching the exe, replacing a DLL another tool installed) need your explicit
     `--approve`
5. **Launch and monitor.** Starts the game with an optional per-game profile (CPU affinity,
   priority, arguments) and records:
   - memory use over time
   - exit code, classified (a nonzero code alone isn't treated as a crash)
   - Windows Application Error events and wrapper logs

   Each run is saved as a session, locally only.
6. **Verify.** Compares sessions with and without a fix (improvement, regression or inconclusive).
   A game is marked "verified stable" only after repeated passing sessions of a defined test.
7. **Restore.** `revert` puts every file and setting back. If something changed since the patch
   (a Steam update, your own edit, another mod), it stops and asks instead of overwriting.

## Quick start

```
pip install -e .[dev]          # Python 3.10+, Windows for the full feature set
legacyforge discover           # Steam, GOG and --dir folders
legacyforge analyze "C:\Games\AoE2\age2_x1\age2_x1.exe" --json report.json
legacyforge plan aoe2-1999 --game-dir "C:\Games\AoE2"
legacyforge apply aoe2-1999 --game-dir "C:\Games\AoE2"
legacyforge launch aoe2-1999 --game-dir "C:\Games\AoE2" --scenario skirmish
legacyforge sessions compare aoe2-1999
legacyforge revert aoe2-1999 --game-dir "C:\Games\AoE2"
```

## Commands

| Command | What it does |
|---|---|
| `discover [--dir D]` | Installed games (Steam, GOG, folders) and which have recipes |
| `analyze EXE [--json F] [-v]` | Read-only report: PE facts, graphics evidence, protection, dependencies, system, recommendations. Given a folder, lists candidate exes |
| `list` | Recipes (bundled + installed from signed bundles) |
| `plan` / `apply RECIPE [--with FIX] [--approve TOKEN] [--param fix.key=value]` | Show and apply a transactional plan |
| `revert RECIPE [--keep-current \| --force]` | Undo; stops if files changed since the patch |
| `recover RECIPE` | Roll back an interrupted apply |
| `status RECIPE`, `history GAME_DIR [--log]` | What's applied, what changed since |
| `profile GAME [--affinity 0,1] [--priority P] [--arg A] [--env K=V]` | Per-game launch profile (nothing system-wide) |
| `launch RECIPE\|EXE [--scenario S] [--minutes N] [-v]` | Run, monitor memory and exit, check the Event Log, record a session |
| `sessions list\|compare\|verify\|purge\|export` | Evidence: baseline vs candidate, "verified stable" rules, privacy controls |
| `settings [--set retention_days=30]` | Diagnostic collection and retention |
| `registry keygen\|trust\|sign\|verify\|install` | Signed recipe bundles |
| `inspect EXE`, `scan` | v0.1 commands, kept |

## Fixes

| Fix | Modifies exe | Notes |
|---|---|---|
| `laa` | yes | Needs a recipe hash match or `--approve laa`; refused on protected exes |
| `dxvk` | no | Pinned 2.5.3; arch-checked DLLs; optional `dxvk.conf` |
| `cnc-ddraw` | no | Pinned 7.1.0.0; DirectDraw (2D) games only; allowlisted `ddraw.ini` settings |
| `dgvoodoo2` | no | You supply the archive (`--param dgvoodoo2.archive=...`); never downloaded or bundled |
| `reshade` | no | Experimental; hash must be pinned before use |
| `compat` | no | Per-user Windows compatibility layers for the exact exe (mode, fullscreen optimizations, DPI, colour) |
| `ini` | no | Edits configs preserving comments and encoding |

Approvals the plan may ask for: `laa`, `laa-signed`, `replace-foreign` (overwrite a DLL LegacyForge
didn't install), `dgvoodoo2-unpinned`.

## Recipes

YAML, schema v2 (v1 still loads): editions with exe SHA-256s, known issues (each must cite
evidence), fixes with status, order, editions and optional flags, incompatible pairs, dependencies,
test plans and recorded evidence. Recipes can't run code. See `src/legacyforge/recipes/civ5.yaml`.

Bundled: `civ4`, `civ5`, `aoe2-1999`, `rise-of-nations-ee`, `rise-of-nations-2003`. None is
verified yet; see [docs/COMPATIBILITY_MATRIX.md](docs/COMPATIBILITY_MATRIX.md).

## Docs

- [Assessment of the v0.1 codebase](docs/ASSESSMENT.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Compatibility matrix](docs/COMPATIBILITY_MATRIX.md)
- [Security considerations](docs/SECURITY.md)
- [Completed vs planned](docs/STATUS.md)

## Testing

```
pytest                          # unit suite: synthetic fixtures, no games needed
pytest -m integration           # on Windows, with LEGACYFORGE_GAME_EXE=<path to a game exe>
```

## Migrating from oldgames 0.1

- The package is `legacyforge`; the `oldgames` command still works.
- Snapshots in `<game>\.oldgames\` are still recognised by `status` and `revert`. New ones go to
  `<game>\.legacyforge\`.
- **Behaviour change:** `laa` now requires `--approve laa` unless the recipe lists the exe's
  SHA-256 under `editions`. Some games crash with LAA, so it is no longer applied on a name match.
- `revert` now refuses to overwrite files changed since the patch; use `--keep-current` or
  `--force`.
- `pefile` is no longer a dependency.

## Prioritized next steps

1. Run the integration test and `analyze` on real installs of the four games; record edition hashes.
2. Validate the Windows-only paths: Event Log, memory counters, Steam hand-off, compat layers, GOG.
3. Record baseline and fix sessions for Civ V late game (the reported crash), then Civ IV big maps.
4. Confirm the Rise of Nations graphics API from a real `analyze`, then add backend options.
5. Engine-specific timing workarounds, and key revocation for registry bundles.
6. GUI on top of `services.py`.

## License

MIT. Downloaded tools keep their own licenses (`src/legacyforge/data/tools.yaml`).
