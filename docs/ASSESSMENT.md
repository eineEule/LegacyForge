# Repository assessment (v0.1 `oldgames`, before the LegacyForge work)

Assessed at commit `9101d01`. Everything below was checked in the source or by running it.

## What existed

| Component | File | Verified behaviour |
|---|---|---|
| CLI | `cli.py` | `list`, `scan`, `inspect`, `plan`, `apply`, `revert`, `status` |
| PE helpers | `pe.py` | Read architecture and LAA flag from the first 4 KiB; set LAA; PE checksum |
| Import listing | `pe.imported_dlls` | Delegated to `pefile` |
| Recipes | `recipe.py`, `recipes/*.yaml` | YAML `safe_load`; fix types from a registry; optional fixes |
| Fixes | `fixes/laa.py`, `dxvk.py`, `reshade.py`, `ini.py` | LAA, DXVK (pinned tarball), ReShade (unpinned, refused by default), INI edits |
| Backup/rollback | `snapshot.py` | Copies a file before first change; `revert` restores and deletes added files |
| Discovery | `detect.py` | Steam libraries + app manifests; recipe `paths` fallback |
| Tool downloads | `tools.py`, `data/tools.yaml` | SHA-256 pinned downloads; unpinned refused |
| Tests | `tests/` | 24 tests |

Dependencies: `pyyaml`, `pefile`. Entry point: `oldgames = oldgames.cli:main`.

## Baseline test run

`pytest`: **24 passed** (Linux, Python 3.13). No Windows-specific code had tests.

## Defects found (reproduced, then fixed)

1. **Truncated executables misparsed silently.** A file cut off inside the COFF header returned
   `PEInfo(machine=332, characteristics=0, magic=0)` instead of an error. Slices past the end of the
   file read as short byte strings.
2. **PE headers beyond 4 KiB rejected.** `read_info` read a fixed 4096 bytes, so valid files with a
   large DOS stub failed with "missing PE signature".
3. **Revert overwrote independent changes.** After `apply`, a user edit to a patched file was
   silently discarded by `revert`. No post-patch hashes were recorded.
4. **No interrupted-apply recovery.** A crash mid-apply left a manifest. It could be reverted, but
   nothing distinguished "interrupted" from "complete".
5. **LAA applied without evidence.** Any recipe could flip LAA with no version check or approval.
6. **Writes were not atomic**, and links in the game folder were followed.
7. **Archive members were trusted.** Sizes weren't limited and link members weren't checked
   (DXVK extraction read members by name, so it wasn't exploitable as written, but nothing enforced it).
8. **Backups were not verified** before or after restore.
9. **Recipe validation was shallow.** Unknown top-level keys and unknown fix parameters were
   accepted, and recipe-relative paths could contain `..`.

## Technical debt

- `pefile` was used only for imports. Replaced with an in-house bounds-checked parser, cross-checked
  against `pefile` in tests where it is installed.
- `Context.track` was optional per fix. Fixes now write through `Context.write`, which always
  tracks and writes atomically.

## Decisions

- **Extended, not rewritten.** The recipe model, fix registry, plan/apply/revert flow and CLI shape
  are kept.
- **Renamed** the package to `legacyforge`. The `oldgames` command remains as an alias, and v0.1
  snapshots in `.oldgames/` are still read and reverted.
- **One intentional behaviour change:** `laa` now needs `--approve laa` unless the recipe lists the
  executable's exact SHA-256 (see [MIGRATION](../README.md#migrating-from-oldgames-01)).
