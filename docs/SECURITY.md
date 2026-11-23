# Security considerations

Threat model: game folders, executables, recipes (bundled, community, local), tool archives and
Windows event data are **untrusted input**. The user is trusted, and their approval is required for
anything risky.

## Implemented

| Area | Control | Where | Tested |
|---|---|---|---|
| Executable parsing | Every offset bounds-checked; header offset, section count, import count, resource depth and size capped; never executed or loaded | `pe.py` | fuzz + truncation tests |
| Static inspection | No downloaded or game code runs during analysis; manifests parsed by regex, not an XML parser (no entity expansion) | `analysis.py`, `pe.py` | yes |
| Recipes | `yaml.safe_load` (no Python tags); strict key allowlists at every level; allowlisted fix parameters (e.g. cnc-ddraw keys, DXVK config key pattern); 256 KiB size cap; `..` rejected in relative paths; game ids restricted | `recipe.py`, `fixes/*` | malicious-recipe tests |
| Exe modification | Only LAA. Needs a recipe hash match or `--approve laa`; signed exes need `--approve laa-signed`; refused outright on protected/packed exes (no DRM bypass); byte-level verification that nothing else changed | `fixes/laa.py`, `pe.py` | yes |
| Archives | No absolute paths, `..`, drive letters, symlinks, hardlinks or devices; member, total, count and compression-ratio limits; members read into memory and written to LegacyForge-chosen paths only | `archive.py` | zip-slip, symlink and bomb tests |
| Downloads | HTTPS only; SHA-256 pinned (mismatch deletes the file); size cap; no tool bundled; dgVoodoo2 never downloaded (redistribution terms unverified) | `tools.py`, `data/tools.yaml` | yes |
| File writes | Links and reparse points refused; containment check inside the game folder; atomic temp-file replace with fsync | `fsutil.py`, `context.py` | symlink test |
| Rollback integrity | Backups hashed and re-verified; restore only when the current file matches a recorded hash; interrupted applies detected | `transaction.py` | yes |
| Proxy DLLs | Foreign DLLs need `--approve replace-foreign`; architecture validated; two backends can't claim one DLL | `fixes/graphics.py`, `engine.py` | yes |
| Registry | Per-user HKCU only; HKLM read-only by construction; exact-exe-path values; previous value restored | `winapi.py`, `fixes/compat.py` | yes |
| Subprocesses | Argument lists, never `shell=True`; user values reach PowerShell only via environment variables; fixed XPath for Event Log | `winapi.py`, `monitor.py` | yes (Linux paths) |
| Privilege | Never elevates; never sets "Run as administrator"; realtime priority refused | `fixes/compat.py`, `monitor.py` | yes |
| Diagnostics privacy | Local only; no memory dumps; retention setting and `purge`; export strips home paths, user and host names and PIDs | `sessions.py` | yes |
| Registry bundles | Ed25519 signature over canonical JSON; local trust store (no trust-on-first-use); per-file SHA-256; path containment; schema validation before install | `registry.py` | tamper and untrusted-key tests |

## Not done / limitations

- Authenticode **validity** is checked by asking Windows (`Get-AuthenticodeSignature`). Off Windows,
  only presence is reported.
- Packing and protection detection is heuristic (section names, entropy, import shape). Absence of
  a finding is not proof the exe is unprotected.
- The data folder (`%LOCALAPPDATA%\LegacyForge`) is protected by normal user file permissions only.
- The registry trust store has no key revocation yet.
