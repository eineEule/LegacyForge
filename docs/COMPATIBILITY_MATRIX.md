# Compatibility matrix

**No game here has been tested under LegacyForge yet.** Every result is *Not tested* until a
recorded session says otherwise. "Recipe fixes" lists what each recipe offers, with the status the
recipe assigns: *suggested* or *experimental*. None is *verified*.

| Game / edition | Recipe | Detection | Recipe fixes | Evidence on file | Result |
|---|---|---|---|---|---|
| Civilization IV: Beyond the Sword (Steam) | `civ4` | Steam 8800, `Beyond the Sword/Civ4BeyondSword.exe` | laa (suggested; community says already set), dxvk d3d9 (experimental, optional), compat FSO (experimental, optional) | CivFanatics threads on big-map crashes and on LAA already being set | Not tested |
| Civilization IV: BtS retail 3.19 | `civ4` | `--game-dir` | as above | none | Not tested |
| Civilization V (Steam, DX11 exe) | `civ5` | Steam 8930, `CivilizationV_DX11.exe` (hash recorded; already LAA, confirmed) | laa (suggested; community says already set), MSAA→2x (suggested), logging (optional), dxvk d3d11 (experimental, optional) | Maintainer report of late-game crashes (YnAEMP 34-civ, 8x MSAA); not reproduced in a session | Not tested |
| Civilization V (Steam, DX9 exe) | `civ5` | `CivilizationV.exe` | laa, logging | none | Not tested |
| Age of Empires II (1999) / The Conquerors | `aoe2-1999` | `--game-dir`, `age2_x1/age2_x1.exe` | cnc-ddraw 7.1.0.0 (suggested), compat DPI (optional) | cnc-ddraw lists AoE II and The Conquerors as supported, with `[EMPIRES2]` / `[age2_x1]` profiles | Not tested |
| Age of Empires II HD / Definitive Edition | none | none | not applicable (different programs) | none | Out of scope |
| Rise of Nations: Extended Edition | `rise-of-nations-ee` | Steam 287450, `riseofnations.exe` (hash recorded) | laa (suggested, needs approval), dxvk d3d11 (experimental, optional) | Analyzed + runtime modules on Windows 11: Direct3D 11 via d3dgl.dll confirmed; patriots.exe confirmed as launcher; ~0.7 GB at main menu | Not tested |
| Rise of Nations (2003 retail) / Thrones and Patriots | `rise-of-nations-2003` | `--game-dir`, `rise.exe` | SkipIntroMovies ini (optional), compat DPI (optional) | Lutris installer metadata (exe name, ini path) | Not tested |

## What the pipeline itself has been checked against

- Synthetic PE32 and PE32+ fixtures with imports, delay imports, version resources, manifests and
  signature directories, plus 400 random corruptions and truncation at every 7–97 bytes.
- Real release binaries: DXVK 2.5.3 `d3d9.dll` and `dxgi.dll`; cnc-ddraw 7.1.0.0 `ddraw.dll` and
  `cnc-ddraw config.exe`. Import lists match `pefile`, except where `pefile` drops descriptors it
  calls damaged (the Windows loader still loads them).
- An end-to-end install and revert of the real cnc-ddraw 7.1.0.0 release into a mock AoE2 folder,
  including the conflict guard.
- The launch → monitor → classify → session pipeline, with a stand-in process on Linux.

## How a row becomes "Verified stable"

1. `legacyforge analyze` and add the exe SHA-256 to the recipe's `editions`.
2. Record baseline sessions without fixes: `legacyforge launch <recipe> --scenario <id>`.
3. Apply one fix; record sessions under the same scenario.
4. `legacyforge sessions compare <game>` reports improvement, regression or inconclusive.
5. `legacyforge sessions verify <game> --scenario <id>` returns `verified-stable` only after 3+
   confirmed passing sessions of the scenario's full length, with one configuration and no crashes.
6. Add the result to the recipe's `evidence` with the session id.
