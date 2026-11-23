# oldgames

Patch and wrap old 32-bit PC games so they run well on modern Windows, using
short, reviewable recipes instead of forum threads.

```
oldgames scan                    # find installed games that have recipes
oldgames plan civ5               # show what would change
oldgames apply civ5 --with dxvk  # apply, including an optional fix
oldgames revert civ5             # put every file back exactly as it was
```

## Why

Old games break in predictable ways: a 2 GB memory limit, Direct3D drivers that
no longer behave, and config defaults from 2005. The fixes are well known but
scattered across wikis and forums. `oldgames` turns each game's fixes into a
recipe that a script runs and that anyone can read.

## A recipe

```yaml
game: rise-of-nations-ee
name: "Rise of Nations: Extended Edition"
detect:
  steam_appid: 287450
  exe: riseofnations.exe
fixes:
  - laa: riseofnations.exe
  - dxvk: {api: d3d9}
    optional: true
notes:
  - "Subscribe to the Community Balance/Bugfix Patch on the Workshop."
```

## Fix types

| Fix       | What it does                                                        |
|-----------|---------------------------------------------------------------------|
| `laa`     | Sets the Large Address Aware flag, so 32-bit games get 4 GB, not 2. |
| `dxvk`    | Installs DXVK (Direct3D 8/9/10/11 to Vulkan) next to the exe.       |
| `reshade` | Installs ReShade post-processing. Experimental.                     |
| `ini`     | Edits config files in place, keeping comments and encoding.         |

Run `oldgames inspect game.exe` to see an exe's architecture, whether it is
already 4 GB aware, and which graphics API it imports.

## Safety

- **Every change is backed up first.** Snapshots live in
  `<game>\.oldgames\<recipe>\`. `revert` restores originals and removes added
  files. If any fix fails, the whole apply is rolled back.
- **No game files and no bundled tools.** Third-party tools are downloaded from
  their official releases at apply time and checked against a SHA-256 pin in
  `src/oldgames/data/tools.yaml`. Unpinned tools are refused unless you pass
  `--allow-unpinned`.
- **Conflicts are caught before anything runs.** For example, DXVK and ReShade
  can't both own `d3d9.dll`.
- Steam "Verify integrity of game files" and game updates undo patches to the
  exe. Run `revert`, then `apply` again.

## Install (development)

```
git clone <this repo> && cd oldgames
python -m pip install -e .[dev]
pytest
```

Requires Python 3.10+ on Windows. Tests run anywhere.

## Roadmap

- v0.2: GOG and Epic detection, widescreen fix packs, ReShade shader presets
- v0.3: built-in virtual LAN for multiplayer (join with a code)
- Signed recipe registry, so community recipes can be trusted before they run
- Small GUI

## License

MIT. Each downloaded tool keeps its own license; see `data/tools.yaml`.
