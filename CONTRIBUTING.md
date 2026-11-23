# Contributing

## Adding a game recipe

1. Copy an existing file in `src/legacyforge/recipes/` and name it after the game.
2. Fill in `detect.steam_appid` (the number in the game's Steam store URL) and
   `detect.exe` (path relative to the install folder).
3. Run `legacyforge analyze "<install folder>\game.exe" --json report.json` and record the exe's
   SHA-256 under `editions`. Exe-modifying fixes only run without approval on a hash match.
4. Add only fixes you have tested. Mark anything that helps some people but
   not everyone as `optional: true`.
5. Put manual steps (Workshop mods, driver advice) in `notes`. Every `known_issues` entry needs
   `evidence` (a source or a recorded session). Never mark a fix `verified` without sessions
   from `legacyforge sessions verify`.
6. Test with `legacyforge plan`, `apply`, play the game, then `revert`. The game
   folder should be byte-identical afterwards.

## Rules

- Never commit game files, extracted assets or third-party binaries.
- New tools go in `data/tools.yaml` with an official URL and a SHA-256 you
  computed and checked yourself.
- Recipes modify executables on other people's machines, so review recipe PRs
  like code.

## Adding a fix type

Subclass `legacyforge.fixes.base.Fix` (or `GraphicsBackend` for proxy DLLs), decorate it with
`@register`, implement `validate` (allowlist every parameter), `writes`, `approvals_needed`,
`describe` and `apply`, and write files only through `ctx.write(path, data)`. Add tests,
including a malicious-parameter test.
