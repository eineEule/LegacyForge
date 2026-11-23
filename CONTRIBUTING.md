# Contributing

## Adding a game recipe

1. Copy an existing file in `src/oldgames/recipes/` and name it after the game.
2. Fill in `detect.steam_appid` (the number in the game's Steam store URL) and
   `detect.exe` (path relative to the install folder).
3. Run `oldgames inspect "<install folder>\game.exe"` to see whether the exe is
   32-bit, whether it is already 4 GB aware, and which graphics API it uses.
4. Add only fixes you have tested. Mark anything that helps some people but
   not everyone as `optional: true`.
5. Put manual steps (Workshop mods, driver advice) in `notes`.
6. Test with `oldgames plan`, `apply`, play the game, then `revert`. The game
   folder should be byte-identical afterwards.

## Rules

- Never commit game files, extracted assets or third-party binaries.
- New tools go in `data/tools.yaml` with an official URL and a SHA-256 you
  computed and checked yourself.
- Recipes modify executables on other people's machines, so review recipe PRs
  like code.

## Adding a fix type

Subclass `oldgames.fixes.base.Fix`, decorate it with `@register`, implement
`validate`, `writes`, `describe` and `apply`, and call `ctx.track(path)`
before touching any file. Then add tests.
