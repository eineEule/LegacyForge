# Using LegacyForge with Claude (MCP)

LegacyForge includes an MCP server, so Claude can analyze your games, explain what it finds, and,
if you allow it, apply and undo fixes. It uses the same engine as the CLI, so every safety rule
still applies.

## Install

```powershell
py -m pip install "legacyforge[mcp] @ git+https://github.com/eineEule/legacyforge"
```

## Claude Desktop

Open **Settings → Developer → Edit Config** (`%APPDATA%\Claude\claude_desktop_config.json`), add the
server, then restart Claude Desktop:

```json
{
  "mcpServers": {
    "legacyforge": {
      "command": "legacyforge-mcp",
      "args": ["--allow-writes"]
    }
  }
}
```

If Claude can't find `legacyforge-mcp`, use the full path, e.g.
`C:\\Users\\<you>\\AppData\\Local\\Programs\\Python\\Python312\\Scripts\\legacyforge-mcp.exe`
(`where legacyforge-mcp` prints it).

## Claude Code

```powershell
claude mcp add legacyforge -- legacyforge-mcp --allow-writes
```

## Permission levels

| Started with | Claude can |
|---|---|
| *(no flags)* | Discover games, analyze executables, preview plans, read history and sessions. Changes nothing |
| `--allow-writes` | Also apply/revert recipes (config, wrapper DLL and Windows compatibility fixes) and record your gameplay verdicts |
| `--allow-exe-patching` | Also apply fixes that modify a game executable (`laa`). Requires `--allow-writes` |
| `--allow-launch` | Also launch games with monitoring in the background |

Start read-only and add flags when you want them.

## Guardrails (enforced in code, not just in instructions)

- **Preview before change.** `apply_recipe` only accepts the `plan_token` returned by
  `plan_recipe`. The token is bound to the exact recipe, folder, fixes, parameters, approvals and
  executable hash, and expires when the server restarts. If anything differs from what you were
  shown, the apply is refused.
- **Your consent stays yours.** Risky steps need approval tokens (`laa`, `replace-foreign`, ...).
  The server tells Claude to include one only after you explicitly agree. Claude Desktop also asks
  you before each tool call that changes something (those tools are marked destructive).
- **Everything is reversible** through the same transaction system as the CLI. Revert stops if
  files changed since the patch.
- **Audit log:** every tool call is appended (sanitized) to `%LOCALAPPDATA%\LegacyForge\mcp-audit.log`.
- **Local only:** the server talks to Claude over stdio on your machine and never exposes a
  network port.

## Try it

- "Why does Civ V crash after a few hours? It's in my Steam library."
- "Analyze C:\Games\AoE2\age2_x1\age2_x1.exe and tell me what you'd change."
- "Show me the plan for the aoe2-1999 recipe." → "OK, apply it."
- "I played for two hours with no crash. Record that and compare with last week."

Claude Desktop also lists a **troubleshoot_game** prompt under the server.

## Tools

Read-only: `discover_games`, `analyze_executable`, `list_recipes`, `plan_recipe`, `recipe_status`,
`modification_history`, `list_sessions`, `compare_sessions`, `verify_stability`.

With flags: `apply_recipe`, `revert_recipe`, `recover_recipe`, `record_gameplay_result`,
`launch_game`.
