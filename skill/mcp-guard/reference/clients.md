# Where MCP clients keep their server config

Back up the file before editing. Keep the server's entry name unchanged.

| Client | File | Top-level key |
| --- | --- | --- |
| Claude Code | `.mcp.json` in the project (shared), or add with `claude mcp add` | `mcpServers` |
| Claude Desktop | macOS `~/Library/Application Support/Claude/claude_desktop_config.json`; Windows `%APPDATA%\Claude\claude_desktop_config.json` | `mcpServers` |
| Cursor | `.cursor/mcp.json` in the project, or `~/.cursor/mcp.json` | `mcpServers` |
| VS Code (Copilot) | `.vscode/mcp.json` in the workspace | `servers` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` | `mcpServers` |

Paths and key names change between client versions; if the file is not where the table says, check the client's own
documentation rather than guessing.

## Before

```json
{
  "mcpServers": {
    "complaints": {
      "command": "python",
      "args": ["-m", "complaintops.mcp_server"],
      "env": {"DATABASE_URL": "postgresql://..."}
    }
  }
}
```

## After

```json
{
  "mcpServers": {
    "complaints": {
      "command": "/home/me/.venvs/guard/bin/mcp-guard",
      "args": ["proxy"],
      "env": {
        "MCP_GUARD_UPSTREAM": "python -m complaintops.mcp_server",
        "MCP_GUARD_POLICY": "/home/me/project/mcp-guard.yaml",
        "MCP_GUARD_USER": "my-agent",
        "MCP_GUARD_AUDIT_LOG": "/home/me/project/audit.jsonl",
        "DATABASE_URL": "postgresql://..."
      }
    }
  }
}
```

The original server's `env` entries move into the gateway's `env`; the gateway passes them on to the server (or only
those listed in `upstream_env` / `sandbox.env`, if set).

For Claude Code from the command line:

```bash
claude mcp add complaints \
  -e MCP_GUARD_UPSTREAM="python -m complaintops.mcp_server" \
  -e MCP_GUARD_POLICY="$PWD/mcp-guard.yaml" -e MCP_GUARD_USER=my-agent \
  -e MCP_GUARD_AUDIT_LOG="$PWD/audit.jsonl" \
  -- mcp-guard proxy
```

For a remote (HTTP) server, `MCP_GUARD_UPSTREAM` is its URL and `MCP_GUARD_UPSTREAM_TOKEN` its bearer token.
