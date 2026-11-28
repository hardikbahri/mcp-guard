# Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| Client shows no tools from the server | The user in `MCP_GUARD_USER` is missing from `users`, or its role grants nothing. Run `mcp-guard check`. |
| One tool missing | Not granted to the user's role, missing under `tools`, or its pin no longer matches (the server changed the tool). `mcp-guard check --upstream ...` says which. If the change is expected, re-pin with `mcp-guard pin "<server>"`. |
| `[mcp-guard] ... blocked` on a call | Read the reason in the message and in `audit.jsonl`: unknown argument, value out of range, call budget, injection or code pattern. Adjust the policy only if the call was legitimate. |
| Session ended | Too many violations or calls in one session (`session:` settings). Usually a loop in the agent. |
| `no policy at ...` | Set `MCP_GUARD_POLICY` to an absolute path, or run from the folder containing `mcp-guard.yaml`. |
| `refusing plain http` | Remote servers need `https://`. Plain http is only allowed to localhost. |
| `sandbox is enabled but 'docker' is not installed` | Install Docker, or remove the `sandbox:` section. |
| Server fails to start behind the gateway | It probably needed environment variables: copy the original `env` entries into the gateway's `env`, and into `upstream_env` / `sandbox.env` if those are set. |
| `mcp-guard: command not found` in the client | Use the full path to the executable in the client config (`which mcp-guard`). |

Reading the audit log: each line is JSON with `mcp_guard.decision` (allow / alert / redact / block / terminate),
`mcp_guard.tool`, `mcp_guard.owasp` (risk ids such as ASI01 goal hijack), `user.name`, and `findings` (what fired and
why; redacted values are never written).
