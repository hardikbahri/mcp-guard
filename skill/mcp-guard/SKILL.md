---
name: mcp-guard
description: Put a security gateway in front of the user's MCP tool servers with MCP Guard. Use when the user wants to secure, lock down, audit or restrict an MCP server or an agent's tool calls, block prompt injection coming through tool results, stop personal data leaving through tools, limit which tools an agent may use, or sandbox an untrusted MCP server.
---

# MCP Guard: secure an MCP server

MCP Guard (open source, MIT) sits between an agent and an MCP tool server. Every tool listing, call and result passes
through it and is allowed, alerted, redacted, blocked or the session is ended, according to a YAML policy:

- role-based tool access (default deny: unlisted tools are hidden and blocked)
- prompt-injection detection in arguments and results (planted instructions are cut from results)
- argument contracts (lengths, ranges, enums, unknown arguments), call budgets, runaway-session termination
- PII and secret redaction, for tools that send data out of the company
- tool pinning: a tool whose description or schema changes after review is hidden (rug pull)
- optional Docker sandbox for local servers; stdio and Streamable HTTP on both sides
- JSON Lines audit log of every decision (ECS fields, mapped to the OWASP Top 10 for Agentic Applications)

Source and docs: https://github.com/hardikbahri/mcp-guard

## Ground rules

- Explain each step before you run it. Ask before editing any MCP client config file, and back it up first
  (copy it to `<file>.bak`).
- Never write secrets (API keys, tokens, JWT secrets) into `mcp-guard.yaml`. Secrets go in environment variables.
- Never weaken a check (for example `on_injection_in_result: allow`, removing pins, `allow_unknown_args: true`)
  without telling the user what it exposes and getting a yes.
- The generated policy is a starting point. Walk the user through it; do not present it as finished.

## If you cannot ask the user

When nobody is there to answer (an unattended run, a script, CI), lock down rather than open up:

- Make only changes that tighten: leave tools flagged REVIEW and tools marked `egress: external` out of the role unless
  the user's request named them (`mcp-guard init --upstream "..." --exclude a,b` does this without editing YAML). Keep
  injection and PII checks on. Never loosen anything.
- Do not edit the client config. Write the new entry to `mcp-client-config.guarded.json` next to it and say what to
  replace.
- Write `mcp-guard-review.md` listing every decision you could not make (for example "notify_customer left out; add it
  to the role if this agent should email customers") and finish by pointing the user to it.

## Steps

### 1. Install

Check whether it is installed with `mcp-guard --help`. If not:

```bash
pip install mcp-guard-gateway
```

(or `pip install git+https://github.com/hardikbahri/mcp-guard`). Python 3.11+ is required. Prefer a virtual
environment, and note the full path of the `mcp-guard` executable it creates; client configs need it.

### 2. Find the server to protect

Read the user's MCP client config (locations in `reference/clients.md`) and list the configured servers. Ask which one
to protect. Record its launch command (`command` + `args`, joined into one string) or, for a remote server, its URL.
Also note any `env` entries the server needs.

### 3. Generate a starter policy

From the folder where the policy should live (for example the project root):

```bash
mcp-guard init --upstream "<server command or URL>"
```

This connects to the server, reads its tools and writes `mcp-guard.yaml`. It prints a client config snippet; keep it.

### 4. Review the policy with the user

Open `mcp-guard.yaml` and go through it together (every setting is explained in `reference/policy.md`, the same file as
`docs/policy.md` in the repository):

1. **Roles.** `init` grants every tool to one role, `agent`. Ask what this agent actually needs and move other tools
   into separate roles or remove them. Least privilege is the main protection.
2. **REVIEW comments.** Tools with names like delete, exec, run or write are flagged and limited to one call per
   session. Ask whether the agent needs them at all.
3. **External tools.** Tools marked `egress: external` (email, notify, post, upload) have personal data redacted from
   their arguments; recipient fields are allowed through. Confirm the recipient field is correct.
4. **Limits.** Tighten `max_length`, `min`/`max` and `max_calls_per_session` where the user knows realistic values.
5. **Untrusted text.** If a tool is meant to receive user-supplied text (support tickets, emails, documents), keep
   `on_injection_in_args: alert` for it so injections are flagged but the tool still works; elsewhere `block`.

### 5. Validate

```bash
mcp-guard check --upstream "<server command or URL>"
```

Fix every `error:` line. Explain each `warning:` and let the user decide. Re-run until there are no errors.

### 6. Point the client at the gateway

With the user's approval, back up the client config, then replace the server's entry so the client launches the
gateway instead (exact format per client in `reference/clients.md`):

- `command`: the full path to `mcp-guard`; `args`: `["proxy"]`
- `env`: `MCP_GUARD_UPSTREAM` (the original command or URL), `MCP_GUARD_POLICY` (absolute path to `mcp-guard.yaml`),
  `MCP_GUARD_USER` (`my-agent`, or the user name in the policy), `MCP_GUARD_AUDIT_LOG` (absolute path), plus any
  `env` entries the original server needed

Keep the entry's name the same so the agent's tool names do not change.

### 7. Verify

Ask the user to restart or reload the client, then confirm:

- the server's tools still appear (only the ones the role grants);
- a normal tool call works;
- `audit.jsonl` has a line per decision. Show the last few: `tail -n 5 audit.jsonl`.

If something fails, see `reference/troubleshooting.md`.

## Optional hardening

- **Sandbox an untrusted local server** (third-party package, server you did not write): build an image containing the
  server and add a `sandbox:` section (no network, read-only, non-root, resource limits, only named env vars). See
  `reference/policy.md`. Requires Docker.
- **Limit what an unsandboxed server inherits:** `upstream_env: [ONLY, THESE, VARS]`.
- **Remote server:** use its `https://` URL as the upstream, pass a token with `MCP_GUARD_UPSTREAM_TOKEN`, and pin
  `upstream_allowed_hosts`.
- **Shared gateway for a team:** `mcp-guard proxy --http --port 8090` with `MCP_GUARD_JWT_SECRET` set; each agent's
  user comes from its JWT `sub`.
- **Keep the policy safe:** it is the security boundary. Keep it in version control behind review, read-only for the
  process running the agent, and run `mcp-guard check` in CI.

## What it does not do

Detection is rule-based: reworded or translated injections can get past it. It checks the MCP traffic and, with the
sandbox, contains a local server; it does not inspect what a remote server does on its own machine. Say so if the
user asks whether they are "fully protected".
