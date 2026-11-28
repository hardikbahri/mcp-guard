# MCP Guard

[![CI](https://github.com/hardikbahri/mcp-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/hardikbahri/mcp-guard/actions/workflows/ci.yml)

Inline security gateway for AI agents and MCP tool servers. It sits between an agent and its tools and checks every
tool listing, call and result, then **allows, alerts, redacts, blocks or terminates** by policy.

```
agent  <--MCP-->  mcp-guard (policy + detectors + audit)  <--MCP-->  tool server
```

Either side can be **stdio** (local processes) or **Streamable HTTP** (remote): put it in front of a local server, a
remote one, or serve a whole team's agents over HTTP.

Built in front of the [ComplaintOps](https://github.com/hardikbahri/complaintops) triage agent.

## What it checks

| Check | OWASP Agentic Top 10 | Action |
| --- | --- | --- |
| Tool not granted to the user's role (RBAC, default deny); roles an agent claims are ignored unless the policy grants them | ASI03 Identity & Privilege Abuse | block, tool hidden from listing |
| Prompt injection in tool arguments (override phrases, chat markup, hidden Unicode, exfiltration directives) | ASI01 Agent Goal Hijack | alert or block, per tool |
| Instructions planted in tool **results** (indirect injection) before they reach the model | ASI06 Memory & Context Poisoning | injected sentence removed |
| Argument contract: unknown args, ranges, lengths, per-tool rate limits | ASI02 Tool Misuse | block |
| Shell, SQL, Python and path-traversal payloads in arguments | ASI05 Unexpected Code Execution | block |
| Poisoned tool descriptions, tool definitions changed after review (sha256 pins) | ASI04 Supply Chain | tool hidden |
| PII (email, phone, card with Luhn, SSN, Aadhaar, PAN, IBAN) and secrets leaving the boundary or entering model context | ASI03 / DLP | redacted |
| Session call budget exceeded, repeated violations | ASI08 Cascading Failures / ASI10 Rogue Agents | session terminated |
| A compromised tool server acting inside its own process (reading secrets, writing files, calling out, exhausting resources) | ASI05 Unexpected Code Execution / ASI04 Supply Chain | contained by the sandbox |

Every decision is written as one JSON line with Elastic Common Schema fields (`@timestamp`, `event.*`, `user.*`,
`rule.*`) so a log forwarder can ship it to Elastic, Splunk or Microsoft Sentinel. Values that were redacted are never logged.

## Live demo (2 minutes, no API key)

```bash
pip install mcp-guard-gateway
python -m mcp_guard.demo.live          # press Enter between scenes
```

The same attacks against a demo complaint-triage tool server, first directly and then through MCP Guard: an indirect
prompt injection with personal data in a search result, an agent tricked into emailing data out, a shell-injection
payload, an abusive argument, repeated violations, and a rug pull (a tool rewritten after review). It ends with the
audit log. The script plays the agent, so every run is identical.

## Quickstart: put it in front of your MCP server

```bash
pip install mcp-guard-gateway        # or: pip install git+https://github.com/hardikbahri/mcp-guard

# 1. discover your server's tools and write a starter policy (mcp-guard.yaml)
mcp-guard init --upstream "python -m your_package.mcp_server"      # or --upstream https://host/mcp

# 2. review it (every setting: docs/policy.md): split tools into roles, tighten limits, read the REVIEW comments
#    leave tools out up front with --exclude run_report,notify_customer; then validate
mcp-guard check --upstream "python -m your_package.mcp_server"

# 3. point your MCP client at the gateway instead of the server (init prints this snippet)
```

```json
{
  "mcpServers": {
    "guarded-tools": {
      "command": "mcp-guard",
      "args": ["proxy"],
      "env": {
        "MCP_GUARD_UPSTREAM": "python -m your_package.mcp_server",
        "MCP_GUARD_POLICY": "/path/to/mcp-guard.yaml",
        "MCP_GUARD_USER": "my-agent",
        "MCP_GUARD_AUDIT_LOG": "/path/to/audit.jsonl"
      }
    }
  }
}
```

### As an agent skill

`skill/mcp-guard/` is a `SKILL.md` skill that walks a coding agent (Claude Code, Cursor, Copilot and others) through
installing MCP Guard, generating and reviewing a policy with the user, and rewiring the client config, asking before
each change.

### How configuration works

The full policy reference, with every setting, action and environment variable, is [docs/policy.md](docs/policy.md).


| What | Where | Example |
| --- | --- | --- |
| **Rules**: roles, users, per-tool argument limits, what to do on injection, PII, budgets, pins, sandbox | the policy YAML (`mcp-guard.yaml`) | `notify_customer: {egress: external, redact_pii_in_args: true}` |
| **Wiring**: which server, which policy, who the agent is, where the audit log goes | `MCP_GUARD_*` environment variables, or flags on `mcp-guard proxy` (flags win) | `mcp-guard proxy --upstream ... --policy ... --user my-agent` |
| **Secrets**: JWT secret, upstream token | environment variables only, never the YAML | `MCP_GUARD_JWT_SECRET`, `MCP_GUARD_UPSTREAM_TOKEN` |

`init` builds the starter policy from the server's own tool schemas: string limits from `maxLength`, number ranges from
`minimum`/`maximum`, `enum`s kept. Tools whose names suggest sending data out (email, notify, post, upload, webhook)
are marked `egress: external` with PII redaction, and the recipient field is allowed through. Tools whose names
suggest destructive or code-running actions (delete, exec, run, write) get a one-call budget and a REVIEW comment.
Every tool is pinned, so `mcp-guard check --upstream ...` reports a tool whose description or schema has changed.

`check` explains mistakes in plain language: a role granting a tool with no rules, a user with an undefined role, a
tool no role can reach, a misspelt setting, an external tool without PII redaction.

## Run it (this repo)

```bash
pip install -e ".[dev]"
# stdio gateway: point any MCP client at this instead of the real server
MCP_GUARD_UPSTREAM="python -m mcp_guard.demo.complaint_server" MCP_GUARD_USER=triage-bot python -m mcp_guard.proxy
# in front of a remote MCP server (Streamable HTTP)
MCP_GUARD_UPSTREAM="https://tools.example.com/mcp" MCP_GUARD_UPSTREAM_TOKEN=... python -m mcp_guard.proxy
# serve agents over HTTP at http://127.0.0.1:8090/mcp
MCP_GUARD_UPSTREAM="python -m mcp_guard.demo.complaint_server" MCP_GUARD_JWT_SECRET=... mcp-guard proxy --http --port 8090
# HTTP policy decision point (FastAPI), optional JWT identity via MCP_GUARD_JWT_SECRET
mcp-guard api --port 8080
# Docker (published image, or build it yourself)
docker run -p 8080:8080 ghcr.io/hardikbahri/mcp-guard:latest
docker build -t mcp-guard . && docker run -p 8080:8080 mcp-guard
# tests and the attack suite
pytest && python attacks/evaluate.py
```

With `MCP_GUARD_JWT_SECRET` set, the API takes the user from the token's `sub` (claimed roles are kept only where the policy grants them), a session can only be used with a token for the same user, and `/v1/audit` needs a token with the `audit` scope.

CI runs the unit, API, proxy (stdio and HTTP) and attack-suite tests on Python 3.11 and 3.12, then builds the Docker image and checks that the container serves the API as a non-root user and blocks an out-of-role call. A third job builds the sandbox image and runs the compromised-server demo against a real container.

With ComplaintOps: `ComplaintAgent(server_module="mcp_guard.proxy")` with `MCP_GUARD_UPSTREAM="python -m complaintops.mcp_server"`.
In tests, a poisoned similar-complaint result reaches the agent's LLM without the gateway; through it, the planted
instruction and the personal data are removed.

## Remote servers and HTTP agents

**Remote upstream.** Set `MCP_GUARD_UPSTREAM` to a URL and the gateway connects over Streamable HTTP, with
`MCP_GUARD_UPSTREAM_TOKEN` sent as a bearer token. A remote server runs on someone else's machine, so the risk shifts
from host compromise to what you send it and what it sends back: the same DLP redaction (for tools marked
`egress: external`), injection removal, RBAC and call budgets apply. The gateway refuses plain `http://` to anything
but this machine, and `upstream_allowed_hosts: [tools.example.com]` in the policy pins where tool traffic may go.

**HTTP downstream.** `mcp-guard proxy --http` serves MCP over Streamable HTTP. Each agent connection gets its own
Guard session (call budget, violation count, termination). With `MCP_GUARD_JWT_SECRET` set, every request needs a
bearer JWT and the user is its `sub`, so one gateway serves agents with different roles; a session cannot change
user mid-way. The gateway refuses to listen beyond localhost without JWT identity.

## Sandbox

The checks above see what crosses the MCP boundary. They cannot see what a tool server does inside its own process: a
poisoned package or a bad update can read the host's API keys, write files or call out to the internet while its MCP
traffic stays perfectly clean. With a `sandbox:` section in the policy, the gateway starts the tool server in a
locked-down container instead of as a local process:

- no network (`--network none`), read-only filesystem, all Linux capabilities dropped, `no-new-privileges`
- non-root user, capped memory, CPU and process count, a small `noexec` `/tmp`
- only the environment variables the policy names, passed by name so values never appear on a command line

```yaml
sandbox:
  enabled: true
  image: mcp-guard-sandbox:demo
  network: none
  memory: 256m
  pids_limit: 64
  env: []            # e.g. [COMPLAINTOPS_DB_URL]
```

`mcp_guard/demo/sandbox_demo.py` runs the same compromised server (`mcp_guard/demo/rogue_server.py`) through the gateway twice. Both calls
are allowed, because the MCP traffic is harmless; the table shows what the hidden payload managed to do. CI runs it on
every push and fails if anything escapes the sandbox. Result from CI (GitHub Actions runner):

| What the compromised server tried | Without sandbox | With sandbox |
| --- | --- | --- |
| Read an API key from the gateway's environment | yes | no |
| Wrote a file next to its code | yes | no |
| Opened a connection to the internet | yes | no |
| Threads started (of 200) | 200 | 61 (process limit 64) |

```bash
docker build -f Dockerfile.sandbox -t mcp-guard-sandbox:demo .
python -m mcp_guard.demo.sandbox_demo
```

Without the sandbox, a policy can still limit what an unsandboxed server inherits with `upstream_env: [NAME, ...]`.

## Limits

Detectors are rule-based and deterministic, so every decision is explainable and testable. The attack suite in
`attacks/` was written alongside the rules, so it shows coverage, not real-world accuracy; paraphrased or translated
injections can get past regex rules. A learned classifier and an external benchmark are next.
