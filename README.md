# MCP Guard

[![CI](https://github.com/hardikbahri/mcp-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/hardikbahri/mcp-guard/actions/workflows/ci.yml)

Inline security gateway for AI agents and MCP tool servers. It sits between an agent and its tools and checks every
tool listing, call and result, then **allows, alerts, redacts, blocks or terminates** by policy.

```
agent  <--MCP-->  mcp-guard (policy + detectors + audit)  <--MCP-->  tool server
```

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

## Run it

```bash
pip install -e ".[dev]"
# stdio gateway: point any MCP client at this instead of the real server
MCP_GUARD_UPSTREAM="python -m demo.complaint_server" MCP_GUARD_USER=triage-bot python -m mcp_guard.proxy
# HTTP policy decision point (FastAPI), optional JWT identity via MCP_GUARD_JWT_SECRET
mcp-guard api --port 8080
# Docker
docker build -t mcp-guard . && docker run -p 8080:8080 mcp-guard
# tests and the attack suite
pytest && python attacks/evaluate.py
```

With `MCP_GUARD_JWT_SECRET` set, the API takes the user from the token's `sub` (claimed roles are kept only where the policy grants them), a session can only be used with a token for the same user, and `/v1/audit` needs a token with the `audit` scope.

CI runs the unit, API, proxy and attack-suite tests on Python 3.11 and 3.12, then builds the Docker image and checks that the container serves the API as a non-root user and blocks an out-of-role call. A third job builds the sandbox image and runs the compromised-server demo against a real container.

With ComplaintOps: `ComplaintAgent(server_module="mcp_guard.proxy")` with `MCP_GUARD_UPSTREAM="python -m complaintops.mcp_server"`.
In tests, a poisoned similar-complaint result reaches the agent's LLM without the gateway; through it, the planted
instruction and the personal data are removed.

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

`demo/sandbox_demo.py` runs the same compromised server (`demo/rogue_server.py`) through the gateway twice. Both calls
are allowed, because the MCP traffic is harmless; the table shows what the hidden payload managed to do. CI runs it on
every push and fails if anything escapes the sandbox.

```bash
docker build -f Dockerfile.sandbox -t mcp-guard-sandbox:demo .
python demo/sandbox_demo.py
```

Without the sandbox, a policy can still limit what an unsandboxed server inherits with `upstream_env: [NAME, ...]`.

## Limits

Detectors are rule-based and deterministic, so every decision is explainable and testable. The attack suite in
`attacks/` was written alongside the rules, so it shows coverage, not real-world accuracy; paraphrased or translated
injections can get past regex rules. A learned classifier and an external benchmark are next.
