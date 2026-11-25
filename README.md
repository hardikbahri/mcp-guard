# MCP Guard

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

With ComplaintOps: `ComplaintAgent(server_module="mcp_guard.proxy")` with `MCP_GUARD_UPSTREAM="python -m complaintops.mcp_server"`.
In tests, a poisoned similar-complaint result reaches the agent's LLM without the gateway; through it, the planted
instruction and the personal data are removed.

## Limits

Detectors are rule-based and deterministic, so every decision is explainable and testable. The attack suite in
`attacks/` was written alongside the rules, so it shows coverage, not real-world accuracy; paraphrased or translated
injections can get past regex rules. A learned classifier and an external benchmark are next.
