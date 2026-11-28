# Policy reference (mcp-guard.yaml)

The policy is the security boundary: keep it in version control behind review, read-only for the process that runs
the agent, and validate it with `mcp-guard check` (in CI too). It is data, loaded with a safe YAML parser, so it
cannot run code. Generate a starting point with `mcp-guard init --upstream "<server>"`.

Default deny: a tool missing from `tools`, or not granted to the caller through `roles`, is hidden and blocked.

```yaml
detectors:
  injection_threshold: 3          # lower = stricter prompt-injection detection

session:
  max_calls: 50                   # calls per session before it is ended
  max_violations_before_terminate: 3

roles:                            # role -> tools it may use
  triage: [classify, search]
  sender: [notify_customer]

users:                            # who the agent acts for -> roles (over HTTP: the JWT sub)
  my-agent: [triage]

tools:
  search:
    args:                         # every argument the tool may receive; others are refused
      text: {max_length: 5000}
      k: {min: 1, max: 10}
      mode: {enum: [fast, exact]}
    allow_unknown_args: false
    on_injection_in_args: alert   # allow | alert | redact | block | terminate
    on_injection_in_result: redact
    redact_pii_in_result: true
    max_calls_per_session: 10

  notify_customer:
    egress: external              # arguments leave the company: PII redacted
    args:
      email: {max_length: 254, allow_pii: true}   # the recipient itself is allowed
      message: {max_length: 2000}
    redact_pii_in_args: true
    on_injection_in_args: block

pins:                             # tool fingerprints as reviewed (`mcp-guard pin "<server>"`)
  search: 3f2a...

sandbox:                          # optional, local servers only, needs Docker
  enabled: true
  image: my-server:latest         # image containing the server; MCP_GUARD_UPSTREAM is the command inside it
  network: none                   # or a named Docker network the server may use
  memory: 256m
  cpus: "0.5"
  pids_limit: 64
  read_only: true
  user: "65534:65534"             # never root
  env: [DATABASE_URL]             # only these variables are passed in, by name
  mounts: ["./models:/models"]    # always read-only

upstream_env: [DATABASE_URL]      # unsandboxed local server: only these variables (default: all)
upstream_allowed_hosts: [tools.example.com]   # remote server: allowed hosts (https required)
```

## Actions

| Action | Effect |
| --- | --- |
| allow | pass through |
| alert | pass through, write an alert to the audit log |
| redact | remove the offending text (injection, PII, secret), pass the rest |
| block | refuse this call; counts as a violation |
| terminate | refuse and end the session |

## Environment variables (wiring and secrets; never put secrets in the YAML)

| Variable | Meaning |
| --- | --- |
| `MCP_GUARD_UPSTREAM` | server command, or its `https://` URL (required) |
| `MCP_GUARD_POLICY` | policy path (default `./mcp-guard.yaml`) |
| `MCP_GUARD_USER` | who the agent acts for |
| `MCP_GUARD_AUDIT_LOG` | audit file (`""` disables) |
| `MCP_GUARD_UPSTREAM_TOKEN` | bearer token for a remote server |
| `MCP_GUARD_SANDBOX` | `1` / `0` forces the sandbox on / off |
| `MCP_GUARD_JWT_SECRET` | HTTP mode: require a JWT per agent |
