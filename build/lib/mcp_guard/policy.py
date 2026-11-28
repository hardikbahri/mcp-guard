"""Security policy: who may call which tool, with which arguments, and what happens when a detector fires.

Loaded from YAML (see policies/complaintops.yaml). Anything not explicitly allowed is denied: a tool missing from the
policy is hidden and blocked, and a user missing from `users` gets no tools.
"""
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

import yaml

ACTIONS = ("allow", "alert", "redact", "block", "terminate")


@dataclass
class ArgRule:
    max_length: int | None = None
    min: float | None = None
    max: float | None = None
    enum: list | None = None
    allow_pii: bool = False      # e.g. the recipient address of an email tool


@dataclass
class ToolPolicy:
    name: str
    args: dict[str, ArgRule] = field(default_factory=dict)
    allow_unknown_args: bool = False
    egress: str = "internal"                 # "external" = arguments leave the trust boundary, so PII is redacted
    on_injection_in_args: str = "block"      # untrusted text the tool is meant to receive can be set to "alert"
    on_injection_in_result: str = "redact"
    redact_pii_in_args: bool | None = None   # None = follow `egress`
    redact_pii_in_result: bool = True
    max_calls_per_session: int | None = None


@dataclass
class Policy:
    roles: dict[str, set[str]]
    users: dict[str, set[str]]
    tools: dict[str, ToolPolicy]
    injection_threshold: int = 3
    max_calls_per_session: int = 50
    max_violations_before_terminate: int = 3
    pins: dict[str, str] = field(default_factory=dict)
    sandbox: dict | None = None              # raw `sandbox:` section, see mcp_guard/sandbox.py
    upstream_env: list[str] | None = None    # env vars an unsandboxed server may see; None = inherit everything
    upstream_allowed_hosts: list[str] | None = None  # hosts a remote (HTTP) upstream may be on; None = any https host

    def roles_of(self, user: str, claimed: list[str] | None = None) -> set[str]:
        """Roles come from the policy's user directory. Roles a caller merely claims are honoured only if the policy
        grants them to that user, so an agent cannot raise its own privileges by asserting a role."""
        granted = self.users.get(user, set())
        return granted & set(claimed) if claimed else granted

    def permitted_tools(self, roles: set[str]) -> set[str]:
        out = set()
        for r in roles:
            out |= self.roles.get(r, set())
        return out & set(self.tools)


def load(path: str | Path) -> Policy:
    raw = yaml.safe_load(Path(path).read_text())
    tools = {}
    for name, t in (raw.get("tools") or {}).items():
        t = dict(t or {})
        args = {a: ArgRule(**(r or {})) for a, r in (t.pop("args", None) or {}).items()}
        tools[name] = ToolPolicy(name=name, args=args, **t)
        for key in ("on_injection_in_args", "on_injection_in_result"):
            if getattr(tools[name], key) not in ACTIONS:
                raise ValueError(f"{name}.{key} must be one of {ACTIONS}")
    s = raw.get("session") or {}
    return Policy(
        roles={r: set(v or []) for r, v in (raw.get("roles") or {}).items()},
        users={u: set(v or []) for u, v in (raw.get("users") or {}).items()},
        tools=tools,
        injection_threshold=(raw.get("detectors") or {}).get("injection_threshold", 3),
        max_calls_per_session=s.get("max_calls", 50),
        max_violations_before_terminate=s.get("max_violations_before_terminate", 3),
        pins=raw.get("pins") or {},
        sandbox=raw.get("sandbox"),
        upstream_env=raw.get("upstream_env"),
        upstream_allowed_hosts=raw.get("upstream_allowed_hosts"),
    )


def tool_fingerprint(name: str, description: str | None, input_schema: dict | None) -> str:
    """Hash of what the model sees about a tool. A changed hash means the server changed the tool after it was reviewed
    (a "rug pull"), so the pinned version no longer applies."""
    blob = json.dumps({"name": name, "description": description or "", "schema": input_schema or {}}, sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()


TOP_LEVEL = {"detectors", "session", "roles", "users", "tools", "pins", "sandbox", "upstream_env",
             "upstream_allowed_hosts"}


def default_path() -> Path:
    """MCP_GUARD_POLICY, else ./mcp-guard.yaml (what `mcp-guard init` writes), else the bundled ComplaintOps policy."""
    import os
    if os.environ.get("MCP_GUARD_POLICY"):
        return Path(os.environ["MCP_GUARD_POLICY"])
    local = Path.cwd() / "mcp-guard.yaml"
    if local.exists():
        return local
    return Path(__file__).resolve().parent.parent / "policies" / "complaintops.yaml"


def check(path: str | Path) -> tuple[list[str], list[str]]:
    """Validate a policy file. Returns (errors, warnings) in plain language; errors mean the gateway would refuse it
    or behave differently from what the file seems to say."""
    errors, warnings = [], []
    try:
        raw = yaml.safe_load(Path(path).read_text()) or {}
    except FileNotFoundError:
        return [f"{path}: file not found (create one with `mcp-guard init`)"], []
    except yaml.YAMLError as e:
        return [f"{path}: not valid YAML: {e}"], []
    if not isinstance(raw, dict):
        return [f"{path}: the top level must be a mapping (detectors:, roles:, users:, tools: ...)"], []
    for k in raw:
        if k not in TOP_LEVEL:
            warnings.append(f"unknown top-level key '{k}' is ignored (known: {', '.join(sorted(TOP_LEVEL))})")
    try:
        pol = load(path)
    except TypeError as e:
        bad = str(e).split("got an unexpected keyword argument")[-1].strip(" '")
        return errors + [f"unknown setting '{bad}' (tool settings: {', '.join(ToolPolicy.__dataclass_fields__)}; "
                         f"argument settings: {', '.join(ArgRule.__dataclass_fields__)})"], warnings
    except (ValueError, AttributeError) as e:
        return errors + [str(e)], warnings

    granted = set()
    for role, tools in pol.roles.items():
        for t in sorted(tools - set(pol.tools)):
            errors.append(f"role '{role}' grants '{t}', which has no entry under tools: it will stay blocked")
        granted |= tools
    for user, roles in pol.users.items():
        for r in sorted(roles - set(pol.roles)):
            errors.append(f"user '{user}' has role '{r}', which is not defined under roles")
    if not pol.users:
        warnings.append("no users: every agent will get no tools (add one under users:)")
    for name, t in pol.tools.items():
        if name not in granted:
            warnings.append(f"tool '{name}' is not granted to any role, so no agent can use it")
        if t.egress == "external" and t.redact_pii_in_args is False:
            warnings.append(f"tool '{name}' sends data out (egress: external) but redact_pii_in_args is false")
        if t.on_injection_in_result == "allow":
            warnings.append(f"tool '{name}' passes prompt injections in its results to the model (on_injection_in_result: allow)")
        if t.allow_unknown_args:
            warnings.append(f"tool '{name}' accepts arguments the policy does not list (allow_unknown_args: true)")
        if pol.pins and name not in pol.pins:
            warnings.append(f"tool '{name}' has no pin, so a change to it would go unnoticed (run `mcp-guard pin`)")
    if pol.sandbox:
        from mcp_guard import sandbox
        try:
            sandbox.from_config(pol.sandbox)
        except (ValueError, TypeError) as e:
            errors.append(f"sandbox: {e}")
    return errors, warnings
