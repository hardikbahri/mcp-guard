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
    )


def tool_fingerprint(name: str, description: str | None, input_schema: dict | None) -> str:
    """Hash of what the model sees about a tool. A changed hash means the server changed the tool after it was reviewed
    (a "rug pull"), so the pinned version no longer applies."""
    blob = json.dumps({"name": name, "description": description or "", "schema": input_schema or {}}, sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()
