"""The decision engine. Every tool listing, tool call and tool result passes through here.

    guard = Guard(policy.load("policies/complaintops.yaml"))
    session = guard.open_session(user="triage-bot")
    visible = guard.visible_tools(session, tools)            # least privilege: the agent only sees what it may call
    d = guard.check_call(session, "search_similar_complaints", {"text": ..., "k": 5})
    if d.action in ("allow", "alert", "redact"): forward d.arguments upstream
    r = guard.check_result(session, "search_similar_complaints", upstream_result)
    if r.action in ("allow", "alert", "redact"): return r.result to the agent

Actions, strongest first: terminate (the session ends; every later call is refused), block (this call is refused),
redact (forwarded with sensitive or injected spans replaced), alert (forwarded unchanged, logged as an alert), allow.
"""
import re
import uuid
from collections import Counter
from dataclasses import asdict, dataclass, field
from typing import Any

from mcp_guard import detectors as det
from mcp_guard.audit import AuditLog
from mcp_guard.owasp import ASI
from mcp_guard.policy import Policy, tool_fingerprint

RANK = {"allow": 0, "alert": 1, "redact": 2, "block": 3, "terminate": 4}


@dataclass
class Finding:
    rule: str
    owasp: str
    severity: str     # low | medium | high | critical
    action: str       # what this finding alone asks for
    detail: str
    where: str = ""

    def to_dict(self):
        d = asdict(self)
        d["owasp_name"] = ASI[self.owasp]
        return d


@dataclass
class Decision:
    action: str = "allow"
    findings: list[Finding] = field(default_factory=list)
    arguments: dict | None = None
    result: Any = None
    message: str = ""

    @property
    def forwarded(self) -> bool:
        return self.action in ("allow", "alert", "redact")

    def add(self, f: Finding):
        self.findings.append(f)
        if RANK[f.action] > RANK[self.action]:
            self.action = f.action


@dataclass
class Session:
    user: str
    roles: set[str]
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    calls: Counter = field(default_factory=Counter)
    violations: int = 0
    terminated: bool = False

    @property
    def total_calls(self):
        return sum(self.calls.values())


class Guard:
    def __init__(self, policy: Policy, audit: AuditLog | None = None):
        self.policy = policy
        self.audit = audit or AuditLog(path="")

    def open_session(self, user: str, claimed_roles: list[str] | None = None) -> Session:
        return Session(user=user, roles=self.policy.roles_of(user, claimed_roles))

    # ------------------------------------------------------------------ tool listing
    def visible_tools(self, session: Session, tools: list[dict]) -> list[dict]:
        """Filter the upstream tool list: only tools this user's roles grant, whose description is clean and whose
        definition matches its pin (when pinned). Hidden tools are logged so a poisoned server shows up in the SIEM."""
        allowed = self.policy.permitted_tools(session.roles)
        out = []
        for t in tools:
            name = t["name"]
            d = Decision()
            if name not in allowed:
                continue  # not a finding: least privilege, simply not offered
            hits = det.find_injection(t.get("description") or "")
            if det.injection_score(hits) >= self.policy.injection_threshold:
                d.add(Finding("tool_description_injection", "ASI04", "high", "block",
                              f"instructions hidden in the tool description: {_kinds(hits)}", "description"))
            pin = self.policy.pins.get(name)
            if pin and pin != tool_fingerprint(name, t.get("description"), t.get("inputSchema")):
                d.add(Finding("tool_definition_changed", "ASI04", "high", "block",
                              "the tool's description or schema changed since it was pinned", "definition"))
            if d.findings:
                d.message = f"tool {name} hidden"
                self.audit.write(action="list_tools", decision=d, session=session, tool=name)
            else:
                out.append(t)
        return out

    # ------------------------------------------------------------------ tool calls
    def check_call(self, session: Session, tool: str, arguments: dict | None) -> Decision:
        args = dict(arguments or {})
        d = Decision(arguments=args)
        p = self.policy
        if session.terminated:
            d.add(Finding("session_terminated", "ASI10", "high", "terminate",
                          "this session was terminated after earlier violations"))
            return self._finish("tool_call", d, session, tool)

        tp = p.tools.get(tool)
        if tool not in p.permitted_tools(session.roles):
            why = "not in the policy" if tp is None else f"not granted to roles {sorted(session.roles) or '[none]'}"
            d.add(Finding("tool_not_permitted", "ASI03", "high", "block", f"{tool} is {why}"))
            return self._finish("tool_call", d, session, tool)

        session.calls[tool] += 1
        if session.total_calls > p.max_calls_per_session:
            d.add(Finding("session_call_budget", "ASI08", "high", "terminate",
                          f"{session.total_calls} calls exceed the session budget of {p.max_calls_per_session} (runaway loop?)"))
        if tp.max_calls_per_session and session.calls[tool] > tp.max_calls_per_session:
            d.add(Finding("tool_rate_limit", "ASI02", "medium", "block",
                          f"{tool} called {session.calls[tool]} times; the limit is {tp.max_calls_per_session}"))

        # argument contract
        for name, value in args.items():
            rule = tp.args.get(name)
            if rule is None:
                if not tp.allow_unknown_args:
                    d.add(Finding("unexpected_argument", "ASI02", "medium", "block", f"argument {name!r} is not allowed", name))
                continue
            if rule.max_length is not None and isinstance(value, str) and len(value) > rule.max_length:
                d.add(Finding("argument_too_long", "ASI02", "medium", "block",
                              f"{len(value)} characters; the limit is {rule.max_length}", name))
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                if (rule.min is not None and value < rule.min) or (rule.max is not None and value > rule.max):
                    d.add(Finding("argument_out_of_range", "ASI02", "medium", "block",
                                  f"{value} is outside [{rule.min}, {rule.max}]", name))
            if rule.enum is not None and value not in rule.enum:
                d.add(Finding("argument_not_allowed", "ASI02", "medium", "block", f"{value!r} is not one of {rule.enum}", name))

        # content of every string argument
        redact_pii = tp.redact_pii_in_args if tp.redact_pii_in_args is not None else tp.egress == "external"
        spans: dict[str, list[det.Hit]] = {}
        for path, s in det.strings_in(args):
            code = det.find_code(s)
            if code:
                d.add(Finding("code_execution_payload", "ASI05", "critical", "block",
                              f"code or command patterns: {_kinds(code)}", path))
            inj = det.find_injection(s)
            if det.injection_score(inj) >= p.injection_threshold:
                d.add(Finding("prompt_injection_in_arguments", "ASI01", "high", tp.on_injection_in_args,
                              f"score {det.injection_score(inj)}: {_kinds(inj)}", path))
                if tp.on_injection_in_args == "redact":
                    spans.setdefault(path, []).extend(h for h in inj if h.kind.startswith("injection:"))
            sens = det.find_sensitive(s)
            secrets = [h for h in sens if h.kind.startswith("secret:")]
            pii = [h for h in sens if h.kind.startswith("pii:")]
            if secrets:
                d.add(Finding("secret_in_arguments", "ASI03", "critical", "redact", f"credentials: {_kinds(secrets)}", path))
                spans.setdefault(path, []).extend(secrets)
            top = re.split(r"[.\[]", path, maxsplit=1)[0]
            if pii and redact_pii and not getattr(tp.args.get(top), "allow_pii", False):
                d.add(Finding("pii_egress", "ASI03", "medium", "redact",
                              f"personal data leaving the trust boundary: {_kinds(pii)}", path))
                spans.setdefault(path, []).extend(pii)
        if d.action == "redact":
            d.arguments = _redact_paths(args, spans)
        return self._finish("tool_call", d, session, tool)

    # ------------------------------------------------------------------ tool results
    def check_result(self, session: Session, tool: str, result: Any) -> Decision:
        """Tool output goes straight into the agent's context (and from there to the LLM provider), so it is checked
        for planted instructions (indirect prompt injection, context poisoning) and for data that must not leave."""
        d = Decision(result=result)
        tp = self.policy.tools.get(tool)
        if tp is None:  # cannot happen for calls that passed check_call, but never pass through unknown output
            d.add(Finding("result_from_unknown_tool", "ASI04", "high", "block", f"{tool} is not in the policy"))
            return self._finish("tool_result", d, session, tool)
        spans: dict[str, list[det.Hit]] = {}
        for path, s in det.strings_in(result):
            inj = det.find_injection(s)
            if det.injection_score(inj) >= self.policy.injection_threshold:
                d.add(Finding("prompt_injection_in_result", "ASI06", "high", tp.on_injection_in_result,
                              f"score {det.injection_score(inj)}: {_kinds(inj)}", path))
                if tp.on_injection_in_result == "redact":
                    spans.setdefault(path, []).extend(inj)
            sens = det.find_sensitive(s)
            secrets = [h for h in sens if h.kind.startswith("secret:")]
            pii = [h for h in sens if h.kind.startswith("pii:")]
            if secrets:
                d.add(Finding("secret_in_result", "ASI03", "critical", "redact", f"credentials: {_kinds(secrets)}", path))
                spans.setdefault(path, []).extend(secrets)
            if pii and tp.redact_pii_in_result:
                d.add(Finding("pii_in_result", "ASI03", "medium", "redact",
                              f"personal data kept out of the model context: {_kinds(pii)}", path))
                spans.setdefault(path, []).extend(pii)
        if d.action == "redact":
            d.result = _redact_paths(result, spans)
        return self._finish("tool_result", d, session, tool)

    # ------------------------------------------------------------------ bookkeeping
    def _finish(self, action: str, d: Decision, session: Session, tool: str) -> Decision:
        if d.action in ("block", "terminate") and not session.terminated:
            session.violations += 1
            if d.action == "block" and session.violations >= self.policy.max_violations_before_terminate:
                d.add(Finding("repeated_violations", "ASI10", "high", "terminate",
                              f"{session.violations} blocked actions in one session"))
        if d.action == "terminate":
            session.terminated = True
        d.message = _message(d, tool)
        self.audit.write(action=action, decision=d, session=session, tool=tool)
        return d


def _kinds(hits) -> str:
    return ", ".join(sorted({h.kind.split(":", 1)[1] for h in hits}))


def _redact_paths(obj, spans: dict[str, list]):
    """Redact only the strings (by path) that had findings, leaving every other value untouched."""
    order = iter([p for p, _ in det.strings_in(obj)])  # map_strings visits strings in the same order as strings_in

    def fn(s):
        p = next(order)
        return det.redact(s, det._merge(spans[p])) if p in spans else s

    return det.map_strings(obj, fn)


def _message(d: Decision, tool: str) -> str:
    if not d.findings:
        return "allowed"
    top = max(d.findings, key=lambda f: RANK[f.action])
    return {"terminate": f"session terminated: {top.detail}",
            "block": f"blocked call to {tool}: {top.detail} [{top.owasp}]",
            "redact": f"{tool}: sensitive or injected content redacted",
            "alert": f"{tool}: allowed with alert ({top.rule})"}.get(d.action, "allowed")
