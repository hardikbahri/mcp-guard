"""Audit log: one JSON object per decision, one per line (JSON Lines).

Field names follow the Elastic Common Schema (`@timestamp`, `event.*`, `user.*`, `rule.*`), so the file can be shipped
as-is to Elastic, Splunk or Microsoft Sentinel by any log forwarder. Redacted values are never written; only the kind
of data found and where.
"""
import collections
import json
import os
import sys
import threading
from datetime import datetime, timezone

SEVERITY = {"low": 21, "medium": 47, "high": 73, "critical": 99}  # ECS risk-score style numbers


class AuditLog:
    def __init__(self, path: str | None = None, keep: int = 1000, echo_stderr: bool = False):
        self.path = path if path is not None else os.environ.get("MCP_GUARD_AUDIT_LOG", "audit.jsonl")
        self.recent = collections.deque(maxlen=keep)
        self.echo_stderr = echo_stderr
        self._lock = threading.Lock()

    def write(self, *, action: str, decision, session, tool: str | None = None) -> dict:
        findings = [f.to_dict() for f in decision.findings]
        worst = max((f["severity"] for f in findings), key=lambda s: SEVERITY[s], default=None)
        rec = {
            "@timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "event": {
                "kind": "alert" if findings else "event",
                "category": ["intrusion_detection"] if findings else ["process"],
                "action": action,
                "outcome": "success" if decision.action in ("allow", "alert", "redact") else "failure",
                "severity": SEVERITY[worst] if worst else 0,
            },
            "user": {"name": session.user, "roles": sorted(session.roles)},
            "session": {"id": session.id, "calls": session.total_calls, "violations": session.violations},
            "mcp_guard": {"decision": decision.action, "tool": tool, "message": decision.message,
                          "owasp": sorted({f["owasp"] for f in findings})},
            "rule": {"name": [f["rule"] for f in findings]},
            "findings": findings,
        }
        line = json.dumps(rec, ensure_ascii=False)
        with self._lock:
            self.recent.append(rec)
            if self.path:
                with open(self.path, "a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
            if self.echo_stderr:
                print(line, file=sys.stderr, flush=True)
        return rec
