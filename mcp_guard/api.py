"""HTTP policy decision point, for gateways that are not MCP-over-stdio (an AI gateway, an API management layer, a
developer agent's hook). The caller asks before forwarding a tool call and again before handing a result to the model.

    uvicorn mcp_guard.api:app --port 8080

Identity: when MCP_GUARD_JWT_SECRET is set, every call needs `Authorization: Bearer <JWT>` (HS256). Opening a session
makes the token's `sub` the user; roles claimed in the token are kept only where the policy grants them to that user.
Later calls on a session must carry a token for the same user, and reading the audit log needs a token whose `scope`
includes `audit`. Without the secret (local development) the user is taken from the request body and nothing is checked.
"""
import os
from pathlib import Path
from typing import Any

import jwt
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from mcp_guard import policy as policy_mod
from mcp_guard.audit import AuditLog
from mcp_guard.engine import Decision, Guard, Session

POLICY = os.environ.get("MCP_GUARD_POLICY", str(Path(__file__).resolve().parent.parent / "policies" / "complaintops.yaml"))
guard = Guard(policy_mod.load(POLICY), AuditLog())
sessions: dict[str, Session] = {}
app = FastAPI(title="MCP Guard", version="0.1.0",
              description="Security checks for AI agent tool traffic: RBAC, prompt injection, tool misuse, DLP.")


class OpenSession(BaseModel):
    user: str | None = None


class ToolList(BaseModel):
    tools: list[dict[str, Any]]


class ToolCall(BaseModel):
    tool: str
    arguments: dict[str, Any] = {}


class ToolResult(BaseModel):
    tool: str
    result: Any


def _claims(authorization: str | None) -> dict | None:
    """Decoded token, or None when JWT identity is switched off (no MCP_GUARD_JWT_SECRET)."""
    secret = os.environ.get("MCP_GUARD_JWT_SECRET")
    if not secret:
        return None
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "bearer token required")
    try:
        claims = jwt.decode(authorization.split(" ", 1)[1], secret, algorithms=["HS256"],
                            audience=os.environ.get("MCP_GUARD_JWT_AUDIENCE", "mcp-guard"))
    except jwt.PyJWTError as e:
        raise HTTPException(401, f"invalid token: {e}") from e
    if not claims.get("sub"):
        raise HTTPException(401, "token has no sub")
    return claims


def _identity(authorization: str | None, body_user: str | None) -> tuple[str, list[str] | None]:
    claims = _claims(authorization)
    if claims is None:
        if not body_user:
            raise HTTPException(400, "user is required")
        return body_user, None
    return claims["sub"], claims.get("roles")


def _session(sid: str, authorization: str | None) -> Session:
    if sid not in sessions:
        raise HTTPException(404, "unknown session")
    s = sessions[sid]
    claims = _claims(authorization)
    if claims is not None and claims["sub"] != s.user:
        raise HTTPException(403, "session belongs to another user")
    return s


def _out(d: Decision) -> dict:
    return {"action": d.action, "forward": d.forwarded, "message": d.message,
            "findings": [f.to_dict() for f in d.findings], "arguments": d.arguments, "result": d.result}


@app.get("/healthz")
def healthz():
    return {"status": "ok", "tools_in_policy": sorted(guard.policy.tools)}


@app.post("/v1/sessions")
def open_session(body: OpenSession, authorization: str | None = Header(default=None)):
    user, claimed = _identity(authorization, body.user)
    s = guard.open_session(user, claimed)
    sessions[s.id] = s
    return {"session_id": s.id, "user": s.user, "roles": sorted(s.roles),
            "permitted_tools": sorted(guard.policy.permitted_tools(s.roles))}


@app.post("/v1/sessions/{sid}/tools")
def filter_tools(sid: str, body: ToolList, authorization: str | None = Header(default=None)):
    return {"tools": guard.visible_tools(_session(sid, authorization), body.tools)}


@app.post("/v1/sessions/{sid}/check-call")
def check_call(sid: str, body: ToolCall, authorization: str | None = Header(default=None)):
    return _out(guard.check_call(_session(sid, authorization), body.tool, body.arguments))


@app.post("/v1/sessions/{sid}/check-result")
def check_result(sid: str, body: ToolResult, authorization: str | None = Header(default=None)):
    return _out(guard.check_result(_session(sid, authorization), body.tool, body.result))


@app.get("/v1/audit")
def audit(limit: int = 50, authorization: str | None = Header(default=None)):
    claims = _claims(authorization)
    if claims is not None and "audit" not in str(claims.get("scope", "")).split():
        raise HTTPException(403, "audit scope required")
    return {"events": list(guard.audit.recent)[-max(1, min(limit, 1000)):]}
