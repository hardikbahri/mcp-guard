"""Inline MCP gateway.

The agent connects to the gateway instead of its tool server; the gateway connects to the real server and sits between
them, so every tool listing, call and result passes through the Guard:

    agent  <--MCP-->  mcp_guard.proxy  <--MCP-->  upstream tool server

Either side can be stdio or Streamable HTTP:

    downstream (agent side)   stdio (default): the agent launches `python -m mcp_guard.proxy`
                              HTTP: `mcp-guard proxy --http --port 8090`, agents connect to http://host:8090/mcp
    upstream (server side)    a command: the gateway launches it (optionally inside the sandbox)
                              a URL: the gateway connects to a remote MCP server over Streamable HTTP

Configuration (environment variables, so any MCP client can use it without code changes):
    MCP_GUARD_UPSTREAM          command that starts the real server, e.g. "python -m complaintops.mcp_server",
                                or the URL of a remote one, e.g. "https://tools.example.com/mcp"     (required)
    MCP_GUARD_UPSTREAM_TOKEN    bearer token sent to a remote upstream (optional)
    MCP_GUARD_POLICY            policy YAML                                 (default: policies/complaintops.yaml)
    MCP_GUARD_USER              who the agent acts for when no token identifies it
    MCP_GUARD_AUDIT_LOG         JSON Lines audit file                       (default: audit.jsonl; "" to disable)
    MCP_GUARD_SANDBOX           "1" forces the policy's sandbox on, "0" forces it off (local upstreams only)
    MCP_GUARD_JWT_SECRET        HTTP mode: require a bearer JWT from each agent; its `sub` is the user
    MCP_GUARD_ALLOW_INSECURE    "1" allows plain http:// to a non-local upstream (testing only)

With a `sandbox:` section in the policy, a local upstream runs inside a locked-down container (mcp_guard/sandbox.py).
A remote upstream can be pinned with `upstream_allowed_hosts:` in the policy.

    python -m mcp_guard.proxy                      # stdio
    python -m mcp_guard.proxy --http --port 8090   # HTTP
"""
import argparse
import ipaddress
import json
import os
import shlex
import sys
import weakref
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlsplit

import anyio
import mcp_types as types
from mcp import Client, StdioServerParameters
from mcp.client.streamable_http import streamable_http_client
from mcp.shared._httpx_utils import create_mcp_http_client
from mcp.server.lowlevel.server import Server
from mcp.server.stdio import stdio_server

from mcp_guard import identity
from mcp_guard import policy as policy_mod
from mcp_guard import sandbox as sandbox_mod
from mcp_guard.audit import AuditLog
from mcp_guard.engine import Guard

DEFAULT_POLICY = Path(__file__).resolve().parent.parent / "policies" / "complaintops.yaml"


def _result_payload(r: types.CallToolResult):
    """What the agent will read from a tool result: structured content if present, otherwise the text blocks."""
    if r.structured_content is not None:
        return {"structured": r.structured_content}
    blocks = []
    for c in r.content:
        if not isinstance(c, types.TextContent):
            blocks.append(None)
            continue
        try:  # JSON text is checked value by value, so a redaction can never break the JSON
            blocks.append({"json": json.loads(c.text)})
        except ValueError:
            blocks.append(c.text)
    return {"content": blocks}


def _rebuild(r: types.CallToolResult, payload) -> types.CallToolResult:
    if "structured" in payload:
        structured = payload["structured"]
        content = [types.TextContent(type="text", text=json.dumps(structured, indent=2))]
        return types.CallToolResult(content=content, structured_content=structured, is_error=r.is_error)
    content = []
    for c, b in zip(r.content, payload["content"]):
        if b is None:
            content.append(c)
        else:
            text = json.dumps(b["json"], indent=2) if isinstance(b, dict) else b
            content.append(types.TextContent(type="text", text=text))
    return types.CallToolResult(content=content, is_error=r.is_error)


def _refusal(message: str) -> types.CallToolResult:
    return types.CallToolResult(content=[types.TextContent(type="text", text=f"[mcp-guard] {message}")], is_error=True)


def build_server(guard: Guard, session_for, upstream_for, lifespan=None) -> Server:
    """The gateway's MCP server. `session_for(ctx)` returns the Guard session of the calling agent and
    `upstream_for(ctx)` the connected upstream Client, so the same handlers serve stdio and HTTP."""

    async def list_tools(ctx, params):
        session = session_for(ctx)
        listed = await upstream_for(ctx).list_tools()
        raw = [t.model_dump(by_alias=True) for t in listed.tools]
        keep = {t["name"] for t in guard.visible_tools(session, raw)}
        return types.ListToolsResult(tools=[t for t in listed.tools if t.name in keep])

    async def call_tool(ctx, params):
        session = session_for(ctx)
        d = guard.check_call(session, params.name, params.arguments or {})
        if not d.forwarded:
            return _refusal(d.message)
        r = await upstream_for(ctx).call_tool(params.name, d.arguments)
        checked = guard.check_result(session, params.name, _result_payload(r))
        if not checked.forwarded:
            return _refusal(checked.message)
        return _rebuild(r, checked.result) if checked.action == "redact" else r

    kw = {"lifespan": lifespan} if lifespan else {}
    return Server("mcp-guard", instructions="Security gateway in front of an MCP tool server.",
                  on_list_tools=list_tools, on_call_tool=call_tool, **kw)


def _is_local(host: str) -> bool:
    if host in ("localhost",):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def check_upstream_url(url: str, pol) -> str:
    """A remote upstream must use https (plain http only to this machine, or with MCP_GUARD_ALLOW_INSECURE=1), and
    when the policy lists `upstream_allowed_hosts` its host must be one of them. Returns the host."""
    u = urlsplit(url)
    host = u.hostname or ""
    if u.scheme not in ("http", "https") or not host:
        raise ValueError(f"upstream URL {url!r} must be http(s)://host/...")
    if u.scheme == "http" and not _is_local(host) and os.environ.get("MCP_GUARD_ALLOW_INSECURE") != "1":
        raise ValueError(f"refusing plain http to {host}: tool traffic would travel unencrypted; use https")
    allowed = pol.upstream_allowed_hosts
    if allowed is not None and host not in allowed:
        raise ValueError(f"upstream host {host!r} is not in the policy's upstream_allowed_hosts {allowed}")
    return host


def connect_upstream(upstream: str, pol, force_sandbox: str | None = None):
    """What to hand to `Client(...)`: a Streamable HTTP transport for a URL, stdio parameters for a command."""
    if upstream.startswith(("http://", "https://")):
        policy_sandbox = bool(pol.sandbox) and pol.sandbox.get("enabled", True)
        if force_sandbox == "1" or (policy_sandbox and force_sandbox != "0"):
            raise ValueError("the sandbox runs local servers; a remote upstream runs on someone else's machine")
        check_upstream_url(upstream, pol)
        headers = {}
        token = os.environ.get("MCP_GUARD_UPSTREAM_TOKEN")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return streamable_http_client(upstream, http_client=create_mcp_http_client(headers=headers))
    return upstream_params(upstream, pol, force_sandbox)


def upstream_params(upstream_cmd: str, pol, force_sandbox: str | None = None) -> StdioServerParameters:
    """How to start the real server: inside the sandbox when the policy (or MCP_GUARD_SANDBOX=1) says so, otherwise
    as a local process that sees only the environment the policy allows."""
    argv = shlex.split(upstream_cmd)
    raw = dict(pol.sandbox or {})
    if force_sandbox == "1":
        raw["enabled"] = True
    elif force_sandbox == "0":
        raw = {}
    sb = sandbox_mod.from_config(raw)
    if sb is not None:
        if not sb.available():
            raise RuntimeError(f"sandbox is enabled but '{sb.runtime}' is not installed")
        cmd = sb.command(argv)
        return StdioServerParameters(command=cmd[0], args=cmd[1:], env=sb.client_env())
    if argv and argv[0] in ("python", "python3"):
        argv[0] = sys.executable  # the upstream server runs in the same environment as the gateway
    return StdioServerParameters(command=argv[0], args=argv[1:], env=sandbox_mod.upstream_env(pol.upstream_env))


async def serve(upstream_cmd: str, policy_path: str, user: str, audit_path: str | None = None):
    """stdio mode: one agent, one Guard session for the life of the process."""
    pol = policy_mod.load(policy_path)
    guard = Guard(pol, AuditLog(path=audit_path))
    session = guard.open_session(user)
    async with Client(connect_upstream(upstream_cmd, pol, os.environ.get("MCP_GUARD_SANDBOX"))) as upstream:
        server = build_server(guard, lambda ctx: session, lambda ctx: upstream)
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())


class _Sessions:
    """HTTP mode: one Guard session per MCP session, bound to the user who opened it."""

    def __init__(self, guard: Guard, default_user: str):
        self.guard, self.default_user = guard, default_user
        self._by_conn = weakref.WeakKeyDictionary()

    def __call__(self, ctx):
        req = ctx.request
        auth = req.headers.get("authorization") if req is not None and hasattr(req, "headers") else None
        try:
            c = identity.claims(auth)
        except identity.AuthError as e:
            raise PermissionError(str(e)) from e
        user, claimed = (c["sub"], c.get("roles")) if c else (self.default_user, None)
        s = self._by_conn.get(ctx.session)
        if s is None:
            s = self.guard.open_session(user, claimed)
            self._by_conn[ctx.session] = s
        elif s.user != user:  # a session cannot change hands mid-way
            raise PermissionError("this MCP session belongs to another user")
        return s


def http_app(upstream: str, policy_path: str, user: str, audit_path: str | None = None, host: str = "127.0.0.1",
             path: str = "/mcp"):
    """HTTP mode: a Streamable HTTP MCP endpoint at `path`. The upstream connection opens with the app and is shared
    by all agent sessions; each agent session gets its own Guard session (call budgets, violations, termination)."""
    if not _is_local(host) and not identity.enabled() and os.environ.get("MCP_GUARD_ALLOW_UNAUTHENTICATED") != "1":
        raise ValueError(f"refusing to listen on {host} without MCP_GUARD_JWT_SECRET: anyone on the network could use "
                         "the tools (set MCP_GUARD_ALLOW_UNAUTHENTICATED=1 to override)")
    pol = policy_mod.load(policy_path)
    guard = Guard(pol, AuditLog(path=audit_path))
    target = connect_upstream(upstream, pol, os.environ.get("MCP_GUARD_SANDBOX"))

    @asynccontextmanager
    async def lifespan(server):
        async with Client(target) as up:
            yield {"upstream": up}

    server = build_server(guard, _Sessions(guard, user), lambda ctx: ctx.lifespan_context["upstream"], lifespan)
    return server.streamable_http_app(streamable_http_path=path, host=host)


def main(argv: list[str] | None = None):
    ap = argparse.ArgumentParser(prog="mcp_guard.proxy", description="MCP security gateway")
    ap.add_argument("--http", action="store_true", help="serve agents over Streamable HTTP instead of stdio")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8090)
    ap.add_argument("--path", default="/mcp")
    a = ap.parse_args(argv)
    upstream = os.environ.get("MCP_GUARD_UPSTREAM")
    if not upstream:
        sys.exit("set MCP_GUARD_UPSTREAM to the command that starts the real MCP server, or its URL")
    policy_path = str(policy_mod.default_path())
    if not Path(policy_path).exists():
        sys.exit(f"no policy at {policy_path}: create one with `mcp-guard init --upstream ...` or set MCP_GUARD_POLICY")
    user = os.environ.get("MCP_GUARD_USER", "anonymous")
    audit = os.environ.get("MCP_GUARD_AUDIT_LOG")
    if a.http:
        import uvicorn
        uvicorn.run(http_app(upstream, policy_path, user, audit, a.host, a.path), host=a.host, port=a.port,
                    log_level="warning")
    else:
        anyio.run(serve, upstream, policy_path, user, audit)


if __name__ == "__main__":
    main()
