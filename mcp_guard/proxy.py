"""Inline MCP gateway over stdio.

The agent launches this module instead of its tool server; the gateway launches the real server and sits between them,
so every tool listing, call and result passes through the Guard:

    agent  <--MCP stdio-->  mcp_guard.proxy  <--MCP stdio-->  upstream tool server

Configuration (environment variables, so any MCP client can use it without code changes):
    MCP_GUARD_UPSTREAM   command that starts the real server, e.g. "python -m complaintops.mcp_server"   (required)
    MCP_GUARD_POLICY     policy YAML                                     (default: policies/complaintops.yaml)
    MCP_GUARD_USER       who the agent acts for; roles come from the policy's user directory
    MCP_GUARD_AUDIT_LOG  JSON Lines audit file                           (default: audit.jsonl; "" to disable)

    python -m mcp_guard.proxy
"""
import json
import os
import shlex
import sys
from pathlib import Path

import anyio
import mcp_types as types
from mcp import Client, StdioServerParameters
from mcp.server.lowlevel.server import Server
from mcp.server.stdio import stdio_server

from mcp_guard import policy as policy_mod
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


def build_server(guard: Guard, session, upstream: Client) -> Server:
    async def list_tools(ctx, params):
        listed = await upstream.list_tools()
        raw = [t.model_dump(by_alias=True) for t in listed.tools]
        keep = {t["name"] for t in guard.visible_tools(session, raw)}
        return types.ListToolsResult(tools=[t for t in listed.tools if t.name in keep])

    async def call_tool(ctx, params):
        d = guard.check_call(session, params.name, params.arguments or {})
        if not d.forwarded:
            return _refusal(d.message)
        r = await upstream.call_tool(params.name, d.arguments)
        checked = guard.check_result(session, params.name, _result_payload(r))
        if not checked.forwarded:
            return _refusal(checked.message)
        return _rebuild(r, checked.result) if checked.action == "redact" else r

    return Server("mcp-guard", instructions="Security gateway in front of an MCP tool server.",
                  on_list_tools=list_tools, on_call_tool=call_tool)


async def serve(upstream_cmd: str, policy_path: str, user: str, audit_path: str | None = None):
    guard = Guard(policy_mod.load(policy_path), AuditLog(path=audit_path))
    session = guard.open_session(user)
    argv = shlex.split(upstream_cmd)
    if argv and argv[0] in ("python", "python3"):
        argv[0] = sys.executable  # the upstream server runs in the same environment as the gateway
    params = StdioServerParameters(command=argv[0], args=argv[1:], env={**os.environ})
    async with Client(params) as upstream:
        server = build_server(guard, session, upstream)
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())


def main():
    upstream = os.environ.get("MCP_GUARD_UPSTREAM")
    if not upstream:
        sys.exit("set MCP_GUARD_UPSTREAM to the command that starts the real MCP server")
    anyio.run(serve, upstream, os.environ.get("MCP_GUARD_POLICY", str(DEFAULT_POLICY)),
              os.environ.get("MCP_GUARD_USER", "anonymous"), os.environ.get("MCP_GUARD_AUDIT_LOG"))


if __name__ == "__main__":
    main()
