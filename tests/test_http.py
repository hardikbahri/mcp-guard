"""Streamable HTTP on both sides of the gateway: a remote upstream server, and agents connecting over HTTP."""
import json
import os
import socket
import subprocess
import sys
import time
from contextlib import contextmanager

import anyio
import jwt
import pytest
from mcp import Client, StdioServerParameters
from mcp.client.streamable_http import streamable_http_client
from mcp.shared._httpx_utils import create_mcp_http_client

from mcp_guard import policy
from mcp_guard.proxy import check_upstream_url, connect_upstream
from tests.conftest import POLICY, ROOT

SECRET = "test-secret-at-least-32-bytes-long!!"


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@contextmanager
def process(args, port, **env):
    p = subprocess.Popen([sys.executable, *args], cwd=str(ROOT), stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                         env={**os.environ, "PYTHONPATH": str(ROOT), **env})
    try:
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                if p.poll() is not None:
                    raise RuntimeError(p.stderr.read().decode())
                time.sleep(0.1)
        else:
            raise RuntimeError("process did not start listening")
        yield f"http://127.0.0.1:{port}/mcp"
    finally:
        p.terminate()
        p.wait(timeout=10)


def remote_server(**env):
    port = free_port()
    return process(["-m", "demo.complaint_server"], port, DEMO_HTTP_PORT=str(port), **env)


def http_gateway(upstream, **env):
    port = free_port()
    return process(["-m", "mcp_guard.proxy", "--http", "--port", str(port)], port, MCP_GUARD_UPSTREAM=upstream,
                   MCP_GUARD_AUDIT_LOG="", **env)


def stdio_gateway(upstream, user, tmp_path):
    return StdioServerParameters(command=sys.executable, args=["-m", "mcp_guard.proxy"], cwd=str(ROOT), env={
        **os.environ, "PYTHONPATH": str(ROOT), "MCP_GUARD_UPSTREAM": upstream, "MCP_GUARD_USER": user,
        "MCP_GUARD_AUDIT_LOG": str(tmp_path / "audit.jsonl")})


def with_client(target, fn):
    async def go():
        async with Client(target) as c:
            return await fn(c)
    return anyio.run(go)


def http_target(url, sub=None):
    headers = {}
    if sub:
        token = jwt.encode({"sub": sub, "aud": "mcp-guard", "exp": int(time.time()) + 300}, SECRET, "HS256")
        headers["Authorization"] = f"Bearer {token}"
    return streamable_http_client(url, http_client=create_mcp_http_client(headers=headers))


async def tool_names(c):
    return sorted(t.name for t in (await c.list_tools()).tools)


# ----------------------------------------------------------------- remote upstream

def test_gateway_in_front_of_a_remote_server(tmp_path):
    with remote_server(DEMO_POISON="1") as url:
        async def fn(c):
            names = await tool_names(c)
            r = await c.call_tool("search_similar_complaints", {"text": "frozen account", "k": 2})
            blocked = await c.call_tool("notify_customer", {"email": "a@b.com", "message": "hi"})
            return names, r, blocked
        names, r, blocked = with_client(stdio_gateway(url, "triage-bot", tmp_path), fn)
    assert names == ["classify_complaint", "flag_for_review", "search_similar_complaints"]
    snippet = json.loads(r.content[0].text)["results"][0]["snippet"]
    assert "ignore all previous" not in snippet.lower() and "jane.doe" not in snippet
    assert "[REMOVED:INJECTION]" in snippet
    assert blocked.is_error and "[mcp-guard]" in blocked.content[0].text


# ----------------------------------------------------------------- agents over HTTP

def test_agent_connects_over_http():
    with http_gateway("python -m demo.complaint_server", MCP_GUARD_USER="dashboard") as url:
        async def fn(c):
            names = await tool_names(c)
            ok = await c.call_tool("classify_complaint", {"text": "The collector keeps calling me."})
            blocked = await c.call_tool("flag_for_review", {"text": "x", "reason": "y"})
            return names, ok, blocked
        names, ok, blocked = with_client(url, fn)
    assert names == ["classify_complaint", "search_similar_complaints"]
    assert not ok.is_error and json.loads(ok.content[0].text)["confidence"] == 0.91
    assert blocked.is_error


def test_http_to_http():
    with remote_server() as up, http_gateway(up, MCP_GUARD_USER="triage-bot") as url:
        names = with_client(url, tool_names)
    assert names == ["classify_complaint", "flag_for_review", "search_similar_complaints"]


def test_jwt_decides_who_the_agent_is():
    with http_gateway("python -m demo.complaint_server", MCP_GUARD_JWT_SECRET=SECRET, MCP_GUARD_USER="triage-bot") as url:
        dashboard = with_client(http_target(url, "dashboard"), tool_names)
        triage = with_client(http_target(url, "triage-bot"), tool_names)
        with pytest.raises(Exception):
            with_client(http_target(url), tool_names)  # no token: refused
    assert dashboard == ["classify_complaint", "search_similar_complaints"]
    assert triage == ["classify_complaint", "flag_for_review", "search_similar_complaints"]


# ----------------------------------------------------------------- upstream URL rules

def test_upstream_url_rules(monkeypatch):
    pol = policy.load(POLICY)
    assert check_upstream_url("https://tools.example.com/mcp", pol) == "tools.example.com"
    assert check_upstream_url("http://127.0.0.1:9000/mcp", pol) == "127.0.0.1"
    with pytest.raises(ValueError, match="plain http"):
        check_upstream_url("http://tools.example.com/mcp", pol)
    monkeypatch.setenv("MCP_GUARD_ALLOW_INSECURE", "1")
    assert check_upstream_url("http://tools.example.com/mcp", pol)
    pol.upstream_allowed_hosts = ["tools.example.com"]
    with pytest.raises(ValueError, match="upstream_allowed_hosts"):
        check_upstream_url("https://evil.example.net/mcp", pol)


def test_sandbox_cannot_wrap_a_remote_server():
    pol = policy.load(ROOT / "policies" / "sandbox_demo.yaml")
    with pytest.raises(ValueError, match="remote upstream"):
        connect_upstream("https://tools.example.com/mcp", pol)


def test_refuses_to_listen_publicly_without_auth(monkeypatch):
    from mcp_guard.proxy import http_app
    monkeypatch.delenv("MCP_GUARD_JWT_SECRET", raising=False)
    with pytest.raises(ValueError, match="without MCP_GUARD_JWT_SECRET"):
        http_app("python -m demo.complaint_server", str(POLICY), "triage-bot", "", host="0.0.0.0")
