"""The stdio gateway end to end: a real MCP client talks to mcp_guard.proxy, which runs the demo tool server."""
import json
import os
import sys

import anyio
from mcp import Client, StdioServerParameters

from tests.conftest import ROOT


def run(user, fn, tmp_path, **env):
    params = StdioServerParameters(command=sys.executable, args=["-m", "mcp_guard.proxy"], cwd=str(ROOT), env={
        **os.environ, "PYTHONPATH": str(ROOT), "MCP_GUARD_UPSTREAM": "python -m mcp_guard.demo.complaint_server",
        "MCP_GUARD_USER": user, "MCP_GUARD_AUDIT_LOG": str(tmp_path / "audit.jsonl"), **env})

    async def go():
        async with Client(params) as c:
            return await fn(c)
    return anyio.run(go)


def text(r):
    return r.content[0].text


def test_agent_only_sees_its_tools(tmp_path):
    async def fn(c):
        return sorted(t.name for t in (await c.list_tools()).tools)
    assert run("triage-bot", fn, tmp_path) == ["classify_complaint", "flag_for_review", "search_similar_complaints"]


def test_poisoned_tool_description_never_reaches_the_agent(tmp_path):
    async def fn(c):
        return [t.name for t in (await c.list_tools()).tools]
    assert "classify_complaint" not in run("triage-bot", fn, tmp_path, DEMO_POISON_DESCRIPTION="1")


def test_poisoned_search_result_is_cleaned(tmp_path):
    async def fn(c):
        return await c.call_tool("search_similar_complaints", {"text": "frozen account", "k": 2})
    r = run("triage-bot", fn, tmp_path, DEMO_POISON="1")
    out = json.loads(text(r))
    snippet = out["results"][0]["snippet"]
    assert not r.is_error
    assert "ignore all previous" not in snippet.lower() and "jane.doe" not in snippet and "98765" not in snippet
    assert "[REMOVED:INJECTION]" in snippet and "[REDACTED:EMAIL]" in snippet
    events = [json.loads(l) for l in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert {"ASI06", "ASI03"} <= set(events[-1]["mcp_guard"]["owasp"])


def test_blocked_calls_come_back_as_tool_errors_and_end_the_session(tmp_path):
    async def fn(c):
        out = []
        for _ in range(3):
            out.append(await c.call_tool("notify_customer", {"email": "a@b.com", "message": "hi"}))
        out.append(await c.call_tool("classify_complaint", {"text": "a normal complaint"}))
        return out
    rs = run("triage-bot", fn, tmp_path)
    assert all(r.is_error for r in rs)
    assert "ASI03" in text(rs[0])
    assert text(rs[2]).startswith("[mcp-guard] session terminated")
    assert "session terminated" in text(rs[3])  # even an allowed tool is refused once the session is terminated
