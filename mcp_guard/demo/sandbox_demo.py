"""Sandbox demo: the same compromised tool server, run through MCP Guard twice.

    1. without the sandbox: the server runs as a local process next to the gateway
    2. with the sandbox:    the server runs in a locked-down container (policies/sandbox_demo.yaml)

In both runs the Guard sees identical, harmless MCP traffic, so it allows the call. The difference is what the server's
hidden payload could do. Needs Docker and the image:  docker build -f Dockerfile.sandbox -t mcp-guard-sandbox:demo .

    python -m mcp_guard.demo.sandbox_demo            # prints a table, writes mcp_guard/demo/sandbox_results.md
Exits 1 if anything escapes the sandboxed run.
"""
import json
import os
import sys
from pathlib import Path

import anyio
from mcp import Client, StdioServerParameters

ROOT = Path(__file__).resolve().parent.parent.parent
POLICY = ROOT / "policies" / "sandbox_demo.yaml"
ROWS = [("secret_read", "Read an API key from the environment"),
        ("file_written", "Wrote a file next to its code"),
        ("internet_reached", "Opened a connection to the internet"),
        ("threads_started", "Threads started (of 200)"),
        ("running_as_root", "Ran as root")]


def run(sandboxed: bool) -> dict:
    env = {**os.environ, "PYTHONPATH": str(ROOT), "MCP_GUARD_UPSTREAM": "python -m mcp_guard.demo.rogue_server",
           "MCP_GUARD_POLICY": str(POLICY), "MCP_GUARD_USER": "demo-bot", "MCP_GUARD_AUDIT_LOG": "",
           "MCP_GUARD_SANDBOX": "1" if sandboxed else "0",
           "HOST_API_KEY": "sk-demo-not-a-real-key"}  # a secret the gateway holds for its own use
    params = StdioServerParameters(command=sys.executable, args=["-m", "mcp_guard.proxy"], cwd=str(ROOT), env=env)

    async def go():
        async with Client(params) as c:
            r = await c.call_tool("summarize_complaint", {"text": "I was charged an overdraft fee twice."})
            assert not r.is_error, r.content[0].text
            return json.loads(r.content[0].text)["probes"]
    return anyio.run(go)


def escaped(p: dict, pids_limit: int = 64) -> list[str]:
    bad = [k for k in ("secret_read", "file_written", "internet_reached", "running_as_root") if p[k]]
    if p["threads_started"] >= pids_limit:
        bad.append("threads_started")
    return bad


def main():
    local, boxed = run(False), run(True)
    fmt = lambda v: ("yes" if v else "no") if isinstance(v, bool) else str(v)
    lines = ["# Sandbox demo results", "",
             "The same compromised tool server, called once through MCP Guard without and once with the sandbox. "
             "The Guard allowed both calls: the MCP traffic was harmless. What differs is what the hidden payload could do.",
             "", "| What the server tried | Without sandbox | With sandbox |", "| --- | --- | --- |"]
    lines += [f"| {label} | {fmt(local[k])} | {fmt(boxed[k])} |" for k, label in ROWS]
    bad = escaped(boxed)
    lines += ["", "Sandbox: " + ("**contained everything**" if not bad else f"**escaped: {', '.join(bad)}**")]
    (ROOT / "mcp_guard" / "demo" / "sandbox_results.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
