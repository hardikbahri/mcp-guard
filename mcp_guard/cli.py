"""Command line: `mcp-guard pin` prints the fingerprints to paste under `pins:` in the policy; `mcp-guard proxy` and
`mcp-guard api` start the two gateways.

    mcp-guard pin "python -m complaintops.mcp_server"
"""
import argparse
import os
import shlex
import sys

import anyio
from mcp import Client, StdioServerParameters

from mcp_guard.policy import tool_fingerprint


async def _pin(cmd: str):
    argv = shlex.split(cmd)
    if argv[0] in ("python", "python3"):
        argv[0] = sys.executable
    async with Client(StdioServerParameters(command=argv[0], args=argv[1:], env={**os.environ})) as c:
        for t in (await c.list_tools()).tools:
            print(f"  {t.name}: {tool_fingerprint(t.name, t.description, t.input_schema)}")


def main():
    p = argparse.ArgumentParser(prog="mcp-guard")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("pin", help="fingerprint every tool of an MCP server").add_argument("upstream")
    sub.add_parser("proxy", help="run the stdio gateway (configured by MCP_GUARD_* variables)")
    api = sub.add_parser("api", help="run the HTTP policy decision point")
    api.add_argument("--port", type=int, default=8080)
    a = p.parse_args()
    if a.cmd == "pin":
        print("pins:")
        anyio.run(_pin, a.upstream)
    elif a.cmd == "proxy":
        from mcp_guard.proxy import main as proxy_main
        proxy_main()
    else:
        import uvicorn
        uvicorn.run("mcp_guard.api:app", host="0.0.0.0", port=a.port)


if __name__ == "__main__":
    main()
