"""Command line.

    mcp-guard init  --upstream "python -m my_server" [--exclude a,b]   write mcp-guard.yaml, print client config
    mcp-guard check [mcp-guard.yaml] [--upstream ...]     validate a policy (and compare its pins with the live server)
    mcp-guard pin   "python -m my_server"                 print tool fingerprints for the policy's `pins:`
    mcp-guard proxy [--upstream ...] [--policy ...] [--user ...] [--http --port 8090]   run the gateway
    mcp-guard api   [--port 8080]                         run the REST policy decision point

Every proxy setting can also come from MCP_GUARD_* environment variables (flags win).
"""
import argparse
import os
import sys
from pathlib import Path

import anyio


def _discover(upstream: str) -> list[dict]:
    from mcp_guard.init import discover
    return anyio.run(discover, upstream)


def cmd_init(a) -> int:
    from mcp_guard.init import build_policy, client_snippet
    out = Path(a.output)
    if out.exists() and not a.force:
        print(f"{out} already exists; use --force to overwrite", file=sys.stderr)
        return 1
    tools = _discover(a.upstream)
    if not tools:
        print("the server listed no tools", file=sys.stderr)
        return 1
    exclude = [x.strip() for x in (a.exclude or "").split(",") if x.strip()]
    try:
        text = build_policy(tools, a.role, a.user, exclude)
    except ValueError as e:
        print(e, file=sys.stderr)
        return 1
    out.write_text(text)
    tools = [t for t in tools if t["name"] not in exclude]
    print(f"wrote {out} with {len(tools)} tools: {', '.join(t['name'] for t in tools)}"
          + (f" (excluded: {', '.join(exclude)})" if exclude else "") + "\n")
    print("Review it (roles, limits, the REVIEW comments), then check it:\n")
    print(f"    mcp-guard check {out}\n")
    print("Point your MCP client at the gateway instead of the server, e.g. in Claude Desktop or Cursor:\n")
    print(client_snippet(a.upstream, out, a.user))
    return 0


def cmd_check(a) -> int:
    from mcp_guard import policy
    path = Path(a.policy) if a.policy else policy.default_path()
    errors, warnings = policy.check(path)
    if not errors and a.upstream:
        pol = policy.load(path)
        live = {t["name"]: t for t in _discover(a.upstream)}
        for name in sorted(set(live) - set(pol.tools)):
            warnings.append(f"server offers '{name}', which the policy does not list: it will be hidden and blocked")
        for name in sorted(set(pol.tools) - set(live)):
            warnings.append(f"policy lists '{name}', which the server does not offer")
        for name, pin in pol.pins.items():
            t = live.get(name)
            if t and policy.tool_fingerprint(name, t.get("description"), t.get("inputSchema")) != pin:
                errors.append(f"'{name}' changed on the server since it was pinned: it will be hidden (ASI04). "
                              "Review the change, then re-pin with `mcp-guard pin`")
    for e in errors:
        print(f"error:   {e}")
    for w in warnings:
        print(f"warning: {w}")
    print(f"{path}: {len(errors)} error(s), {len(warnings)} warning(s)")
    return 1 if errors else 0


def cmd_pin(a) -> int:
    from mcp_guard.policy import tool_fingerprint
    print("pins:")
    for t in _discover(a.upstream):
        print(f"  {t['name']}: {tool_fingerprint(t['name'], t.get('description'), t.get('inputSchema'))}")
    return 0


def cmd_proxy(a) -> int:
    for flag, var in (("upstream", "MCP_GUARD_UPSTREAM"), ("policy", "MCP_GUARD_POLICY"), ("user", "MCP_GUARD_USER"),
                      ("audit_log", "MCP_GUARD_AUDIT_LOG")):
        if getattr(a, flag) is not None:
            os.environ[var] = getattr(a, flag)
    from mcp_guard.proxy import main as proxy_main
    proxy_main((["--http"] if a.http else []) + ["--host", a.host, "--port", str(a.port), "--path", a.path])
    return 0


def cmd_api(a) -> int:
    import uvicorn
    uvicorn.run("mcp_guard.api:app", host=a.host, port=a.port)
    return 0


def main(argv: list[str] | None = None):
    p = argparse.ArgumentParser(prog="mcp-guard", description="Security gateway for AI agents and MCP tool servers")
    sub = p.add_subparsers(dest="cmd", required=True)

    i = sub.add_parser("init", help="discover a server's tools and write a starter policy")
    i.add_argument("--upstream", required=True, help='command that starts the server, or its URL')
    i.add_argument("--output", "-o", default="mcp-guard.yaml")
    i.add_argument("--role", default="agent")
    i.add_argument("--user", default="my-agent")
    i.add_argument("--exclude", help="comma-separated tools to leave out (hidden and blocked), e.g. run_report,notify_customer")
    i.add_argument("--force", action="store_true")
    i.set_defaults(fn=cmd_init)

    c = sub.add_parser("check", help="validate a policy file")
    c.add_argument("policy", nargs="?", help="default: MCP_GUARD_POLICY or ./mcp-guard.yaml")
    c.add_argument("--upstream", help="also compare the policy with the live server")
    c.set_defaults(fn=cmd_check)

    pn = sub.add_parser("pin", help="fingerprint every tool of an MCP server")
    pn.add_argument("upstream")
    pn.set_defaults(fn=cmd_pin)

    px = sub.add_parser("proxy", help="run the gateway")
    px.add_argument("--upstream")
    px.add_argument("--policy")
    px.add_argument("--user")
    px.add_argument("--audit-log", dest="audit_log")
    px.add_argument("--http", action="store_true", help="serve agents over Streamable HTTP instead of stdio")
    px.add_argument("--host", default="127.0.0.1")
    px.add_argument("--port", type=int, default=8090)
    px.add_argument("--path", default="/mcp")
    px.set_defaults(fn=cmd_proxy)

    api = sub.add_parser("api", help="run the REST policy decision point")
    api.add_argument("--host", default="127.0.0.1")
    api.add_argument("--port", type=int, default=8080)
    api.set_defaults(fn=cmd_api)

    a = p.parse_args(argv)
    sys.exit(a.fn(a))


if __name__ == "__main__":
    main()
