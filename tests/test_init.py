"""Onboarding: `mcp-guard init` writes a working starter policy, `mcp-guard check` explains what is wrong with one."""
import os
import subprocess
import sys

import anyio
import yaml
from mcp import Client, StdioServerParameters

from mcp_guard import policy
from mcp_guard.init import arg_rules, build_policy
from tests.conftest import ROOT

ENV = {**os.environ, "PYTHONPATH": str(ROOT)}
SERVER = "python -m mcp_guard.demo.complaint_server"


def cli(*args, cwd):
    return subprocess.run([sys.executable, "-m", "mcp_guard.cli", *args], cwd=cwd, env=ENV, capture_output=True,
                          text=True, timeout=60)


def test_arg_rules_come_from_the_tool_schema():
    schema = {"properties": {"text": {"type": "string"}, "code": {"type": "string", "maxLength": 12},
                             "k": {"type": "integer", "minimum": 1, "maximum": 10},
                             "mode": {"type": "string", "enum": ["a", "b"]}, "tags": {"type": "array"},
                             "opt": {"anyOf": [{"type": "string"}, {"type": "null"}]}, "n": {"type": ["integer", "null"], "maximum": 5}}}
    assert arg_rules(schema) == {"text": {"max_length": 10000}, "code": {"max_length": 12}, "k": {"min": 1, "max": 10},
                                 "mode": {"enum": ["a", "b"]}, "tags": {}, "opt": {"max_length": 10000},
                                 "n": {"max": 5}}


def test_starter_policy_flags_risky_tools(tmp_path):
    tools = [{"name": "notify_customer", "inputSchema": {"properties": {"email": {"type": "string"}}}},
             {"name": "delete_records", "inputSchema": {}}, {"name": "classify", "inputSchema": {}}]
    p = tmp_path / "p.yaml"
    p.write_text(build_policy(tools))
    pol = policy.load(p)
    assert pol.tools["notify_customer"].egress == "external" and pol.tools["notify_customer"].on_injection_in_args == "block"
    assert pol.tools["notify_customer"].args["email"].allow_pii
    assert pol.tools["delete_records"].max_calls_per_session == 1 and "REVIEW" in p.read_text()
    assert pol.tools["classify"].egress == "internal"
    assert policy.check(p) == ([], [])


def test_init_then_check_then_proxy(tmp_path):
    r = cli("init", "--upstream", SERVER, cwd=tmp_path)
    assert r.returncode == 0, r.stderr
    out = tmp_path / "mcp-guard.yaml"
    assert "wrote mcp-guard.yaml with 5 tools" in r.stdout and '"command": "mcp-guard"' in r.stdout
    assert cli("init", "--upstream", SERVER, cwd=tmp_path).returncode == 1  # will not overwrite
    pol = policy.load(out)
    assert set(pol.pins) == set(pol.tools) == {"classify_complaint", "search_similar_complaints", "flag_for_review",
                                               "notify_customer", "run_report"}

    r = cli("check", str(out), "--upstream", SERVER, cwd=tmp_path)
    assert r.returncode == 0 and "0 error(s)" in r.stdout, r.stdout

    params = StdioServerParameters(command=sys.executable, args=["-m", "mcp_guard.cli", "proxy", "--upstream", SERVER,
                                   "--policy", str(out), "--user", "my-agent", "--audit-log", ""], cwd=str(tmp_path),
                                   env=ENV)

    async def go():
        async with Client(params) as c:
            return sorted(t.name for t in (await c.list_tools()).tools)
    assert len(anyio.run(go)) == 5


def test_check_catches_a_changed_tool(tmp_path):
    cli("init", "--upstream", SERVER, cwd=tmp_path)
    r = subprocess.run([sys.executable, "-m", "mcp_guard.cli", "check", "mcp-guard.yaml", "--upstream", SERVER],
                       cwd=tmp_path, env={**ENV, "DEMO_POISON_DESCRIPTION": "1"}, capture_output=True, text=True)
    assert r.returncode == 1 and "'classify_complaint' changed on the server" in r.stdout


def test_check_explains_mistakes(tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text(yaml.safe_dump({
        "roles": {"agent": ["classify", "missing_tool"]}, "users": {"bot": ["agent", "ghost_role"]},
        "tools": {"classify": {"args": {"text": {"max_length": 100}}}, "orphan": {}}, "colour": "blue"}))
    errors, warnings = policy.check(p)
    assert any("'missing_tool', which has no entry under tools" in e for e in errors)
    assert any("role 'ghost_role'" in e for e in errors)
    assert any("'orphan' is not granted" in w for w in warnings)
    assert any("unknown top-level key 'colour'" in w for w in warnings)
    p.write_text(yaml.safe_dump({"users": {"bot": ["agent"]}, "roles": {"agent": ["t"]},
                                 "tools": {"t": {"args": {"text": {"maxlen": 5}}}}}))
    errors, _ = policy.check(p)
    assert errors and "unknown setting 'maxlen'" in errors[0]
    assert policy.check(tmp_path / "nope.yaml")[0][0].endswith("file not found (create one with `mcp-guard init`)")
