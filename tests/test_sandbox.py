"""Sandbox: the docker command it builds, the environment it lets through, and how the proxy uses it.
The end-to-end run (a real container) is demo/sandbox_demo.py, which CI runs in the docker job."""
import shutil
import subprocess

import pytest

from mcp_guard import policy, sandbox
from mcp_guard.proxy import upstream_params
from tests.conftest import POLICY, ROOT

DEMO_POLICY = ROOT / "policies" / "sandbox_demo.yaml"


def flags(cmd):
    return " ".join(cmd)


def test_command_locks_the_container_down():
    sb = sandbox.Sandbox(image="img:1")
    cmd = sb.command(["python", "-m", "demo.rogue_server"])
    s = flags(cmd)
    for f in ("--network none", "--cap-drop ALL", "--security-opt no-new-privileges", "--read-only",
              "--memory 256m", "--memory-swap 256m", "--pids-limit 64", "--user 65534:65534", "--rm -i"):
        assert f in s, f
    assert cmd[-4:] == ["img:1", "python", "-m", "demo.rogue_server"]


def test_secrets_are_passed_by_name_only():
    sb = sandbox.Sandbox(image="img", env=["DB_URL"])
    cmd = sb.command(["srv"])
    assert "--env" in cmd and "DB_URL" in cmd
    assert not any(a.startswith("DB_URL=") for a in cmd)  # no NAME=value on the command line
    env = sb.client_env({"PATH": "/bin", "DB_URL": "pg://x", "OPENAI_API_KEY": "sk-1", "AWS_SECRET_ACCESS_KEY": "a"})
    assert env == {"PATH": "/bin", "DB_URL": "pg://x"}


def test_mounts_are_read_only():
    cmd = sandbox.Sandbox(image="img", mounts=["./models:/models"]).command(["srv"])
    vol = cmd[cmd.index("--volume") + 1]
    assert vol.endswith(":/models:ro") and vol.startswith("/")


@pytest.mark.parametrize("bad", [{"network": "host"}, {"user": "root"}, {"user": "0:0"}, {"mounts": ["nocolon"]}])
def test_unsafe_settings_are_refused(bad):
    with pytest.raises(ValueError):
        sandbox.Sandbox(image="img", **bad)


def test_config_needs_an_image_and_can_be_disabled():
    assert sandbox.from_config(None) is None
    assert sandbox.from_config({"enabled": False, "image": "x"}) is None
    with pytest.raises(ValueError):
        sandbox.from_config({"enabled": True})


def test_unsandboxed_server_env_follows_the_allowlist():
    src = {"PATH": "/bin", "HOME": "/h", "OPENAI_API_KEY": "sk-1", "DB_URL": "pg://x"}
    assert sandbox.upstream_env(None, src) == src  # no allowlist: inherits everything (previous behaviour)
    assert sandbox.upstream_env(["DB_URL"], src) == {"PATH": "/bin", "HOME": "/h", "DB_URL": "pg://x"}


def test_proxy_wraps_the_upstream_in_docker(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setenv("HOST_API_KEY", "sk-demo")
    p = upstream_params("python -m demo.rogue_server", policy.load(DEMO_POLICY))
    assert p.command == "docker" and "--network" in p.args and p.args[-3:] == ["python", "-m", "demo.rogue_server"]
    assert "HOST_API_KEY" not in p.env


def test_sandbox_can_be_switched_off_and_on(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/docker")
    off = upstream_params("python -m demo.rogue_server", policy.load(DEMO_POLICY), force_sandbox="0")
    assert off.command != "docker"
    with pytest.raises(ValueError):  # forcing it on needs an image in the policy
        upstream_params("python -m demo.complaint_server", policy.load(POLICY), force_sandbox="1")


def test_missing_docker_fails_loudly(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: None)
    with pytest.raises(RuntimeError, match="not installed"):
        upstream_params("python -m demo.rogue_server", policy.load(DEMO_POLICY))


def _docker_ok():
    try:
        return subprocess.run(["docker", "image", "inspect", "mcp-guard-sandbox:demo"], capture_output=True,
                              timeout=20).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


@pytest.mark.skipif(not _docker_ok(), reason="needs Docker and the mcp-guard-sandbox:demo image")
def test_rogue_server_is_contained():
    import sys
    sys.path.insert(0, str(ROOT / "demo"))
    import sandbox_demo
    assert sandbox_demo.escaped(sandbox_demo.run(True)) == []
