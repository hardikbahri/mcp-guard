"""Run the upstream MCP tool server inside a locked-down container.

The Guard checks what crosses the MCP boundary: tool listings, arguments and results. It cannot see what a tool server
does inside its own process. A compromised or malicious server (a poisoned package, a "rug pull" update, a code path an
injected argument reaches) can read the host's secrets, write files or call out to the internet without sending a
single suspicious MCP message. The sandbox limits that blast radius: the server runs in a container with no network,
a read-only filesystem, no Linux capabilities, a non-root user, capped memory, CPU and process count, and only the
environment variables the policy names.

OWASP Agentic Top 10: ASI05 Unexpected Code Execution, ASI04 Supply Chain (contains a bad server), ASI08 Cascading
Failures (resource limits).

Policy section (all keys optional except image):

    sandbox:
      enabled: true
      image: mcp-guard-sandbox:latest      # image that contains the tool server
      network: none                        # "none" or a docker network name the server is allowed to use
      memory: 256m
      cpus: "0.5"
      pids_limit: 64
      read_only: true
      tmpfs: /tmp:rw,noexec,nosuid,size=16m
      user: "65534:65534"                  # nobody
      env: [COMPLAINTOPS_DB_URL]           # names passed through; values are never written on the command line
      mounts: ["./models:/models"]         # host:container, always mounted read-only
"""
import os
import shutil
from dataclasses import dataclass, field

# Variables the docker client itself needs to reach the daemon. They go to the `docker` process only,
# never into the container (the container gets nothing unless named in `env`).
DOCKER_CLIENT_ENV = ("PATH", "HOME", "DOCKER_HOST", "DOCKER_CONFIG", "DOCKER_CONTEXT", "DOCKER_CERT_PATH",
                     "DOCKER_TLS_VERIFY", "SYSTEMROOT", "USERPROFILE", "TEMP", "TMP")


@dataclass
class Sandbox:
    image: str
    enabled: bool = True
    network: str = "none"
    memory: str = "256m"
    cpus: str = "0.5"
    pids_limit: int = 64
    read_only: bool = True
    tmpfs: str | None = "/tmp:rw,noexec,nosuid,size=16m"
    user: str = "65534:65534"
    env: list[str] = field(default_factory=list)
    mounts: list[str] = field(default_factory=list)
    runtime: str = "docker"

    def __post_init__(self):
        if self.network == "host":
            raise ValueError("sandbox.network: 'host' would give the server the host's network; use 'none' or a named network")
        if str(self.user).split(":")[0] in ("0", "root"):
            raise ValueError("sandbox.user must not be root")
        for m in self.mounts:
            if m.count(":") < 1:
                raise ValueError(f"sandbox.mounts entry {m!r} must be host:container")

    def command(self, argv: list[str]) -> list[str]:
        """The full `docker run` command that starts `argv` inside the container, with stdio attached for MCP."""
        cmd = [self.runtime, "run", "--rm", "-i",
               "--network", self.network,
               "--cap-drop", "ALL",
               "--security-opt", "no-new-privileges",
               "--memory", self.memory, "--memory-swap", self.memory,  # same value = no swap on top
               "--cpus", str(self.cpus),
               "--pids-limit", str(self.pids_limit),
               "--user", str(self.user)]
        if self.read_only:
            cmd.append("--read-only")
        if self.tmpfs:
            cmd += ["--tmpfs", self.tmpfs]
        for name in self.env:
            cmd += ["--env", name]  # name only: docker copies the value from its own environment
        for m in self.mounts:
            host, _, rest = m.partition(":")
            target = rest.split(":")[0]
            cmd += ["--volume", f"{os.path.abspath(host)}:{target}:ro"]
        return cmd + [self.image, *argv]

    def client_env(self, source: dict[str, str] | None = None) -> dict[str, str]:
        """Environment for the docker client process: what it needs to reach the daemon plus the named pass-through
        variables. Everything else in the gateway's environment (API keys, cloud credentials) stays out."""
        source = os.environ if source is None else source
        keep = set(DOCKER_CLIENT_ENV) | set(self.env)
        return {k: v for k, v in source.items() if k in keep}

    def available(self) -> bool:
        return shutil.which(self.runtime) is not None


def from_config(raw: dict | None) -> Sandbox | None:
    """Build the sandbox from the policy's `sandbox:` section; None when absent or disabled."""
    if not raw or not raw.get("enabled", True):
        return None
    if not raw.get("image"):
        raise ValueError("sandbox.image is required when the sandbox is enabled")
    return Sandbox(**raw)


BASE_ENV = ("PATH", "HOME", "LANG", "LC_ALL", "PYTHONPATH", "VIRTUAL_ENV", "SYSTEMROOT", "TEMP", "TMP")


def upstream_env(passthrough: list[str] | None, source: dict[str, str] | None = None) -> dict[str, str]:
    """Environment for an unsandboxed upstream server. With no allowlist (policy `upstream_env` unset) the server
    inherits the gateway's whole environment, as before. With an allowlist it gets the basics a Python process needs
    plus the named variables, so it cannot read secrets the gateway holds for other purposes."""
    source = os.environ if source is None else source
    if passthrough is None:
        return dict(source)
    keep = set(BASE_ENV) | set(passthrough)
    return {k: v for k, v in source.items() if k in keep}
