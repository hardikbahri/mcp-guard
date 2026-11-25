import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from mcp_guard import policy  # noqa: E402
from mcp_guard.engine import Guard  # noqa: E402

POLICY = ROOT / "policies" / "complaintops.yaml"


@pytest.fixture
def guard():
    return Guard(policy.load(POLICY))
