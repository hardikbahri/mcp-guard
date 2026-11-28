"""The live demo must keep telling the same story: run it end to end and check the key moments."""
import os
import subprocess
import sys

from tests.conftest import ROOT


def test_live_demo_runs_and_shows_every_beat():
    r = subprocess.run([sys.executable, "-m", "mcp_guard.demo.live", "--no-pause"], cwd=str(ROOT), timeout=180,
                       capture_output=True, text=True, env={**os.environ, "PYTHONPATH": str(ROOT), "NO_COLOR": "1"})
    out = r.stdout
    assert r.returncode == 0, r.stderr[-2000:]
    assert "5 tools: classify_complaint" in out and '"sent_to": "dump@evil.example"' in out      # without the guard
    assert "3 tools: classify_complaint, search_similar_complaints, flag_for_review" in out       # least privilege
    assert "[REDACTED:EMAIL]" in out and "[REMOVED:INJECTION]" in out                             # cleaned result
    assert "notify_customer is not granted" in out and "[ASI05]" in out and "5000 is outside" in out
    assert "session terminated: 4 blocked actions" in out                                         # cut off
    assert "2 tools: search_similar_complaints, flag_for_review" in out                           # rug pull
    assert "terminate" in out and "Full log:" in out                                              # audit
